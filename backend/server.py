"""
DarkIntel-AI — Unified Backend Server
======================================
Single FastAPI application that serves ALL modules:
  - NLP Analysis (entity extraction, threat scoring, slang decoding)
  - Leak Detection (credentials, financial, API keys, crypto wallets)
  - Impact Estimation (users affected, business risk)
  - Identity Linking (cross-platform actor profiles)
  - Dashboard data (stats, threat feed, real-time monitoring)

Run:
    python server.py
    # or: uvicorn server:app --reload --port 8000
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("darkintel")

# ── ensure sub-packages are importable ──────────────────────────────
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env")
load_dotenv(ROOT / "nlp" / ".env")

# ── local imports ───────────────────────────────────────────────────
from nlp.entity_extractor import EntityExtractor
from nlp.language_detector import normalize_text_for_analysis
from nlp.threat_scorer import KEYWORDS, calculate_base_score
from nlp.slang_decoder import decode_message, get_slang_dictionary

from leak_detection.credential_detector import CredentialDetector
from leak_detection.financial_detector import FinancialDetector
from leak_detection.impact_estimator import estimate_impact
from leak_detection.identity_linker import link_identities

from alerts.alert_engine import build_prioritized_alerts
from analytics.company_lookup import build_company_risk_report
from correlation.signal_correlator import correlate_sources
from crawler.sources import sanitize_sources
from crawler.tor_client import TorClient
from ingestion.content_extractor import extract_text_from_bytes, extract_text_from_url
from ingestion.ingestor import ThreatIngestor

# Optional: Groq client (used when API key is configured)
_groq_available = False
try:
    from nlp.groq_client import GroqClient
    from nlp.prompts import ENTITY_EXTRACTION_PROMPT

    _groq_available = bool(os.getenv("GROQ_API_KEY"))
except Exception:
    pass

# ====================================================================
# FastAPI App
# ====================================================================

app = FastAPI(
    title="DarkIntel-AI",
    description="Dark Web Threat Intelligence System — Unified API",
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── singletons ──────────────────────────────────────────────────────
entity_extractor = EntityExtractor()
credential_detector = CredentialDetector()
financial_detector = FinancialDetector()

CRAWL_STATE: dict[str, Any] = {
    "status": "idle",
    "started_at": None,
    "completed_at": None,
    "last_error": None,
    "tor_connected": False,
    "active_proxy": None,
    "results_count": 0,
}
CRAWLED_RECORDS: list[dict[str, Any]] = []

WATCHLIST: dict[str, set[str]] = {
    "companies": set(),
    "domains": set(),
}

MONITOR_STATE: dict[str, Any] = {
    "running": False,
    "started_at": None,
    "stopped_at": None,
    "last_tick": None,
    "interval_seconds": 120,
    "tor_proxy": "127.0.0.1:9050",
    "source_prefix": "monitor",
    "urls": [],
    "ticks_completed": 0,
    "last_error": None,
    "last_result": None,
}
_MONITOR_STOP = threading.Event()
_MONITOR_THREAD: threading.Thread | None = None
_MONITOR_LOCK = threading.Lock()


# ====================================================================
# Request / Response models
# ====================================================================


class TextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)


class MultiTextRequest(BaseModel):
    texts: list[str] = Field(default_factory=list)


class AlertsRequest(BaseModel):
    texts: list[str] = Field(default_factory=list)
    min_priority: str = Field(default="MEDIUM")


class IngestItem(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    source: str = Field(default="manual")
    language: str = Field(default="unknown")


class IngestRequest(BaseModel):
    items: list[IngestItem] = Field(default_factory=list)


class IngestFilePathRequest(BaseModel):
    path: str = Field(..., min_length=1, max_length=500)
    source: str = Field(default="file_path_ingest")
    language: str = Field(default="unknown")


class CrawlRequest(BaseModel):
    urls: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=25, ge=5, le=120)
    tor_proxy: str = Field(default="127.0.0.1:9050")
    source_prefix: str = Field(default="tor_live")


class MonitorStartRequest(BaseModel):
    urls: list[str] = Field(default_factory=list)
    interval_seconds: int = Field(default=120, ge=30, le=3600)
    tor_proxy: str = Field(default="127.0.0.1:9050")
    source_prefix: str = Field(default="monitor")


class WatchlistRequest(BaseModel):
    companies: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)


class PostsRequest(BaseModel):
    posts: list[dict[str, Any]] = Field(default_factory=list)


# ====================================================================
# Global Exception Handlers
# ====================================================================


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    logger.error("Validation error on %s: %s", request.url.path, exc.errors())
    return JSONResponse(
        status_code=422,
        content={"error": "Validation failed", "details": exc.errors()},
    )


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException):
    logger.error(
        "HTTP error on %s: %d - %s", request.url.path, exc.status_code, exc.detail
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )


@app.exception_handler(Exception)
async def general_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s: %s", request.url.path, str(exc))
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred",
        },
    )


# ====================================================================
# Health endpoint
# ====================================================================


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "DarkIntel-AI",
        "groq_available": _groq_available,
        "real_data_only": True,
        "records_buffered": INGESTOR.recent(limit=0).get("total_buffered", 0),
        "crawler_records": len(CRAWLED_RECORDS),
        "monitor_running": bool(MONITOR_STATE.get("running")),
        "watchlist": {
            "companies": len(WATCHLIST.get("companies", set())),
            "domains": len(WATCHLIST.get("domains", set())),
        },
        "timestamp": datetime.now().isoformat(),
    }


# ====================================================================
# NLP — Analyze text
# ====================================================================


@app.post("/api/nlp/analyze")
def nlp_analyze(req: TextRequest):
    started = time.perf_counter()
    lang_info = normalize_text_for_analysis(req.text)
    text = lang_info["normalized_text"]

    # 1. Regex-based entity extraction
    regex_entities = entity_extractor.extract_regex_entities(text)

    # 2. Slang decoding
    slang_result = decode_message(text)

    # 3. Threat scoring
    score, level = calculate_base_score(text, regex_entities)
    # Boost score based on slang
    score = min(score + slang_result["risk_boost"], 100)
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"

    # 4. LLM analysis (optional — only if Groq key is set)
    llm_data: dict[str, Any] = {}
    organizations: list[str] = []
    summary = ""
    if _groq_available:
        try:
            groq = GroqClient(model="llama-3.3-70b-versatile")
            prompt = ENTITY_EXTRACTION_PROMPT.format(text=text)
            llm_data = groq.analyze_text(prompt)
            if isinstance(llm_data, dict) and not llm_data.get("error"):
                orgs = llm_data.get("organizations", [])
                organizations = [str(o) for o in orgs] if isinstance(orgs, list) else []
                summary = str(llm_data.get("summary", ""))
        except Exception:
            pass

    factors = []
    text_lower = text.lower()
    if any(kw in text_lower for kw in KEYWORDS):
        factors.append("keyword_match")
    if len(regex_entities.get("wallets", [])) > 0:
        factors.append("wallets_present")
    if len(regex_entities.get("credentials", [])) > 0:
        factors.append("credentials_present")
    if len(regex_entities.get("emails", [])) > 2:
        factors.append("multiple_emails")
    if len(regex_entities.get("ips", [])) > 0:
        factors.append("ips_present")
    if len(regex_entities.get("domains", [])) > 0:
        factors.append("domains_present")
    if len(regex_entities.get("companies", [])) > 0:
        factors.append("companies_present")
    if slang_result["slang_count"] > 0:
        factors.append("dark_web_slang_detected")

    elapsed = (time.perf_counter() - started) * 1000

    return {
        "entities": {
            "wallets": regex_entities.get("wallets", []),
            "emails": regex_entities.get("emails", []),
            "ips": regex_entities.get("ips", []),
            "domains": regex_entities.get("domains", []),
            "credentials": regex_entities.get("credentials", []),
            "companies": list(
                dict.fromkeys(regex_entities.get("companies", []) + organizations)
            ),
            "organizations": organizations,
        },
        "threat_score": {"score": score, "level": level, "factors": factors},
        "slang": slang_result,
        "language": {
            "detected": lang_info["detected_language"],
            "translated_to_english": lang_info["translated_to_english"],
        },
        "original_text": lang_info["original_text"],
        "summary": summary
        or f"Analyzed {len(text)} chars. Found {slang_result['slang_count']} slang terms.",
        "processing_time_ms": round(elapsed, 2),
    }


# ====================================================================
# NLP — Slang decoder (standalone)
# ====================================================================


@app.post("/api/nlp/slang/decode")
def slang_decode(req: TextRequest):
    return decode_message(req.text)


@app.get("/api/nlp/slang/dictionary")
def slang_dictionary():
    return get_slang_dictionary()


# ====================================================================
# Leak Detection — Detect all
# ====================================================================


@app.post("/api/leaks/detect")
def leaks_detect(req: TextRequest):
    started = time.perf_counter()
    lang_info = normalize_text_for_analysis(req.text)
    text = lang_info["normalized_text"]

    cred = credential_detector.detect_all_credentials(text)
    fin = financial_detector.detect_financial(text)

    result = {
        "credentials": cred["credentials"],
        "financial": fin["financial_data"],
        "api_keys": cred["api_keys"],
        "crypto_wallets": cred["crypto_wallets"],
        "total_count": cred["count"] + fin["count"],
        "max_severity": _max_severity([cred["max_severity"], fin["max_severity"]]),
        "language": {
            "detected": lang_info["detected_language"],
            "translated_to_english": lang_info["translated_to_english"],
        },
        "processing_time_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    return result


# ====================================================================
# Leak Detection — Impact estimation
# ====================================================================


@app.post("/api/leaks/impact")
def leaks_impact(req: TextRequest):
    """Detect leaks AND estimate business impact in one call."""
    lang_info = normalize_text_for_analysis(req.text)
    text = lang_info["normalized_text"]
    cred = credential_detector.detect_all_credentials(text)
    fin = financial_detector.detect_financial(text)

    leak_data = {
        "credentials": cred["credentials"],
        "financial": fin["financial_data"],
        "api_keys": cred["api_keys"],
        "crypto_wallets": cred["crypto_wallets"],
    }

    impact = estimate_impact(leak_data)
    return {
        "leaks": leak_data,
        "impact": impact,
        "language": {
            "detected": lang_info["detected_language"],
            "translated_to_english": lang_info["translated_to_english"],
        },
    }


# ====================================================================
# Identity Linking
# ====================================================================


@app.post("/api/leaks/identities")
def leaks_identities(req: PostsRequest):
    """Link identities across multiple posts."""
    posts = req.posts
    if not posts:
        return {
            "identity_profiles": [],
            "linked_actors": [],
            "cross_platform_links": 0,
            "total_identities": 0,
            "total_linked": 0,
            "summary": "No real posts provided. Ingest or crawl sources first.",
        }
    return link_identities(posts)


# ====================================================================
# Threat Feed (real ingested/crawled data)
# ====================================================================


@app.get("/api/threats/feed")
def threat_feed(
    limit: int = 20,
    only_new: bool = False,
    new_window_minutes: int = 180,
    min_score: int = 20,
):
    """Get analyzed threat feed from real ingested/crawled data only.

    Args:
        limit: Maximum number of threats to return
        only_new: If True, only return threats seen within new_window_minutes
        new_window_minutes: Window for "new" threat detection
        min_score: Minimum threat score to include (default 20, filters noise)
    """
    now = datetime.now()
    live_items = INGESTOR.recent(limit=max(limit * 5, 200)).get("items", [])
    threats = []
    for i, item in enumerate(live_items):
        msg = str(item.get("text", ""))
        if not msg.strip():
            continue

        first_seen = item.get("first_seen_at") or item.get("ingested_at")
        is_new = False
        try:
            dt = datetime.fromisoformat(str(first_seen))
            is_new = ((now - dt).total_seconds() / 60.0) <= max(new_window_minutes, 1)
        except Exception:
            is_new = False

        if only_new and not is_new:
            continue

        entities = entity_extractor.extract_regex_entities(msg)
        score, level = calculate_base_score(msg, entities)

        # Noise filter: skip low-score benign content
        if score < min_score:
            continue

        slang = decode_message(msg)
        threats.append(
            {
                "id": str(item.get("id", f"threat_{i:03d}")),
                "content": msg[:220] + ("..." if len(msg) > 220 else ""),
                "full_content": msg,
                "entities": entities,
                "threat_score": score,
                "threat_level": level,
                "severity": level,  # Alias for UI consistency
                "slang_count": slang["slang_count"],
                "source": item.get("source", "unknown"),
                "timestamp": item.get("ingested_at", datetime.now().isoformat()),
                "first_seen_at": first_seen,
                "is_new": is_new,
                "occurrences": int(item.get("occurrences", 1)),
            }
        )
        if len(threats) >= max(limit, 0):
            break

    return {
        "threats": threats,
        "total": len(threats),
        "real_data_only": True,
        "min_score_applied": min_score,
    }


@app.get("/api/threats/new")
def new_threats(limit: int = 20, window_minutes: int = 180):
    """Return only newly-seen unique threats within a recent window."""
    return threat_feed(limit=limit, only_new=True, new_window_minutes=window_minutes)


# ====================================================================
# Dashboard data
# ====================================================================


@app.get("/api/dashboard/stats")
def dashboard_stats():
    """Get summary statistics for the dashboard."""
    items = INGESTOR.recent(limit=1000).get("items", [])
    levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_entities = 0
    for item in items:
        msg = str(item.get("text", ""))
        if not msg.strip():
            continue
        ents = entity_extractor.extract_regex_entities(msg)
        _, level = calculate_base_score(msg, ents)
        levels[level] = levels.get(level, 0) + 1
        total_entities += sum(len(v) for v in ents.values())

    return {
        "total_threats_analyzed": len(items),
        "threat_distribution": levels,
        "total_entities_extracted": total_entities,
        "modules_active": 8,
        "crawler_records": len(CRAWLED_RECORDS),
        "real_data_only": True,
        "last_scan": datetime.now().isoformat(),
        "status": "operational",
    }


@app.get("/api/dashboard/data")
def dashboard_data():
    """Get full dashboard data payload."""
    stats = dashboard_stats()
    feed = threat_feed(limit=10)

    posts = []
    for item in INGESTOR.recent(limit=120).get("items", []):
        posts.append(
            {
                "id": item.get("id"),
                "content": item.get("text", ""),
                "platform": item.get("source", "unknown"),
            }
        )
    identities = (
        link_identities(posts)
        if posts
        else {
            "total_identities": 0,
            "cross_platform_links": 0,
            "linked_actors": [],
        }
    )

    return {
        "stats": stats,
        "recent_threats": feed["threats"][:5],
        "identity_summary": {
            "total_identities": identities["total_identities"],
            "cross_platform_links": identities["cross_platform_links"],
            "linked_actors": identities["linked_actors"][:5],
        },
        "real_data_only": True,
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/analytics/early-warning")
def early_warning():
    """Detect emerging attack signals from recent real-world ingest stream."""
    now = datetime.now()
    items = INGESTOR.recent(limit=1000).get("items", [])

    current_hour: list[dict[str, Any]] = []
    previous_hour: list[dict[str, Any]] = []
    for item in items:
        ts_raw = item.get("ingested_at")
        try:
            ts = datetime.fromisoformat(str(ts_raw))
        except Exception:
            continue

        age_min = (now - ts).total_seconds() / 60.0
        if 0 <= age_min <= 60:
            current_hour.append(item)
        elif 60 < age_min <= 120:
            previous_hour.append(item)

    def score_of(record: dict[str, Any]) -> int:
        text = str(record.get("text", ""))
        ents = entity_extractor.extract_regex_entities(text)
        score, _ = calculate_base_score(text, ents)
        score = min(score + decode_message(text).get("risk_boost", 0), 100)
        return score

    current_scores = [score_of(r) for r in current_hour]
    previous_scores = [score_of(r) for r in previous_hour]

    high_current = sum(1 for s in current_scores if s >= 65)
    high_previous = sum(1 for s in previous_scores if s >= 65)
    critical_current = sum(1 for s in current_scores if s >= 85)

    current_count = len(current_hour)
    prev_count = len(previous_hour)
    surge_ratio = round((current_count / max(prev_count, 1)), 2)

    level = "LOW"
    if current_count >= 4 and surge_ratio >= 2.0:
        level = "HIGH"
    if high_current >= 4 or critical_current >= 2:
        level = "HIGH"
    if (critical_current >= 3 and surge_ratio >= 1.5) or high_current >= 7:
        level = "CRITICAL"
    elif high_current >= 2:
        level = "MEDIUM"

    top_companies: dict[str, int] = {}
    for item in current_hour:
        companies = entity_extractor.extract_regex_entities(
            str(item.get("text", ""))
        ).get("companies", [])
        for c in companies:
            top_companies[c] = top_companies.get(c, 0) + 1

    top_company_list = [
        {"company": k, "mentions": v}
        for k, v in sorted(top_companies.items(), key=lambda kv: kv[1], reverse=True)[
            :5
        ]
    ]

    return {
        "warning_level": level,
        "current_window_records": current_count,
        "previous_window_records": prev_count,
        "surge_ratio": surge_ratio,
        "high_risk_current": high_current,
        "high_risk_previous": high_previous,
        "critical_current": critical_current,
        "top_companies": top_company_list,
        "summary": (
            f"Early-warning level {level}. "
            f"Current hour={current_count}, previous hour={prev_count}, surge={surge_ratio}x."
        ),
    }


# ====================================================================
# Signal Correlation
# ====================================================================


@app.post("/api/correlate")
def correlate_signals(req: MultiTextRequest):
    """Correlate weak signals across multiple threat sources."""
    sources = [{"text": t, "label": f"source_{i}"} for i, t in enumerate(req.texts)]
    return correlate_sources(sources)


# ====================================================================
# Alert Generation
# ====================================================================


@app.get("/api/alerts")
def get_alerts(limit: int = 20, min_priority: str = "MEDIUM"):
    """Generate prioritized alerts from real ingested feed."""
    items = INGESTOR.recent(limit=max(limit * 5, 200)).get("items", [])

    sample_items: list[dict[str, Any]] = []
    for it in items:
        text = str(it.get("text", "")).strip()
        if not text:
            continue
        sample_items.append(it)
        if len(sample_items) >= max(limit, 0):
            break

    sample_texts = [str(it.get("text", "")) for it in sample_items]
    payload = build_prioritized_alerts(
        sample_texts,
        min_priority=min_priority.upper(),
    )

    source_index_map: dict[str, dict[str, Any]] = {}
    for idx, it in enumerate(sample_items):
        key = f"source_{idx}"
        source_index_map[key] = {
            "threat_id": str(it.get("id", "")),
            "source": str(it.get("source", "unknown")),
            "timestamp": str(it.get("ingested_at", "")),
            "preview": str(it.get("text", ""))[:120],
            "occurrences": int(it.get("occurrences", 1)),
        }

    for alert in payload.get("alerts", []):
        labels = [s for s in alert.get("sources", []) if isinstance(s, str)]
        related_threat_ids: list[str] = []
        related_sources: list[dict[str, Any]] = []

        for label in labels:
            mapped = source_index_map.get(label)
            if not mapped:
                continue
            threat_id = str(mapped.get("threat_id", ""))
            if threat_id and threat_id not in related_threat_ids:
                related_threat_ids.append(threat_id)
            related_sources.append(mapped)

        alert["related_threat_ids"] = related_threat_ids
        alert["related_sources"] = related_sources

    payload["source_index_map"] = source_index_map
    return payload


@app.post("/api/alerts/generate")
def generate_alerts(req: AlertsRequest):
    """Generate prioritized alerts from provided text inputs."""
    return build_prioritized_alerts(req.texts, min_priority=req.min_priority.upper())


@app.post("/api/correlate/auto")
def auto_correlate_pipeline(req: TextRequest):
    """Auto-correlation pipeline: Leak Detection → Threat Feed → Alerts.

    This endpoint:
    1. Detects leaks in the input text
    2. If CRITICAL/HIGH severity found, auto-ingests to threat feed
    3. Runs correlation across recent data
    4. Generates prioritized alerts

    Returns the full pipeline result for the UI.
    """
    from datetime import datetime

    # Step 1: Detect leaks
    lang_info = normalize_text_for_analysis(req.text)
    text = lang_info["normalized_text"]
    cred = credential_detector.detect_all_credentials(text)
    fin = financial_detector.detect_financial(text)

    leak_data = {
        "credentials": cred["credentials"],
        "financial": fin["financial_data"],
        "api_keys": cred["api_keys"],
        "crypto_wallets": cred["crypto_wallets"],
    }

    max_sev = _max_severity([cred["max_severity"], fin["max_severity"]])
    total_leaks = cred["count"] + fin["count"]

    # Step 2: Auto-ingest to threat feed if significant findings
    auto_ingested = False
    ingest_result = None
    if max_sev in ("CRITICAL", "HIGH") or total_leaks >= 3:
        ingest_result = INGESTOR.ingest_many(
            [
                {
                    "text": req.text,
                    "source": "auto_correlation_pipeline",
                    "language": lang_info.get("detected_language", "unknown"),
                }
            ]
        )
        auto_ingested = True

    # Step 3: Run correlation on recent data
    recent_items = INGESTOR.recent(limit=50).get("items", [])
    sources_for_corr = []
    for i, item in enumerate(recent_items):
        item_text = str(item.get("text", "")).strip()
        if item_text:
            sources_for_corr.append({"text": item_text, "label": f"source_{i}"})

    correlation_result = (
        correlate_sources(sources_for_corr)
        if sources_for_corr
        else {
            "correlated_entities": [],
            "signals": [],
            "summary": "No sources for correlation.",
        }
    )

    # Step 4: Generate alerts from recent feed
    sample_texts = [s["text"] for s in sources_for_corr[:30]]
    alerts_result = build_prioritized_alerts(sample_texts, min_priority="LOW")

    # Step 5: Estimate impact
    impact = estimate_impact(leak_data)

    return {
        "pipeline": "auto_correlate",
        "input_severity": max_sev,
        "total_leaks_detected": total_leaks,
        "auto_ingested": auto_ingested,
        "ingest_result": ingest_result,
        "leaks": leak_data,
        "impact": impact,
        "correlation": {
            "total_correlations": correlation_result.get("total_correlations", 0),
            "high_confidence_signals": correlation_result.get(
                "high_confidence_signals", 0
            ),
            "signals": correlation_result.get("signals", [])[:10],
            "summary": correlation_result.get("summary", ""),
        },
        "alerts": {
            "total_alerts": alerts_result.get("total_alerts", 0),
            "distribution": alerts_result.get("distribution", {}),
            "top_alerts": alerts_result.get("alerts", [])[:10],
            "summary": alerts_result.get("summary", ""),
        },
        "language": {
            "detected": lang_info.get("detected_language", "unknown"),
            "translated": lang_info.get("translated_to_english", False),
        },
    }


# ====================================================================
# Ingestion
# ====================================================================


INGEST_CACHE_PATH = ROOT / "data" / "ingest_cache.json"
INGESTOR = ThreatIngestor(max_items=1000, persist_path=str(INGEST_CACHE_PATH))


@app.post("/api/ingest")
def ingest_sources(req: IngestRequest):
    """Ingest unstructured threat sources into in-memory buffer."""
    payload = [item.model_dump() for item in req.items]
    return INGESTOR.ingest_many(payload)


@app.post("/api/ingest/file")
async def ingest_file(
    file: UploadFile = File(...),
    source: str = Form(default="file_upload"),
    language: str = Form(default="unknown"),
):
    """Ingest data from file of any form (text/json/csv/pdf/image)."""
    filename = file.filename or "uploaded.bin"
    payload = await file.read()
    extracted = extract_text_from_bytes(
        payload, filename=filename, content_type=file.content_type
    )
    text = str(extracted.get("text", "")).strip()
    if not text:
        return {
            "ingested_count": 0,
            "summary": "No extractable text found in uploaded file.",
            "file": {
                "name": filename,
                "kind": extracted.get("kind"),
                "warnings": extracted.get("warnings", []),
            },
        }

    ing = INGESTOR.ingest_many(
        [
            {
                "text": text,
                "source": source,
                "language": language,
            }
        ]
    )
    return {
        "file": {
            "name": filename,
            "kind": extracted.get("kind"),
            "length": extracted.get("length", 0),
            "warnings": extracted.get("warnings", []),
        },
        "ingest_result": ing,
    }


@app.post("/api/ingest/file-path")
def ingest_file_path(req: IngestFilePathRequest):
    """Ingest data from a local file path on backend host."""
    candidate = Path(req.path).expanduser()
    if not candidate.is_absolute():
        candidate = ROOT / candidate

    file_path = candidate.resolve()
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="File path not found")

    # Restrict to known safe roots to avoid arbitrary file exfiltration.
    allowed_roots = [ROOT.parent.resolve(), ROOT.resolve()]
    if not any(
        str(file_path).lower().startswith(str(root).lower()) for root in allowed_roots
    ):
        raise HTTPException(
            status_code=400,
            detail="File path outside allowed project/workspace roots",
        )

    payload = file_path.read_bytes()
    extracted = extract_text_from_bytes(
        payload,
        filename=file_path.name,
        content_type=None,
    )
    text = str(extracted.get("text", "")).strip()
    if not text:
        return {
            "ingested_count": 0,
            "summary": "No extractable text found in file path.",
            "file": {
                "path": str(file_path),
                "name": file_path.name,
                "kind": extracted.get("kind"),
                "warnings": extracted.get("warnings", []),
            },
        }

    ing = INGESTOR.ingest_many(
        [
            {
                "text": text,
                "source": req.source,
                "language": req.language,
            }
        ]
    )
    return {
        "file": {
            "path": str(file_path),
            "name": file_path.name,
            "kind": extracted.get("kind"),
            "length": extracted.get("length", 0),
            "warnings": extracted.get("warnings", []),
        },
        "ingest_result": ing,
    }


@app.post("/api/ingest/url")
def ingest_url(url: str = Form(...), source: str = Form(default="url_fetch")):
    """Ingest data from URL (supports html/json/csv/pdf/image payloads)."""
    extracted = extract_text_from_url(url)
    text = str(extracted.get("text", "")).strip()
    if not text:
        return {
            "ingested_count": 0,
            "summary": "No extractable text found at URL.",
            "url": url,
            "kind": extracted.get("kind"),
            "warnings": extracted.get("warnings", []),
        }

    ing = INGESTOR.ingest_many(
        [
            {
                "text": text,
                "source": source,
                "language": "unknown",
            }
        ]
    )
    return {
        "url": url,
        "kind": extracted.get("kind"),
        "warnings": extracted.get("warnings", []),
        "ingest_result": ing,
    }


@app.get("/api/ingest/recent")
def ingest_recent(limit: int = 20, source_type: str | None = None):
    """Return recent ingested source records."""
    data = INGESTOR.recent(limit=limit, source_type=source_type)
    data["persist_path"] = str(INGEST_CACHE_PATH)
    return data


def _resolve_tor_client(
    tor_proxy: str, timeout_seconds: int
) -> tuple[TorClient | None, dict[str, Any], str]:
    """Resolve Tor client with automatic 9050 -> 9150 fallback."""
    client = TorClient(tor_proxy=tor_proxy, timeout=timeout_seconds)
    conn = client.check_connection()
    active_proxy = tor_proxy

    if not conn.get("connected") and tor_proxy.strip() == "127.0.0.1:9050":
        alt_proxy = "127.0.0.1:9150"
        alt_client = TorClient(tor_proxy=alt_proxy, timeout=timeout_seconds)
        alt_conn = alt_client.check_connection()
        if alt_conn.get("connected"):
            client = alt_client
            conn = alt_conn
            active_proxy = alt_proxy

    if not conn.get("connected"):
        return None, conn, active_proxy
    return client, conn, active_proxy


def _evaluate_watchlist_hits(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Find watchlist matches and generate high-priority alerts from matches."""
    companies = WATCHLIST.get("companies", set())
    domains = WATCHLIST.get("domains", set())
    if not companies and not domains:
        return {
            "companies": [],
            "domains": [],
            "matched_records": 0,
            "alerts": {"total_alerts": 0, "distribution": {}},
        }

    hit_companies: set[str] = set()
    hit_domains: set[str] = set()
    matched_texts: list[str] = []

    for rec in records:
        text = str(rec.get("text", ""))
        if not text:
            continue
        lower = text.lower()
        c_hit = [c for c in companies if c.lower() in lower]
        d_hit = [d for d in domains if d.lower() in lower]
        if c_hit or d_hit:
            hit_companies.update(c_hit)
            hit_domains.update(d_hit)
            matched_texts.append(text)

    alerts = build_prioritized_alerts(matched_texts, min_priority="HIGH")
    distribution = alerts.get("distribution", {}) if isinstance(alerts, dict) else {}
    active_levels = [
        lv for lv, count in distribution.items() if isinstance(count, int) and count > 0
    ]
    highest_priority = _max_severity(active_levels)

    return {
        "companies": sorted(hit_companies),
        "domains": sorted(hit_domains),
        "matched_records": len(matched_texts),
        "highest_priority": highest_priority,
        "alerts": {
            "total_alerts": alerts.get("total_alerts", 0),
            "distribution": distribution,
        },
    }


def _run_crawl_once(
    urls: list[str],
    timeout_seconds: int,
    tor_proxy: str,
    source_prefix: str,
) -> dict[str, Any]:
    """Run one crawl cycle and ingest successful payloads."""
    CRAWL_STATE.update(
        {
            "status": "running",
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "last_error": None,
            "tor_connected": False,
            "active_proxy": tor_proxy,
            "results_count": 0,
        }
    )

    if not urls:
        msg = "No live .onion URLs provided"
        CRAWL_STATE.update(
            {
                "status": "failed",
                "completed_at": datetime.now().isoformat(),
                "last_error": msg,
            }
        )
        return {"ok": False, "status_code": 400, "error": msg}

    sources = sanitize_sources(
        [
            {
                "url": u,
                "source": f"{source_prefix}_source",
                "category": "unknown",
            }
            for u in urls
        ]
    )
    if not sources:
        msg = "No valid .onion URLs provided"
        CRAWL_STATE.update(
            {
                "status": "failed",
                "completed_at": datetime.now().isoformat(),
                "last_error": msg,
            }
        )
        return {"ok": False, "status_code": 400, "error": msg}

    client, conn, active_proxy = _resolve_tor_client(tor_proxy, timeout_seconds)
    CRAWL_STATE["active_proxy"] = active_proxy
    CRAWL_STATE["tor_connected"] = bool(conn.get("connected"))
    if client is None:
        friendly = _friendly_tor_error(conn.get("message", "unknown_error"))
        CRAWL_STATE.update(
            {
                "status": "failed",
                "completed_at": datetime.now().isoformat(),
                "last_error": friendly,
            }
        )
        return {"ok": False, "status_code": 502, "error": friendly}

    crawled_now: list[dict[str, Any]] = []
    ingested_payload: list[dict[str, str]] = []
    for src in sources:
        result = client.fetch_onion(src["url"])
        row = {
            "url": src["url"],
            "source": src["source"],
            "category": src["category"],
            "timestamp": datetime.now().isoformat(),
            "status": result.get("status", "failed"),
            "title": result.get("content", {}).get("title", "")
            if result.get("content")
            else "",
            "text": result.get("content", {}).get("text", "")
            if result.get("content")
            else "",
            "error": result.get("error"),
        }
        crawled_now.append(row)
        if row["status"] == "success" and row["text"]:
            ingested_payload.append(
                {
                    "text": row["text"],
                    "source": src["source"],
                    "language": "unknown",
                }
            )

    CRAWLED_RECORDS.extend(crawled_now)
    ingest_result = INGESTOR.ingest_many(ingested_payload)
    watchlist_result = _evaluate_watchlist_hits(ingest_result.get("records", []))

    CRAWL_STATE.update(
        {
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "results_count": len(crawled_now),
            "last_error": None,
        }
    )

    return {
        "ok": True,
        "status_code": 200,
        "crawl_state": dict(CRAWL_STATE),
        "active_proxy": CRAWL_STATE.get("active_proxy"),
        "sources_attempted": len(sources),
        "sources_successful": len([x for x in crawled_now if x["status"] == "success"]),
        "sources_failed": len([x for x in crawled_now if x["status"] != "success"]),
        "ingest_result": ingest_result,
        "watchlist": watchlist_result,
        "results_preview": crawled_now[:10],
    }


def _monitor_result_snapshot(result: dict[str, Any]) -> dict[str, Any]:
    ingest_result = result.get("ingest_result", {}) if isinstance(result, dict) else {}
    watchlist_result = result.get("watchlist", {}) if isinstance(result, dict) else {}
    watchlist_alerts = (
        watchlist_result.get("alerts", {}) if isinstance(watchlist_result, dict) else {}
    )

    return {
        "ok": result.get("ok"),
        "sources_successful": result.get("sources_successful", 0),
        "sources_failed": result.get("sources_failed", 0),
        "ingested_count": int(ingest_result.get("ingested_count", 0)),
        "updated_count": int(ingest_result.get("updated_count", 0)),
        "watchlist": watchlist_result,
        "watchlist_matches": int(watchlist_result.get("matched_records", 0)),
        "watchlist_alerts_total": int(watchlist_alerts.get("total_alerts", 0)),
        "highest_priority": str(watchlist_result.get("highest_priority", "LOW")),
    }


def _monitor_worker() -> None:
    """Background loop for proactive periodic crawling."""
    while not _MONITOR_STOP.is_set():
        with _MONITOR_LOCK:
            if not MONITOR_STATE.get("running"):
                break
            urls = list(MONITOR_STATE.get("urls", []))
            interval = int(MONITOR_STATE.get("interval_seconds", 120))
            tor_proxy = str(MONITOR_STATE.get("tor_proxy", "127.0.0.1:9050"))
            source_prefix = str(MONITOR_STATE.get("source_prefix", "monitor"))

        result = _run_crawl_once(
            urls=urls,
            timeout_seconds=25,
            tor_proxy=tor_proxy,
            source_prefix=source_prefix,
        )

        with _MONITOR_LOCK:
            MONITOR_STATE["last_tick"] = datetime.now().isoformat()
            MONITOR_STATE["ticks_completed"] = (
                int(MONITOR_STATE.get("ticks_completed", 0)) + 1
            )
            MONITOR_STATE["last_result"] = _monitor_result_snapshot(result)
            MONITOR_STATE["last_error"] = (
                None if result.get("ok") else result.get("error")
            )

        if _MONITOR_STOP.wait(interval):
            break

    with _MONITOR_LOCK:
        MONITOR_STATE["running"] = False
        MONITOR_STATE["stopped_at"] = datetime.now().isoformat()


# ====================================================================
# Live Tor Crawler
# ====================================================================


@app.post("/api/crawler/start")
def crawler_start(req: CrawlRequest):
    """Run a Tor crawl and ingest fetched unstructured records."""
    result = _run_crawl_once(
        urls=req.urls,
        timeout_seconds=req.timeout_seconds,
        tor_proxy=req.tor_proxy,
        source_prefix=req.source_prefix,
    )
    if not result.get("ok"):
        raise HTTPException(
            status_code=int(result.get("status_code", 500)),
            detail=str(result.get("error", "crawl_failed")),
        )
    return result


@app.get("/api/crawler/status")
def crawler_status():
    """Return latest Tor crawl status."""
    return dict(CRAWL_STATE)


@app.get("/api/crawler/results")
def crawler_results(limit: int = 20):
    """Return latest crawled records."""
    return {
        "count": min(max(limit, 0), len(CRAWLED_RECORDS)),
        "total": len(CRAWLED_RECORDS),
        "items": CRAWLED_RECORDS[-max(limit, 0) :],
    }


# ====================================================================
# Proactive Monitor + Watchlist
# ====================================================================


@app.post("/api/monitor/start")
def monitor_start(req: MonitorStartRequest):
    """Start periodic proactive monitoring loop."""
    global _MONITOR_THREAD
    urls = sanitize_sources(
        [
            {
                "url": u,
                "source": f"{req.source_prefix}_source",
                "category": "unknown",
            }
            for u in req.urls
        ]
    )
    if not urls:
        raise HTTPException(
            status_code=400, detail="No valid .onion URLs provided for monitor"
        )

    with _MONITOR_LOCK:
        if MONITOR_STATE.get("running"):
            return dict(MONITOR_STATE)

        MONITOR_STATE.update(
            {
                "running": True,
                "started_at": datetime.now().isoformat(),
                "stopped_at": None,
                "last_tick": None,
                "interval_seconds": req.interval_seconds,
                "tor_proxy": req.tor_proxy,
                "source_prefix": req.source_prefix,
                "urls": [x["url"] for x in urls],
                "ticks_completed": 0,
                "last_error": None,
                "last_result": None,
            }
        )

    _MONITOR_STOP.clear()
    _MONITOR_THREAD = threading.Thread(
        target=_monitor_worker, name="darkintel-monitor", daemon=True
    )
    _MONITOR_THREAD.start()
    return dict(MONITOR_STATE)


@app.post("/api/monitor/stop")
def monitor_stop():
    """Stop periodic proactive monitoring loop."""
    _MONITOR_STOP.set()
    with _MONITOR_LOCK:
        MONITOR_STATE["running"] = False
        MONITOR_STATE["stopped_at"] = datetime.now().isoformat()
    return dict(MONITOR_STATE)


@app.get("/api/monitor/status")
def monitor_status():
    """Get current proactive monitor status."""
    with _MONITOR_LOCK:
        return dict(MONITOR_STATE)


@app.post("/api/monitor/tick")
def monitor_tick(req: CrawlRequest):
    """Run one manual monitor cycle with watchlist evaluation."""
    result = _run_crawl_once(
        urls=req.urls,
        timeout_seconds=req.timeout_seconds,
        tor_proxy=req.tor_proxy,
        source_prefix=req.source_prefix,
    )
    if not result.get("ok"):
        raise HTTPException(
            status_code=int(result.get("status_code", 500)),
            detail=str(result.get("error", "monitor_tick_failed")),
        )

    with _MONITOR_LOCK:
        MONITOR_STATE["last_tick"] = datetime.now().isoformat()
        MONITOR_STATE["ticks_completed"] = (
            int(MONITOR_STATE.get("ticks_completed", 0)) + 1
        )
        MONITOR_STATE["last_result"] = _monitor_result_snapshot(result)
        MONITOR_STATE["last_error"] = None

    return result


@app.post("/api/watchlist/set")
def watchlist_set(req: WatchlistRequest):
    """Replace watchlist values used for proactive escalation."""
    WATCHLIST["companies"] = {
        x.strip() for x in req.companies if isinstance(x, str) and x.strip()
    }
    WATCHLIST["domains"] = {
        x.strip().lower() for x in req.domains if isinstance(x, str) and x.strip()
    }
    return {
        "companies": sorted(WATCHLIST["companies"]),
        "domains": sorted(WATCHLIST["domains"]),
        "counts": {
            "companies": len(WATCHLIST["companies"]),
            "domains": len(WATCHLIST["domains"]),
        },
    }


@app.get("/api/watchlist")
def watchlist_get():
    """Read active watchlist."""
    return {
        "companies": sorted(WATCHLIST["companies"]),
        "domains": sorted(WATCHLIST["domains"]),
        "counts": {
            "companies": len(WATCHLIST["companies"]),
            "domains": len(WATCHLIST["domains"]),
        },
    }


# ====================================================================
# Company Breach Lookup
# ====================================================================


@app.get("/api/company/lookup")
def company_lookup(name: str):
    """Lookup company breach/risk indicators from unstructured intelligence."""
    records = []

    # Live crawled + ingested records
    records.extend(CRAWLED_RECORDS)
    recent_ingested = INGESTOR.recent(limit=500).get("items", [])
    records.extend(recent_ingested)

    return build_company_risk_report(name, records)


# ====================================================================
# Helpers
# ====================================================================


def _max_severity(levels: list[str]) -> str:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if not levels:
        return "LOW"
    return max(levels, key=lambda lv: order.get(lv, 0))


def _friendly_tor_error(message: str) -> str:
    text = str(message or "")
    if "10061" in text or "actively refused" in text:
        return (
            "Tor proxy unreachable. Start Tor service/browser and use proxy "
            "127.0.0.1:9050 (service) or 127.0.0.1:9150 (Tor Browser)."
        )
    if "timed out" in text.lower():
        return "Tor request timed out. Verify Tor is running and internet is available."
    return f"Tor unavailable: {text}"


# ====================================================================
# Startup Event — Pre-seed threat data
# ====================================================================


@app.on_event("startup")
def preseed_threat_data():
    """Pre-seed test threat data on startup for demo/hackathon purposes."""
    import json as _json

    test_data_path = ROOT.parent / "test_threat_data.json"
    if not test_data_path.exists():
        logger.warning("Pre-seed file not found: %s", test_data_path)
        return

    try:
        raw = test_data_path.read_text(encoding="utf-8")
        records = _json.loads(raw)
        if not isinstance(records, list):
            logger.warning("Pre-seed file is not a list, skipping.")
            return

        items_to_ingest = []
        for rec in records:
            text = rec.get("text", "").strip()
            if not text:
                continue
            items_to_ingest.append(
                {
                    "text": text,
                    "source": rec.get("source", "preseed_test_data"),
                    "language": rec.get("language", "en"),
                }
            )

        if items_to_ingest:
            result = INGESTOR.ingest_many(items_to_ingest)
            logger.info(
                "Pre-seeded %d threat records from test_threat_data.json (ingested=%d, updated=%d)",
                len(items_to_ingest),
                result.get("ingested_count", 0),
                result.get("updated_count", 0),
            )
        else:
            logger.info("Pre-seed file had no valid records.")
    except Exception as e:
        logger.error("Failed to pre-seed threat data: %s", str(e))


# ====================================================================
# Entry point
# ====================================================================

if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger("darkintel")

    port = int(os.getenv("PORT", "8000"))
    logger.info("DarkIntel-AI server starting on http://localhost:%d", port)
    logger.info("API docs at http://localhost:%d/docs", port)
    logger.info("Groq LLM: %s", "available" if _groq_available else "not configured")
    logger.info("Mode: real-data-only")

    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=True)
