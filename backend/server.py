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


class CrawlRequest(BaseModel):
    urls: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=25, ge=5, le=120)
    tor_proxy: str = Field(default="127.0.0.1:9050")
    source_prefix: str = Field(default="tor_live")


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
def threat_feed(limit: int = 20):
    """Get analyzed threat feed from real ingested/crawled data only."""
    live_items = INGESTOR.recent(limit=max(limit * 5, 200)).get("items", [])
    threats = []
    for i, item in enumerate(live_items[: max(limit, 0)]):
        msg = str(item.get("text", ""))
        if not msg.strip():
            continue
        entities = entity_extractor.extract_regex_entities(msg)
        score, level = calculate_base_score(msg, entities)
        slang = decode_message(msg)
        threats.append(
            {
                "id": str(item.get("id", f"threat_{i:03d}")),
                "content": msg[:220] + ("..." if len(msg) > 220 else ""),
                "full_content": msg,
                "entities": entities,
                "threat_score": score,
                "threat_level": level,
                "slang_count": slang["slang_count"],
                "source": item.get("source", "unknown"),
                "timestamp": item.get("ingested_at", datetime.now().isoformat()),
            }
        )
    return {"threats": threats, "total": len(threats), "real_data_only": True}


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
    sample = [
        str(it.get("text", "")) for it in items if str(it.get("text", "")).strip()
    ]
    return build_prioritized_alerts(
        sample[: max(limit, 0)], min_priority=min_priority.upper()
    )


@app.post("/api/alerts/generate")
def generate_alerts(req: AlertsRequest):
    """Generate prioritized alerts from provided text inputs."""
    return build_prioritized_alerts(req.texts, min_priority=req.min_priority.upper())


# ====================================================================
# Ingestion
# ====================================================================


INGESTOR = ThreatIngestor(max_items=1000)


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
    return INGESTOR.recent(limit=limit, source_type=source_type)


# ====================================================================
# Live Tor Crawler
# ====================================================================


@app.post("/api/crawler/start")
def crawler_start(req: CrawlRequest):
    """Run a Tor crawl and ingest fetched unstructured records."""
    CRAWL_STATE.update(
        {
            "status": "running",
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "last_error": None,
            "tor_connected": False,
            "active_proxy": req.tor_proxy,
            "results_count": 0,
        }
    )

    urls = req.urls
    if not urls:
        CRAWL_STATE.update(
            {"status": "failed", "last_error": "no_live_sources_provided"}
        )
        raise HTTPException(status_code=400, detail="No live .onion URLs provided")
    sources = sanitize_sources(
        [
            {
                "url": u,
                "source": f"{req.source_prefix}_source",
                "category": "unknown",
            }
            for u in urls
        ]
    )
    if not sources:
        CRAWL_STATE.update({"status": "failed", "last_error": "no_valid_onion_sources"})
        raise HTTPException(status_code=400, detail="No valid .onion URLs provided")

    client = TorClient(tor_proxy=req.tor_proxy, timeout=req.timeout_seconds)
    conn = client.check_connection()

    # Auto-fallback for common Tor Browser port when service port is unavailable.
    if not conn.get("connected") and req.tor_proxy.strip() == "127.0.0.1:9050":
        alt_proxy = "127.0.0.1:9150"
        alt_client = TorClient(tor_proxy=alt_proxy, timeout=req.timeout_seconds)
        alt_conn = alt_client.check_connection()
        if alt_conn.get("connected"):
            client = alt_client
            conn = alt_conn
            CRAWL_STATE["active_proxy"] = alt_proxy

    CRAWL_STATE["tor_connected"] = bool(conn.get("connected"))
    if not conn.get("connected"):
        friendly = _friendly_tor_error(conn.get("message", "unknown_error"))
        CRAWL_STATE.update(
            {
                "status": "failed",
                "completed_at": datetime.now().isoformat(),
                "last_error": friendly,
            }
        )
        raise HTTPException(status_code=502, detail=friendly)

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
                {"text": row["text"], "source": src["source"], "language": "unknown"}
            )

    CRAWLED_RECORDS.extend(crawled_now)
    ingest_result = INGESTOR.ingest_many(ingested_payload)
    CRAWL_STATE.update(
        {
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "results_count": len(crawled_now),
            "last_error": None,
        }
    )
    return {
        "crawl_state": CRAWL_STATE,
        "active_proxy": CRAWL_STATE.get("active_proxy"),
        "sources_attempted": len(sources),
        "sources_successful": len([x for x in crawled_now if x["status"] == "success"]),
        "sources_failed": len([x for x in crawled_now if x["status"] != "success"]),
        "ingest_result": ingest_result,
        "results_preview": crawled_now[:10],
    }


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
