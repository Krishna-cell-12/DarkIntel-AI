"""
DarkIntel-AI — Unified Backend Server
======================================
Single FastAPI application that serves ALL modules:
  - NLP Analysis (entity extraction, threat scoring, slang decoding)
  - Leak Detection (credentials, financial, API keys, crypto wallets)
  - Impact Estimation (users affected, business risk)
  - Identity Linking (cross-platform actor profiles)
  - Dashboard data (stats, threat feed, demo data)

Run:
    python server.py
    # or: uvicorn server:app --reload --port 8000
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
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
from nlp.threat_scorer import KEYWORDS, calculate_base_score
from nlp.slang_decoder import decode_message, get_slang_dictionary

from leak_detection.credential_detector import CredentialDetector
from leak_detection.financial_detector import FinancialDetector
from leak_detection.impact_estimator import estimate_impact
from leak_detection.identity_linker import link_identities

from alerts.alert_engine import build_prioritized_alerts
from correlation.signal_correlator import correlate_sources

# Optional: Groq client (works without API key in demo mode)
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
    allow_origins=["http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── singletons ──────────────────────────────────────────────────────
entity_extractor = EntityExtractor()
credential_detector = CredentialDetector()
financial_detector = FinancialDetector()

# ── load demo / precomputed data ────────────────────────────────────
DATA_DIR = ROOT.parent / "data"


def _load_json(name: str) -> Any:
    path = DATA_DIR / name
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


SYNTHETIC_THREATS: list[str] = _load_json("synthetic_threats.json")
PRECOMPUTED_ENTITIES: list[dict] = _load_json("precomputed_entities.json")


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
        "demo_data_loaded": len(SYNTHETIC_THREATS) > 0,
        "timestamp": datetime.now().isoformat(),
    }


# ====================================================================
# NLP — Analyze text
# ====================================================================


@app.post("/api/nlp/analyze")
def nlp_analyze(req: TextRequest):
    started = time.perf_counter()
    text = req.text

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
    if len(regex_entities.get("emails", [])) > 2:
        factors.append("multiple_emails")
    if len(regex_entities.get("ips", [])) > 0:
        factors.append("ips_present")
    if slang_result["slang_count"] > 0:
        factors.append("dark_web_slang_detected")

    elapsed = (time.perf_counter() - started) * 1000

    return {
        "entities": {
            "wallets": regex_entities.get("wallets", []),
            "emails": regex_entities.get("emails", []),
            "ips": regex_entities.get("ips", []),
            "organizations": organizations,
        },
        "threat_score": {"score": score, "level": level, "factors": factors},
        "slang": slang_result,
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
    text = req.text

    cred = credential_detector.detect_all_credentials(text)
    fin = financial_detector.detect_financial(text)

    result = {
        "credentials": cred["credentials"],
        "financial": fin["financial_data"],
        "api_keys": cred["api_keys"],
        "crypto_wallets": cred["crypto_wallets"],
        "total_count": cred["count"] + fin["count"],
        "max_severity": _max_severity([cred["max_severity"], fin["max_severity"]]),
        "processing_time_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    return result


# ====================================================================
# Leak Detection — Impact estimation
# ====================================================================


@app.post("/api/leaks/impact")
def leaks_impact(req: TextRequest):
    """Detect leaks AND estimate business impact in one call."""
    text = req.text
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
    }


# ====================================================================
# Identity Linking
# ====================================================================


@app.post("/api/leaks/identities")
def leaks_identities(req: PostsRequest):
    """Link identities across multiple posts."""
    posts = req.posts
    if not posts:
        # Use demo data if no posts provided
        posts = [
            {"id": f"demo_{i}", "content": msg, "platform": f"forum_{i % 3}"}
            for i, msg in enumerate(SYNTHETIC_THREATS[:10])
        ]
    return link_identities(posts)


# ====================================================================
# Threat Feed (demo data)
# ====================================================================


@app.get("/api/threats/feed")
def threat_feed(limit: int = 20):
    """Get the threat feed — uses precomputed demo data."""
    threats = []
    for i, msg in enumerate(SYNTHETIC_THREATS[:limit]):
        entities = entity_extractor.extract_regex_entities(msg)
        score, level = calculate_base_score(msg, entities)
        slang = decode_message(msg)
        threats.append(
            {
                "id": f"threat_{i:03d}",
                "content": msg[:200] + ("..." if len(msg) > 200 else ""),
                "full_content": msg,
                "entities": entities,
                "threat_score": score,
                "threat_level": level,
                "slang_count": slang["slang_count"],
                "timestamp": datetime.now().isoformat(),
            }
        )
    return {"threats": threats, "total": len(threats)}


# ====================================================================
# Dashboard data
# ====================================================================


@app.get("/api/dashboard/stats")
def dashboard_stats():
    """Get summary statistics for the dashboard."""
    # Compute from synthetic threats
    levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_entities = 0
    for msg in SYNTHETIC_THREATS:
        ents = entity_extractor.extract_regex_entities(msg)
        _, level = calculate_base_score(msg, ents)
        levels[level] = levels.get(level, 0) + 1
        total_entities += sum(len(v) for v in ents.values())

    return {
        "total_threats_analyzed": len(SYNTHETIC_THREATS),
        "threat_distribution": levels,
        "total_entities_extracted": total_entities,
        "modules_active": 5,
        "last_scan": datetime.now().isoformat(),
        "status": "operational",
    }


@app.get("/api/dashboard/data")
def dashboard_data():
    """Get full dashboard data payload."""
    stats = dashboard_stats()
    feed = threat_feed(limit=10)

    # Identity linking on demo data
    posts = [
        {"id": f"post_{i}", "content": msg, "platform": f"forum_{i % 3}"}
        for i, msg in enumerate(SYNTHETIC_THREATS[:20])
    ]
    identities = link_identities(posts)

    return {
        "stats": stats,
        "recent_threats": feed["threats"][:5],
        "identity_summary": {
            "total_identities": identities["total_identities"],
            "cross_platform_links": identities["cross_platform_links"],
            "linked_actors": identities["linked_actors"][:5],
        },
        "timestamp": datetime.now().isoformat(),
    }


# ====================================================================
# Precomputed entities endpoint
# ====================================================================


@app.get("/api/precomputed/entities")
def precomputed_entities():
    """Return precomputed entity extraction results."""
    return {"count": len(PRECOMPUTED_ENTITIES), "data": PRECOMPUTED_ENTITIES[:20]}


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
    """Generate prioritized alerts from the threat feed."""
    sample = SYNTHETIC_THREATS[: max(limit, 0)]
    return build_prioritized_alerts(sample, min_priority=min_priority.upper())


@app.post("/api/alerts/generate")
def generate_alerts(req: AlertsRequest):
    """Generate prioritized alerts from provided text inputs."""
    return build_prioritized_alerts(req.texts, min_priority=req.min_priority.upper())


# ====================================================================
# Helpers
# ====================================================================


def _max_severity(levels: list[str]) -> str:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if not levels:
        return "LOW"
    return max(levels, key=lambda lv: order.get(lv, 0))


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
    logger.info(
        "Groq LLM: %s", "available" if _groq_available else "demo mode (no API key)"
    )
    logger.info("Demo data: %d synthetic threats loaded", len(SYNTHETIC_THREATS))

    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=True)
