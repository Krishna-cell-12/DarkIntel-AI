"""FastAPI service for credential and financial leak detection."""

from __future__ import annotations

import hashlib
import json
import logging
import random
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware

from .cache import TTLCache
from .config import CACHE_TTL_SECONDS, DEMO_MODE, LOG_LEVEL, MAX_TEXT_LENGTH
from .credential_detector import CredentialDetector
from .financial_detector import FinancialDetector
from .models import (
    DetectionRequest,
    DetectionResponse,
    FullDetectionResponse,
    LeakItem,
    StatsResponse,
)

logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger(__name__)

app = FastAPI(title="Leak Detection Module", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

router = APIRouter(prefix="/api/leak-detection", tags=["Leak Detection"])

credential_detector = CredentialDetector()
financial_detector = FinancialDetector()
cache = TTLCache(ttl_seconds=CACHE_TTL_SECONDS)

stats = {
    "total_scans": 0,
    "total_leaks_detected": 0,
    "by_type": {},
}


def _load_demo_data() -> list[dict[str, Any]]:
    project_root = Path(__file__).resolve().parents[3]
    demo_path = project_root / "data" / "leaked_credentials.json"
    if not demo_path.exists():
        logger.warning("Demo data file not found: %s", demo_path)
        return []
    with demo_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


DEMO_SAMPLES = _load_demo_data()


def _hash_text(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _max_severity_from_groups(groups: list[list[dict[str, Any]]]) -> str:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    levels = [item.get("severity", "LOW") for group in groups for item in group]
    if not levels:
        return "LOW"
    return max(levels, key=lambda lvl: order.get(lvl, 0))


def _severity_breakdown(groups: list[list[dict[str, Any]]]) -> dict[str, int]:
    result = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in [entry for group in groups for entry in group]:
        level = item.get("severity", "LOW")
        result[level] = result.get(level, 0) + 1
    return result


def _increment_stats(*groups: list[dict[str, Any]]) -> None:
    stats["total_scans"] += 1
    count = 0
    for group in groups:
        for item in group:
            count += 1
            leak_type = item.get("type", "unknown")
            stats["by_type"][leak_type] = stats["by_type"].get(leak_type, 0) + 1
    stats["total_leaks_detected"] += count


def _ensure_valid_text(request: DetectionRequest) -> str:
    text = request.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    limit = min(request.max_length, MAX_TEXT_LENGTH)
    if len(text) > limit:
        raise HTTPException(
            status_code=413, detail=f"Text exceeds limit of {limit} characters"
        )
    return text


def _demo_payload(text: str) -> dict[str, Any]:
    if not DEMO_SAMPLES:
        return {
            "credentials": [],
            "financial": [],
            "api_keys": [],
            "crypto_wallets": [],
            "total_count": 0,
            "max_severity": "LOW",
        }

    digest = _hash_text(text)
    seed = int(digest[-8:], 16)
    random.seed(seed)

    idx = seed % len(DEMO_SAMPLES)
    sample = DEMO_SAMPLES[idx].get("detection_result", {})
    payload = {
        "credentials": sample.get("credentials", []),
        "financial": sample.get("financial", []),
        "api_keys": sample.get("api_keys", []),
        "crypto_wallets": sample.get("crypto_wallets", []),
    }
    payload["total_count"] = sum(
        len(payload[key])
        for key in ("credentials", "financial", "api_keys", "crypto_wallets")
    )
    payload["max_severity"] = _max_severity_from_groups(
        [
            payload["credentials"],
            payload["financial"],
            payload["api_keys"],
            payload["crypto_wallets"],
        ]
    )
    return payload


def _to_leak_items(
    items: list[dict[str, Any]], value_key_candidates: list[str]
) -> list[LeakItem]:
    output: list[LeakItem] = []
    for item in items:
        value_masked = ""
        for key in value_key_candidates:
            if key in item and item[key] is not None:
                value_masked = str(item[key])
                break
        output.append(
            LeakItem(
                type=item.get("type", "unknown"),
                value_masked=value_masked or "masked",
                severity=item.get("severity", "LOW"),
                severity_score=int(item.get("severity_score", 0)),
                context=item.get("context", ""),
            )
        )
    return output


@router.post("/detect/credentials", response_model=DetectionResponse)
async def detect_credentials(request: DetectionRequest, response: Response):
    started = time.perf_counter()
    text = _ensure_valid_text(request)

    if DEMO_MODE:
        logger.info("DEMO MODE - Using pre-detected data")
        demo = _demo_payload(text)
        credentials = demo["credentials"]
        _increment_stats(credentials)
        response.headers["X-Demo-Mode"] = "true"
        time.sleep(random.uniform(0.3, 0.8))
        return DetectionResponse(
            leaks=_to_leak_items(
                credentials, ["password_masked", "url_masked", "email", "address"]
            ),
            count=len(credentials),
            max_severity=_max_severity_from_groups([credentials]),
            processing_time_ms=(time.perf_counter() - started) * 1000,
            demo_mode=True,
        )

    cache_key = f"cred:{_hash_text(text)}"
    cached = cache.get(cache_key)
    if cached is None:
        result = credential_detector.detect_all_credentials(text)
        credentials = result["credentials"]
        cache.set(cache_key, credentials)
    else:
        credentials = cached

    _increment_stats(credentials)
    return DetectionResponse(
        leaks=_to_leak_items(
            credentials, ["password_masked", "url_masked", "email", "address"]
        ),
        count=len(credentials),
        max_severity=_max_severity_from_groups([credentials]),
        processing_time_ms=(time.perf_counter() - started) * 1000,
        demo_mode=False,
    )


@router.post("/detect/financial", response_model=DetectionResponse)
async def detect_financial(request: DetectionRequest, response: Response):
    started = time.perf_counter()
    text = _ensure_valid_text(request)

    if DEMO_MODE:
        logger.info("DEMO MODE - Using pre-detected data")
        demo = _demo_payload(text)
        financial = demo["financial"]
        _increment_stats(financial)
        response.headers["X-Demo-Mode"] = "true"
        time.sleep(random.uniform(0.3, 0.8))
        return DetectionResponse(
            leaks=_to_leak_items(
                financial, ["card_number", "account_masked", "ssn_masked"]
            ),
            count=len(financial),
            max_severity=_max_severity_from_groups([financial]),
            processing_time_ms=(time.perf_counter() - started) * 1000,
            demo_mode=True,
        )

    cache_key = f"fin:{_hash_text(text)}"
    cached = cache.get(cache_key)
    if cached is None:
        result = financial_detector.detect_financial(text)
        financial = result["financial_data"]
        cache.set(cache_key, financial)
    else:
        financial = cached

    _increment_stats(financial)
    return DetectionResponse(
        leaks=_to_leak_items(
            financial, ["card_number", "account_masked", "ssn_masked"]
        ),
        count=len(financial),
        max_severity=_max_severity_from_groups([financial]),
        processing_time_ms=(time.perf_counter() - started) * 1000,
        demo_mode=False,
    )


@router.post("/detect/api-keys", response_model=DetectionResponse)
async def detect_api_keys(request: DetectionRequest, response: Response):
    started = time.perf_counter()
    text = _ensure_valid_text(request)

    if DEMO_MODE:
        logger.info("DEMO MODE - Using pre-detected data")
        demo = _demo_payload(text)
        api_keys = demo["api_keys"]
        _increment_stats(api_keys)
        response.headers["X-Demo-Mode"] = "true"
        time.sleep(random.uniform(0.3, 0.8))
        return DetectionResponse(
            leaks=_to_leak_items(api_keys, ["key_prefix", "provider"]),
            count=len(api_keys),
            max_severity=_max_severity_from_groups([api_keys]),
            processing_time_ms=(time.perf_counter() - started) * 1000,
            demo_mode=True,
        )

    api_keys = credential_detector.detect_api_keys(text)
    _increment_stats(api_keys)
    return DetectionResponse(
        leaks=_to_leak_items(api_keys, ["key_prefix", "provider"]),
        count=len(api_keys),
        max_severity=_max_severity_from_groups([api_keys]),
        processing_time_ms=(time.perf_counter() - started) * 1000,
        demo_mode=False,
    )


@router.post("/detect/all", response_model=FullDetectionResponse)
async def detect_all(request: DetectionRequest, response: Response):
    started = time.perf_counter()
    text = _ensure_valid_text(request)

    if DEMO_MODE:
        logger.info("DEMO MODE - Using pre-detected data")
        payload = _demo_payload(text)
        credentials = payload["credentials"]
        financial = payload["financial"]
        api_keys = payload["api_keys"]
        wallets = payload["crypto_wallets"]
        _increment_stats(credentials, financial, api_keys, wallets)
        response.headers["X-Demo-Mode"] = "true"
        time.sleep(random.uniform(0.3, 0.8))
        return FullDetectionResponse(
            credentials=credentials,
            financial=financial,
            api_keys=api_keys,
            crypto_wallets=wallets,
            total_count=payload["total_count"],
            max_severity=payload["max_severity"],
            severity_breakdown=_severity_breakdown(
                [credentials, financial, api_keys, wallets]
            ),
            processing_time_ms=(time.perf_counter() - started) * 1000,
            demo_mode=True,
        )

    cred = credential_detector.detect_all_credentials(text)
    fin = financial_detector.detect_financial(text)
    credentials = cred["credentials"]
    financial = fin["financial_data"]
    api_keys = cred["api_keys"]
    wallets = cred["crypto_wallets"]

    _increment_stats(credentials, financial, api_keys, wallets)
    return FullDetectionResponse(
        credentials=credentials,
        financial=financial,
        api_keys=api_keys,
        crypto_wallets=wallets,
        total_count=len(credentials) + len(financial) + len(api_keys) + len(wallets),
        max_severity=_max_severity_from_groups(
            [credentials, financial, api_keys, wallets]
        ),
        severity_breakdown=_severity_breakdown(
            [credentials, financial, api_keys, wallets]
        ),
        processing_time_ms=(time.perf_counter() - started) * 1000,
        demo_mode=False,
    )


@router.get("/stats", response_model=StatsResponse)
async def get_stats():
    return StatsResponse(
        total_scans=stats["total_scans"],
        total_leaks_detected=stats["total_leaks_detected"],
        by_type=stats["by_type"],
        demo_mode=DEMO_MODE,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "demo_mode": DEMO_MODE}


app.include_router(router)
