"""Company-centric breach and risk lookup over collected intelligence."""

from __future__ import annotations

from typing import Any

from alerts.alert_engine import build_prioritized_alerts
from correlation.signal_correlator import correlate_sources
from nlp.entity_extractor import EntityExtractor
from nlp.slang_decoder import decode_message
from nlp.threat_scorer import calculate_base_score


def build_company_risk_report(
    company: str, records: list[dict[str, Any]]
) -> dict[str, Any]:
    """Generate breach/risk report for one company from unstructured records."""
    term = (company or "").strip()
    if not term:
        return {
            "company": term,
            "overall_risk": "LOW",
            "breach_evidence": [],
            "risk_indicators": {},
            "summary": "No company name provided.",
            "recommendations": [],
        }

    extractor = EntityExtractor()
    matched: list[dict[str, Any]] = []
    texts: list[str] = []

    for rec in records:
        text = str(rec.get("text", ""))
        source = str(rec.get("source", "unknown"))
        if term.lower() not in text.lower():
            continue

        entities = extractor.extract_regex_entities(text)
        score, level = calculate_base_score(text, entities)
        slang = decode_message(text)
        boosted = min(score + slang.get("risk_boost", 0), 100)

        matched.append(
            {
                "source": source,
                "content": text[:350],
                "threat_score": boosted,
                "risk_level": _score_to_level(boosted, level),
                "entities_found": [
                    *entities.get("emails", [])[:3],
                    *entities.get("ips", [])[:3],
                    *entities.get("wallets", [])[:2],
                    *entities.get("btcs", [])[:2],
                ],
                "slang_count": slang.get("slang_count", 0),
                "timestamp": rec.get("timestamp") or rec.get("ingested_at"),
            }
        )
        texts.append(text)

    if not matched:
        return {
            "company": term,
            "overall_risk": "LOW",
            "breach_evidence": [],
            "risk_indicators": {
                "matches": 0,
                "credential_mentions": 0,
                "infrastructure_mentions": 0,
                "financial_mentions": 0,
                "slang_hits": 0,
            },
            "summary": f"No direct breach mentions found for {term}.",
            "recommendations": [
                "Continue monitoring for company mentions across dark-web sources.",
                "Set up watchlist alerts for company domains and executive emails.",
            ],
        }

    corr_payload = [{"text": t, "label": f"rec_{i}"} for i, t in enumerate(texts)]
    correlation = correlate_sources(corr_payload)
    alerts = build_prioritized_alerts(texts, min_priority="MEDIUM")

    credential_mentions = sum(
        1 for m in matched if any("@" in e for e in m["entities_found"])
    )
    infra_mentions = sum(
        1 for m in matched if any(_looks_like_ip(e) for e in m["entities_found"])
    )
    financial_mentions = sum(
        1 for m in matched if any(_looks_like_wallet(e) for e in m["entities_found"])
    )
    slang_hits = sum(int(m.get("slang_count", 0)) for m in matched)

    max_score = max(m["threat_score"] for m in matched)
    overall_risk = _score_to_level(max_score, "LOW")

    return {
        "company": term,
        "overall_risk": overall_risk,
        "breach_evidence": sorted(
            matched, key=lambda x: x["threat_score"], reverse=True
        )[:20],
        "risk_indicators": {
            "matches": len(matched),
            "credential_mentions": credential_mentions,
            "infrastructure_mentions": infra_mentions,
            "financial_mentions": financial_mentions,
            "slang_hits": slang_hits,
            "correlated_entities": correlation.get("total_correlations", 0),
            "high_confidence_signals": correlation.get("high_confidence_signals", 0),
            "prioritized_alerts": alerts.get("total_alerts", 0),
        },
        "summary": (
            f"Found {len(matched)} dark-web mention(s) for {term}. "
            f"Overall risk assessed as {overall_risk}."
        ),
        "recommendations": _recommendations(overall_risk),
    }


def _score_to_level(score: int, fallback: str) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return fallback if fallback in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "LOW"


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _looks_like_wallet(value: str) -> bool:
    return value.startswith("0x") or value.startswith("bc1") or value.startswith("1")


def _recommendations(risk: str) -> list[str]:
    common = [
        "Enable continuous monitoring for company domains, emails, and wallet indicators.",
        "Review exposed credentials and enforce immediate password and key rotation.",
    ]
    if risk in {"CRITICAL", "HIGH"}:
        return common + [
            "Trigger incident response and dark-web takedown/legal workflow immediately.",
            "Notify affected teams and prepare customer breach communication plan.",
        ]
    if risk == "MEDIUM":
        return common + [
            "Increase threat hunting on infrastructure and monitor suspicious logins.",
        ]
    return common
