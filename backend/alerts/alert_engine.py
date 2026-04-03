"""Alert generation and prioritization engine.

Builds prioritized alerts from threat correlations and per-message scoring.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from correlation.signal_correlator import correlate_sources
from nlp.entity_extractor import EntityExtractor
from nlp.slang_decoder import decode_message
from nlp.threat_scorer import calculate_base_score


def build_prioritized_alerts(
    texts: list[str],
    min_priority: str = "MEDIUM",
) -> dict[str, Any]:
    """Build prioritized alerts from threat text inputs.

    Parameters
    ----------
    texts:
        Raw text inputs from multiple sources.
    min_priority:
        Minimum alert priority to keep: LOW/MEDIUM/HIGH/CRITICAL.
    """
    clean_texts = [t for t in texts if isinstance(t, str) and t.strip()]
    if not clean_texts:
        return {
            "alerts": [],
            "total_alerts": 0,
            "distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "summary": "No valid threat text provided.",
        }

    extractor = EntityExtractor()
    sources = [{"text": t, "label": f"source_{i}"} for i, t in enumerate(clean_texts)]
    correlation = correlate_sources(sources)

    alerts: list[dict[str, Any]] = []

    # 1) Correlation-based alerts
    for signal in correlation.get("signals", []):
        priority = signal.get("priority", "MEDIUM")
        alerts.append(
            {
                "id": f"corr_{len(alerts):04d}",
                "type": "correlation_signal",
                "priority": priority,
                "title": _signal_title(signal),
                "description": signal.get("description", "Correlation signal detected"),
                "sources": signal.get("sources", []),
                "score": _priority_score(priority),
                "created_at": datetime.now().isoformat(),
            }
        )

    # 2) Message-level risk alerts
    for idx, text in enumerate(clean_texts):
        entities = extractor.extract_regex_entities(text)
        base_score, level = calculate_base_score(text, entities)
        slang = decode_message(text)
        final_score = min(base_score + slang.get("risk_boost", 0), 100)
        final_level = _score_to_priority(final_score, fallback=level)
        if final_score < 40:
            continue

        reasons = []
        if entities.get("emails"):
            reasons.append("credential indicators")
        if entities.get("ips"):
            reasons.append("infrastructure indicators")
        if entities.get("wallets") or entities.get("btcs"):
            reasons.append("financial indicators")
        if slang.get("slang_count", 0) > 0:
            reasons.append("dark-web slang detected")

        alerts.append(
            {
                "id": f"msg_{idx:04d}",
                "type": "message_risk",
                "priority": final_level,
                "title": f"High-risk source_{idx} content",
                "description": (
                    f"Threat score {final_score}/100 in source_{idx}"
                    + (f" ({', '.join(reasons)})" if reasons else "")
                ),
                "sources": [f"source_{idx}"],
                "score": final_score,
                "created_at": datetime.now().isoformat(),
            }
        )

    # Filter and sort
    alerts = [
        a
        for a in alerts
        if _priority_rank(a["priority"]) >= _priority_rank(min_priority)
    ]
    alerts.sort(key=lambda a: (_priority_rank(a["priority"]), a["score"]), reverse=True)

    distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for alert in alerts:
        distribution[alert["priority"]] = distribution.get(alert["priority"], 0) + 1

    return {
        "alerts": alerts,
        "total_alerts": len(alerts),
        "distribution": distribution,
        "correlation_summary": correlation.get("summary", ""),
        "summary": (
            f"Generated {len(alerts)} alerts from {len(clean_texts)} source(s). "
            f"CRITICAL={distribution['CRITICAL']}, HIGH={distribution['HIGH']}."
        ),
    }


def _signal_title(signal: dict[str, Any]) -> str:
    stype = signal.get("type", "signal")
    if stype == "multi_source_actor":
        return "Multi-source actor correlation"
    if stype == "financial_threat_actor":
        return "Financial threat actor indicators"
    if stype == "infrastructure_credential_link":
        return "Infrastructure + credential linkage"
    return "Correlation signal detected"


def _priority_rank(priority: str) -> int:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order.get(priority.upper(), 1)


def _priority_score(priority: str) -> int:
    scores = {"LOW": 30, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 90}
    return scores.get(priority.upper(), 50)


def _score_to_priority(score: int, fallback: str = "LOW") -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if fallback in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return fallback
    return "LOW"
