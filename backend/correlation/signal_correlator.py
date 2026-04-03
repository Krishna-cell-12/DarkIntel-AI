"""Signal Correlation Engine.

Cross-references entities (emails, IPs, wallets, usernames) across multiple
threat sources to identify connected actors, recurring indicators of
compromise, and weak signal patterns that suggest coordinated activity.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_WALLET_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_BTC_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_USERNAME_RE = re.compile(r"@([a-zA-Z0-9_]{3,20})")


def _extract_entities(text: str) -> dict[str, list[str]]:
    return {
        "emails": list(set(_EMAIL_RE.findall(text))),
        "ips": list(set(_IP_RE.findall(text))),
        "wallets": list(set(_WALLET_RE.findall(text) + _BTC_RE.findall(text))),
        "usernames": list(set(_USERNAME_RE.findall(text))),
    }


def correlate_sources(sources: list[dict[str, str]]) -> dict[str, Any]:
    """Correlate entities across multiple threat sources."""
    if not sources:
        return {
            "correlated_entities": [],
            "source_connections": [],
            "signals": [],
            "summary": "No sources provided for correlation.",
        }

    source_entities: list[dict[str, Any]] = []
    for src in sources:
        text = src.get("text", "")
        label = src.get("label", "unknown")
        entities = _extract_entities(text)
        source_entities.append(
            {
                "label": label,
                "text_length": len(text),
                "entities": entities,
                "entity_count": sum(len(v) for v in entities.values()),
            }
        )

    entity_index: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"type": "", "sources": [], "count": 0}
    )

    for src_data in source_entities:
        label = src_data["label"]
        for entity_type, values in src_data["entities"].items():
            for value in values:
                key = value.lower()
                entry = entity_index[key]
                entry["type"] = entity_type
                if label not in entry["sources"]:
                    entry["sources"].append(label)
                entry["count"] = len(entry["sources"])

    correlated = []
    for value, info in entity_index.items():
        if info["count"] >= 2:
            correlated.append(
                {
                    "entity": value,
                    "type": info["type"],
                    "source_count": info["count"],
                    "sources": info["sources"],
                    "confidence": _calc_confidence(info["count"], info["type"]),
                }
            )

    correlated.sort(key=lambda x: (-x["confidence"], -x["source_count"]))

    source_connections = _build_connections(correlated, source_entities)
    signals = _generate_signals(correlated, source_entities)

    total_correlations = len(correlated)
    high_confidence = sum(1 for c in correlated if c["confidence"] >= 70)

    return {
        "correlated_entities": correlated,
        "source_connections": source_connections,
        "signals": signals,
        "total_sources": len(sources),
        "total_correlations": total_correlations,
        "high_confidence_signals": high_confidence,
        "summary": (
            f"Analyzed {len(sources)} sources. "
            f"Found {total_correlations} correlated entities. "
            f"{high_confidence} high-confidence signals detected."
        ),
    }


def _calc_confidence(source_count: int, entity_type: str) -> int:
    base = min(source_count * 25, 75)
    type_bonus = {
        "emails": 15,
        "wallets": 10,
        "ips": 5,
        "usernames": 10,
    }
    return min(base + type_bonus.get(entity_type, 5), 100)


def _build_connections(
    correlated: list[dict],
    source_entities: list[dict],
) -> list[dict[str, Any]]:
    connections = []
    for i, src_a in enumerate(source_entities):
        for j, src_b in enumerate(source_entities):
            if j <= i:
                continue
            shared = []
            for entity in correlated:
                if (
                    src_a["label"] in entity["sources"]
                    and src_b["label"] in entity["sources"]
                ):
                    shared.append(entity["entity"])
            if shared:
                connections.append(
                    {
                        "source_a": src_a["label"],
                        "source_b": src_b["label"],
                        "shared_entities": shared,
                        "connection_strength": len(shared),
                    }
                )
    connections.sort(key=lambda x: -x["connection_strength"])
    return connections


def _generate_signals(
    correlated: list[dict],
    source_entities: list[dict],
) -> list[dict[str, Any]]:
    signals = []

    for entity in correlated:
        if entity["source_count"] >= 3:
            signals.append(
                {
                    "type": "multi_source_actor",
                    "priority": "CRITICAL",
                    "entity": entity["entity"],
                    "entity_type": entity["type"],
                    "sources": entity["sources"],
                    "description": (
                        f"{entity['type'].title()} '{entity['entity']}' found in "
                        f"{entity['source_count']} different sources — possible coordinated actor"
                    ),
                }
            )

    email_sources = set()
    wallet_sources = set()
    for src in source_entities:
        if src["entities"]["emails"]:
            email_sources.add(src["label"])
        if src["entities"]["wallets"]:
            wallet_sources.add(src["label"])
    overlap = email_sources & wallet_sources
    if overlap:
        signals.append(
            {
                "type": "financial_threat_actor",
                "priority": "HIGH",
                "sources": list(overlap),
                "description": (
                    f"Sources contain both emails and crypto wallets — "
                    f"possible financial threat actors in: {', '.join(overlap)}"
                ),
            }
        )

    for src in source_entities:
        if src["entities"]["ips"] and src["entities"]["emails"]:
            signals.append(
                {
                    "type": "infrastructure_credential_link",
                    "priority": "HIGH",
                    "sources": [src["label"]],
                    "description": (
                        f"Source '{src['label']}' contains both IP addresses "
                        f"and email addresses — possible infrastructure leak"
                    ),
                }
            )

    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    signals.sort(key=lambda s: priority_order.get(s["priority"], 4))

    return signals
