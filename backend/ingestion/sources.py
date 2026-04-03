"""Source classification helpers for ingestion."""

from __future__ import annotations


def classify_source_type(source: str) -> str:
    """Classify source label into a normalized source type."""
    src = (source or "").strip().lower()
    if not src:
        return "unknown"

    if any(k in src for k in ("telegram", "t.me", "discord")):
        return "messaging"
    if any(k in src for k in ("onion", "forum", "breachforums")):
        return "forum"
    if any(k in src for k in ("paste", "pastebin", "dump")):
        return "paste"
    if any(k in src for k in ("market", "shop", "vendor")):
        return "market"
    if any(k in src for k in ("github", "gitlab", "repo")):
        return "code"
    return "unknown"


def infer_quality_flags(text: str) -> dict[str, bool | str]:
    """Infer simple quality flags for ingested unstructured text."""
    clean = (text or "").strip()
    length = len(clean)
    if length == 0:
        bucket = "empty"
    elif length < 80:
        bucket = "short"
    elif length < 400:
        bucket = "medium"
    else:
        bucket = "long"

    return {
        "is_empty": length == 0,
        "has_email_like": "@" in clean,
        "has_ip_like": any(ch.isdigit() for ch in clean) and "." in clean,
        "length_bucket": bucket,
    }
