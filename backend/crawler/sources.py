"""Source sanitation helpers for .onion monitoring."""

from __future__ import annotations

from urllib.parse import urlparse


def _normalize_onion_url(raw: str) -> str:
    value = (raw or "").strip().strip("'\"")
    if not value:
        return ""

    if ".onion" not in value.lower():
        return ""

    if not value.startswith(("http://", "https://")):
        value = f"http://{value}"

    parsed = urlparse(value)
    if not parsed.netloc or ".onion" not in parsed.netloc.lower():
        return ""

    return value


def sanitize_sources(items: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep only valid .onion source entries."""
    clean: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = _normalize_onion_url(str(item.get("url", "")))
        if not url:
            continue
        clean.append(
            {
                "url": url,
                "source": str(item.get("source", "onion_source")).strip()
                or "onion_source",
                "category": str(item.get("category", "unknown")).strip() or "unknown",
            }
        )
    return clean
