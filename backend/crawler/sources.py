"""Curated crawl source presets for .onion monitoring."""

from __future__ import annotations


DEFAULT_ONION_SOURCES: list[dict[str, str]] = [
    {
        "url": "http://exampleonion1.onion",
        "source": "forum_watch_1",
        "category": "forum",
    },
    {
        "url": "http://exampleonion2.onion",
        "source": "paste_watch_1",
        "category": "paste",
    },
]


def sanitize_sources(items: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep only valid .onion source entries."""
    clean: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "")).strip()
        if not url or ".onion" not in url:
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
