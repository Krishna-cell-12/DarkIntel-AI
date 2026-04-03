"""Cross-Platform Identity Linker — Brownie Point #2.

Correlates the same identity (email, username, alias, wallet) across
multiple dark web forum posts to build unified threat actor profiles.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

# Regex patterns for identity extraction
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_USERNAME_RE = re.compile(r"@([a-zA-Z0-9_]{3,20})")
_WALLET_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_BTC_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")


def _extract_identifiers(text: str) -> dict[str, list[str]]:
    """Extract all identity-related identifiers from text."""
    return {
        "emails": list(set(_EMAIL_RE.findall(text))),
        "usernames": list(set(_USERNAME_RE.findall(text))),
        "wallets": list(set(_WALLET_RE.findall(text) + _BTC_RE.findall(text))),
    }


def link_identities(posts: list[dict[str, Any]]) -> dict[str, Any]:
    """Find and link the same identity across multiple posts/platforms.

    Parameters
    ----------
    posts:
        List of dicts, each with at least:
            - ``id`` or ``source``: identifier for the post
            - ``content``: the text content
            - ``platform`` (optional): platform/forum name

    Returns
    -------
    dict with:
        - ``identity_profiles``: list of linked identity profiles
        - ``cross_platform_links``: count of identities seen on 2+ platforms
        - ``total_identities``: total unique identities found
    """
    # Map: identifier_value -> list of {post_id, platform, identifier_type}
    identity_map: dict[str, list[dict[str, str]]] = defaultdict(list)

    for post in posts:
        post_id = post.get("id", post.get("source", "unknown"))
        platform = post.get("platform", post.get("source", "unknown"))
        content = post.get("content", post.get("message", ""))

        identifiers = _extract_identifiers(content)

        for id_type, values in identifiers.items():
            for value in values:
                identity_map[value.lower()].append({
                    "post_id": str(post_id),
                    "platform": str(platform),
                    "identifier_type": id_type,
                    "raw_value": value,
                })

    # Build unified profiles — group identifiers that co-occur in same posts
    profiles: list[dict[str, Any]] = []
    cross_platform_count = 0

    for identity_value, appearances in identity_map.items():
        if len(appearances) < 1:
            continue

        unique_platforms = set(a["platform"] for a in appearances)
        unique_posts = set(a["post_id"] for a in appearances)
        id_type = appearances[0]["identifier_type"]

        is_cross_platform = len(unique_platforms) > 1
        if is_cross_platform:
            cross_platform_count += 1

        profile = {
            "identity": identity_value,
            "identity_type": id_type,
            "appearances": len(appearances),
            "platforms": list(unique_platforms),
            "posts": list(unique_posts),
            "is_cross_platform": is_cross_platform,
            "risk_level": _assess_identity_risk(len(appearances), is_cross_platform),
        }
        profiles.append(profile)

    # Sort: cross-platform first, then by appearance count
    profiles.sort(key=lambda p: (-p["is_cross_platform"], -p["appearances"]))

    # Build summary of linked actors (identities appearing in 2+ posts)
    linked_actors = [p for p in profiles if p["appearances"] >= 2]

    return {
        "identity_profiles": profiles,
        "linked_actors": linked_actors,
        "cross_platform_links": cross_platform_count,
        "total_identities": len(profiles),
        "total_linked": len(linked_actors),
        "summary": (
            f"Found {len(profiles)} unique identities. "
            f"{len(linked_actors)} appear in multiple posts. "
            f"{cross_platform_count} linked across platforms."
        ),
    }


def _assess_identity_risk(appearances: int, is_cross_platform: bool) -> str:
    """Assess risk level of an identity based on activity."""
    if is_cross_platform and appearances >= 3:
        return "CRITICAL"
    if is_cross_platform or appearances >= 3:
        return "HIGH"
    if appearances >= 2:
        return "MEDIUM"
    return "LOW"
