"""Utility helpers for leak detection module."""

from __future__ import annotations


def extract_context(text: str, start: int, end: int, window: int = 60) -> str:
    """Return a snippet of *text* surrounding the match at [start, end)."""
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    snippet = text[ctx_start:ctx_end].replace("\n", " ").strip()
    if ctx_start > 0:
        snippet = "..." + snippet
    if ctx_end < len(text):
        snippet = snippet + "..."
    return snippet


def mask_secret(value: str) -> str:
    """Mask a secret, showing first 2 and last 2 characters."""
    if len(value) <= 4:
        return "****"
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def mask_card_number(card: str) -> str:
    """Mask a credit card number, showing last 4 digits."""
    digits = "".join(c for c in card if c.isdigit())
    if len(digits) < 4:
        return "****"
    return f"****-****-****-{digits[-4:]}"


def mask_last4(value: str) -> str:
    """Mask everything except the last 4 characters."""
    if len(value) <= 4:
        return value
    return "*" * (len(value) - 4) + value[-4:]


def card_type_from_number(card: str) -> str | None:
    """Determine card network from the card number prefix."""
    digits = "".join(c for c in card if c.isdigit())
    if not digits:
        return None

    if digits[0] == "4":
        return "Visa"
    if digits[:2] in ("51", "52", "53", "54", "55"):
        return "Mastercard"
    if digits[:2] in ("34", "37"):
        return "American Express"
    if digits[:4] == "6011" or digits[:2] == "65":
        return "Discover"
    if digits[:2] in ("36", "38"):
        return "Diners Club"
    if digits[:4] == "3528" or digits[:2] == "35":
        return "JCB"
    return "Unknown"
