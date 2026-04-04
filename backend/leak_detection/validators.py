"""Validation helpers for leak detection."""

from __future__ import annotations


def validate_luhn(card_number: str) -> bool:
    """Validate a card number using the Luhn algorithm.

    Strips non-digit characters before checking.
    Returns ``True`` when the number passes the Luhn check.
    """
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d

    return total % 10 == 0
