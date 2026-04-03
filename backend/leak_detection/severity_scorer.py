"""Severity scoring engine for detected leaks."""

from __future__ import annotations

from collections import namedtuple

SeverityResult = namedtuple("SeverityResult", ["level", "score"])

# Base scores by leak type
_BASE_SCORES: dict[str, int] = {
    "email_password_pair": 75,
    "database_url": 90,
    "ssh_private_key": 95,
    "api_key_aws": 90,
    "api_key_google": 80,
    "api_key_github": 75,
    "api_key_stripe": 90,
    "api_key_slack": 65,
    "api_key_openai": 70,
    "api_key_mailgun": 65,
    "api_key_twilio": 70,
    "credit_card_with_cvv": 95,
    "credit_card_no_cvv": 70,
    "bank_account": 80,
    "ssn": 90,
    "crypto_wallet": 40,
}

# Context keywords that boost severity
_BOOSTERS: list[tuple[str, int]] = [
    ("admin", 10),
    ("root", 10),
    ("production", 15),
    ("prod", 15),
    ("live", 10),
    ("master", 5),
    ("private", 5),
    ("secret", 5),
    ("password", 5),
]


def _level_from_score(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def calculate_severity(
    leak_type: str,
    *,
    context: str = "",
) -> SeverityResult:
    """Calculate severity for a detected leak.

    Parameters
    ----------
    leak_type:
        One of the keys in ``_BASE_SCORES``.
    context:
        Surrounding text — used to boost the score when certain keywords appear.
    """
    score = _BASE_SCORES.get(leak_type, 50)

    context_lower = context.lower()
    for keyword, boost in _BOOSTERS:
        if keyword in context_lower:
            score = min(score + boost, 100)

    return SeverityResult(level=_level_from_score(score), score=score)
