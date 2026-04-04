"""Leak Impact Estimation Engine — Brownie Point #3.

Estimates the business impact of detected leaks:
- Number of users potentially affected
- Types of data exposed
- Business risk level
"""

from __future__ import annotations

from typing import Any


# Data type weights for business risk calculation
_DATA_TYPE_WEIGHTS: dict[str, float] = {
    "email_password": 0.7,
    "database_url": 0.9,
    "ssh_private_key": 0.95,
    "aws": 0.9,
    "google": 0.7,
    "github": 0.6,
    "stripe": 0.95,
    "slack": 0.5,
    "openai": 0.6,
    "credit_card_with_cvv": 0.95,
    "credit_card_no_cvv": 0.7,
    "bank_account": 0.85,
    "ssn": 0.95,
    "ethereum_wallet": 0.4,
    "bitcoin_wallet": 0.4,
}

# Friendly names for data types
_DATA_TYPE_LABELS: dict[str, str] = {
    "email_password": "Credentials (Email + Password)",
    "database_url": "Database Connection Strings",
    "ssh_private_key": "SSH Private Keys",
    "aws": "AWS Access Keys",
    "google": "Google API Keys",
    "github": "GitHub Tokens",
    "stripe": "Stripe Payment Keys",
    "slack": "Slack Tokens",
    "openai": "OpenAI API Keys",
    "credit_card_with_cvv": "Credit Cards (with CVV)",
    "credit_card_no_cvv": "Credit Cards (no CVV)",
    "bank_account": "Bank Account Numbers",
    "ssn": "Social Security Numbers",
    "ethereum_wallet": "Ethereum Wallet Addresses",
    "bitcoin_wallet": "Bitcoin Wallet Addresses",
}


def estimate_impact(leak_results: dict[str, Any]) -> dict[str, Any]:
    """Estimate the business impact of detected leaks.

    Parameters
    ----------
    leak_results:
        The output from the full leak detection pipeline, expected to contain
        keys: ``credentials``, ``financial``, ``api_keys``, ``crypto_wallets``.

    Returns
    -------
    dict with:
        - ``users_affected``: estimated number of affected users
        - ``data_types_exposed``: list of data type descriptions
        - ``business_risk``: CRITICAL / HIGH / MEDIUM / LOW
        - ``risk_score``: 0-100 numeric score
        - ``financial_exposure``: estimated financial risk category
        - ``recommendations``: list of recommended actions
    """
    credentials = leak_results.get("credentials", [])
    financial = leak_results.get("financial", [])
    api_keys = leak_results.get("api_keys", [])
    crypto_wallets = leak_results.get("crypto_wallets", [])

    all_items = credentials + financial + api_keys + crypto_wallets

    if not all_items:
        return {
            "users_affected": 0,
            "data_types_exposed": [],
            "business_risk": "NONE",
            "risk_score": 0,
            "financial_exposure": "NONE",
            "recommendations": [],
            "summary": "No leaks detected.",
        }

    # --- Users affected estimation ---
    # Each credential pair ≈ 1 user; DB URLs may expose many; API keys affect org
    users = 0
    for item in credentials:
        t = item.get("type", "")
        if t == "email_password":
            users += 1
        elif t == "database_url":
            users += 500  # a DB URL can expose hundreds of records
        elif t == "ssh_private_key":
            users += 50  # server access can affect many
    for item in financial:
        users += 1  # each card/SSN = 1 person
    for item in api_keys:
        users += 100  # API key breach can affect org-wide
    users = max(users, len(all_items))

    # --- Data types exposed ---
    seen_types: set[str] = set()
    for item in all_items:
        t = item.get("type", "unknown")
        seen_types.add(t)

    data_types_exposed = [
        {
            "type": t,
            "label": _DATA_TYPE_LABELS.get(t, t.replace("_", " ").title()),
            "count": sum(1 for i in all_items if i.get("type") == t),
            "weight": _DATA_TYPE_WEIGHTS.get(t, 0.5),
        }
        for t in sorted(seen_types)
    ]

    # --- Risk score ---
    max_weight = max((d["weight"] for d in data_types_exposed), default=0)
    volume_factor = min(len(all_items) / 20, 1.0)  # caps at 20 items
    risk_score = int(min((max_weight * 70 + volume_factor * 30), 100))

    # --- Business risk level ---
    if risk_score >= 85:
        business_risk = "CRITICAL"
    elif risk_score >= 65:
        business_risk = "HIGH"
    elif risk_score >= 35:
        business_risk = "MEDIUM"
    else:
        business_risk = "LOW"

    # --- Financial exposure ---
    has_financial = any(
        item.get("type", "").startswith("credit_card") or item.get("type") == "bank_account"
        for item in all_items
    )
    has_payment_keys = any(item.get("type") == "stripe" for item in api_keys)
    if has_financial or has_payment_keys:
        financial_exposure = "HIGH — Direct financial data compromised"
    elif any(item.get("type") in ("aws", "database_url") for item in all_items):
        financial_exposure = "MEDIUM — Infrastructure access could lead to financial loss"
    else:
        financial_exposure = "LOW — No direct financial data"

    # --- Recommendations ---
    recommendations = []
    if any(i.get("type") == "email_password" for i in credentials):
        recommendations.append("Force password resets for all affected accounts")
    if any(i.get("type") == "database_url" for i in credentials):
        recommendations.append("Rotate database credentials immediately")
    if any(i.get("type") == "ssh_private_key" for i in credentials):
        recommendations.append("Revoke and regenerate all SSH keys")
    if api_keys:
        recommendations.append("Revoke and rotate all exposed API keys")
    if financial:
        recommendations.append("Notify affected card holders and issue replacements")
        recommendations.append("Report to relevant financial authorities")
    if not recommendations:
        recommendations.append("Monitor for further indicators of compromise")

    return {
        "users_affected": users,
        "data_types_exposed": data_types_exposed,
        "business_risk": business_risk,
        "risk_score": risk_score,
        "financial_exposure": financial_exposure,
        "recommendations": recommendations,
        "summary": (
            f"Estimated {users:,} users affected. "
            f"{len(seen_types)} data type(s) exposed. "
            f"Business risk: {business_risk}."
        ),
    }
