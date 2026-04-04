from typing import Any, Dict, List, Tuple


KEYWORDS = ["leak", "breach", "exploit", "vulnerability", "hack", "stolen"]


def calculate_base_score(text: str, entities_dict: Dict[str, Any]) -> Tuple[int, str]:
    score = 0
    text_lower = (text or "").lower()

    if any(keyword in text_lower for keyword in KEYWORDS):
        score += 10

    wallets: List[str] = entities_dict.get("wallets") or []
    emails: List[str] = entities_dict.get("emails") or []
    ips: List[str] = entities_dict.get("ips") or []

    if len(wallets) > 0:
        score += 20
    if len(emails) > 2:
        score += 15
    if len(ips) > 0:
        score += 10

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    score = min(score, 100)
    return score, level

