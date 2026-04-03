from typing import Any, Dict, List, Tuple


KEYWORDS = ["leak", "breach", "exploit", "vulnerability", "hack", "stolen"]
HIGH_SEVERITY_KEYWORDS = [
    "zero-day",
    "0day",
    "ransomware",
    "rootkit",
    "trojan",
    "backdoor",
    "c2",
    "botnet",
    "fullz",
    "dumps",
    "combos",
    "carding",
    "cvv",
    "stealer",
    "webshell",
    "rat",
    "rce",
    "sqli",
    "lpe",
    "raas",
    "decryptor",
    "locker",
    "encryptor",
]


def calculate_base_score(text: str, entities_dict: Dict[str, Any]) -> Tuple[int, str]:
    score = 0
    text_lower = (text or "").lower()

    if any(keyword in text_lower for keyword in KEYWORDS):
        score += 15

    if any(keyword in text_lower for keyword in HIGH_SEVERITY_KEYWORDS):
        score += 30

    wallets: List[str] = entities_dict.get("wallets") or []
    emails: List[str] = entities_dict.get("emails") or []
    ips: List[str] = entities_dict.get("ips") or []

    if len(wallets) > 0:
        score += 20
    if len(emails) > 2:
        score += 15
    elif len(emails) > 0:
        score += 5
    if len(ips) > 0:
        score += 10

    text_len = len(text_lower)
    if text_len > 200:
        score += 10
    elif text_len > 100:
        score += 5

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
