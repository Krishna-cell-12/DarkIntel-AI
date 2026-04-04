"""Dark Web Slang Decoder — Brownie Point #1.

Translates coded language and slang commonly used on dark web forums
into plain-English descriptions for threat analysts.
"""

from __future__ import annotations

import re
from typing import Any

# Comprehensive dark web slang dictionary
SLANG_DICTIONARY: dict[str, str] = {
    # Credential & Data Theft
    "fresh": "freshly obtained stolen data (often credentials/logs)",
    "fresh logs": "recently stolen credentials / session cookies",
    "logs": "stolen browser session data or credentials",
    "fullz": "complete identity data (name, SSN, DOB, address, etc.)",
    "cc dumps": "stolen credit card magnetic stripe data",
    "dumps": "stolen credit card data or database exports",
    "combos": "username:password combination lists",
    "combo list": "list of email:password or user:password pairs",
    "stealer logs": "data exfiltrated by info-stealer malware",
    "clouds": "stolen cloud service credentials (AWS, Azure, GCP)",
    "cookies": "stolen browser session cookies for account takeover",
    "config": "tool configuration file for credential stuffing attacks",
    "hits": "valid/working stolen credentials after testing",
    "dehashed": "credentials obtained from breached database lookups",
    # Financial Fraud
    "carding": "using stolen credit card data for purchases",
    "bins": "bank identification numbers used to generate fake cards",
    "cvv": "credit card verification value (stolen card details)",
    "cc": "stolen credit card information",
    "cashout": "converting stolen funds/crypto to real money",
    "drop": "shipping address/person used to receive fraudulently-purchased goods",
    "money mule": "person who transfers stolen money on behalf of criminals",
    "loading": "putting stolen funds onto prepaid cards",
    "swipe": "cloned credit card with stolen magnetic stripe data",
    # Hacking & Exploits
    "zero day": "previously unknown software vulnerability",
    "0day": "previously unknown software vulnerability",
    "rat": "remote access trojan (backdoor malware)",
    "botnet": "network of compromised computers under attacker control",
    "c2": "command and control server for malware",
    "c&c": "command and control infrastructure",
    "shell": "remote command execution access on compromised server",
    "webshell": "malicious script providing web-based remote access",
    "rootkit": "deeply embedded malware that hides its presence",
    "crypter": "tool to make malware undetectable by antivirus",
    "fud": "fully undetectable (malware bypassing all antivirus)",
    "exploit kit": "toolkit for automatically exploiting browser vulnerabilities",
    "payload": "malicious code delivered through an exploit",
    "backdoor": "hidden unauthorized access point in a system",
    "brute": "brute-force password guessing attack",
    "sqli": "SQL injection attack to access databases",
    "rce": "remote code execution vulnerability",
    "lpe": "local privilege escalation exploit",
    # Ransomware
    "raas": "ransomware-as-a-service (rented ransomware operation)",
    "locker": "ransomware that locks the victim's system",
    "encryptor": "ransomware that encrypts victim files",
    "decryptor": "tool to decrypt files after ransom payment",
    "ransom note": "message demanding payment to restore access",
    # Communication & Operations
    "opsec": "operational security practices to avoid detection",
    "burner": "disposable phone/email used for anonymity",
    "pgp": "encrypted communication using PGP keys",
    "wickr": "encrypted messaging app popular in dark web",
    "jabber": "XMPP messaging used for criminal communication",
    "tor": "the onion router network for anonymous browsing",
    "vpn": "virtual private network for hiding IP address",
    "proxy": "intermediary server to mask network origin",
    "socks": "SOCKS proxy for routing traffic anonymously",
    # Dark Web Marketplace
    "vendor": "seller on a dark web marketplace",
    "escrow": "marketplace holds payment until buyer confirms delivery",
    "fe": "finalize early — release payment before confirming delivery",
    "pgp verified": "seller identity verified using PGP signature",
    "bulk": "large quantity purchase at discount",
    "sample": "free/cheap test product to verify quality",
    "vouched": "endorsed by trusted community member",
    "ripper": "scammer on dark web marketplace",
    "exit scam": "marketplace/vendor disappearing with funds",
}

# Non-English slang aliases mapped to existing meanings
MULTILINGUAL_ALIASES: dict[str, str] = {
    # Russian dark web slang
    "свежие": "fresh",
    "логи": "logs",
    "фулз": "fullz",
    "кардинг": "carding",
    "дампы": "dumps",
    "комбо": "combos",
    "слив": "dumps",  # leak/dump
    "малварь": "rat",  # malware
    "ботнет": "botnet",
    "крипт": "crypter",
    "эксплоит": "exploit kit",
    "шелл": "shell",
    "бэкдор": "backdoor",
    "рансом": "locker",  # ransomware
    "биткойн": "cashout",
    "дроп": "drop",
    "обнал": "cashout",  # cashing out
    "пробив": "dehashed",  # database lookup
    "база": "dumps",  # database
    "аккаунты": "logs",  # accounts
    "пароли": "combos",  # passwords
    "куки": "cookies",
    "прокси": "proxy",
    "впн": "vpn",
    "тор": "tor",
    # Chinese dark web slang (Pinyin and characters)
    "数据": "dumps",  # data
    "密码": "combos",  # passwords
    "账号": "logs",  # accounts
    "信用卡": "cc",  # credit card
    "身份证": "fullz",  # ID card / identity
    "黑客": "shell",  # hacker
    "木马": "rat",  # trojan
    "病毒": "payload",  # virus
    "漏洞": "zero day",  # vulnerability
    "肉鸡": "botnet",  # compromised hosts ("meat chickens")
    "挖矿": "crypter",  # mining (cryptominer)
    "代理": "proxy",  # proxy
    "洗钱": "cashout",  # money laundering
    "诈骗": "ripper",  # fraud/scam
    "钓鱼": "payload",  # phishing
    "社工": "fullz",  # social engineering
    "暗网": "tor",  # dark web
    "比特币": "cashout",  # bitcoin
    # Spanish dark web slang
    "credenciales": "logs",
    "tarjetas": "cc",
    "contraseñas": "combos",
    "datos robados": "dumps",
    "cuentas": "logs",
    "billetera": "cashout",
    "estafa": "ripper",
    "hackeo": "shell",
    # French dark web slang
    "identites completes": "fullz",
    "cartes volees": "cc dumps",
    "mots de passe": "combos",
    "donnees volees": "dumps",
    "comptes": "logs",
    "piratage": "shell",
    # Portuguese dark web slang
    "senhas": "combos",
    "cartoes": "cc",
    "contas": "logs",
    "vazamento": "dumps",  # leak
    # German dark web slang
    "passwörter": "combos",
    "kreditkarten": "cc",
    "konten": "logs",
    "datenleck": "dumps",
}

# Compile regex patterns for efficient matching
_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(rf"\b{re.escape(slang)}\b", re.IGNORECASE), slang, meaning)
    for slang, meaning in SLANG_DICTIONARY.items()
]

_ALIAS_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(rf"\b{re.escape(alias)}\b", re.IGNORECASE),
        alias,
        SLANG_DICTIONARY[normalized],
    )
    for alias, normalized in MULTILINGUAL_ALIASES.items()
    if normalized in SLANG_DICTIONARY
]

_ALL_PATTERNS = _PATTERNS + _ALIAS_PATTERNS


def decode_message(text: str) -> dict[str, Any]:
    """Decode dark web slang in a message.

    Returns a dict with:
        - ``decoded_text``: the original text with slang annotated
        - ``slang_found``: list of {term, meaning, position} dicts
        - ``slang_count``: total number of slang terms detected
        - ``risk_boost``: suggested risk score boost based on slang density
    """
    slang_found: list[dict[str, Any]] = []
    seen_terms: set[str] = set()

    for pattern, term, meaning in _ALL_PATTERNS:
        for match in pattern.finditer(text):
            key = (term.lower(), match.start())
            if key not in seen_terms:
                seen_terms.add(key)
                slang_found.append(
                    {
                        "term": match.group(0),
                        "normalized_term": term,
                        "meaning": meaning,
                        "position": match.start(),
                    }
                )

    # Sort by position in text
    slang_found.sort(key=lambda x: x["position"])

    # Build annotated text
    decoded_text = text
    for item in reversed(slang_found):
        pos = item["position"]
        end = pos + len(item["term"])
        annotation = f"{item['term']} [{item['meaning']}]"
        decoded_text = decoded_text[:pos] + annotation + decoded_text[end:]

    # Risk boost based on slang density
    risk_boost = min(len(slang_found) * 5, 30)

    return {
        "original_text": text,
        "decoded_text": decoded_text,
        "slang_found": slang_found,
        "slang_count": len(slang_found),
        "risk_boost": risk_boost,
    }


def get_slang_dictionary() -> dict[str, str]:
    """Return the full slang dictionary for reference."""
    return dict(SLANG_DICTIONARY)
