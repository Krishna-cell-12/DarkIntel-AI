"""Regex patterns used by leak detectors."""

from __future__ import annotations

import re

EMAIL_PASSWORD_PATTERNS = [
    r"([\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,})\s*[:|]\s*(\S{6,})",
    r"([\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,})\s+(\S{6,})",
]

EMAIL_VALIDATION_PATTERN = r"^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$"

DATABASE_URL_PATTERN = (
    r"\b(postgres(?:ql)?|mysql|mongodb)://([^:\s/]+):([^@\s]+)@([^/\s]+)/(\w+)"
)

SSH_PRIVATE_KEY_PATTERN = r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"

API_KEY_PATTERNS = {
    "aws": r"\bAKIA[0-9A-Z]{16}\b",
    "google": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "github": r"\bghp_[0-9a-zA-Z]{36}\b",
    "github_oauth": r"\bgho_[0-9a-zA-Z]{36}\b",
    "stripe": r"\bsk_live_[0-9a-zA-Z]{24}\b",
    "slack": r"\bxox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}\b",
    "openai": r"\bsk-[a-zA-Z0-9]{48,51}\b",
    "mailgun": r"\bkey-[0-9a-zA-Z]{32}\b",
    "twilio": r"\bSK[0-9a-fA-F]{32}\b",
}

CREDIT_CARD_PATTERN = r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15}\b"
CVV_PATTERN = r"\b\d{3,4}\b"
BANK_ACCOUNT_PATTERN = r"\b\d{9,12}\b"
ROUTING_NUMBER_PATTERN = r"\b[0-3]\d{8}\b"
SSN_PATTERN = r"\b\d{3}-\d{2}-\d{4}\b"

WALLET_PATTERNS = {
    "ethereum": r"\b0x[a-fA-F0-9]{40}\b",
    "bitcoin": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-z0-9]{39,59}\b",
    "litecoin": r"\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b",
    "dogecoin": r"\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b",
    "monero": r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
}

COMPILED_EMAIL_PASSWORD_PATTERNS = [re.compile(p) for p in EMAIL_PASSWORD_PATTERNS]
COMPILED_EMAIL_VALIDATION = re.compile(EMAIL_VALIDATION_PATTERN)
COMPILED_DATABASE_URL = re.compile(DATABASE_URL_PATTERN, re.IGNORECASE)
COMPILED_SSH_PRIVATE_KEY = re.compile(SSH_PRIVATE_KEY_PATTERN)
COMPILED_API_KEYS = {
    name: re.compile(pattern) for name, pattern in API_KEY_PATTERNS.items()
}

COMPILED_CREDIT_CARD = re.compile(CREDIT_CARD_PATTERN)
COMPILED_CVV = re.compile(CVV_PATTERN)
COMPILED_BANK_ACCOUNT = re.compile(BANK_ACCOUNT_PATTERN)
COMPILED_ROUTING = re.compile(ROUTING_NUMBER_PATTERN)
COMPILED_SSN = re.compile(SSN_PATTERN)

COMPILED_WALLETS = {
    name: re.compile(pattern) for name, pattern in WALLET_PATTERNS.items()
}
