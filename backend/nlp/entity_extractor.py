import re
from typing import Dict, List


class EntityExtractor:
    wallet_pattern = r"0x[a-fA-F0-9]{40}"
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    btc_pattern = r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    credential_pattern = (
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*[:|]\s*[^\s]{4,}\b"
    )
    company_pattern = (
        r"\b(?:[A-Z][a-zA-Z0-9&.-]*\s+){0,3}"
        r"(?:[A-Z][a-zA-Z0-9&.-]*\s+)"
        r"(?:Inc|Corp|Corporation|Ltd|Limited|LLC|PLC|Group|Systems|Technologies|Bank|Labs)\b"
    )

    def __init__(self) -> None:
        self._wallet_re = re.compile(self.wallet_pattern)
        self._email_re = re.compile(self.email_pattern)
        self._ip_re = re.compile(self.ip_pattern)
        self._btc_re = re.compile(self.btc_pattern)
        self._domain_re = re.compile(self.domain_pattern)
        self._credential_re = re.compile(self.credential_pattern)
        self._company_re = re.compile(self.company_pattern)

    def extract_regex_entities(self, text: str) -> Dict[str, List[str]]:
        raw_domains = self._domain_re.findall(text)
        emails = self._email_re.findall(text)
        domains = []
        seen = set()
        for domain in raw_domains:
            d = domain.lower()
            if any(d in e.lower() for e in emails):
                continue
            if d not in seen:
                seen.add(d)
                domains.append(domain)

        companies = []
        for c in self._company_re.findall(text):
            value = " ".join(c.split())
            if value not in companies:
                companies.append(value)

        return {
            "wallets": self._wallet_re.findall(text),
            "emails": emails,
            "ips": self._ip_re.findall(text),
            "btcs": self._btc_re.findall(text),
            "domains": domains,
            "companies": companies,
            "credentials": self._credential_re.findall(text),
        }
