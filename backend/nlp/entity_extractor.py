import re
from typing import Dict, List


class EntityExtractor:
    wallet_pattern = r'0x[a-fA-F0-9]{40}'
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'

    def __init__(self) -> None:
        self._wallet_re = re.compile(self.wallet_pattern)
        self._email_re = re.compile(self.email_pattern)
        self._ip_re = re.compile(self.ip_pattern)
        self._btc_re = re.compile(self.btc_pattern)

    def extract_regex_entities(self, text: str) -> Dict[str, List[str]]:
        return {
            "wallets": self._wallet_re.findall(text),
            "emails": self._email_re.findall(text),
            "ips": self._ip_re.findall(text),
            "btcs": self._btc_re.findall(text),
        }

