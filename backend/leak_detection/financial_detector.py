"""Financial data detector using regex and validation helpers."""

from __future__ import annotations

from typing import Any

from . import patterns
from .severity_scorer import calculate_severity
from .utils import card_type_from_number, extract_context, mask_card_number, mask_last4
from .validators import validate_luhn


class FinancialDetector:
    def detect_credit_cards(self, text: str) -> list[dict[str, Any]]:
        if not text.strip():
            return []

        findings: list[dict[str, Any]] = []
        cvv_positions = [
            (m.start(), m.end()) for m in patterns.COMPILED_CVV.finditer(text)
        ]

        for match in patterns.COMPILED_CREDIT_CARD.finditer(text):
            card_raw = match.group(0)
            if not validate_luhn(card_raw):
                continue

            has_cvv = self._has_cvv_near(match.start(), match.end(), cvv_positions)
            leak_type = "credit_card_with_cvv" if has_cvv else "credit_card_no_cvv"
            severity = calculate_severity(leak_type, context=text)
            findings.append(
                {
                    "type": leak_type,
                    "card_number": mask_card_number(card_raw),
                    "card_type": card_type_from_number(card_raw) or "Unknown",
                    "cvv_found": has_cvv,
                    "severity": severity.level,
                    "severity_score": severity.score,
                    "context": extract_context(text, match.start(), match.end()),
                }
            )
        return findings

    def detect_bank_accounts(self, text: str) -> list[dict[str, Any]]:
        if not text.strip():
            return []

        accounts = [m for m in patterns.COMPILED_BANK_ACCOUNT.finditer(text)]
        routings = [m.group(0) for m in patterns.COMPILED_ROUTING.finditer(text)]
        findings: list[dict[str, Any]] = []

        for match in accounts:
            account = match.group(0)
            if account in routings:
                continue
            severity = calculate_severity("bank_account", context=text)
            findings.append(
                {
                    "type": "bank_account",
                    "account_masked": mask_last4(account),
                    "routing_number": routings[0] if routings else None,
                    "severity": severity.level,
                    "severity_score": severity.score,
                    "context": extract_context(text, match.start(), match.end()),
                }
            )
        return findings

    def detect_ssn(self, text: str) -> list[dict[str, Any]]:
        if not text.strip():
            return []

        findings: list[dict[str, Any]] = []
        for match in patterns.COMPILED_SSN.finditer(text):
            ssn = match.group(0)
            severity = calculate_severity("ssn", context=text)
            findings.append(
                {
                    "type": "ssn",
                    "ssn_masked": f"***-**-{ssn[-4:]}",
                    "severity": severity.level,
                    "severity_score": severity.score,
                    "context": extract_context(text, match.start(), match.end()),
                }
            )
        return findings

    def detect_financial(self, text: str) -> dict[str, Any]:
        cards = self.detect_credit_cards(text)
        banks = self.detect_bank_accounts(text)
        ssns = self.detect_ssn(text)
        all_items = cards + banks + ssns

        return {
            "financial_data": all_items,
            "count": len(all_items),
            "max_severity": self._max_severity(
                [item["severity"] for item in all_items]
            ),
        }

    @staticmethod
    def _has_cvv_near(
        start: int,
        end: int,
        cvv_positions: list[tuple[int, int]],
        max_distance: int = 40,
    ) -> bool:
        for cvv_start, cvv_end in cvv_positions:
            if cvv_end < start:
                if start - cvv_end <= max_distance:
                    return True
            elif cvv_start > end:
                if cvv_start - end <= max_distance:
                    return True
            else:
                return True
        return False

    @staticmethod
    def _max_severity(levels: list[str]) -> str:
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if not levels:
            return "LOW"
        return max(levels, key=lambda lvl: order.get(lvl, 0))
