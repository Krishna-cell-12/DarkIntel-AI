"""Credential and secret detector using regex patterns."""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from . import patterns
from .config import PROCESSING_TIMEOUT
from .severity_scorer import calculate_severity
from .utils import extract_context, mask_secret

logger = logging.getLogger(__name__)


class CredentialDetector:
    def __init__(self) -> None:
        self._timeout = PROCESSING_TIMEOUT

    def detect_email_password(self, text: str) -> list[dict[str, Any]]:
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        if not text.strip():
            return []

        started = time.perf_counter()
        findings: list[dict[str, Any]] = []
        for compiled in patterns.COMPILED_EMAIL_PASSWORD_PATTERNS:
            if time.perf_counter() - started > self._timeout:
                logger.warning("email/password detection timed out")
                break
            try:
                for match in compiled.finditer(text):
                    email = match.group(1)
                    password = match.group(2)
                    if not patterns.COMPILED_EMAIL_VALIDATION.match(email):
                        continue
                    if len(password) < 6:
                        continue
                    if email == "test@test.com" and password.lower().startswith(
                        "password"
                    ):
                        continue
                    severity = calculate_severity("email_password_pair", context=text)
                    findings.append(
                        {
                            "type": "email_password",
                            "email": email,
                            "password_masked": mask_secret(password),
                            "severity": severity.level,
                            "severity_score": severity.score,
                            "context": extract_context(
                                text, match.start(), match.end()
                            ),
                        }
                    )
            except re.error as exc:
                logger.warning("regex error for email/password pattern: %s", exc)
                continue
        return self._dedupe(findings)

    def detect_database_urls(self, text: str) -> list[dict[str, Any]]:
        if not text.strip():
            return []
        findings: list[dict[str, Any]] = []
        for match in patterns.COMPILED_DATABASE_URL.finditer(text):
            db_type, user, password, host, db_name = match.groups()
            masked = f"{db_type}://{user}:****@{host}/{db_name}"
            severity = calculate_severity("database_url", context=text)
            findings.append(
                {
                    "type": "database_url",
                    "url_masked": masked,
                    "database_type": db_type,
                    "severity": severity.level,
                    "severity_score": severity.score,
                    "context": extract_context(text, match.start(), match.end()),
                }
            )
        return findings

    def detect_ssh_keys(self, text: str) -> list[dict[str, Any]]:
        if not text.strip():
            return []
        findings: list[dict[str, Any]] = []
        for match in patterns.COMPILED_SSH_PRIVATE_KEY.finditer(text):
            severity = calculate_severity("ssh_private_key", context=text)
            findings.append(
                {
                    "type": "ssh_private_key",
                    "key_type": "private_key",
                    "severity": severity.level,
                    "severity_score": severity.score,
                    "context": extract_context(text, match.start(), match.end()),
                }
            )
        return findings

    def detect_api_keys(self, text: str) -> list[dict[str, Any]]:
        if not text.strip():
            return []

        findings: list[dict[str, Any]] = []
        clean_text = self._strip_comment_and_code_lines(text)
        for provider, compiled in patterns.COMPILED_API_KEYS.items():
            for match in compiled.finditer(clean_text):
                raw = match.group(0)
                if raw == "AKIAIOSFODNN7EXAMPLE":
                    continue
                if "your_api_key_here" in raw.lower():
                    continue
                leak_type = (
                    f"api_key_{provider}"
                    if provider != "github_oauth"
                    else "api_key_github"
                )
                severity = calculate_severity(leak_type, context=clean_text)
                findings.append(
                    {
                        "type": provider,
                        "key_prefix": f"{raw[:4]}****",
                        "provider": provider.replace("_", " ").title(),
                        "severity": severity.level,
                        "severity_score": severity.score,
                        "context": extract_context(
                            clean_text, match.start(), match.end()
                        ),
                    }
                )
        return self._dedupe(findings)

    def detect_crypto_wallets(self, text: str) -> list[dict[str, Any]]:
        if not text.strip():
            return []
        findings: list[dict[str, Any]] = []
        lowered = text.lower()
        has_private_key_context = "private key" in lowered or "seed phrase" in lowered

        for chain, compiled in patterns.COMPILED_WALLETS.items():
            for match in compiled.finditer(text):
                address = match.group(0)
                leak_type = (
                    "crypto_wallet"
                    if not has_private_key_context
                    else "ssh_private_key"
                )
                severity = calculate_severity(leak_type, context=text)
                if has_private_key_context:
                    severity = calculate_severity("ssh_private_key", context=text)
                findings.append(
                    {
                        "type": f"{chain}_wallet",
                        "address": f"{address[:6]}...{address[-4:]}",
                        "severity": severity.level,
                        "severity_score": severity.score,
                        "has_private_key_nearby": has_private_key_context,
                        "context": extract_context(text, match.start(), match.end()),
                    }
                )
        return findings

    def detect_all_credentials(self, text: str) -> dict[str, Any]:
        email_password = self.detect_email_password(text)
        database_urls = self.detect_database_urls(text)
        ssh_keys = self.detect_ssh_keys(text)
        api_keys = self.detect_api_keys(text)
        wallets = self.detect_crypto_wallets(text)

        all_credentials = email_password + database_urls + ssh_keys
        all_severities = [
            item["severity"] for item in all_credentials + api_keys + wallets
        ]
        max_severity = self._max_severity(all_severities)

        return {
            "credentials": all_credentials,
            "api_keys": api_keys,
            "crypto_wallets": wallets,
            "count": len(all_credentials) + len(api_keys) + len(wallets),
            "max_severity": max_severity,
        }

    @staticmethod
    def _strip_comment_and_code_lines(text: str) -> str:
        filtered_lines: list[str] = []
        in_code_block = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("```"):
                in_code_block = not in_code_block
                continue
            if in_code_block:
                continue
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            filtered_lines.append(line)
        return "\n".join(filtered_lines)

    @staticmethod
    def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str]] = set()
        result: list[dict[str, Any]] = []
        for item in items:
            key = (item.get("type", ""), str(item.get("context", "")))
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    @staticmethod
    def _max_severity(levels: list[str]) -> str:
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if not levels:
            return "LOW"
        return max(levels, key=lambda lvl: order.get(lvl, 0))
