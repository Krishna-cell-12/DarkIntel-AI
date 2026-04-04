"""Tor-backed HTTP client for fetching .onion pages."""

from __future__ import annotations

from typing import Any

import requests
from bs4 import BeautifulSoup


class TorClient:
    """Minimal Tor client using SOCKS5 proxy via requests."""

    def __init__(self, tor_proxy: str = "127.0.0.1:9050", timeout: int = 25):
        self.tor_proxy = tor_proxy
        self.timeout = timeout
        self.session = requests.Session()
        self.session.proxies = {
            "http": f"socks5h://{tor_proxy}",
            "https": f"socks5h://{tor_proxy}",
        }

    def check_connection(self) -> dict[str, Any]:
        """Validate Tor proxy connectivity."""
        try:
            r = self.session.get("https://check.torproject.org", timeout=self.timeout)
            ok = r.status_code == 200
            return {
                "connected": ok,
                "status_code": r.status_code,
                "message": "Tor reachable" if ok else "Tor check failed",
            }
        except Exception as exc:
            return {"connected": False, "status_code": None, "message": str(exc)}

    def fetch_onion(self, url: str) -> dict[str, Any]:
        """Fetch and parse one .onion URL."""
        if ".onion" not in url:
            return {"status": "failed", "url": url, "error": "not_onion_url"}

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    )
                },
            )
            if resp.status_code != 200:
                return {
                    "status": "failed",
                    "url": url,
                    "status_code": resp.status_code,
                    "error": "http_error",
                }
            parsed = _extract_content(resp.text)
            return {
                "status": "success",
                "url": url,
                "status_code": resp.status_code,
                "content": parsed,
            }
        except Exception as exc:
            return {"status": "failed", "url": url, "error": str(exc)}


def _extract_content(html: str) -> dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    title = (soup.title.string or "").strip() if soup.title else ""
    text = " ".join(soup.get_text(separator=" ").split())
    text = text[:12000]
    links = [a.get("href") for a in soup.find_all("a", href=True)][:40]
    return {
        "title": title,
        "text": text,
        "links": links,
    }
