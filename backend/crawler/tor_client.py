"""Tor-backed HTTP client for fetching .onion pages."""

from __future__ import annotations

import socket
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
        """Validate Tor proxy connectivity.

        We first verify that the SOCKS proxy port is reachable. This avoids
        false negatives caused by TLS issues against external check endpoints.
        """
        host, port = _split_proxy(self.tor_proxy)

        # 1) Direct socket reachability check (most reliable local signal)
        try:
            with socket.create_connection((host, port), timeout=4):
                pass
        except Exception as exc:
            return {
                "connected": False,
                "status_code": None,
                "message": f"SOCKS proxy not reachable on {host}:{port}: {exc}",
            }

        # 2) Lightweight HTTP probe through SOCKS (best-effort only)
        try:
            r = self.session.get("http://check.torproject.org", timeout=self.timeout)
            return {
                "connected": True,
                "status_code": r.status_code,
                "message": "Tor proxy reachable",
            }
        except Exception as exc:
            # Proxy is reachable; external probe failed. Continue as connected.
            return {
                "connected": True,
                "status_code": None,
                "message": f"Tor proxy reachable; probe skipped: {exc}",
            }

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


def _split_proxy(proxy: str) -> tuple[str, int]:
    value = (proxy or "127.0.0.1:9050").strip()
    host, _, port = value.partition(":")
    try:
        return (host or "127.0.0.1", int(port or "9050"))
    except Exception:
        return (host or "127.0.0.1", 9050)
