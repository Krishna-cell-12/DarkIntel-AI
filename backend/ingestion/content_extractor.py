"""Extract normalized text from heterogeneous source formats."""

from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover
    PdfReader = None

try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None

try:
    import pytesseract
except Exception:  # pragma: no cover
    pytesseract = None


TEXT_EXTS = {".txt", ".log", ".md", ".text", ".xml"}
HTML_EXTS = {".html", ".htm"}
JSON_EXTS = {".json"}
CSV_EXTS = {".csv"}
PDF_EXTS = {".pdf"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"}


def detect_content_kind(filename: str, content_type: str | None = None) -> str:
    ext = Path(filename or "").suffix.lower()
    ctype = (content_type or "").lower()

    if ext in PDF_EXTS or "pdf" in ctype:
        return "pdf"
    if ext in IMAGE_EXTS or ctype.startswith("image/"):
        return "image"
    if ext in JSON_EXTS or "json" in ctype:
        return "json"
    if ext in CSV_EXTS or "csv" in ctype:
        return "csv"
    if ext in HTML_EXTS or "html" in ctype:
        return "html"
    if ext in TEXT_EXTS or ctype.startswith("text/"):
        return "text"
    return "text"


def extract_text_from_bytes(
    data: bytes,
    filename: str,
    content_type: str | None = None,
) -> dict[str, Any]:
    kind = detect_content_kind(filename, content_type)
    warnings: list[str] = []

    if kind == "text":
        text = _decode_bytes(data)
        return _result(text, kind, warnings)

    if kind == "html":
        html = _decode_bytes(data)
        text = _html_to_text(html)
        return _result(text, kind, warnings)

    if kind == "json":
        raw = _decode_bytes(data)
        text = _json_to_text(raw)
        return _result(text, kind, warnings)

    if kind == "csv":
        raw = _decode_bytes(data)
        text = _csv_to_text(raw)
        return _result(text, kind, warnings)

    if kind == "pdf":
        if PdfReader is None:
            return _result("", kind, ["pypdf_not_installed"])
        text = _pdf_to_text(data)
        return _result(text, kind, warnings)

    if kind == "image":
        if Image is None or pytesseract is None:
            return _result("", kind, ["ocr_dependencies_missing"])
        _configure_tesseract_if_needed()
        text = _ocr_image(data)
        return _result(text, kind, warnings)

    text = _decode_bytes(data)
    return _result(text, "text", warnings)


def extract_text_from_url(url: str, timeout: int = 20) -> dict[str, Any]:
    warnings: list[str] = []
    try:
        response = requests.get(url, timeout=timeout)
    except requests.exceptions.SSLError:
        response = requests.get(url, timeout=timeout, verify=False)
        warnings.append("ssl_verification_disabled")
    ctype = (response.headers.get("content-type") or "").lower()
    payload = response.content

    kind = "html" if "html" in ctype else "text"
    if "json" in ctype:
        kind = "json"
    elif "csv" in ctype:
        kind = "csv"
    elif "pdf" in ctype:
        kind = "pdf"
    elif ctype.startswith("image/"):
        kind = "image"

    # Reuse byte-based extractor with inferred pseudo filename extension.
    ext = {
        "html": ".html",
        "json": ".json",
        "csv": ".csv",
        "pdf": ".pdf",
        "image": ".png",
        "text": ".txt",
    }.get(kind, ".txt")
    out = extract_text_from_bytes(payload, filename=f"fetched{ext}", content_type=ctype)
    if warnings:
        out["warnings"] = [*warnings, *(out.get("warnings") or [])]
    return out


def _result(text: str, kind: str, warnings: list[str]) -> dict[str, Any]:
    clean = " ".join((text or "").split())
    return {
        "text": clean[:120000],
        "kind": kind,
        "warnings": warnings,
        "length": len(clean),
    }


def _decode_bytes(data: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", errors="ignore")


def _html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return soup.get_text(separator=" ")


def _json_to_text(raw: str) -> str:
    try:
        obj = json.loads(raw)
    except Exception:
        return raw

    parts: list[str] = []

    def _render_scalar(v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, bool):
            return "true" if v else "false"
        return str(v)

    def visit(node: Any) -> None:
        if isinstance(node, list):
            if all(isinstance(item, dict) for item in node):
                for item in node:
                    text = _dict_to_line(item)
                    if text:
                        parts.append(text)
                return
            for item in node:
                visit(item)
            return

        if isinstance(node, dict):
            line = _dict_to_line(node)
            if line:
                parts.append(line)
            return

        scalar = _render_scalar(node).strip()
        if scalar:
            parts.append(scalar)

    def _dict_to_line(d: dict[str, Any]) -> str:
        preferred_keys = [
            "text",
            "content",
            "message",
            "body",
            "description",
            "title",
            "summary",
            "source",
            "language",
        ]
        chunks: list[str] = []
        seen: set[str] = set()

        for key in preferred_keys:
            if key not in d:
                continue
            value = _render_scalar(d.get(key)).strip()
            if not value:
                continue
            token = f"{key}: {value}"
            if token in seen:
                continue
            seen.add(token)
            chunks.append(token)

        for key, value in d.items():
            if key in preferred_keys:
                continue
            if isinstance(value, (dict, list)):
                continue
            value_text = _render_scalar(value).strip()
            if not value_text:
                continue
            token = f"{key}: {value_text}"
            if token in seen:
                continue
            seen.add(token)
            chunks.append(token)

        return " | ".join(chunks)

    visit(obj)
    return "\n".join(parts)


def _csv_to_text(raw: str) -> str:
    reader = csv.reader(io.StringIO(raw))
    rows = []
    for row in reader:
        rows.append(" | ".join(str(c) for c in row))
    return "\n".join(rows)


def _pdf_to_text(data: bytes) -> str:
    if PdfReader is None:
        return ""
    reader = PdfReader(io.BytesIO(data))
    out = []
    for page in reader.pages:
        out.append(page.extract_text() or "")
    return "\n".join(out)


def _configure_tesseract_if_needed() -> None:
    if pytesseract is None:
        return
    cmd = os.getenv("TESSERACT_CMD", "").strip()
    if cmd and os.path.exists(cmd):
        pytesseract.pytesseract.tesseract_cmd = cmd
        return
    win_default = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.path.exists(win_default):
        pytesseract.pytesseract.tesseract_cmd = win_default


def _ocr_image(data: bytes) -> str:
    if Image is None or pytesseract is None:
        return ""
    image = Image.open(io.BytesIO(data))
    return pytesseract.image_to_string(image)
