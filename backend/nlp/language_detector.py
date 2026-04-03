"""Language detection and lightweight translation helpers."""

from __future__ import annotations

from typing import Any

try:
    from langdetect import detect as _detect_language
except Exception:  # pragma: no cover - safe fallback when dependency missing
    _detect_language = None

try:
    from deep_translator import GoogleTranslator
except Exception:  # pragma: no cover - safe fallback when dependency missing
    GoogleTranslator = None


def normalize_text_for_analysis(text: str) -> dict[str, Any]:
    """Detect language and optionally translate to English.

    Returns a dict with original text, normalized text and translation metadata.
    Falls back gracefully when dependencies/network are unavailable.
    """
    raw = text or ""
    detected = "unknown"
    translated = False
    normalized = raw

    try:
        if _detect_language and raw.strip():
            detected = _detect_language(raw)
    except Exception:
        detected = "unknown"

    can_translate = detected not in ("unknown", "en") and GoogleTranslator is not None
    if can_translate:
        try:
            normalized = GoogleTranslator(source="auto", target="en").translate(raw)
            translated = True
        except Exception:
            normalized = raw
            translated = False

    return {
        "original_text": raw,
        "normalized_text": normalized,
        "detected_language": detected,
        "translated_to_english": translated,
    }
