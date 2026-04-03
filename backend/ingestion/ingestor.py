"""In-memory ingestion service for unstructured threat sources."""

from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Any
from uuid import uuid4

from nlp.entity_extractor import EntityExtractor

from .sources import classify_source_type, infer_quality_flags


class ThreatIngestor:
    """Collect and normalize raw threat inputs for downstream analysis."""

    def __init__(self, max_items: int = 500) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=max_items)
        self._extractor = EntityExtractor()

    def ingest(
        self, text: str, source: str = "manual", language: str = "unknown"
    ) -> dict[str, Any]:
        clean_text = (text or "").strip()
        entities = self._extractor.extract_regex_entities(clean_text)
        flags = infer_quality_flags(clean_text)
        source_type = classify_source_type(source)

        record = {
            "id": str(uuid4()),
            "text": clean_text,
            "source": source,
            "source_type": source_type,
            "language": language,
            "entities": entities,
            "entity_count": sum(len(v) for v in entities.values()),
            "quality_flags": flags,
            "ingested_at": datetime.now().isoformat(),
        }
        self._items.appendleft(record)
        return record

    def ingest_many(self, items: list[dict[str, str]]) -> dict[str, Any]:
        created = []
        for item in items:
            text = item.get("text", "") if isinstance(item, dict) else ""
            source = (
                item.get("source", "manual") if isinstance(item, dict) else "manual"
            )
            language = (
                item.get("language", "unknown") if isinstance(item, dict) else "unknown"
            )
            if not isinstance(text, str):
                continue
            if not text.strip():
                continue
            created.append(self.ingest(text=text, source=source, language=language))

        return {
            "ingested_count": len(created),
            "records": created,
            "summary": f"Ingested {len(created)} record(s).",
        }

    def recent(self, limit: int = 20, source_type: str | None = None) -> dict[str, Any]:
        items = list(self._items)
        if source_type:
            normalized = source_type.strip().lower()
            items = [
                x for x in items if str(x.get("source_type", "")).lower() == normalized
            ]
        out = items[: max(limit, 0)]
        return {
            "count": len(out),
            "items": out,
            "total_buffered": len(self._items),
        }
