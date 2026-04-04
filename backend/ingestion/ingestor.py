"""Ingestion service for unstructured threat sources with persistence."""

from __future__ import annotations

import hashlib
import json
from collections import deque
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from nlp.entity_extractor import EntityExtractor

from .sources import classify_source_type, infer_quality_flags


class ThreatIngestor:
    """Collect and normalize raw threat inputs for downstream analysis."""

    def __init__(self, max_items: int = 500, persist_path: str | None = None) -> None:
        self._max_items = max_items
        self._items: deque[dict[str, Any]] = deque()
        self._extractor = EntityExtractor()
        self._by_fingerprint: dict[str, dict[str, Any]] = {}
        self._lock = RLock()
        self._persist_path = (
            Path(persist_path)
            if persist_path
            else Path(__file__).resolve().parents[1] / "data" / "ingest_cache.json"
        )
        self._load_from_disk()

    @staticmethod
    def _normalize_text(text: str) -> str:
        return " ".join((text or "").strip().split()).lower()

    @classmethod
    def _fingerprint(cls, text: str) -> str:
        normalized = cls._normalize_text(text)
        return hashlib.sha1(normalized.encode("utf-8")).hexdigest()

    @staticmethod
    def _clean_values(values: list[Any], fallback: str) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for raw in values:
            value = str(raw).strip()
            if not value or value in seen:
                continue
            seen.add(value)
            out.append(value)
        if not out and fallback:
            out = [fallback]
        return out

    def _save_to_disk(self) -> None:
        payload = {
            "saved_at": datetime.now().isoformat(),
            "max_items": self._max_items,
            "records": list(self._items),
        }
        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._persist_path.with_suffix(
                self._persist_path.suffix + ".tmp"
            )
            tmp_path.write_text(
                json.dumps(payload, ensure_ascii=False),
                encoding="utf-8",
            )
            tmp_path.replace(self._persist_path)
        except Exception:
            return

    def _normalize_loaded_record(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        text = str(raw.get("text", "")).strip()
        if not text:
            return None

        source = str(raw.get("source", "unknown")).strip() or "unknown"
        language = str(raw.get("language", "unknown")).strip() or "unknown"
        fp = str(raw.get("fingerprint", "")).strip() or self._fingerprint(text)

        entities = raw.get("entities")
        if not isinstance(entities, dict):
            entities = self._extractor.extract_regex_entities(text)

        entity_count_raw = raw.get("entity_count")
        entity_count = (
            int(entity_count_raw)
            if isinstance(entity_count_raw, int)
            else sum(len(v) for v in entities.values())
        )

        quality_flags = raw.get("quality_flags")
        if not isinstance(quality_flags, list):
            quality_flags = infer_quality_flags(text)

        first_seen = str(
            raw.get("first_seen_at")
            or raw.get("ingested_at")
            or datetime.now().isoformat()
        )
        last_seen = str(raw.get("last_seen_at") or raw.get("ingested_at") or first_seen)
        ingested_at = str(raw.get("ingested_at") or first_seen)

        occurrences = raw.get("occurrences", 1)
        try:
            occurrences = max(1, int(occurrences))
        except Exception:
            occurrences = 1

        sources = self._clean_values(
            list(raw.get("sources", []) or []), fallback=source
        )
        languages = self._clean_values(
            list(raw.get("languages", []) or []),
            fallback=language,
        )

        return {
            "id": str(raw.get("id") or uuid4()),
            "fingerprint": fp,
            "text": text,
            "source": source,
            "source_type": str(raw.get("source_type") or classify_source_type(source)),
            "language": language,
            "sources": sources,
            "languages": languages,
            "entities": entities,
            "entity_count": entity_count,
            "quality_flags": quality_flags,
            "first_seen_at": first_seen,
            "last_seen_at": last_seen,
            "ingested_at": ingested_at,
            "occurrences": occurrences,
            "is_new": bool(raw.get("is_new", False)),
        }

    def _load_from_disk(self) -> None:
        with self._lock:
            if not self._persist_path.exists():
                return

            try:
                payload = json.loads(self._persist_path.read_text(encoding="utf-8"))
            except Exception:
                return

            records: list[Any]
            if isinstance(payload, dict):
                records = list(payload.get("records", []) or [])
            elif isinstance(payload, list):
                records = payload
            else:
                return

            loaded: list[dict[str, Any]] = []
            seen_fingerprints: set[str] = set()
            for raw in records:
                if not isinstance(raw, dict):
                    continue
                normalized = self._normalize_loaded_record(raw)
                if normalized is None:
                    continue

                fp = str(normalized.get("fingerprint", ""))
                if not fp or fp in seen_fingerprints:
                    continue
                seen_fingerprints.add(fp)

                loaded.append(normalized)
                if len(loaded) >= self._max_items:
                    break

            self._items = deque(loaded)
            self._by_fingerprint = {
                str(x.get("fingerprint")): x
                for x in loaded
                if str(x.get("fingerprint", ""))
            }

    def ingest(
        self,
        text: str,
        source: str = "manual",
        language: str = "unknown",
        persist: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            clean_text = (text or "").strip()
            if not clean_text:
                return {}

            fp = self._fingerprint(clean_text)
            now = datetime.now().isoformat()

            existing = self._by_fingerprint.get(fp)
            if existing is not None:
                existing["last_seen_at"] = now
                existing["occurrences"] = int(existing.get("occurrences", 1)) + 1

                if source:
                    existing["source"] = source
                    existing["sources"] = self._clean_values(
                        [*existing.get("sources", []), source],
                        fallback=source,
                    )
                    existing["source_type"] = classify_source_type(source)

                if language:
                    existing["language"] = language
                    existing["languages"] = self._clean_values(
                        [*existing.get("languages", []), language],
                        fallback=language,
                    )

                existing["is_new"] = False

                try:
                    self._items.remove(existing)
                except ValueError:
                    pass
                self._items.appendleft(existing)

                if persist:
                    self._save_to_disk()
                return existing

            entities = self._extractor.extract_regex_entities(clean_text)
            flags = infer_quality_flags(clean_text)
            source_type = classify_source_type(source)

            record = {
                "id": str(uuid4()),
                "fingerprint": fp,
                "text": clean_text,
                "source": source,
                "source_type": source_type,
                "language": language,
                "sources": [source] if source else [],
                "languages": [language] if language else [],
                "entities": entities,
                "entity_count": sum(len(v) for v in entities.values()),
                "quality_flags": flags,
                "first_seen_at": now,
                "last_seen_at": now,
                "ingested_at": now,
                "occurrences": 1,
                "is_new": True,
            }

            if len(self._items) >= self._max_items:
                removed = self._items.pop()
                removed_fp = str(removed.get("fingerprint", ""))
                if removed_fp:
                    self._by_fingerprint.pop(removed_fp, None)

            self._items.appendleft(record)
            self._by_fingerprint[fp] = record

            if persist:
                self._save_to_disk()
            return record

    def ingest_many(self, items: list[dict[str, str]]) -> dict[str, Any]:
        with self._lock:
            created: list[dict[str, Any]] = []
            updated: list[dict[str, Any]] = []
            for item in items:
                text = item.get("text", "") if isinstance(item, dict) else ""
                source = (
                    item.get("source", "manual") if isinstance(item, dict) else "manual"
                )
                language = (
                    item.get("language", "unknown")
                    if isinstance(item, dict)
                    else "unknown"
                )
                if not isinstance(text, str):
                    continue
                clean = text.strip()
                if not clean:
                    continue

                fp = self._fingerprint(clean)
                was_existing = fp in self._by_fingerprint
                rec = self.ingest(
                    text=clean,
                    source=source,
                    language=language,
                    persist=False,
                )
                if not rec:
                    continue
                if was_existing:
                    updated.append(rec)
                else:
                    created.append(rec)

            merged_records: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            for rec in [*created, *updated]:
                rid = str(rec.get("id", ""))
                if rid and rid in seen_ids:
                    continue
                if rid:
                    seen_ids.add(rid)
                merged_records.append(rec)

            if created or updated:
                self._save_to_disk()

            return {
                "ingested_count": len(created),
                "updated_count": len(updated),
                "records": merged_records,
                "new_records": created,
                "updated_records": updated,
                "summary": (
                    f"Ingested {len(created)} new record(s), "
                    f"merged {len(updated)} recurring record(s)."
                ),
            }

    def recent(self, limit: int = 20, source_type: str | None = None) -> dict[str, Any]:
        with self._lock:
            items = list(self._items)
            if source_type:
                normalized = source_type.strip().lower()
                items = [
                    x
                    for x in items
                    if str(x.get("source_type", "")).lower() == normalized
                ]
            out = items[: max(limit, 0)]
            return {
                "count": len(out),
                "items": out,
                "total_buffered": len(self._items),
                "persist_path": str(self._persist_path),
            }
