"""Pydantic models for leak detection API."""

from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, Field


class DetectionRequest(BaseModel):
    text: str = Field(..., min_length=1)
    max_length: int = Field(default=10000, ge=1, le=100000)


class LeakItem(BaseModel):
    type: str
    value_masked: str
    severity: str
    severity_score: int
    context: str


class DetectionResponse(BaseModel):
    leaks: List[LeakItem]
    count: int
    max_severity: str
    processing_time_ms: float
    demo_mode: bool = False


class FullDetectionResponse(BaseModel):
    credentials: List[dict]
    financial: List[dict]
    api_keys: List[dict]
    crypto_wallets: List[dict] = []
    total_count: int
    max_severity: str
    severity_breakdown: Dict[str, int]
    processing_time_ms: float
    demo_mode: bool = False


class StatsResponse(BaseModel):
    total_scans: int
    total_leaks_detected: int
    by_type: Dict[str, int]
    demo_mode: bool = False
