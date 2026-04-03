from typing import List, Literal

from pydantic import BaseModel, Field


class EntitiesModel(BaseModel):
    wallets: List[str] = []
    emails: List[str] = []
    ips: List[str] = []
    organizations: List[str] = []


class ThreatScoreModel(BaseModel):
    score: int = Field(ge=0, le=100)
    level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    factors: List[str] = []


class AnalysisResponse(BaseModel):
    entities: EntitiesModel
    threat_score: ThreatScoreModel
    summary: str

