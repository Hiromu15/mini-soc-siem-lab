from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventOut(BaseModel):
    id: int
    timestamp: datetime
    source: str
    ip: str
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    event_type: str
    raw_data: dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class AuthEventOut(BaseModel):
    id: int
    timestamp: datetime
    ip: str
    username: str | None = None
    success: bool
    reason: str | None = None
    raw_data: dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class AlertOut(BaseModel):
    id: int
    timestamp: datetime
    alert_type: str
    severity: str
    ip: str | None = None
    path: str | None = None
    title: str
    description: str
    evidence: dict[str, Any]
    recommendation: str
    status: str

    model_config = ConfigDict(from_attributes=True)


class IngestResult(BaseModel):
    ingested: int
    ids: list[int]


class DetectionRunResult(BaseModel):
    created_alerts: int
    alerts: list[AlertOut]


class SeverityCounts(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0


class CountItem(BaseModel):
    name: str = Field(..., examples=["sqli_suspicion"])
    count: int


class SummaryOut(BaseModel):
    total_events: int
    total_auth_events: int
    total_alerts: int
    severity_counts: SeverityCounts
    alert_type_counts: list[CountItem]
    source_ip_ranking: list[CountItem]
    latest_alerts: list[AlertOut]

