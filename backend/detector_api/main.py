from __future__ import annotations

from collections.abc import Sequence
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from detector_api.database import SessionLocal, get_db, init_db
from detector_api.detection.engine import run_detection, seed_detection_rules
from detector_api.ingest.auth_parser import normalize_auth_log
from detector_api.ingest.nginx_parser import normalize_nginx_log
from detector_api.models import Alert, AuthEvent, Event
from detector_api.schemas import (
    AlertOut,
    CountItem,
    DetectionRunResult,
    IngestResult,
    SeverityCounts,
    SummaryOut,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    with SessionLocal() as db:
        seed_detection_rules(db)
    yield


app = FastAPI(
    title="Mini SOC SIEM Lab Detector API",
    version="0.1.0",
    description="Defensive log ingestion and detection API for a local SOC/SIEM lab.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "detector-api"}


@app.post("/ingest/nginx", response_model=IngestResult)
def ingest_nginx(payload: Any = Body(...), db: Session = Depends(get_db)) -> IngestResult:
    items = _ensure_list(payload)
    ids: list[int] = []
    for item in items:
        normalized = normalize_nginx_log(item)
        event = Event(**normalized)
        db.add(event)
        db.flush()
        ids.append(event.id)
    db.commit()
    return IngestResult(ingested=len(ids), ids=ids)


@app.post("/ingest/auth", response_model=IngestResult)
def ingest_auth(payload: Any = Body(...), db: Session = Depends(get_db)) -> IngestResult:
    items = _ensure_list(payload)
    ids: list[int] = []
    for item in items:
        normalized = normalize_auth_log(item)
        event = AuthEvent(**normalized)
        db.add(event)
        db.flush()
        ids.append(event.id)
    db.commit()
    return IngestResult(ingested=len(ids), ids=ids)


@app.post("/detect/run", response_model=DetectionRunResult)
def detect_run(db: Session = Depends(get_db)) -> DetectionRunResult:
    seed_detection_rules(db)
    alerts = run_detection(db)
    return DetectionRunResult(
        created_alerts=len(alerts),
        alerts=[AlertOut.model_validate(alert) for alert in alerts],
    )


@app.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    db: Session = Depends(get_db),
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> Sequence[Alert]:
    query = select(Alert)
    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity.lower())
    query = query.order_by(Alert.timestamp.desc(), Alert.id.desc()).limit(limit)
    return db.scalars(query).all()


@app.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.get("/stats/summary", response_model=SummaryOut)
def stats_summary(db: Session = Depends(get_db)) -> SummaryOut:
    total_events = db.scalar(select(func.count(Event.id))) or 0
    total_auth_events = db.scalar(select(func.count(AuthEvent.id))) or 0
    total_alerts = db.scalar(select(func.count(Alert.id))) or 0

    severity_rows = db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    ).all()
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for severity, count in severity_rows:
        severity_counts[str(severity).lower()] = count

    type_rows = db.execute(
        select(Alert.alert_type, func.count(Alert.id)).group_by(Alert.alert_type)
    ).all()
    ip_rows = db.execute(
        select(Alert.ip, func.count(Alert.id))
        .where(Alert.ip.is_not(None))
        .group_by(Alert.ip)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    ).all()
    latest_alerts = db.scalars(
        select(Alert).order_by(Alert.timestamp.desc(), Alert.id.desc()).limit(10)
    ).all()

    return SummaryOut(
        total_events=total_events,
        total_auth_events=total_auth_events,
        total_alerts=total_alerts,
        severity_counts=SeverityCounts(**severity_counts),
        alert_type_counts=[CountItem(name=name, count=count) for name, count in type_rows],
        source_ip_ranking=[CountItem(name=ip, count=count) for ip, count in ip_rows],
        latest_alerts=[AlertOut.model_validate(alert) for alert in latest_alerts],
    )


def _ensure_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
        return payload
    raise HTTPException(
        status_code=422,
        detail="Payload must be a JSON object or a list of objects",
    )
