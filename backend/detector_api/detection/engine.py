from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from typing import Any
from urllib.parse import unquote_plus

from sqlalchemy import select
from sqlalchemy.orm import Session

from detector_api.detection.rules import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_MINUTES,
    DEFAULT_RULES,
    DIRECTORY_SCAN_THRESHOLD,
    DIRECTORY_SCAN_WINDOW_MINUTES,
    PATH_TRAVERSAL_PATTERNS,
    RECOMMENDATIONS,
    SQLI_PATTERNS,
    SUSPICIOUS_USER_AGENTS,
    XSS_PATTERNS,
)
from detector_api.models import Alert, AuthEvent, DetectionRule, Event


def seed_detection_rules(db: Session) -> None:
    existing = {row.name for row in db.scalars(select(DetectionRule)).all()}
    for rule in DEFAULT_RULES:
        if rule["name"] not in existing:
            db.add(DetectionRule(enabled=True, **rule))
    db.commit()


def run_detection(db: Session) -> list[Alert]:
    enabled_types = {
        rule.alert_type
        for rule in db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))).all()
    }
    created: list[Alert] = []

    if "brute_force_suspicion" in enabled_types:
        created.extend(_detect_brute_force(db))
    if "directory_scan_suspicion" in enabled_types:
        created.extend(_detect_directory_scan(db))

    events = db.scalars(select(Event).order_by(Event.timestamp.asc())).all()
    for event in events:
        if "sqli_suspicion" in enabled_types:
            alert = _detect_pattern_event(
                db,
                event,
                alert_type="sqli_suspicion",
                severity="high",
                title="SQL Injection suspicion",
                patterns=SQLI_PATTERNS,
                description="The request path or query string contains SQL Injection indicators.",
            )
            if alert:
                created.append(alert)

        if "xss_suspicion" in enabled_types:
            alert = _detect_pattern_event(
                db,
                event,
                alert_type="xss_suspicion",
                severity="medium",
                title="XSS suspicion",
                patterns=XSS_PATTERNS,
                description="The request path or query string contains XSS indicators.",
            )
            if alert:
                created.append(alert)

        if "path_traversal_suspicion" in enabled_types:
            alert = _detect_pattern_event(
                db,
                event,
                alert_type="path_traversal_suspicion",
                severity="high",
                title="Path traversal suspicion",
                patterns=PATH_TRAVERSAL_PATTERNS,
                description=(
                    "The request path contains directory traversal or sensitive file indicators."
                ),
            )
            if alert:
                created.append(alert)

        if "suspicious_user_agent" in enabled_types:
            alert = _detect_suspicious_user_agent(db, event)
            if alert:
                created.append(alert)

    db.commit()
    for alert in created:
        db.refresh(alert)
    return created


def _detect_brute_force(db: Session) -> list[Alert]:
    failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    failures = db.scalars(
        select(AuthEvent)
        .where(AuthEvent.success.is_(False))
        .order_by(AuthEvent.ip.asc(), AuthEvent.timestamp.asc())
    ).all()
    for event in failures:
        failures_by_ip[event.ip].append(event)

    created: list[Alert] = []
    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
    for ip, events in failures_by_ip.items():
        left = 0
        for right, event in enumerate(events):
            while event.timestamp - events[left].timestamp > window:
                left += 1
            window_events = events[left : right + 1]
            if len(window_events) >= BRUTE_FORCE_THRESHOLD:
                evidence = {
                    "failed_attempts": len(window_events),
                    "threshold": BRUTE_FORCE_THRESHOLD,
                    "window_minutes": BRUTE_FORCE_WINDOW_MINUTES,
                    "first_seen": window_events[0].timestamp.isoformat(),
                    "last_seen": window_events[-1].timestamp.isoformat(),
                    "usernames": sorted({item.username for item in window_events if item.username}),
                }
                alert = _create_alert_if_new(
                    db,
                    timestamp=window_events[-1].timestamp,
                    alert_type="brute_force_suspicion",
                    severity="high",
                    ip=ip,
                    path="/login",
                    title="Brute force login suspicion",
                    description="Many failed login attempts were observed from the same IP.",
                    evidence=evidence,
                )
                if alert:
                    created.append(alert)
                break
    return created


def _detect_directory_scan(db: Session) -> list[Alert]:
    not_found_by_ip: dict[str, list[Event]] = defaultdict(list)
    events = db.scalars(
        select(Event)
        .where(Event.status_code == 404)
        .order_by(Event.ip.asc(), Event.timestamp.asc())
    ).all()
    for event in events:
        not_found_by_ip[event.ip].append(event)

    created: list[Alert] = []
    window = timedelta(minutes=DIRECTORY_SCAN_WINDOW_MINUTES)
    for ip, ip_events in not_found_by_ip.items():
        left = 0
        for right, event in enumerate(ip_events):
            while event.timestamp - ip_events[left].timestamp > window:
                left += 1
            window_events = ip_events[left : right + 1]
            if len(window_events) >= DIRECTORY_SCAN_THRESHOLD:
                evidence = {
                    "not_found_count": len(window_events),
                    "threshold": DIRECTORY_SCAN_THRESHOLD,
                    "window_minutes": DIRECTORY_SCAN_WINDOW_MINUTES,
                    "sample_paths": [item.path for item in window_events[:10]],
                }
                alert = _create_alert_if_new(
                    db,
                    timestamp=window_events[-1].timestamp,
                    alert_type="directory_scan_suspicion",
                    severity="low",
                    ip=ip,
                    path="multiple 404 paths",
                    title="Directory discovery suspicion",
                    description="Many 404 responses were observed from the same IP.",
                    evidence=evidence,
                )
                if alert:
                    created.append(alert)
                break
    return created


def _detect_pattern_event(
    db: Session,
    event: Event,
    *,
    alert_type: str,
    severity: str,
    title: str,
    patterns: list[str],
    description: str,
) -> Alert | None:
    path = event.path or ""
    decoded_path = unquote_plus(path)
    haystack = f"{path}\n{decoded_path}"

    for pattern in patterns:
        if re.search(pattern, haystack):
            evidence = {
                "path": path,
                "decoded_path": decoded_path,
                "matched_pattern": pattern,
                "status_code": event.status_code,
                "method": event.method,
            }
            return _create_alert_if_new(
                db,
                timestamp=event.timestamp,
                alert_type=alert_type,
                severity=severity,
                ip=event.ip,
                path=path,
                title=title,
                description=description,
                evidence=evidence,
            )
    return None


def _detect_suspicious_user_agent(db: Session, event: Event) -> Alert | None:
    user_agent = event.user_agent or ""
    lowered = user_agent.lower()
    for indicator in SUSPICIOUS_USER_AGENTS:
        if indicator in lowered:
            evidence = {
                "user_agent": user_agent,
                "matched_indicator": indicator,
                "path": event.path,
                "status_code": event.status_code,
            }
            return _create_alert_if_new(
                db,
                timestamp=event.timestamp,
                alert_type="suspicious_user_agent",
                severity="medium",
                ip=event.ip,
                path=event.path,
                title="Suspicious user-agent",
                description=(
                    "The user-agent matches a known scanner or security testing tool string."
                ),
                evidence=evidence,
            )
    return None


def _create_alert_if_new(
    db: Session,
    *,
    timestamp,
    alert_type: str,
    severity: str,
    ip: str | None,
    path: str | None,
    title: str,
    description: str,
    evidence: dict[str, Any],
) -> Alert | None:
    existing = db.scalar(
        select(Alert).where(
            Alert.alert_type == alert_type,
            Alert.ip == ip,
            Alert.path == path,
            Alert.status == "open",
        )
    )
    if existing:
        return None

    alert = Alert(
        timestamp=timestamp,
        alert_type=alert_type,
        severity=severity,
        ip=ip,
        path=path,
        title=title,
        description=description,
        evidence=evidence,
        recommendation=RECOMMENDATIONS[alert_type],
        status="open",
    )
    db.add(alert)
    db.flush()
    return alert
