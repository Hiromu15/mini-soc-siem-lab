from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from detector_api.database import Base, SessionLocal, engine
from detector_api.detection.engine import seed_detection_rules
from detector_api.main import app


@pytest.fixture
def client() -> TestClient:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_detection_rules(db)

    with TestClient(app) as test_client:
        yield test_client


def test_brute_force_alert_created_when_failed_logins_exceed_threshold(client: TestClient) -> None:
    now = datetime.now(UTC)
    payload = [
        {
            "timestamp": (now + timedelta(seconds=index * 20)).isoformat(),
            "ip": "198.51.100.10",
            "username": "admin",
            "success": False,
            "reason": "invalid_credentials",
        }
        for index in range(10)
    ]

    assert client.post("/ingest/auth", json=payload).status_code == 200
    result = client.post("/detect/run")

    assert result.status_code == 200
    alerts = client.get("/alerts").json()
    assert "brute_force_suspicion" in {alert["alert_type"] for alert in alerts}


def test_sqli_path_is_detected(client: TestClient) -> None:
    ingest_nginx(client, path="/search?q=%27%20OR%20%271%27%3D%271")

    client.post("/detect/run")

    alerts = client.get("/alerts").json()
    assert "sqli_suspicion" in {alert["alert_type"] for alert in alerts}


def test_xss_path_is_detected(client: TestClient) -> None:
    ingest_nginx(client, path="/search?q=%3Cscript%3Ealert(1)%3C/script%3E")

    client.post("/detect/run")

    alerts = client.get("/alerts").json()
    assert "xss_suspicion" in {alert["alert_type"] for alert in alerts}


def test_path_traversal_is_detected(client: TestClient) -> None:
    ingest_nginx(client, path="/download?file=../../etc/passwd", status_code=404)

    client.post("/detect/run")

    alerts = client.get("/alerts").json()
    assert "path_traversal_suspicion" in {alert["alert_type"] for alert in alerts}


def test_directory_scan_alert_created_when_404_threshold_exceeded(client: TestClient) -> None:
    now = datetime.now(UTC)
    payload = [
        {
            "timestamp": (now + timedelta(seconds=index * 10)).isoformat(),
            "source": "nginx",
            "ip": "203.0.113.20",
            "method": "GET",
            "path": f"/missing-{index}",
            "status_code": 404,
            "user_agent": "Mozilla/5.0",
        }
        for index in range(20)
    ]

    assert client.post("/ingest/nginx", json=payload).status_code == 200
    client.post("/detect/run")

    alerts = client.get("/alerts").json()
    assert "directory_scan_suspicion" in {alert["alert_type"] for alert in alerts}


def test_suspicious_user_agent_is_detected(client: TestClient) -> None:
    ingest_nginx(client, path="/admin", status_code=401, user_agent="Nikto/2.5 local-lab")

    client.post("/detect/run")

    alerts = client.get("/alerts").json()
    assert "suspicious_user_agent" in {alert["alert_type"] for alert in alerts}


def test_stats_summary_returns_dashboard_shape(client: TestClient) -> None:
    ingest_nginx(client, path="/search?q=%27%20OR%20%271%27%3D%271")
    client.post("/detect/run")

    response = client.get("/stats/summary")

    assert response.status_code == 200
    data = response.json()
    assert set(data) == {
        "total_events",
        "total_auth_events",
        "total_alerts",
        "severity_counts",
        "alert_type_counts",
        "source_ip_ranking",
        "latest_alerts",
    }
    assert {"high", "medium", "low"} <= set(data["severity_counts"])
    assert isinstance(data["latest_alerts"], list)


def test_scheduler_status_returns_configuration(client: TestClient) -> None:
    response = client.get("/detect/scheduler")

    assert response.status_code == 200
    data = response.json()
    assert set(data) == {
        "enabled",
        "running",
        "interval_seconds",
        "last_run_at",
        "last_created_alerts",
        "last_error",
    }
    assert data["interval_seconds"] >= 5


def ingest_nginx(
    client: TestClient,
    *,
    path: str,
    status_code: int = 200,
    user_agent: str = "Mozilla/5.0",
) -> None:
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "nginx",
        "ip": "192.0.2.50",
        "method": "GET",
        "path": path,
        "status_code": status_code,
        "user_agent": user_agent,
    }
    assert client.post("/ingest/nginx", json=payload).status_code == 200
