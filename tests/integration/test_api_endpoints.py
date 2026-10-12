"""Integration tests for FastAPI control plane endpoints."""

from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from log_corr.alerts.dispatcher import AlertDispatcher
from log_corr.api.app import create_app
from log_corr.config.settings import Settings
from log_corr.db.database import DatabaseManager
from log_corr.engine.correlator import CorrelationEngine
from log_corr.rules.rule_catalog import get_default_rules


@pytest.fixture
def client(temp_dir: Path) -> Generator[TestClient, None, None]:
    """Create isolated test client with dedicated SQLite DB and engine."""
    db_file = temp_dir / "api_test.db"
    db = DatabaseManager(db_file)
    engine = CorrelationEngine(cooldown_seconds=0)
    for rule in get_default_rules():
        engine.register_rule(rule)
        db.save_rule(rule)

    dispatcher = AlertDispatcher(enable_console=False)
    settings = Settings(db_path=db_file, enable_console_alerts=False)

    app = create_app(settings=settings, db=db, engine=engine, dispatcher=dispatcher)
    with TestClient(app) as test_client:
        yield test_client


def test_health_check(client: TestClient) -> None:
    """Verify /health returns 200 and operational statistics."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "Security Log Correlation" in data["app_name"]
    assert data["active_rules_count"] >= 5


def test_ingest_and_trigger_incident(client: TestClient) -> None:
    """Verify POST /api/v1/logs/ingest triggers correlation incident on 5 SSH failures."""
    ip = "192.168.100.55"
    log_lines = [
        f"Oct 12 12:00:0{i} srv sshd[{i}]: Failed password for root from {ip} port 500{i} ssh2"
        for i in range(5)
    ]

    resp = client.post("/api/v1/logs/ingest", json={"logs": log_lines})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ingested_count"] == 5
    assert data["incidents_count"] >= 1
    assert data["incidents"][0]["rule_id"] == "R-SSH-BRUTE-01"
    assert data["incidents"][0]["entity_keys"] == {"source_ip": ip}


def test_ingest_empty_payload(client: TestClient) -> None:
    """Verify empty ingestion request returns 0 counts without error."""
    resp = client.post("/api/v1/logs/ingest", json={"logs": []})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ingested_count"] == 0
    assert data["incidents_count"] == 0


def test_incident_lifecycle_and_queries(client: TestClient) -> None:
    """Verify listing, retrieving, and updating incident lifecycle status."""
    # First ingest 5 failures to generate an incident
    ip = "10.20.30.40"
    logs = [
        f"Oct 12 10:00:0{i} host sshd[10{i}]: Failed password for admin from {ip} port 4000{i} ssh2"
        for i in range(5)
    ]
    client.post("/api/v1/logs/ingest", json={"logs": logs})

    # List incidents
    list_resp = client.get("/api/v1/incidents")
    assert list_resp.status_code == 200
    incidents = list_resp.json()
    assert len(incidents) >= 1
    inc_id = incidents[0]["incident_id"]

    # Get single incident
    get_resp = client.get(f"/api/v1/incidents/{inc_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["incident_id"] == inc_id

    # Update status to resolved
    patch_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "resolved"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "resolved"

    # Verify updated in query
    resolved_resp = client.get("/api/v1/incidents?status=resolved")
    assert resolved_resp.status_code == 200
    assert any(i["incident_id"] == inc_id for i in resolved_resp.json())

    # 404 on non-existent incident
    assert client.get("/api/v1/incidents/INC-NOTFOUND").status_code == 404
    assert (
        client.patch(
            "/api/v1/incidents/INC-NOTFOUND/status", json={"status": "resolved"}
        ).status_code
        == 404
    )


def test_rules_endpoints(client: TestClient) -> None:
    """Verify /api/v1/rules listing, creation, and deletion."""
    # List rules
    rules_resp = client.get("/api/v1/rules")
    assert rules_resp.status_code == 200
    assert len(rules_resp.json()) >= 5

    # Create new rule
    new_rule = {
        "rule_id": "R-CUSTOM-API-01",
        "name": "Custom API Rule",
        "description": "API created rule",
        "rule_type": "threshold",
        "window_seconds": 60,
        "group_by_fields": ["source_ip"],
        "threshold_count": 3,
        "match_filter": {"action": "api_test"},
        "severity": "medium",
        "attack_stages": ["reconnaissance"],
        "mitre_attack_ids": ["T1046"],
    }
    create_resp = client.post("/api/v1/rules", json=new_rule)
    assert create_resp.status_code == 201
    assert create_resp.json()["rule_id"] == "R-CUSTOM-API-01"

    # Delete rule
    del_resp = client.delete("/api/v1/rules/R-CUSTOM-API-01")
    assert del_resp.status_code == 204

    # Delete again returns 404
    del_404 = client.delete("/api/v1/rules/R-CUSTOM-API-01")
    assert del_404.status_code == 404


def test_alerts_endpoint(client: TestClient) -> None:
    """Verify /api/v1/alerts endpoint."""
    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
