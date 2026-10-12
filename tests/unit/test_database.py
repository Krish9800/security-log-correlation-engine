"""Unit tests for SQLite WAL persistence engine."""

from datetime import datetime, timezone
from pathlib import Path

from log_corr.db.database import DatabaseManager
from log_corr.models.enums import (
    AttackStage,
    CorrelationRuleType,
    IncidentStatus,
    LogFormat,
    Severity,
)
from log_corr.models.schemas import (
    AlertNotification,
    CorrelatedIncident,
    CorrelationRule,
    NormalizedLogEvent,
)


def test_database_init_and_wal(temp_dir: Path) -> None:
    """Verify database initialization and WAL journal mode."""
    db_file = temp_dir / "test_wal.db"
    db = DatabaseManager(db_file)
    cur = db._conn.cursor()
    mode = cur.execute("PRAGMA journal_mode;").fetchone()[0]
    assert mode.lower() == "wal"
    cur.close()
    db.close()


def test_event_crud(temp_dir: Path) -> None:
    """Verify event persistence and querying."""
    db = DatabaseManager(temp_dir / "events.db")
    now = datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc)

    ev1 = NormalizedLogEvent(
        raw_log="log 1",
        format=LogFormat.SYSLOG,
        source_ip="192.168.1.5",
        user="root",
        action="auth_failure",
        timestamp=now,
    )
    ev2 = NormalizedLogEvent(
        raw_log="log 2",
        format=LogFormat.JSON,
        source_ip="192.168.1.10",
        user="ubuntu",
        action="sudo_exec",
        timestamp=now,
    )

    db.save_event(ev1)
    retrieved = db.get_event(ev1.event_id)
    assert retrieved is not None
    assert retrieved.event_id == ev1.event_id
    assert retrieved.source_ip == "192.168.1.5"

    # Batch save
    saved_count = db.save_events([ev2])
    assert saved_count == 1

    # Filtered list
    events = db.list_events(source_ip="192.168.1.10")
    assert len(events) == 1
    assert events[0].action == "sudo_exec"

    assert db.get_event("NONEXISTENT") is None
    db.close()


def test_rule_crud(temp_dir: Path) -> None:
    """Verify rule persistence, update, list, and delete."""
    db = DatabaseManager(temp_dir / "rules.db")
    rule = CorrelationRule(
        rule_id="R-TEST-01",
        name="Test Rule",
        description="test description",
        rule_type=CorrelationRuleType.THRESHOLD,
        threshold_count=3,
        match_filter={"action": "test"},
        group_by_fields=["source_ip"],
        severity=Severity.HIGH,
        attack_stages=[AttackStage.CREDENTIAL_ACCESS],
        mitre_attack_ids=["T1110"],
    )

    db.save_rule(rule)
    r = db.get_rule("R-TEST-01")
    assert r is not None
    assert r.rule_id == "R-TEST-01"
    assert r.threshold_count == 3
    assert r.severity == Severity.HIGH

    all_rules = db.list_rules()
    assert len(all_rules) == 1

    assert db.delete_rule("R-TEST-01") is True
    assert db.delete_rule("R-TEST-01") is False
    assert db.get_rule("R-TEST-01") is None
    db.close()


def test_incident_and_alert_crud(temp_dir: Path) -> None:
    """Verify incident and alert persistence and status lifecycle."""
    db = DatabaseManager(temp_dir / "incidents.db")
    now = datetime(2026, 10, 12, 14, 0, 0, tzinfo=timezone.utc)

    ev = NormalizedLogEvent(
        raw_log="auth fail",
        source_ip="10.0.0.1",
        user="admin",
        action="auth_failure",
        timestamp=now,
    )
    incident = CorrelatedIncident(
        incident_id="INC-001",
        rule_id="R-TEST",
        rule_name="Test Rule",
        rule_type=CorrelationRuleType.THRESHOLD,
        severity=Severity.CRITICAL,
        risk_score=85.0,
        status=IncidentStatus.OPEN,
        entity_keys={"source_ip": "10.0.0.1"},
        attack_stages=[AttackStage.CREDENTIAL_ACCESS],
        mitre_attack_ids=["T1110"],
        matched_events=[ev],
        event_count=1,
        window_seconds=60,
        first_event_time=now,
        last_event_time=now,
    )

    db.save_incident(incident)
    retrieved = db.get_incident("INC-001")
    assert retrieved is not None
    assert retrieved.incident_id == "INC-001"
    assert retrieved.risk_score == 85.0
    assert len(retrieved.matched_events) == 1
    assert retrieved.matched_events[0].source_ip == "10.0.0.1"

    # Status update
    updated = db.update_incident_status("INC-001", IncidentStatus.RESOLVED)
    assert updated is True
    updated_inc = db.get_incident("INC-001")
    assert updated_inc is not None
    assert updated_inc.status == IncidentStatus.RESOLVED

    # List incidents with filter
    resolved_list = db.list_incidents(status="resolved")
    assert len(resolved_list) == 1

    # Alert save and list
    alert = AlertNotification(
        alert_id="ALT-001",
        incident_id="INC-001",
        rule_id="R-TEST",
        rule_name="Test Rule",
        severity=Severity.CRITICAL,
        risk_score=85.0,
        title="Critical Incident",
        description="Alert desc",
        affected_entities={"source_ip": "10.0.0.1"},
        mitre_tactics=["Credential Access"],
        timestamp=now,
        channel="console",
    )
    db.save_alert(alert)
    alerts = db.list_alerts()
    assert len(alerts) == 1
    assert alerts[0].alert_id == "ALT-001"
    db.close()
