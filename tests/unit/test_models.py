"""Unit tests for domain models, enums, and schemas."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

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


def test_domain_enums() -> None:
    """Verify enum members and values."""
    assert LogFormat.SYSLOG.value == "syslog"
    assert LogFormat.CEF.value == "cef"
    assert LogFormat.JSON.value == "json"
    assert LogFormat.WINDOWS_EVENT.value == "windows_event"

    assert Severity.INFO.weight == 1
    assert Severity.LOW.weight == 3
    assert Severity.MEDIUM.weight == 5
    assert Severity.HIGH.weight == 8
    assert Severity.CRITICAL.weight == 10

    assert CorrelationRuleType.THRESHOLD.value == "threshold"
    assert CorrelationRuleType.SEQUENCE.value == "sequence"
    assert CorrelationRuleType.COMPOSITE.value == "composite"

    assert AttackStage.RECONNAISSANCE.value == "reconnaissance"
    assert AttackStage.CREDENTIAL_ACCESS.value == "credential_access"
    assert AttackStage.PRIVILEGE_ESCALATION.value == "privilege_escalation"

    assert IncidentStatus.OPEN.value == "open"
    assert IncidentStatus.RESOLVED.value == "resolved"


def test_normalized_log_event_creation() -> None:
    """Verify creation and defaults of NormalizedLogEvent."""
    now = datetime.now(timezone.utc)
    event = NormalizedLogEvent(
        raw_log="Feb 10 12:00:00 server sshd[123]: Failed password for root from 192.168.1.100",
        format=LogFormat.SYSLOG,
        source_host="server",
        source_ip="192.168.1.100",
        source_port=54321,
        destination_ip="192.168.1.10",
        destination_port=22,
        user="root",
        action="auth_failure",
        status="failure",
        severity=Severity.MEDIUM,
        attack_stage=AttackStage.CREDENTIAL_ACCESS,
        mitre_technique_id="T1110",
        metadata={"service": "sshd", "pid": 123},
    )

    assert event.event_id is not None
    assert event.format == LogFormat.SYSLOG
    assert event.source_ip == "192.168.1.100"
    assert event.source_port == 54321
    assert event.destination_port == 22
    assert event.user == "root"
    assert event.action == "auth_failure"
    assert event.severity == Severity.MEDIUM
    assert event.attack_stage == AttackStage.CREDENTIAL_ACCESS
    assert event.metadata["service"] == "sshd"
    assert event.timestamp >= now


def test_normalized_log_event_entity_extraction() -> None:
    """Verify entity extraction via get_entity_value."""
    event = NormalizedLogEvent(
        raw_log="sample log line",
        source_host="sensor-01",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.1",
        user="analyst",
        action="login",
        metadata={"custom_uuid": "xyz-123", "empty_key": None},
    )

    assert event.get_entity_value("source_ip") == "10.0.0.5"
    assert event.get_entity_value("destination_ip") == "10.0.0.1"
    assert event.get_entity_value("user") == "analyst"
    assert event.get_entity_value("source_host") == "sensor-01"
    assert event.get_entity_value("custom_uuid") == "xyz-123"
    assert event.get_entity_value("empty_key") is None
    assert event.get_entity_value("nonexistent") is None


def test_normalized_log_event_timestamp_harmonization() -> None:
    """Verify naive and ISO string timestamps are harmonized to UTC."""
    naive_dt = datetime(2026, 10, 12, 12, 0, 0)
    event1 = NormalizedLogEvent(raw_log="log", action="test", timestamp=naive_dt)
    assert event1.timestamp.tzinfo == timezone.utc

    iso_str = "2026-10-12T14:30:00+02:00"
    event2 = NormalizedLogEvent(
        raw_log="log",
        action="test",
        timestamp=iso_str,  # type: ignore[arg-type]
    )
    assert event2.timestamp.tzinfo == timezone.utc
    assert event2.timestamp.hour == 12  # 14:30 +02:00 -> 12:30 UTC


def test_normalized_log_event_invalid_inputs() -> None:
    """Verify validation errors on invalid ports or timestamp types."""
    with pytest.raises(ValidationError):
        NormalizedLogEvent(raw_log="log", action="test", source_port=70000)

    with pytest.raises(ValidationError):
        NormalizedLogEvent(raw_log="log", action="test", source_port=-1)

    with pytest.raises(ValidationError):
        NormalizedLogEvent(raw_log="log", action="test", timestamp=12345)  # type: ignore[arg-type]


def test_correlation_rule_threshold() -> None:
    """Verify threshold correlation rule validation."""
    rule = CorrelationRule(
        rule_id="R-BRUTE-01",
        name="SSH Brute Force",
        description="Multiple failed SSH logins from single IP",
        rule_type=CorrelationRuleType.THRESHOLD,
        window_seconds=60,
        group_by_fields=["source_ip"],
        threshold_count=5,
        match_filter={"action": "auth_failure"},
        severity=Severity.HIGH,
        attack_stages=[AttackStage.CREDENTIAL_ACCESS],
        mitre_attack_ids=["T1110.001"],
    )

    assert rule.threshold_count == 5
    assert rule.enabled is True
    assert rule.group_by_fields == ["source_ip"]


def test_correlation_rule_threshold_invalid() -> None:
    """Verify threshold rule raises when threshold_count or match_filter is missing."""
    with pytest.raises(ValueError, match="threshold_count is required"):
        CorrelationRule(
            rule_id="R-FAIL",
            name="Fail Rule",
            description="desc",
            rule_type=CorrelationRuleType.THRESHOLD,
            match_filter={"action": "auth_failure"},
        )

    with pytest.raises(ValueError, match="match_filter must not be empty"):
        CorrelationRule(
            rule_id="R-FAIL-2",
            name="Fail Rule",
            description="desc",
            rule_type=CorrelationRuleType.THRESHOLD,
            threshold_count=3,
            match_filter={},
        )


def test_correlation_rule_sequence() -> None:
    """Verify sequence correlation rule validation."""
    rule = CorrelationRule(
        rule_id="R-SEQ-01",
        name="Brute Force to Sudo Escalation",
        description="Brute force followed by privileged sudo command",
        rule_type=CorrelationRuleType.SEQUENCE,
        window_seconds=120,
        group_by_fields=["source_ip", "user"],
        sequence_filters=[
            {"action": "auth_failure"},
            {"action": "sudo_exec"},
        ],
        severity=Severity.CRITICAL,
        attack_stages=[AttackStage.CREDENTIAL_ACCESS, AttackStage.PRIVILEGE_ESCALATION],
    )

    assert len(rule.sequence_filters) == 2
    assert rule.severity == Severity.CRITICAL


def test_correlation_rule_sequence_invalid() -> None:
    """Verify sequence rule raises when sequence_filters has < 2 stages."""
    with pytest.raises(ValueError, match="at least 2 stages"):
        CorrelationRule(
            rule_id="R-SEQ-FAIL",
            name="Invalid Sequence",
            description="desc",
            rule_type=CorrelationRuleType.SEQUENCE,
            sequence_filters=[{"action": "login"}],
        )


def test_correlated_incident_and_risk_scoring() -> None:
    """Verify CorrelatedIncident creation, default summary, and risk calculation."""
    now = datetime.now(timezone.utc)
    ev1 = NormalizedLogEvent(
        raw_log="log 1",
        source_ip="192.168.1.50",
        user="ubuntu",
        action="auth_failure",
        severity=Severity.LOW,
    )
    ev2 = NormalizedLogEvent(
        raw_log="log 2",
        source_ip="192.168.1.50",
        user="ubuntu",
        action="sudo_exec",
        severity=Severity.HIGH,
    )

    incident = CorrelatedIncident(
        rule_id="R-SEQ-01",
        rule_name="Brute Force to Sudo Escalation",
        rule_type=CorrelationRuleType.SEQUENCE,
        severity=Severity.CRITICAL,
        entity_keys={"source_ip": "192.168.1.50", "user": "ubuntu"},
        attack_stages=[AttackStage.CREDENTIAL_ACCESS, AttackStage.PRIVILEGE_ESCALATION],
        mitre_attack_ids=["T1110", "T1548.003"],
        matched_events=[ev1, ev2],
        window_seconds=120,
        first_event_time=now,
        last_event_time=now,
    )

    assert incident.event_count == 2
    assert "CRITICAL incident [R-SEQ-01]" in incident.summary
    assert incident.status == IncidentStatus.OPEN

    score = incident.calculate_risk_score()
    # CRITICAL (10 * 7 = 70) + volume (2 * 2 = 4) + stage (2 stages * 5 = 10) = 84.0
    assert score == 84.0
    assert incident.risk_score == 84.0


def test_alert_notification() -> None:
    """Verify AlertNotification instantiation and fields."""
    now = datetime.now(timezone.utc)
    alert = AlertNotification(
        incident_id="INC-12345678",
        rule_id="R-BRUTE-01",
        rule_name="SSH Brute Force",
        severity=Severity.HIGH,
        risk_score=78.5,
        title="High Severity SSH Brute Force Detected",
        description="5 failed attempts from 10.0.0.1 within 60s",
        affected_entities={"source_ip": "10.0.0.1"},
        mitre_tactics=["Credential Access"],
        timestamp=now,
        channel="console",
    )

    assert alert.alert_id.startswith("ALT-")
    assert alert.incident_id == "INC-12345678"
    assert alert.severity == Severity.HIGH
    assert alert.risk_score == 78.5
    assert alert.dispatched is False
