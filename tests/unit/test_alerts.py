"""Unit tests for incident synthesis and multi-channel alert notification dispatcher."""

import json
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from log_corr.alerts.dispatcher import AlertDispatcher
from log_corr.models.enums import AttackStage, CorrelationRuleType, Severity
from log_corr.models.schemas import CorrelatedIncident, NormalizedLogEvent


@pytest.fixture
def sample_incident() -> CorrelatedIncident:
    """Provide a sample CorrelatedIncident for alert tests."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    ev = NormalizedLogEvent(
        raw_log="auth failure",
        source_ip="198.51.100.9",
        user="admin",
        action="auth_failure",
        attack_stage=AttackStage.CREDENTIAL_ACCESS,
        timestamp=now,
    )
    return CorrelatedIncident(
        incident_id="INC-TEST001",
        rule_id="R-SSH-BRUTE-01",
        rule_name="SSH Password Brute Force",
        rule_type=CorrelationRuleType.THRESHOLD,
        severity=Severity.HIGH,
        risk_score=75.0,
        entity_keys={"source_ip": "198.51.100.9"},
        attack_stages=[AttackStage.CREDENTIAL_ACCESS],
        mitre_attack_ids=["T1110.001"],
        matched_events=[ev],
        event_count=5,
        window_seconds=60,
        first_event_time=now,
        last_event_time=now,
    )


def test_create_notification(sample_incident: CorrelatedIncident) -> None:
    """Verify AlertNotification field synthesis."""
    dispatcher = AlertDispatcher()
    alert = dispatcher.create_notification(sample_incident, channel="console")

    assert alert.incident_id == "INC-TEST001"
    assert alert.rule_id == "R-SSH-BRUTE-01"
    assert alert.severity == Severity.HIGH
    assert alert.risk_score == 75.0
    assert "SSH Password Brute Force" in alert.title
    assert "198.51.100.9" in str(alert.affected_entities)
    assert "Credential Access" in alert.mitre_tactics
    assert alert.dispatched is False


def test_dispatch_console(
    sample_incident: CorrelatedIncident, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify console alert dispatch."""
    dispatcher = AlertDispatcher(enable_console=True)
    alert = dispatcher.dispatch(sample_incident, channel="console")

    assert alert.dispatched is True
    captured = capsys.readouterr()
    assert "ALERT" in captured.out
    assert "[HIGH]" in captured.out
    assert "198.51.100.9" in captured.out


def test_dispatch_file(sample_incident: CorrelatedIncident, temp_dir: Path) -> None:
    """Verify file JSON lines alert dispatch."""
    alert_file = temp_dir / "alerts.jsonl"
    dispatcher = AlertDispatcher(enable_console=False, output_file=alert_file)

    alert = dispatcher.dispatch(sample_incident, channel="file")
    assert alert.dispatched is True
    assert alert_file.is_file()

    content = alert_file.read_text(encoding="utf-8").strip()
    data = json.loads(content)
    assert data["incident_id"] == "INC-TEST001"
    assert data["rule_id"] == "R-SSH-BRUTE-01"
    assert data["severity"] == "high"


def test_dispatch_webhook_success(sample_incident: CorrelatedIncident) -> None:
    """Verify successful webhook dispatch."""
    dispatcher = AlertDispatcher(
        enable_console=False,
        webhook_url="https://siem.corp.internal/api/alerts",
    )

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        alert = dispatcher.dispatch(sample_incident, channel="webhook")
        assert alert.dispatched is True
        mock_urlopen.assert_called_once()


def test_dispatch_webhook_failure(sample_incident: CorrelatedIncident) -> None:
    """Verify webhook dispatch error handling does not raise unhandled exceptions."""
    dispatcher = AlertDispatcher(
        enable_console=False,
        webhook_url="https://unreachable.invalid/webhook",
    )

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        alert = dispatcher.dispatch(sample_incident, channel="webhook")
        assert alert.dispatched is False


def test_dispatch_all_and_history(sample_incident: CorrelatedIncident, temp_dir: Path) -> None:
    """Verify dispatch to all channels and alert history tracking."""
    alert_file = temp_dir / "all_alerts.jsonl"
    dispatcher = AlertDispatcher(
        enable_console=True,
        output_file=alert_file,
        webhook_url="https://hooks.slack.com/services/TEST",
    )

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        alert = dispatcher.dispatch(sample_incident, channel="all")
        assert alert.dispatched is True

    history = dispatcher.get_alert_history()
    assert len(history) == 1
    assert history[0].incident_id == "INC-TEST001"

    dispatcher.clear_history()
    assert len(dispatcher.get_alert_history()) == 0
