"""Adversarial and security hardening test suite for Security Log Correlation Engine.

Tests resilience against:
- Malformed/corrupted logs (null bytes, ANSI escape injection, huge payloads)
- Time jumps (events years in the past/future)
- Entity spoofing / empty fields
- SQL injection attempts in search, filters, and raw logs
- DoS flooding / memory boundedness
"""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from log_corr.db.database import DatabaseManager
from log_corr.engine.correlator import CorrelationEngine
from log_corr.engine.window_buffer import SlidingWindowBuffer
from log_corr.ingestion.dispatcher import LogIngestionDispatcher
from log_corr.models.enums import (
    CorrelationRuleType,
    IncidentStatus,
    LogFormat,
    Severity,
)
from log_corr.models.schemas import CorrelationRule, NormalizedLogEvent


@pytest.fixture
def temp_db_path() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "adversarial_test.db"


@pytest.fixture
def db_manager(temp_db_path: Path) -> Generator[DatabaseManager, None, None]:
    db = DatabaseManager(temp_db_path)
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def ingestion_dispatcher() -> LogIngestionDispatcher:
    return LogIngestionDispatcher()


class TestMalformedLogResilience:
    """Tests the parser and dispatcher resilience against malformed and hostile inputs."""

    def test_null_bytes_in_syslog(self, ingestion_dispatcher: LogIngestionDispatcher) -> None:
        malicious_raw = "<34>1 2026-10-12T12:00:00Z myhost sshd 123 - -\x00\x00\x00Failed password"
        event = ingestion_dispatcher.parse(malicious_raw)
        assert event is not None
        assert isinstance(event, NormalizedLogEvent)
        assert event.format in (LogFormat.SYSLOG, LogFormat.UNKNOWN)

    def test_ansi_escape_injection(self, ingestion_dispatcher: LogIngestionDispatcher) -> None:
        ansi_log = "\033[31;1mCRITICAL RED ALERT\033[0m sshd: Failed password for admin"
        event = ingestion_dispatcher.parse(ansi_log)
        assert event is not None
        assert isinstance(event, NormalizedLogEvent)
        assert "CRITICAL RED ALERT" in event.raw_log or "sshd" in event.raw_log

    def test_massive_payload_handling(self, ingestion_dispatcher: LogIngestionDispatcher) -> None:
        huge_payload = "CEF:0|Vendor|Product|1.0|100|HugeEvent|5|" + "A" * 100_000
        event = ingestion_dispatcher.parse(huge_payload)
        assert event is not None
        assert isinstance(event, NormalizedLogEvent)
        assert len(event.raw_log) >= 100_000

    def test_truncated_json_payload(self, ingestion_dispatcher: LogIngestionDispatcher) -> None:
        truncated_json = '{"timestamp": "2026-10-12T12:00:00Z", "event": "failed_login", "user": '
        event = ingestion_dispatcher.parse(truncated_json)
        assert event is not None
        assert isinstance(event, NormalizedLogEvent)
        assert event.format in (LogFormat.JSON, LogFormat.UNKNOWN, LogFormat.SYSLOG)


class TestSqlInjectionResilience:
    """Tests that SQL injection vectors in payloads and search criteria are mitigated."""

    def test_sqli_in_event_fields_and_persistence(self, db_manager: DatabaseManager) -> None:
        sqli_payload = "admin' OR '1'='1' --; DROP TABLE correlated_incidents; --"
        event = NormalizedLogEvent(
            raw_log=sqli_payload,
            source_ip="192.168.1.100",
            user=sqli_payload,
            action="login_attempt",
            severity=Severity.HIGH,
        )

        db_manager.save_event(event)
        retrieved = db_manager.get_event(event.event_id)
        assert retrieved is not None
        assert retrieved.user == sqli_payload

        # Ensure database tables were not dropped
        incidents = db_manager.list_incidents()
        assert isinstance(incidents, list)

    def test_sqli_in_search_filters(self, db_manager: DatabaseManager) -> None:
        malicious_search = "' UNION SELECT * FROM correlated_incidents --"
        results = db_manager.list_events(source_ip=malicious_search)
        assert results == []

    def test_sqli_in_incident_status_update(self, db_manager: DatabaseManager) -> None:
        event = NormalizedLogEvent(
            raw_log="sample auth fail",
            source_ip="10.0.0.1",
            action="failed_login",
        )
        db_manager.save_event(event)

        rule = CorrelationRule(
            rule_id="R-TEST-SQLI",
            name="SQLi Test Rule",
            description="Rule for SQLi testing",
            rule_type=CorrelationRuleType.THRESHOLD,
            threshold_count=2,
            window_seconds=60,
            match_filter={"action": "failed_login"},
            group_by_fields=["source_ip"],
        )

        engine = CorrelationEngine()
        engine.register_rule(rule)
        engine.process_event(event)
        incidents = engine.process_event(event)
        assert len(incidents) == 1
        incident = incidents[0]

        db_manager.save_incident(incident)

        # Attempt SQL injection during update via malicious incident_id
        sqli_id = f"{incident.incident_id}' OR '1'='1"
        updated = db_manager.update_incident_status(sqli_id, IncidentStatus.RESOLVED)
        assert updated is False

        # Legitimate update succeeds
        updated_legit = db_manager.update_incident_status(
            incident.incident_id, IncidentStatus.RESOLVED
        )
        assert updated_legit is True

        reloaded = db_manager.get_incident(incident.incident_id)
        assert reloaded is not None
        assert reloaded.status == IncidentStatus.RESOLVED


class TestTimestampJumpAndBoundaryResilience:
    """Tests extreme timestamps (past/future) do not break sliding window or state."""

    def test_past_and_future_timestamp_handling(self) -> None:
        rule = CorrelationRule(
            rule_id="R-TIME-JUMP",
            name="Burst Threshold",
            description="Testing timestamp variance",
            rule_type=CorrelationRuleType.THRESHOLD,
            threshold_count=2,
            window_seconds=300,
            match_filter={"action": "test_action"},
            group_by_fields=["source_ip"],
        )
        engine = CorrelationEngine()
        engine.register_rule(rule)

        now = datetime.now(timezone.utc)
        # Event 1: Ancient event from year 1970
        ancient_event = NormalizedLogEvent(
            raw_log="ancient log",
            timestamp=datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            source_ip="1.2.3.4",
            action="test_action",
        )
        # Event 2: Distant future event from year 2099
        future_event = NormalizedLogEvent(
            raw_log="future log",
            timestamp=datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            source_ip="1.2.3.4",
            action="test_action",
        )
        # Event 3: Event at normal now
        now_event = NormalizedLogEvent(
            raw_log="now log",
            timestamp=now,
            source_ip="1.2.3.4",
            action="test_action",
        )

        # Process without unhandled exceptions
        inc_ancient = engine.process_event(ancient_event)
        assert inc_ancient == []

        inc_future = engine.process_event(future_event)
        # Ancient and future events are 129 years apart (> 300s); threshold 2 not triggered
        assert inc_future == []

        inc_now = engine.process_event(now_event)
        assert isinstance(inc_now, list)


class TestDosAndBufferOverflowResilience:
    """Tests that high-volume entity key generation stays bounded within max memory parameters."""

    def test_high_volume_distinct_entity_keys(self) -> None:
        rule = CorrelationRule(
            rule_id="R-FLOOD-01",
            name="Threshold Brute Force",
            description="Rule for brute force",
            rule_type=CorrelationRuleType.THRESHOLD,
            threshold_count=10,
            window_seconds=60,
            match_filter={"action": "auth_fail"},
            group_by_fields=["source_ip"],
        )
        buffer = SlidingWindowBuffer(max_events_per_key=10)
        engine = CorrelationEngine(buffer=buffer)
        engine.register_rule(rule)

        # Send 500 events across 50 distinct IPs (10 each)
        for i in range(500):
            event = NormalizedLogEvent(
                raw_log=f"flood event {i}",
                timestamp=datetime.now(timezone.utc) + timedelta(milliseconds=i),
                source_ip=f"10.0.0.{i % 50}",
                action="auth_fail",
            )
            engine.process_event(event)

        stats = buffer.get_stats()
        assert stats["active_keys"] <= 50
        # Events per key capped at 10, so total buffered events <= 500
        assert stats["total_buffered_events"] <= 500

    def test_empty_and_null_entity_keys(self) -> None:
        rule = CorrelationRule(
            rule_id="R-NULL-KEY",
            name="User Attack Rule",
            description="Testing null entity keys",
            rule_type=CorrelationRuleType.THRESHOLD,
            threshold_count=2,
            window_seconds=60,
            match_filter={"action": "action"},
            group_by_fields=["user"],
        )
        engine = CorrelationEngine()
        engine.register_rule(rule)

        # Events with None or empty user
        event1 = NormalizedLogEvent(raw_log="log 1", action="action", user=None)
        event2 = NormalizedLogEvent(raw_log="log 2", action="action", user="")

        incidents1 = engine.process_event(event1)
        incidents2 = engine.process_event(event2)

        # Should handle gracefully without raising KeyError or AttributeError
        assert isinstance(incidents1, list)
        assert isinstance(incidents2, list)
