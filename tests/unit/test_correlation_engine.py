"""Unit tests for sliding-window buffer and correlation engine."""

from datetime import datetime, timedelta, timezone

from log_corr.engine.correlator import CorrelationEngine
from log_corr.engine.window_buffer import SlidingWindowBuffer
from log_corr.models.enums import AttackStage, CorrelationRuleType, Severity
from log_corr.models.schemas import CorrelationRule, NormalizedLogEvent


def test_sliding_window_buffer_operations() -> None:
    """Verify add, retrieve, evict, purge, and stats operations on SlidingWindowBuffer."""
    buffer = SlidingWindowBuffer(max_events_per_key=3)
    base_time = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)

    ev1 = NormalizedLogEvent(raw_log="log 1", action="scan", timestamp=base_time)
    ev2 = NormalizedLogEvent(
        raw_log="log 2", action="scan", timestamp=base_time + timedelta(seconds=10)
    )
    ev3 = NormalizedLogEvent(
        raw_log="log 3", action="scan", timestamp=base_time + timedelta(seconds=20)
    )
    ev4 = NormalizedLogEvent(
        raw_log="log 4", action="scan", timestamp=base_time + timedelta(seconds=30)
    )

    buffer.add_event("host:srv1", ev1)
    buffer.add_event("host:srv1", ev2)
    buffer.add_event("host:srv1", ev3)
    buffer.add_event("host:srv1", ev4)

    # Max events per key is 3, so ev1 should have been evicted
    events = buffer.get_window_events(
        "host:srv1", window_seconds=60, reference_time=base_time + timedelta(seconds=30)
    )
    assert len(events) == 3
    assert events[0].raw_log == "log 2"
    assert events[-1].raw_log == "log 4"

    stats = buffer.get_stats()
    assert stats["active_keys"] == 1
    assert stats["total_buffered_events"] == 3

    assert "host:srv1" in buffer.get_active_entity_keys()

    # Test purge
    purged = buffer.purge_expired(
        max_idle_seconds=0, reference_time=base_time + timedelta(seconds=100)
    )
    assert purged == 1
    assert buffer.get_stats()["active_keys"] == 0

    buffer.clear()
    assert len(buffer.get_active_entity_keys()) == 0


def test_threshold_rule_correlation() -> None:
    """Verify threshold detection (e.g., 5 failed logins within 60s)."""
    engine = CorrelationEngine(cooldown_seconds=10)
    rule = CorrelationRule(
        rule_id="R-SSH-BRUTE",
        name="SSH Brute Force Detection",
        description="5 failed logins within 60s from single IP",
        rule_type=CorrelationRuleType.THRESHOLD,
        window_seconds=60,
        group_by_fields=["source_ip"],
        threshold_count=5,
        match_filter={"action": "auth_failure"},
        severity=Severity.HIGH,
        attack_stages=[AttackStage.CREDENTIAL_ACCESS],
        mitre_attack_ids=["T1110.001"],
    )
    engine.register_rule(rule)
    assert engine.get_rule("R-SSH-BRUTE") is not None
    assert len(engine.list_rules(enabled_only=True)) == 1

    base_time = datetime(2026, 10, 12, 15, 0, 0, tzinfo=timezone.utc)
    ip = "198.51.100.44"

    # Send 4 failed logins (should NOT trigger)
    incidents: list[object] = []
    for i in range(4):
        ev = NormalizedLogEvent(
            raw_log=f"fail {i}",
            source_ip=ip,
            action="auth_failure",
            timestamp=base_time + timedelta(seconds=i * 2),
        )
        incidents.extend(engine.process_event(ev))

    assert len(incidents) == 0

    # 5th failed login triggers incident
    ev5 = NormalizedLogEvent(
        raw_log="fail 5",
        source_ip=ip,
        action="auth_failure",
        timestamp=base_time + timedelta(seconds=8),
    )
    new_incidents = engine.process_event(ev5)
    assert len(new_incidents) == 1
    inc = new_incidents[0]
    assert inc.rule_id == "R-SSH-BRUTE"
    assert inc.event_count == 5
    assert inc.entity_keys == {"source_ip": ip}
    assert inc.severity == Severity.HIGH
    assert inc.risk_score >= 60.0

    # 6th immediate failed login is suppressed by cooldown
    ev6 = NormalizedLogEvent(
        raw_log="fail 6",
        source_ip=ip,
        action="auth_failure",
        timestamp=base_time + timedelta(seconds=9),
    )
    cooldown_incidents = engine.process_event(ev6)
    assert len(cooldown_incidents) == 0


def test_multi_stage_sequence_detection_brute_force_to_sudo() -> None:
    """Verify sequence detection: brute-force -> privilege escalation from same IP & user."""
    engine = CorrelationEngine(cooldown_seconds=5)
    rule = CorrelationRule(
        rule_id="R-MULTI-BRUTE-SUDO",
        name="Brute Force to Sudo Privilege Escalation",
        description="SSH auth failure followed by sudo execution from same user and IP",
        rule_type=CorrelationRuleType.SEQUENCE,
        window_seconds=120,
        group_by_fields=["source_ip", "user"],
        sequence_filters=[
            {"action": "auth_failure"},
            {"action": "sudo_exec"},
        ],
        severity=Severity.CRITICAL,
        attack_stages=[AttackStage.CREDENTIAL_ACCESS, AttackStage.PRIVILEGE_ESCALATION],
        mitre_attack_ids=["T1110.001", "T1548.003"],
    )
    engine.register_rule(rule)

    base_time = datetime(2026, 10, 12, 16, 0, 0, tzinfo=timezone.utc)
    attacker_ip = "203.0.113.88"
    target_user = "victim_user"

    # Stage 1: Auth Failure
    ev1 = NormalizedLogEvent(
        raw_log="auth failure",
        source_ip=attacker_ip,
        user=target_user,
        action="auth_failure",
        attack_stage=AttackStage.CREDENTIAL_ACCESS,
        timestamp=base_time,
    )
    incidents_1 = engine.process_event(ev1)
    assert len(incidents_1) == 0

    # Stage 2: Sudo execution 15 seconds later
    ev2 = NormalizedLogEvent(
        raw_log="sudo command executed",
        source_ip=attacker_ip,
        user=target_user,
        action="sudo_exec",
        attack_stage=AttackStage.PRIVILEGE_ESCALATION,
        timestamp=base_time + timedelta(seconds=15),
    )
    incidents_2 = engine.process_event(ev2)
    assert len(incidents_2) == 1

    incident = incidents_2[0]
    assert incident.rule_id == "R-MULTI-BRUTE-SUDO"
    assert incident.severity == Severity.CRITICAL
    assert incident.event_count == 2
    assert incident.entity_keys == {"source_ip": attacker_ip, "user": target_user}
    assert AttackStage.CREDENTIAL_ACCESS in incident.attack_stages
    assert AttackStage.PRIVILEGE_ESCALATION in incident.attack_stages
    assert "T1110.001" in incident.mitre_attack_ids
    assert "T1548.003" in incident.mitre_attack_ids
    assert incident.risk_score >= 80.0


def test_sequence_out_of_order_does_not_trigger() -> None:
    """Verify that an inverted sequence (sudo before auth failure) does NOT trigger."""
    engine = CorrelationEngine(cooldown_seconds=0)
    rule = CorrelationRule(
        rule_id="R-SEQ-ORDER",
        name="Ordered Attack Sequence",
        description="Stage A followed by Stage B",
        rule_type=CorrelationRuleType.SEQUENCE,
        window_seconds=60,
        group_by_fields=["source_ip"],
        sequence_filters=[
            {"action": "port_probe"},
            {"action": "web_exploit"},
        ],
        severity=Severity.HIGH,
    )
    engine.register_rule(rule)

    base_time = datetime(2026, 10, 12, 17, 0, 0, tzinfo=timezone.utc)
    ip = "192.168.10.15"

    # Send web_exploit FIRST, then port_probe SECOND
    ev1 = NormalizedLogEvent(
        raw_log="web exploit",
        source_ip=ip,
        action="web_exploit",
        timestamp=base_time,
    )
    ev2 = NormalizedLogEvent(
        raw_log="port probe",
        source_ip=ip,
        action="port_probe",
        timestamp=base_time + timedelta(seconds=5),
    )

    inc1 = engine.process_event(ev1)
    inc2 = engine.process_event(ev2)
    assert len(inc1) == 0
    assert len(inc2) == 0


def test_composite_multi_stage_rule_and_batch() -> None:
    """Verify composite correlation rule requiring multiple stages across batch events."""
    engine = CorrelationEngine(cooldown_seconds=0)
    rule = CorrelationRule(
        rule_id="R-COMPOSITE-01",
        name="Multi-Stage Attack Chain",
        description="Combination of reconnaissance and initial access",
        rule_type=CorrelationRuleType.COMPOSITE,
        window_seconds=300,
        group_by_fields=["source_ip"],
        attack_stages=[AttackStage.RECONNAISSANCE, AttackStage.INITIAL_ACCESS],
        severity=Severity.HIGH,
    )
    engine.register_rule(rule)

    base = datetime(2026, 10, 12, 18, 0, 0, tzinfo=timezone.utc)
    ip = "10.0.0.99"

    events = [
        NormalizedLogEvent(
            raw_log="probe",
            source_ip=ip,
            action="port_probe",
            attack_stage=AttackStage.RECONNAISSANCE,
            timestamp=base,
        ),
        NormalizedLogEvent(
            raw_log="exploit",
            source_ip=ip,
            action="web_exploit",
            attack_stage=AttackStage.INITIAL_ACCESS,
            timestamp=base + timedelta(seconds=30),
        ),
    ]

    incidents = engine.process_batch(events)
    assert len(incidents) == 1
    assert incidents[0].rule_id == "R-COMPOSITE-01"
    assert incidents[0].event_count == 2


def test_rule_unregistration_and_missing_entity_field() -> None:
    """Verify rule unregistration and event lacking required group_by field."""
    engine = CorrelationEngine()
    rule = CorrelationRule(
        rule_id="R-TEST",
        name="Test Rule",
        description="desc",
        rule_type=CorrelationRuleType.THRESHOLD,
        threshold_count=2,
        match_filter={"action": "test"},
        group_by_fields=["user"],
    )
    engine.register_rule(rule)
    assert engine.unregister_rule("R-TEST") is True
    assert engine.unregister_rule("NONEXISTENT") is False

    engine.register_rule(rule)
    # Event without user field should be safely skipped
    ev_no_user = NormalizedLogEvent(raw_log="log", action="test", user=None)
    incidents = engine.process_event(ev_no_user)
    assert len(incidents) == 0


def test_correlation_engine_filters_and_clear() -> None:
    """Verify metadata filters, disabled rules, and engine clear."""
    engine = CorrelationEngine(cooldown_seconds=0)

    # Disabled rule
    disabled_rule = CorrelationRule(
        rule_id="R-DISABLED",
        name="Disabled Rule",
        description="desc",
        rule_type=CorrelationRuleType.THRESHOLD,
        enabled=False,
        threshold_count=2,
        match_filter={"action": "alert"},
    )
    # Rule with metadata and status filter
    filter_rule = CorrelationRule(
        rule_id="R-FILTER",
        name="Filter Rule",
        description="desc",
        rule_type=CorrelationRuleType.THRESHOLD,
        threshold_count=2,
        match_filter={"action": "probe", "status": "failure", "env": "prod"},
        group_by_fields=["source_ip"],
    )
    engine.register_rule(disabled_rule)
    engine.register_rule(filter_rule)

    assert len(engine.list_rules(enabled_only=True)) == 1
    assert len(engine.list_rules(enabled_only=False)) == 2

    # Events matching filter
    ev1 = NormalizedLogEvent(
        raw_log="ev1",
        action="probe",
        status="failure",
        source_ip="1.1.1.1",
        metadata={"env": "prod"},
    )
    ev2 = NormalizedLogEvent(
        raw_log="ev2",
        action="probe",
        status="failure",
        source_ip="1.1.1.1",
        metadata={"env": "prod"},
    )
    # Non-matching event (different env metadata)
    ev_mismatch = NormalizedLogEvent(
        raw_log="ev_bad",
        action="probe",
        status="failure",
        source_ip="1.1.1.1",
        metadata={"env": "dev"},
    )

    engine.process_event(ev_mismatch)
    engine.process_event(ev1)
    incidents = engine.process_event(ev2)
    assert len(incidents) == 1
    assert incidents[0].rule_id == "R-FILTER"

    # Test clear
    engine.clear()
    assert len(engine.buffer.get_active_entity_keys()) == 0
