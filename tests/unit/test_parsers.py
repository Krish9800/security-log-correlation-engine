"""Unit tests for multi-format log parsers and ingestion dispatcher."""

from pathlib import Path

import pytest

from log_corr.ingestion.cef_parser import CEFParser
from log_corr.ingestion.dispatcher import LogIngestionDispatcher
from log_corr.ingestion.json_parser import JSONLogParser
from log_corr.ingestion.syslog_parser import SyslogParser
from log_corr.ingestion.windows_parser import WindowsEventParser
from log_corr.models.enums import AttackStage, LogFormat, Severity


def test_syslog_rfc5424_parsing() -> None:
    """Verify RFC 5424 syslog parsing."""
    parser = SyslogParser()
    raw = (
        "<134>1 2026-10-12T12:00:00.000Z bastion.corp.net sshd 4321 ID47 - "
        "Failed password for invalid user admin from 192.168.1.100 port 52341 ssh2"
    )
    event = parser.parse(raw)

    assert event.format == LogFormat.SYSLOG
    assert event.source_host == "bastion.corp.net"
    assert event.source_ip == "192.168.1.100"
    assert event.source_port == 52341
    assert event.user == "admin"
    assert event.action == "auth_failure"
    assert event.attack_stage == AttackStage.CREDENTIAL_ACCESS
    assert event.mitre_technique_id == "T1110.001"
    assert event.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)


def test_syslog_rfc3164_sudo_parsing() -> None:
    """Verify RFC 3164 BSD syslog parsing for sudo escalation."""
    parser = SyslogParser()
    raw = (
        "<34>Oct 12 14:15:30 srv-app01 sudo[8812]: pam_unix(sudo:session): "
        "session opened for user root by ubuntu(uid=1000)"
    )
    event = parser.parse(raw)

    assert event.format == LogFormat.SYSLOG
    assert event.source_host == "srv-app01"
    assert event.action == "sudo_exec"
    assert event.attack_stage == AttackStage.PRIVILEGE_ESCALATION
    assert event.mitre_technique_id == "T1548.003"


def test_syslog_auth_success_and_fallback() -> None:
    """Verify syslog auth success and fallback on malformed lines."""
    parser = SyslogParser()
    success_raw = (
        "Oct 12 10:00:00 srv01 sshd[123]: Accepted publickey for analyst "
        "from 10.0.0.50 port 49123 ssh2"
    )
    ev_success = parser.parse(success_raw)
    assert ev_success.action == "auth_success"
    assert ev_success.user == "analyst"
    assert ev_success.source_ip == "10.0.0.50"

    empty_ev = parser.parse("   ")
    assert empty_ev.action == "empty_line"

    malformed_ev = parser.parse("non-standard unstructured text from 1.2.3.4 port 80")
    assert malformed_ev.source_ip == "1.2.3.4"
    assert malformed_ev.source_port == 80


def test_cef_parser_valid_and_port_scan() -> None:
    """Verify ArcSight CEF parser with extensions."""
    parser = CEFParser()
    raw = (
        "CEF:0|NetworkSec|EdgeSensor|3.2|PORT_SCAN|TCP SYN Port Scan|7|"
        "src=192.168.1.200 dst=10.0.0.1 spt=54321 dpt=80 proto=TCP msg=High rate port scan"
    )
    event = parser.parse(raw)

    assert event.format == LogFormat.CEF
    assert event.source_ip == "192.168.1.200"
    assert event.destination_ip == "10.0.0.1"
    assert event.source_port == 54321
    assert event.destination_port == 80
    assert event.severity == Severity.HIGH
    assert event.action == "port_probe"
    assert event.attack_stage == AttackStage.RECONNAISSANCE
    assert event.mitre_technique_id == "T1046"


def test_cef_parser_escaped_chars_and_malformed() -> None:
    """Verify CEF parser handles escaped characters and malformed headers."""
    parser = CEFParser()
    raw = r"CEF:0|SecApp|Scanner|1.0|LOGIN|User Login|4|suser=admin msg=User\=Admin\ Logged\ In"
    ev = parser.parse(raw)
    assert ev.user == "admin"
    assert ev.severity == Severity.MEDIUM

    bad_header = parser.parse("CEF:0|OnlyTwoPipes")
    assert bad_header.action == "malformed_cef_fields"

    no_cef = parser.parse("Just plain text without CEF")
    assert no_cef.action == "invalid_cef_header"


def test_json_parser_structured() -> None:
    """Verify JSON structured log parser with diverse fields."""
    parser = JSONLogParser()
    raw = """
    {
        "timestamp": "2026-10-12T13:45:00Z",
        "hostname": "k8s-node-01",
        "src_ip": "10.10.10.5",
        "dst_ip": "10.10.10.1",
        "dst_port": 443,
        "username": "developer",
        "action": "auth_failure",
        "status": "failure",
        "log_level": "error",
        "attack_stage": "credential_access",
        "mitre_technique_id": "T1110"
    }
    """
    event = parser.parse(raw)

    assert event.format == LogFormat.JSON
    assert event.source_host == "k8s-node-01"
    assert event.source_ip == "10.10.10.5"
    assert event.destination_port == 443
    assert event.user == "developer"
    assert event.action == "auth_failure"
    assert event.severity == Severity.HIGH
    assert event.attack_stage == AttackStage.CREDENTIAL_ACCESS


def test_json_parser_epoch_nested_and_invalid() -> None:
    """Verify JSON epoch timestamp, nested fields, and invalid JSON string."""
    parser = JSONLogParser()
    raw_epoch = '{"timestamp": 1728734400, "source": {"ip": "172.16.0.4"}, "action": "exfil_data"}'
    ev = parser.parse(raw_epoch)
    assert ev.source_ip == "172.16.0.4"
    assert ev.attack_stage == AttackStage.EXFILTRATION

    bad_json = parser.parse("{not valid json}")
    assert bad_json.action == "invalid_json"

    non_dict = parser.parse('["item1", "item2"]')
    assert non_dict.action == "invalid_json"


def test_windows_parser_json_and_text() -> None:
    """Verify Windows Event parser with Event ID 4625 (auth failure) and 4672 (privilege)."""
    parser = WindowsEventParser()

    # Event ID 4625 JSON format
    raw_4625 = """
    {
        "EventID": 4625,
        "Computer": "DC01.CORP.LOCAL",
        "TimeCreated": "2026-10-12T15:00:00Z",
        "EventData": {
            "TargetUserName": "Administrator",
            "IpAddress": "192.168.10.50",
            "IpPort": 51234
        }
    }
    """
    ev_4625 = parser.parse(raw_4625)
    assert ev_4625.format == LogFormat.WINDOWS_EVENT
    assert ev_4625.action == "auth_failure"
    assert ev_4625.attack_stage == AttackStage.CREDENTIAL_ACCESS
    assert ev_4625.user == "Administrator"
    assert ev_4625.source_ip == "192.168.10.50"
    assert ev_4625.source_port == 51234
    assert ev_4625.source_host == "DC01.CORP.LOCAL"

    # Event ID 4672 Text format
    raw_4672 = "EventID=4672, SubjectUserName=admin, WorkstationName=WORKSTATION09"
    ev_4672 = parser.parse(raw_4672)
    assert ev_4672.action == "privilege_assigned"
    assert ev_4672.attack_stage == AttackStage.PRIVILEGE_ESCALATION
    assert ev_4672.user == "admin"
    assert ev_4672.source_host == "WORKSTATION09"

    # Invalid line
    bad_win = parser.parse("---")
    assert bad_win.action == "invalid_windows_event"


def test_dispatcher_auto_detection() -> None:
    """Verify LogIngestionDispatcher format detection."""
    dispatcher = LogIngestionDispatcher()

    assert (
        dispatcher.detect_format("CEF:0|Vendor|Product|1.0|0|Test|1|src=1.2.3.4") == LogFormat.CEF
    )
    assert (
        dispatcher.detect_format('{"EventID": 4624, "TargetUserName": "admin"}')
        == LogFormat.WINDOWS_EVENT
    )
    assert dispatcher.detect_format('{"action": "test", "src_ip": "1.1.1.1"}') == LogFormat.JSON
    assert (
        dispatcher.detect_format("<134>1 2026-10-12T12:00:00Z host app - - - msg")
        == LogFormat.SYSLOG
    )
    assert dispatcher.detect_format("Oct 12 12:00:00 host app: message") == LogFormat.SYSLOG
    assert dispatcher.detect_format("") == LogFormat.UNKNOWN


def test_dispatcher_batch_and_file_parsing(temp_dir: Path) -> None:
    """Verify batch line parsing and reading from file."""
    dispatcher = LogIngestionDispatcher()
    lines = [
        "CEF:0|Acme|App|1.0|SCAN|Port Scan|5|src=10.0.0.1 spt=1000",
        '{"action": "login", "user": "alice", "src_ip": "10.0.0.2"}',
        "Oct 12 12:00:00 server sudo: pam_unix: sudo exec for alice",
    ]

    events = dispatcher.parse_lines(lines)
    assert len(events) == 3
    assert events[0].format == LogFormat.CEF
    assert events[1].format == LogFormat.JSON
    assert events[2].format == LogFormat.SYSLOG

    # Test file parsing
    log_file = temp_dir / "mixed_logs.log"
    log_file.write_text("\n".join(lines), encoding="utf-8")

    file_events = dispatcher.parse_file(log_file)
    assert len(file_events) == 3
    assert file_events[0].source_ip == "10.0.0.1"
    assert file_events[1].user == "alice"

    with pytest.raises(FileNotFoundError):
        dispatcher.parse_file(temp_dir / "nonexistent.log")


def test_windows_event_ids_coverage() -> None:
    """Verify Windows Event IDs 4624, 4720, 4688, 7045 and unknown."""
    parser = WindowsEventParser()

    ev_4624 = parser.parse('{"EventID": 4624, "TargetUserName": "alice", "IpAddress": "10.0.0.5"}')
    assert ev_4624.action == "auth_success"
    assert ev_4624.attack_stage == AttackStage.INITIAL_ACCESS

    ev_4720 = parser.parse('{"EventID": 4720, "TargetUserName": "backdoor_user"}')
    assert ev_4720.action == "user_created"
    assert ev_4720.mitre_technique_id == "T1136.001"

    ev_4688 = parser.parse('{"EventID": 4688, "CommandLine": "powershell.exe -enc ..."}')
    assert ev_4688.action == "process_create"
    assert ev_4688.attack_stage == AttackStage.INITIAL_ACCESS

    ev_7045 = parser.parse('{"EventID": 7045, "ServiceName": "MaliciousSvc"}')
    assert ev_7045.action == "service_install"
    assert ev_7045.attack_stage == AttackStage.PRIVILEGE_ESCALATION

    ev_unknown = parser.parse('{"EventID": 9999, "Computer": "HOST01"}')
    assert ev_unknown.action == "win_event_9999"


def test_cef_timestamp_and_severity_coverage() -> None:
    """Verify CEF epoch milliseconds and textual severity mapping."""
    parser = CEFParser()
    raw = (
        "CEF:0|Vendor|App|1.0|SQLI|SQL Injection|High|"
        "src=1.2.3.4 dst=5.6.7.8 spt=1234 dpt=80 rt=1728734400000 suser=attacker"
    )
    ev = parser.parse(raw)
    assert ev.severity == Severity.HIGH
    assert ev.action == "web_exploit"
    assert ev.attack_stage == AttackStage.INITIAL_ACCESS
    assert ev.user == "attacker"

    raw_crit = "CEF:0|Vendor|App|1.0|ROOT_ACCESS|Privilege Escalation|Critical|msg=Root access"
    ev_crit = parser.parse(raw_crit)
    assert ev_crit.severity == Severity.CRITICAL
    assert ev_crit.action == "privilege_escalation"

    raw_warn = "CEF:0|Vendor|App|1.0|MISC|Other|Warning|msg=Warning occurred"
    ev_warn = parser.parse(raw_warn)
    assert ev_warn.severity == Severity.MEDIUM


def test_syslog_pri_and_port_scan_detection() -> None:
    """Verify syslog PRI severity calculation and port scan inference."""
    parser = SyslogParser()
    raw_emerg = "<0>1 2026-10-12T00:00:00Z myhost kernel - - - System panic emergency"
    ev_emerg = parser.parse(raw_emerg)
    assert ev_emerg.severity == Severity.CRITICAL

    raw_warn = "<12>1 2026-10-12T00:00:00Z myhost app - - - Warning condition"
    ev_warn = parser.parse(raw_warn)
    assert ev_warn.severity == Severity.MEDIUM

    raw_probe = "Oct 12 11:00:00 fw iptables: Connection refused from 192.168.1.10 port 4444"
    ev_probe = parser.parse(raw_probe)
    assert ev_probe.action == "port_probe"
    assert ev_probe.attack_stage == AttackStage.RECONNAISSANCE


def test_dispatcher_explicit_hints_and_fallback() -> None:
    """Verify dispatcher explicit format hints and fallback behavior."""
    dispatcher = LogIngestionDispatcher()
    ev_explicit = dispatcher.parse('{"custom": "data"}', format_hint=LogFormat.JSON)
    assert ev_explicit.format == LogFormat.JSON

    unrecognized = dispatcher.parse("random string with no structure")
    assert unrecognized.format == LogFormat.UNKNOWN
