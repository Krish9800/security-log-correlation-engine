"""Parser for Syslog messages compliant with RFC 5424 and RFC 3164 (BSD)."""

import re
from datetime import datetime, timezone
from typing import Any

from log_corr.models.enums import AttackStage, LogFormat, Severity
from log_corr.models.schemas import NormalizedLogEvent


class SyslogParser:
    """Parses RFC 5424 and RFC 3164 syslog formatted lines into NormalizedLogEvent."""

    # RFC 5424 Regex: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
    RFC5424_PATTERN = re.compile(
        r"^<(?P<pri>\d{1,3})>1\s+"
        r"(?P<timestamp>[^\s]+)\s+"
        r"(?P<hostname>[^\s]+)\s+"
        r"(?P<appname>[^\s]+)\s+"
        r"(?P<procid>[^\s]+)\s+"
        r"(?P<msgid>[^\s]+)\s*"
        r"(?P<rest>.*)$"
    )

    # RFC 3164 Regex: <PRI>MMM DD HH:MM:SS HOSTNAME TAG[PID]: MSG
    RFC3164_PATTERN = re.compile(
        r"^(?:<(?P<pri>\d{1,3})>)?\s*"
        r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>[^\s:]+)\s+"
        r"(?P<tag>[a-zA-Z0-9_\-\.\/]+)(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<message>.*)$"
    )

    # IP and Port extraction patterns
    IP_PATTERN = re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
    PORT_PATTERN = re.compile(r"\bport\s+(?P<port>\d{1,5})\b", re.IGNORECASE)
    USER_PATTERN = re.compile(
        r"\b(?:for|user|user=)\s+(?:invalid user\s+)?(?P<user>[a-zA-Z0-9_\.\-]+)", re.IGNORECASE
    )

    def parse(self, raw_line: str) -> NormalizedLogEvent:
        """Parse raw syslog line into a NormalizedLogEvent."""
        sanitized = raw_line.strip()
        if not sanitized:
            return NormalizedLogEvent(
                raw_log=raw_line,
                format=LogFormat.SYSLOG,
                action="empty_line",
                status="failure",
            )

        rfc5424_match = self.RFC5424_PATTERN.match(sanitized)
        if rfc5424_match:
            return self._parse_rfc5424(sanitized, rfc5424_match.groupdict())

        rfc3164_match = self.RFC3164_PATTERN.match(sanitized)
        if rfc3164_match:
            return self._parse_rfc3164(sanitized, rfc3164_match.groupdict())

        # Fallback generic syslog extraction
        return self._parse_fallback(sanitized)

    def _parse_rfc5424(self, raw_line: str, groups: dict[str, str]) -> NormalizedLogEvent:
        pri = int(groups["pri"])
        severity = self._pri_to_severity(pri)
        timestamp = self._parse_iso_timestamp(groups["timestamp"])
        hostname = groups["hostname"] if groups["hostname"] != "-" else "localhost"
        appname = groups["appname"] if groups["appname"] != "-" else "unknown"
        message = groups.get("rest", "")

        extracted_ip = self._extract_ip(message)
        extracted_port = self._extract_port(message)
        extracted_user = self._extract_user(message)
        action, stage, mitre, status = self._infer_security_context(message, appname)

        metadata: dict[str, Any] = {
            "appname": appname,
            "procid": groups.get("procid"),
            "msgid": groups.get("msgid"),
            "pri": pri,
        }

        return NormalizedLogEvent(
            raw_log=raw_line,
            timestamp=timestamp,
            format=LogFormat.SYSLOG,
            source_host=hostname,
            source_ip=extracted_ip,
            source_port=extracted_port,
            user=extracted_user,
            action=action,
            status=status,
            severity=severity,
            attack_stage=stage,
            mitre_technique_id=mitre,
            metadata=metadata,
        )

    def _parse_rfc3164(self, raw_line: str, groups: dict[str, str]) -> NormalizedLogEvent:
        pri_str = groups.get("pri")
        pri = int(pri_str) if pri_str is not None else 13
        severity = self._pri_to_severity(pri)
        timestamp = self._parse_bsd_timestamp(groups["timestamp"])
        hostname = groups["hostname"]
        appname = groups.get("tag", "syslog")
        message = groups.get("message", "")

        extracted_ip = self._extract_ip(message)
        extracted_port = self._extract_port(message)
        extracted_user = self._extract_user(message)
        action, stage, mitre, status = self._infer_security_context(message, appname)

        metadata: dict[str, Any] = {
            "appname": appname,
            "pid": groups.get("pid"),
            "pri": pri,
        }

        return NormalizedLogEvent(
            raw_log=raw_line,
            timestamp=timestamp,
            format=LogFormat.SYSLOG,
            source_host=hostname,
            source_ip=extracted_ip,
            source_port=extracted_port,
            user=extracted_user,
            action=action,
            status=status,
            severity=severity,
            attack_stage=stage,
            mitre_technique_id=mitre,
            metadata=metadata,
        )

    def _parse_fallback(self, raw_line: str) -> NormalizedLogEvent:
        extracted_ip = self._extract_ip(raw_line)
        extracted_port = self._extract_port(raw_line)
        extracted_user = self._extract_user(raw_line)
        action, stage, mitre, status = self._infer_security_context(raw_line, "syslog")

        return NormalizedLogEvent(
            raw_log=raw_line,
            timestamp=datetime.now(timezone.utc),
            format=LogFormat.SYSLOG,
            source_host="localhost",
            source_ip=extracted_ip,
            source_port=extracted_port,
            user=extracted_user,
            action=action,
            status=status,
            severity=Severity.LOW,
            attack_stage=stage,
            mitre_technique_id=mitre,
            metadata={"parser_note": "parsed_via_fallback"},
        )

    def _pri_to_severity(self, pri: int) -> Severity:
        syslog_severity = pri % 8
        # 0=Emergency, 1=Alert, 2=Critical -> CRITICAL
        # 3=Error -> HIGH
        # 4=Warning -> MEDIUM
        # 5=Notice, 6=Informational -> LOW / INFO
        # 7=Debug -> INFO
        if syslog_severity in (0, 1, 2):
            return Severity.CRITICAL
        if syslog_severity == 3:
            return Severity.HIGH
        if syslog_severity == 4:
            return Severity.MEDIUM
        if syslog_severity == 5:
            return Severity.LOW
        return Severity.INFO

    def _parse_iso_timestamp(self, ts_str: str) -> datetime:
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    def _parse_bsd_timestamp(self, ts_str: str) -> datetime:
        try:
            current_year = datetime.now(timezone.utc).year
            dt = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    def _extract_ip(self, text: str) -> str | None:
        match = self.IP_PATTERN.search(text)
        return match.group("ip") if match else None

    def _extract_port(self, text: str) -> int | None:
        match = self.PORT_PATTERN.search(text)
        if match:
            val = int(match.group("port"))
            return val if 0 <= val <= 65535 else None
        return None

    def _extract_user(self, text: str) -> str | None:
        match = self.USER_PATTERN.search(text)
        return match.group("user") if match else None

    def _infer_security_context(
        self, text: str, appname: str
    ) -> tuple[str, AttackStage, str | None, str]:
        lower = text.lower()
        if "sudo" in appname.lower() or "sudo:" in lower or "command=" in lower:
            return ("sudo_exec", AttackStage.PRIVILEGE_ESCALATION, "T1548.003", "success")
        if "failed password" in lower or "authentication failure" in lower:
            return ("auth_failure", AttackStage.CREDENTIAL_ACCESS, "T1110.001", "failure")
        if (
            "accepted password" in lower
            or "accepted publickey" in lower
            or "session opened" in lower
        ):
            return ("auth_success", AttackStage.INITIAL_ACCESS, "T1078", "success")
        if "connection refused" in lower or "port scan" in lower or "drop" in lower:
            return ("port_probe", AttackStage.RECONNAISSANCE, "T1046", "failure")
        return ("syslog_event", AttackStage.UNKNOWN, None, "success")
