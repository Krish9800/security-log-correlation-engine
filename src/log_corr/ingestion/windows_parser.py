"""Parser for Windows Security and System Event Logs."""

import json
import re
from datetime import datetime, timezone
from typing import Any

from log_corr.models.enums import AttackStage, LogFormat, Severity
from log_corr.models.schemas import NormalizedLogEvent


class WindowsEventParser:
    """Parses Windows Event logs (Event IDs 4624, 4625, 4672, 4720, 4688, 7045)."""

    # Text key-value regex: Key: Value or Key=Value
    TEXT_KV_PATTERN = re.compile(r"(?P<key>[a-zA-Z0-9_]+)\s*[:=]\s*(?P<val>[^\r\n,]+)")

    # Mapping of Windows Security Event IDs to detection context
    EVENT_ID_METADATA: dict[int, dict[str, Any]] = {
        4624: {
            "action": "auth_success",
            "stage": AttackStage.INITIAL_ACCESS,
            "mitre": "T1078",
            "severity": Severity.INFO,
            "status": "success",
            "desc": "Successful Account Logon",
        },
        4625: {
            "action": "auth_failure",
            "stage": AttackStage.CREDENTIAL_ACCESS,
            "mitre": "T1110.001",
            "severity": Severity.MEDIUM,
            "status": "failure",
            "desc": "Account Logon Failure",
        },
        4672: {
            "action": "privilege_assigned",
            "stage": AttackStage.PRIVILEGE_ESCALATION,
            "mitre": "T1078",
            "severity": Severity.HIGH,
            "status": "success",
            "desc": "Special Privileges Assigned to New Logon",
        },
        4720: {
            "action": "user_created",
            "stage": AttackStage.INITIAL_ACCESS,
            "mitre": "T1136.001",
            "severity": Severity.HIGH,
            "status": "success",
            "desc": "User Account Created",
        },
        4688: {
            "action": "process_create",
            "stage": AttackStage.INITIAL_ACCESS,
            "mitre": "T1059",
            "severity": Severity.LOW,
            "status": "success",
            "desc": "New Process Created",
        },
        7045: {
            "action": "service_install",
            "stage": AttackStage.PRIVILEGE_ESCALATION,
            "mitre": "T1543.003",
            "severity": Severity.HIGH,
            "status": "success",
            "desc": "Service Installed in System",
        },
    }

    def parse(self, raw_line: str) -> NormalizedLogEvent:
        """Parse raw Windows event line (JSON or key-value text) into NormalizedLogEvent."""
        sanitized = raw_line.strip()
        data: dict[str, Any] = {}

        if sanitized.startswith("{") and sanitized.endswith("}"):
            try:
                parsed_json = json.loads(sanitized)
                if isinstance(parsed_json, dict):
                    data = parsed_json
            except Exception:
                data = {}

        if not data:
            data = self._parse_text_kv(sanitized)

        if not data:
            return NormalizedLogEvent(
                raw_log=raw_line,
                format=LogFormat.WINDOWS_EVENT,
                action="invalid_windows_event",
                status="failure",
                severity=Severity.LOW,
            )

        event_id = self._extract_event_id(data)
        event_meta = self.EVENT_ID_METADATA.get(
            event_id,
            {
                "action": f"win_event_{event_id}" if event_id else "windows_event",
                "stage": AttackStage.UNKNOWN,
                "mitre": None,
                "severity": Severity.INFO,
                "status": "success",
                "desc": "Windows Event",
            },
        )

        user = self._extract_user(data)
        source_ip = self._extract_ip(data)
        source_port = self._extract_port(data)
        source_host = self._extract_host(data)
        timestamp = self._extract_timestamp(data)

        metadata: dict[str, Any] = {
            "event_id": event_id,
            "description": event_meta["desc"],
            **data,
        }

        return NormalizedLogEvent(
            raw_log=raw_line,
            timestamp=timestamp,
            format=LogFormat.WINDOWS_EVENT,
            source_host=source_host,
            source_ip=source_ip,
            source_port=source_port,
            user=user,
            action=str(event_meta["action"]),
            status=str(event_meta["status"]),
            severity=event_meta["severity"],
            attack_stage=event_meta["stage"],
            mitre_technique_id=event_meta["mitre"],
            metadata=metadata,
        )

    def _parse_text_kv(self, text: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for m in self.TEXT_KV_PATTERN.finditer(text):
            k = m.group("key").strip()
            v = m.group("val").strip()
            result[k] = v
        return result

    def _extract_event_id(self, data: dict[str, Any]) -> int:
        for k in ["EventID", "EventId", "event_id", "Id", "id"]:
            if k in data and data[k] is not None:
                try:
                    return int(data[k])
                except (ValueError, TypeError):
                    continue
        return 0

    def _extract_user(self, data: dict[str, Any]) -> str | None:
        # Check EventData sub-dictionary if present
        event_data = data.get("EventData", {})
        if isinstance(event_data, dict):
            for k in ["TargetUserName", "SubjectUserName", "user", "AccountName"]:
                if k in event_data and event_data[k]:
                    val = str(event_data[k]).strip()
                    if val and val != "-":
                        return val

        for k in ["TargetUserName", "SubjectUserName", "user", "username", "AccountName"]:
            if k in data and data[k]:
                val = str(data[k]).strip()
                if val and val != "-":
                    return val
        return None

    def _extract_ip(self, data: dict[str, Any]) -> str | None:
        event_data = data.get("EventData", {})
        if isinstance(event_data, dict):
            for k in ["IpAddress", "SourceIp", "ClientIP", "ip"]:
                if k in event_data and event_data[k]:
                    val = str(event_data[k]).strip()
                    if val and val != "-":
                        return val

        for k in ["IpAddress", "SourceIp", "ClientIP", "ip"]:
            if k in data and data[k]:
                val = str(data[k]).strip()
                if val and val != "-":
                    return val
        return None

    def _extract_port(self, data: dict[str, Any]) -> int | None:
        event_data = data.get("EventData", {})
        if isinstance(event_data, dict):
            for k in ["IpPort", "SourcePort", "port"]:
                if k in event_data and event_data[k]:
                    try:
                        p = int(event_data[k])
                        if 0 <= p <= 65535:
                            return p
                    except (ValueError, TypeError):
                        p = None

        for k in ["IpPort", "SourcePort", "port"]:
            if k in data and data[k]:
                try:
                    p = int(data[k])
                    if 0 <= p <= 65535:
                        return p
                except (ValueError, TypeError):
                    p = None
        return None

    def _extract_host(self, data: dict[str, Any]) -> str:
        for k in ["Computer", "ComputerName", "WorkstationName", "host", "hostname"]:
            if k in data and data[k]:
                val = str(data[k]).strip()
                if val and val != "-":
                    return val
        return "windows-host"

    def _extract_timestamp(self, data: dict[str, Any]) -> datetime:
        for k in ["TimeCreated", "timestamp", "DateTime", "time"]:
            if k in data and data[k]:
                val = str(data[k]).strip()
                try:
                    dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                except (ValueError, TypeError, OSError):
                    val = ""
        return datetime.now(timezone.utc)
