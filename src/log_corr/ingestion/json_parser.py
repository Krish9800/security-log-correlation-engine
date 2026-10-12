"""Parser for JSON structured logs."""

import json
from datetime import datetime, timezone
from typing import Any

from log_corr.models.enums import AttackStage, LogFormat, Severity
from log_corr.models.schemas import NormalizedLogEvent


class JSONLogParser:
    """Parses arbitrary JSON structured logs into NormalizedLogEvent."""

    def parse(self, raw_line: str) -> NormalizedLogEvent:
        """Parse raw JSON log line into NormalizedLogEvent."""
        sanitized = raw_line.strip()
        try:
            data = json.loads(sanitized)
            if not isinstance(data, dict):
                raise ValueError("JSON log payload must be an object")
        except Exception:
            return NormalizedLogEvent(
                raw_log=raw_line,
                format=LogFormat.JSON,
                action="invalid_json",
                status="failure",
                severity=Severity.LOW,
            )

        # Extract normalized attributes using aliases and nested structures
        timestamp = self._extract_timestamp(data)
        source_host = (
            self._find_first_str(data, ["host", "hostname", "source_host", "server", "host.name"])
            or "localhost"
        )
        source_ip = self._find_first_str(
            data, ["src_ip", "source_ip", "src", "client_ip", "remote_addr", "ip", "source.ip"]
        )
        dest_ip = self._find_first_str(
            data,
            ["dst_ip", "destination_ip", "dst", "server_ip", "target_ip", "destination.ip"],
        )
        source_port = self._find_port(
            data, ["src_port", "source_port", "spt", "client_port", "source.port"]
        )
        dest_port = self._find_port(
            data,
            ["dst_port", "destination_port", "dpt", "port", "target_port", "destination.port"],
        )
        user = self._find_first_str(
            data, ["user", "username", "account", "identity", "actor", "target_user", "user.name"]
        )
        action = (
            self._find_first_str(
                data, ["action", "event_type", "event", "activity", "command", "msg", "message"]
            )
            or "json_event"
        )
        status = self._find_first_str(data, ["status", "result", "outcome"]) or "success"
        severity = self._extract_severity(data)
        stage = self._extract_attack_stage(data, action)
        mitre_id = self._find_first_str(
            data, ["mitre_technique_id", "technique_id", "technique", "mitre"]
        )

        return NormalizedLogEvent(
            raw_log=raw_line,
            timestamp=timestamp,
            format=LogFormat.JSON,
            source_host=source_host,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=dest_ip,
            destination_port=dest_port,
            user=user,
            action=action,
            status=status,
            severity=severity,
            attack_stage=stage,
            mitre_technique_id=mitre_id,
            metadata=data,
        )

    def _find_first_str(self, data: dict[str, Any], keys: list[str]) -> str | None:
        for k in keys:
            if k in data and data[k] is not None:
                val = str(data[k]).strip()
                if val:
                    return val
            # Check nested dict (e.g. source.ip)
            if "." in k:
                subkeys = k.split(".")
                curr: Any = data
                for sk in subkeys:
                    if isinstance(curr, dict) and sk in curr:
                        curr = curr[sk]
                    else:
                        curr = None
                        break
                if curr is not None:
                    s = str(curr).strip()
                    if s:
                        return s
        return None

    def _find_port(self, data: dict[str, Any], keys: list[str]) -> int | None:
        for k in keys:
            if k in data and data[k] is not None:
                try:
                    num = int(data[k])
                    if 0 <= num <= 65535:
                        return num
                except (ValueError, TypeError):
                    continue
        return None

    def _extract_timestamp(self, data: dict[str, Any]) -> datetime:
        candidates = ["timestamp", "@timestamp", "time", "datetime", "created_at"]
        for c in candidates:
            if c in data and data[c] is not None:
                val = data[c]
                if isinstance(val, (int, float)):
                    # Epoch seconds or milliseconds
                    epoch = float(val) / 1000.0 if float(val) > 1e11 else float(val)
                    return datetime.fromtimestamp(epoch, tz=timezone.utc)
                if isinstance(val, str):
                    try:
                        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                    except (ValueError, TypeError, OSError):
                        dt = None
        return datetime.now(timezone.utc)

    def _extract_severity(self, data: dict[str, Any]) -> Severity:
        raw_sev = self._find_first_str(data, ["severity", "level", "log_level", "priority"])
        if not raw_sev:
            return Severity.INFO
        lowered = raw_sev.lower()
        if lowered in ("critical", "crit", "fatal", "emergency", "alert"):
            return Severity.CRITICAL
        if lowered in ("high", "error", "err"):
            return Severity.HIGH
        if lowered in ("medium", "med", "warning", "warn"):
            return Severity.MEDIUM
        if lowered in ("low", "notice"):
            return Severity.LOW
        return Severity.INFO

    def _extract_attack_stage(self, data: dict[str, Any], action: str) -> AttackStage:
        raw_stage = self._find_first_str(data, ["attack_stage", "stage", "tactic"])
        if raw_stage:
            try:
                return AttackStage(raw_stage.lower())
            except ValueError:
                pass
        # Heuristic inference from action
        act_lower = action.lower()
        if "recon" in act_lower or "port_scan" in act_lower:
            return AttackStage.RECONNAISSANCE
        if "brute" in act_lower or "auth_fail" in act_lower or "failed_login" in act_lower:
            return AttackStage.CREDENTIAL_ACCESS
        if "sudo" in act_lower or "priv_esc" in act_lower or "privilege" in act_lower:
            return AttackStage.PRIVILEGE_ESCALATION
        if "lateral" in act_lower or "psexec" in act_lower or "remote_desktop" in act_lower:
            return AttackStage.LATERAL_MOVEMENT
        if "exfil" in act_lower or "data_transfer" in act_lower:
            return AttackStage.EXFILTRATION
        if "login" in act_lower or "logon" in act_lower or "access" in act_lower:
            return AttackStage.INITIAL_ACCESS
        return AttackStage.UNKNOWN
