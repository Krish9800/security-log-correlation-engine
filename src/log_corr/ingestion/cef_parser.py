"""Parser for ArcSight Common Event Format (CEF) logs."""

import re
from datetime import datetime, timezone
from typing import Any

from log_corr.models.enums import AttackStage, LogFormat, Severity
from log_corr.models.schemas import NormalizedLogEvent


class CEFParser:
    """Parses ArcSight Common Event Format (CEF) log lines into NormalizedLogEvent."""

    # CEF Header format:
    # CEF:Version|Device Vendor|Device Product|Device Version|
    # Device Event Class ID|Name|Severity|Extension
    CEF_HEADER_PREFIX = "CEF:"

    # Extension key splitter pattern for linear O(N) extraction
    EXT_KEY_SPLIT_PATTERN = re.compile(r"(?:^|\s+)([a-zA-Z0-9_\-\.]+)=\s*")

    def parse(self, raw_line: str) -> NormalizedLogEvent:
        """Parse raw CEF log line into NormalizedLogEvent."""
        sanitized = raw_line.strip()
        idx = sanitized.find(self.CEF_HEADER_PREFIX)
        if idx == -1:
            return NormalizedLogEvent(
                raw_log=raw_line,
                format=LogFormat.CEF,
                action="invalid_cef_header",
                status="failure",
                severity=Severity.LOW,
            )

        cef_content = sanitized[idx + len(self.CEF_HEADER_PREFIX) :]
        parts = self._split_cef_header(cef_content)
        if len(parts) < 7:
            return NormalizedLogEvent(
                raw_log=raw_line,
                format=LogFormat.CEF,
                action="malformed_cef_fields",
                status="failure",
                severity=Severity.LOW,
            )

        # parts: [version, vendor, product, dev_version, class_id, name, severity, ext]
        version = parts[0]
        vendor = parts[1]
        product = parts[2]
        dev_version = parts[3]
        class_id = parts[4]
        name = parts[5]
        sev_str = parts[6]
        extension_str = parts[7] if len(parts) > 7 else ""

        extensions = self._parse_extensions(extension_str)
        severity = self._map_cef_severity(sev_str)

        source_ip = extensions.get("src") or extensions.get("sourceAddress")
        destination_ip = extensions.get("dst") or extensions.get("destinationAddress")
        source_port = self._safe_int(extensions.get("spt") or extensions.get("sourcePort"))
        dest_port = self._safe_int(extensions.get("dpt") or extensions.get("destinationPort"))
        user = (
            extensions.get("suser")
            or extensions.get("duser")
            or extensions.get("sourceUserName")
            or extensions.get("destinationUserName")
            or extensions.get("user")
        )

        source_host = (
            extensions.get("shost")
            or extensions.get("sourceHostName")
            or extensions.get("dhost")
            or f"{vendor}-{product}"
        )

        action, stage, mitre, status = self._infer_security_context(class_id, name, extensions)

        metadata: dict[str, Any] = {
            "cef_version": version,
            "device_vendor": vendor,
            "device_product": product,
            "device_version": dev_version,
            "event_class_id": class_id,
            "event_name": name,
            **extensions,
        }

        # Timestamp from extension 'rt' or 'start' or 'end' if present
        timestamp = self._parse_cef_timestamp(extensions.get("rt") or extensions.get("start"))

        return NormalizedLogEvent(
            raw_log=raw_line,
            timestamp=timestamp,
            format=LogFormat.CEF,
            source_host=source_host,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=dest_port,
            user=user,
            action=action,
            status=status,
            severity=severity,
            attack_stage=stage,
            mitre_technique_id=mitre,
            metadata=metadata,
        )

    def _split_cef_header(self, content: str) -> list[str]:
        """Split CEF pipe-delimited fields while respecting escaped pipes."""
        parts: list[str] = []
        current: list[str] = []
        escaped = False
        pipe_count = 0

        for char in content:
            if pipe_count >= 7:
                # Everything after the 7th pipe belongs to the extension payload
                current.append(char)
                continue

            if escaped:
                current.append(char)
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "|":
                parts.append("".join(current))
                current = []
                pipe_count += 1
            else:
                current.append(char)

        parts.append("".join(current))
        return parts

    def _parse_extensions(self, extension_str: str) -> dict[str, str]:
        """Extract key-value pairs from CEF extension field in linear O(N) time."""
        result: dict[str, str] = {}
        if not extension_str or "=" not in extension_str:
            return result

        tokens = self.EXT_KEY_SPLIT_PATTERN.split(extension_str)
        # tokens structure: [preceding_text, key1, val1, key2, val2, ...]
        for i in range(1, len(tokens), 2):
            key = tokens[i].strip()
            raw_val = tokens[i + 1].strip() if i + 1 < len(tokens) else ""
            val = raw_val.replace("\\=", "=").replace("\\\\", "\\")
            result[key] = val
        return result

    def _map_cef_severity(self, sev_str: str) -> Severity:
        try:
            val = int(sev_str)
            if val <= 3:
                return Severity.LOW
            if val <= 6:
                return Severity.MEDIUM
            if val <= 8:
                return Severity.HIGH
            return Severity.CRITICAL
        except ValueError:
            lowered = sev_str.lower()
            if "crit" in lowered or "emerg" in lowered:
                return Severity.CRITICAL
            if "high" in lowered or "err" in lowered:
                return Severity.HIGH
            if "med" in lowered or "warn" in lowered:
                return Severity.MEDIUM
            return Severity.LOW

    def _safe_int(self, val: str | None) -> int | None:
        if val is None:
            return None
        try:
            num = int(val)
            return num if 0 <= num <= 65535 else None
        except ValueError:
            return None

    def _parse_cef_timestamp(self, ts_str: str | None) -> datetime:
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            # Handle epoch milliseconds
            if ts_str.isdigit() and len(ts_str) >= 10:
                epoch = int(ts_str) / 1000.0 if len(ts_str) > 10 else int(ts_str)
                return datetime.fromtimestamp(epoch, tz=timezone.utc)
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    def _infer_security_context(
        self, class_id: str, name: str, ext: dict[str, str]
    ) -> tuple[str, AttackStage, str | None, str]:
        combined = f"{class_id} {name} {ext.get('msg', '')}".lower()
        if "port_scan" in combined or "recon" in combined or "scanner" in combined:
            return ("port_probe", AttackStage.RECONNAISSANCE, "T1046", "failure")
        if "auth_fail" in combined or "login fail" in combined or "bad_credentials" in combined:
            return ("auth_failure", AttackStage.CREDENTIAL_ACCESS, "T1110", "failure")
        if "login success" in combined or "auth_success" in combined:
            return ("auth_success", AttackStage.INITIAL_ACCESS, "T1078", "success")
        if "privilege" in combined or "sudo" in combined or "elevation" in combined:
            return ("privilege_escalation", AttackStage.PRIVILEGE_ESCALATION, "T1548", "success")
        if "exploit" in combined or "sqli" in combined or "xss" in combined:
            return ("web_exploit", AttackStage.INITIAL_ACCESS, "T1190", "success")
        return (class_id.lower() or "cef_event", AttackStage.UNKNOWN, None, "success")
