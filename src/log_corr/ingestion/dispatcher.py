"""Log Ingestion Dispatcher auto-detecting formats and generating NormalizedLogEvents."""

import re
from collections.abc import Iterable
from pathlib import Path

from log_corr.ingestion.cef_parser import CEFParser
from log_corr.ingestion.json_parser import JSONLogParser
from log_corr.ingestion.syslog_parser import SyslogParser
from log_corr.ingestion.windows_parser import WindowsEventParser
from log_corr.models.enums import AttackStage, LogFormat, Severity
from log_corr.models.schemas import NormalizedLogEvent


class LogIngestionDispatcher:
    """Auto-detects log formats and routes raw logs to the appropriate parser."""

    SYSLOG_MONTHS_PATTERN = re.compile(
        r"^(?:<\d{1,3}>)?\s*(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    )

    def __init__(self) -> None:
        self.syslog_parser = SyslogParser()
        self.cef_parser = CEFParser()
        self.json_parser = JSONLogParser()
        self.windows_parser = WindowsEventParser()

    def detect_format(self, raw_line: str) -> LogFormat:
        """Heuristically identify the log format of a raw line."""
        sanitized = raw_line.strip()
        if not sanitized:
            return LogFormat.UNKNOWN

        # CEF check
        if "CEF:" in sanitized:
            return LogFormat.CEF

        # Windows Event check
        if "EventID" in sanitized or "TargetUserName" in sanitized or "EventData" in sanitized:
            return LogFormat.WINDOWS_EVENT

        # JSON check
        if sanitized.startswith("{") and sanitized.endswith("}"):
            return LogFormat.JSON

        # Syslog check (RFC 5424 starts with <PRI>1 or RFC 3164 with month)
        if sanitized.startswith("<") or self.SYSLOG_MONTHS_PATTERN.match(sanitized):
            return LogFormat.SYSLOG

        # Default fallback to syslog if it has traditional hostname: msg structure
        if ":" in sanitized and len(sanitized.split(":", 1)[0].split()) <= 4:
            return LogFormat.SYSLOG

        return LogFormat.UNKNOWN

    def parse(self, raw_line: str, format_hint: LogFormat | None = None) -> NormalizedLogEvent:
        """Parse raw line into NormalizedLogEvent using hint or auto-detection."""
        sanitized = raw_line.strip()
        fmt = (
            format_hint
            if format_hint and format_hint != LogFormat.UNKNOWN
            else self.detect_format(sanitized)
        )

        try:
            if fmt == LogFormat.CEF:
                return self.cef_parser.parse(raw_line)
            if fmt == LogFormat.WINDOWS_EVENT:
                return self.windows_parser.parse(raw_line)
            if fmt == LogFormat.JSON:
                return self.json_parser.parse(raw_line)
            if fmt == LogFormat.SYSLOG:
                return self.syslog_parser.parse(raw_line)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            return NormalizedLogEvent(
                raw_log=raw_line,
                format=LogFormat.UNKNOWN,
                action="parsing_error",
                status="failure",
                severity=Severity.LOW,
                attack_stage=AttackStage.UNKNOWN,
                metadata={"error": str(exc)},
            )

        # Defensive fallback if specific parser failed or format is unknown
        return NormalizedLogEvent(
            raw_log=raw_line,
            format=LogFormat.UNKNOWN,
            action="unrecognized_log",
            status="unknown",
            severity=Severity.INFO,
            attack_stage=AttackStage.UNKNOWN,
        )

    def parse_lines(self, lines: Iterable[str]) -> list[NormalizedLogEvent]:
        """Parse a collection of log lines in order."""
        return [self.parse(line) for line in lines if line.strip()]

    def parse_file(self, file_path: Path | str) -> list[NormalizedLogEvent]:
        """Read a log file and parse all non-empty lines."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {path}")

        events: list[NormalizedLogEvent] = []
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    events.append(self.parse(line))
        return events
