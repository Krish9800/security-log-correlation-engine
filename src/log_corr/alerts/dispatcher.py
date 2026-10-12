"""Incident synthesis and multi-channel alert notification dispatcher."""

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from log_corr.models.schemas import AlertNotification, CorrelatedIncident


class AlertDispatcher:
    """Dispatches CorrelatedIncident notifications across console, file, and webhook channels."""

    def __init__(
        self,
        enable_console: bool = True,
        output_file: Path | str | None = None,
        webhook_url: str | None = None,
        webhook_timeout_seconds: float = 3.0,
    ) -> None:
        self.enable_console = enable_console
        self.output_file = Path(output_file) if output_file else None
        self.webhook_url = webhook_url
        self.webhook_timeout_seconds = webhook_timeout_seconds
        self._history: list[AlertNotification] = []

    def create_notification(
        self, incident: CorrelatedIncident, channel: str = "console"
    ) -> AlertNotification:
        """Construct an AlertNotification payload from a CorrelatedIncident."""
        title = f"[{incident.severity.value.upper()}] Security Incident: {incident.rule_name}"
        mitre_tactics = [stage.value.replace("_", " ").title() for stage in incident.attack_stages]

        description = (
            f"Rule {incident.rule_id} triggered with {incident.event_count} events "
            f"within a {incident.window_seconds}s sliding window. "
            f"Risk Score: {incident.risk_score}/100. "
            f"Entities: {incident.entity_keys}"
        )

        return AlertNotification(
            incident_id=incident.incident_id,
            rule_id=incident.rule_id,
            rule_name=incident.rule_name,
            severity=incident.severity,
            risk_score=incident.risk_score,
            title=title,
            description=description,
            affected_entities=incident.entity_keys,
            mitre_tactics=mitre_tactics,
            timestamp=datetime.now(timezone.utc),
            channel=channel,
            dispatched=False,
        )

    def dispatch(
        self, incident: CorrelatedIncident, channel: str | None = None
    ) -> AlertNotification:
        """Synthesize notification and route to configured target channels."""
        target_channel = channel or ("all" if self.webhook_url else "console")
        alert = self.create_notification(incident, channel=target_channel)

        success = False
        if target_channel in ("console", "all") and self.enable_console:
            self._dispatch_console(alert)
            success = True

        if (target_channel in ("file", "all")) and self.output_file:
            self._dispatch_file(alert)
            success = True

        if (target_channel in ("webhook", "all")) and self.webhook_url:
            webhook_ok = self._dispatch_webhook(alert)
            success = success or webhook_ok

        alert.dispatched = success
        self._history.append(alert)
        return alert

    def _dispatch_console(self, alert: AlertNotification) -> None:
        """Render notification to console."""
        # Standard formatted text representation
        tag = f"[{alert.severity.value.upper()}]"
        entities = ", ".join(f"{k}={v}" for k, v in alert.affected_entities.items())
        line = (
            f"ALERT {alert.alert_id} | {tag} {alert.title} | "
            f"Risk: {alert.risk_score} | Entities: ({entities})"
        )
        print(line)

    def _dispatch_file(self, alert: AlertNotification) -> None:
        """Append notification as JSON line to output file."""
        if not self.output_file:
            return
        try:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            payload = alert.model_dump(mode="json")
            with self.output_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        except (OSError, ValueError):
            pass

    def _dispatch_webhook(self, alert: AlertNotification) -> bool:
        """POST notification payload to HTTP webhook endpoint."""
        if not self.webhook_url:
            return False

        try:
            payload_bytes = json.dumps(alert.model_dump(mode="json")).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=payload_bytes,
                headers={"Content-Type": "application/json", "User-Agent": "LogCorrEngine/0.1.0"},
                method="POST",
            )
            with urllib.request.urlopen(  # nosec B310
                req, timeout=self.webhook_timeout_seconds
            ) as resp:
                status_code: int = getattr(resp, "status", 200)
                return 200 <= status_code < 300
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return False

    def get_alert_history(self) -> list[AlertNotification]:
        """Return history of all dispatched alerts in this session."""
        return list(self._history)

    def clear_history(self) -> None:
        """Reset internal alert history buffer."""
        self._history.clear()
