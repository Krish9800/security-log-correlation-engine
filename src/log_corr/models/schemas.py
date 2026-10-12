"""Domain models, enums, and schemas for Security Log Correlation Engine."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ============================================================================
# Domain Enums
# ============================================================================


class LogFormat(str, Enum):
    """Supported log ingestion formats."""

    SYSLOG = "syslog"
    CEF = "cef"
    JSON = "json"
    WINDOWS_EVENT = "windows_event"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Standard security event and incident severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        """Return numerical risk weight."""
        weights = {
            Severity.INFO: 1,
            Severity.LOW: 3,
            Severity.MEDIUM: 5,
            Severity.HIGH: 8,
            Severity.CRITICAL: 10,
        }
        return weights[self]


class CorrelationRuleType(str, Enum):
    """Classification of correlation detection logic."""

    THRESHOLD = "threshold"
    SEQUENCE = "sequence"
    COMPOSITE = "composite"


class AttackStage(str, Enum):
    """MITRE ATT&CK kill chain tactic classification."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    UNKNOWN = "unknown"


class IncidentStatus(str, Enum):
    """Operational lifecycle status of correlated security incidents."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# ============================================================================
# Schemas
# ============================================================================


class NormalizedLogEvent(BaseModel):
    """Canonical, normalized representation of an ingested log event."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_log: str = Field(description="Raw log line before normalization")
    format: LogFormat = Field(default=LogFormat.UNKNOWN)
    source_host: str = Field(default="localhost", description="Reporting host or sensor")
    source_ip: str | None = Field(default=None, description="Source IPv4/IPv6 address")
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_ip: str | None = Field(default=None, description="Destination IPv4/IPv6 address")
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    user: str | None = Field(default=None, description="Target or executing username")
    action: str = Field(description="Security action, e.g., auth_failure, port_probe, sudo_exec")
    status: str = Field(default="success", description="Outcome status, e.g. success, failure")
    severity: Severity = Field(default=Severity.INFO)
    attack_stage: AttackStage = Field(default=AttackStage.UNKNOWN)
    mitre_technique_id: str | None = Field(default=None, description="MITRE Technique, e.g. T1110")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary auxiliary fields")

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_utc_timestamp(cls, value: Any) -> datetime:
        """Ensure timestamps are timezone-aware and harmonized to UTC."""
        if isinstance(value, str):
            dt = datetime.fromisoformat(value)
        elif isinstance(value, datetime):
            dt = value
        else:
            raise ValueError(f"Invalid timestamp type: {type(value)}")

        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def get_entity_value(self, field_name: str) -> str | None:
        """Extract entity field value dynamically for grouping and correlation."""
        if field_name == "source_ip":
            return self.source_ip
        if field_name == "destination_ip":
            return self.destination_ip
        if field_name == "user":
            return self.user
        if field_name == "source_host":
            return self.source_host
        if field_name in self.metadata:
            meta_val = self.metadata[field_name]
            return str(meta_val) if meta_val is not None else None
        return None


class CorrelationRule(BaseModel):
    """Specification of a stateful time-window correlation rule."""

    model_config = ConfigDict(extra="ignore")

    rule_id: str = Field(description="Unique rule identifier, e.g., R-SSH-BRUTE-01")
    name: str = Field(description="Human-readable rule name")
    description: str = Field(description="Detailed explanation of detected activity")
    rule_type: CorrelationRuleType = Field(description="Detection logic classification")
    enabled: bool = Field(default=True)
    window_seconds: int = Field(default=60, gt=0, description="Sliding window duration in seconds")
    group_by_fields: list[str] = Field(
        default_factory=lambda: ["source_ip"],
        description="Fields to group events into distinct state windows",
    )

    # Threshold-specific configuration
    threshold_count: int | None = Field(
        default=None, ge=2, description="Minimum count of matching events to trigger"
    )
    match_filter: dict[str, Any] = Field(
        default_factory=dict, description="Attribute matching filter dictionary for threshold"
    )

    # Sequence-specific configuration
    sequence_filters: list[dict[str, Any]] = Field(
        default_factory=list, description="Ordered list of state transition filter dictionaries"
    )

    # Severity & MITRE ATT&CK Attribution
    severity: Severity = Field(default=Severity.HIGH)
    attack_stages: list[AttackStage] = Field(default_factory=list)
    mitre_attack_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_rule_parameters(self) -> "CorrelationRule":
        """Validate that rule parameters match the specified rule type."""
        if self.rule_type == CorrelationRuleType.THRESHOLD:
            if self.threshold_count is None:
                raise ValueError("threshold_count is required for THRESHOLD rules")
            if not self.match_filter:
                raise ValueError("match_filter must not be empty for THRESHOLD rules")
        elif self.rule_type == CorrelationRuleType.SEQUENCE:
            if len(self.sequence_filters) < 2:
                raise ValueError(
                    "sequence_filters must contain at least 2 stages for SEQUENCE rules"
                )
        return self


class CorrelatedIncident(BaseModel):
    """Synthesized security incident generated by one or more matching correlation rules."""

    model_config = ConfigDict(extra="ignore")

    incident_id: str = Field(default_factory=lambda: f"INC-{uuid4().hex[:8].upper()}")
    rule_id: str
    rule_name: str
    rule_type: CorrelationRuleType
    severity: Severity
    risk_score: float = Field(default=50.0, ge=0.0, le=100.0)
    status: IncidentStatus = Field(default=IncidentStatus.OPEN)
    entity_keys: dict[str, str] = Field(
        default_factory=dict, description="Entity grouping keys and values"
    )
    attack_stages: list[AttackStage] = Field(default_factory=list)
    mitre_attack_ids: list[str] = Field(default_factory=list)
    matched_events: list[NormalizedLogEvent] = Field(default_factory=list)
    event_count: int = Field(default=0, ge=0)
    window_seconds: int = Field(gt=0)
    first_event_time: datetime
    last_event_time: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    summary: str = Field(default="")

    @model_validator(mode="after")
    def compute_defaults(self) -> "CorrelatedIncident":
        """Auto-compute event count, timestamps, and summary if not set."""
        if self.matched_events and self.event_count == 0:
            self.event_count = len(self.matched_events)
        if not self.summary:
            entity_str = ", ".join(f"{k}={v}" for k, v in self.entity_keys.items())
            self.summary = (
                f"{self.severity.value.upper()} incident [{self.rule_id}]: {self.rule_name} "
                f"triggered with {self.event_count} events across entity ({entity_str})"
            )
        return self

    def calculate_risk_score(self) -> float:
        """Calculate dynamic multi-factor risk score (0 - 100)."""
        base_weight = self.severity.weight * 7.0  # Base 7 to 70
        volume_factor = min(self.event_count * 2.0, 20.0)  # Up to 20 for volume
        stage_factor = min(len(set(self.attack_stages)) * 5.0, 10.0)  # Multi-stage bonus
        score = min(max(base_weight + volume_factor + stage_factor, 0.0), 100.0)
        self.risk_score = round(score, 1)
        return self.risk_score


class AlertNotification(BaseModel):
    """External alert notification payload dispatched to operators or integrations."""

    model_config = ConfigDict(extra="ignore")

    alert_id: str = Field(default_factory=lambda: f"ALT-{uuid4().hex[:8].upper()}")
    incident_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    risk_score: float = Field(ge=0.0, le=100.0)
    title: str
    description: str
    affected_entities: dict[str, str] = Field(default_factory=dict)
    mitre_tactics: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    channel: str = Field(default="console")
    dispatched: bool = Field(default=False)
