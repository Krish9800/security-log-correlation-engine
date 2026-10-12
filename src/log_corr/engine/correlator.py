"""Correlation Engine evaluating streaming security events against stateful rules."""

from datetime import datetime
from threading import RLock
from typing import Any

from log_corr.engine.window_buffer import SlidingWindowBuffer
from log_corr.models.enums import AttackStage, CorrelationRuleType
from log_corr.models.schemas import CorrelatedIncident, CorrelationRule, NormalizedLogEvent


class CorrelationEngine:
    """Stateful detection engine that evaluates NormalizedLogEvents against correlation rules."""

    def __init__(
        self,
        buffer: SlidingWindowBuffer | None = None,
        cooldown_seconds: int = 30,
    ) -> None:
        self.buffer = buffer or SlidingWindowBuffer()
        self.cooldown_seconds = cooldown_seconds
        self._rules: dict[str, CorrelationRule] = {}
        # Key: "rule_id::entity_key" -> last trigger datetime
        self._cooldown_tracker: dict[str, datetime] = {}
        self._lock = RLock()

    def register_rule(self, rule: CorrelationRule) -> None:
        """Register or update a correlation rule."""
        with self._lock:
            self._rules[rule.rule_id] = rule

    def unregister_rule(self, rule_id: str) -> bool:
        """Unregister a correlation rule by ID. Returns True if removed."""
        with self._lock:
            return self._rules.pop(rule_id, None) is not None

    def get_rule(self, rule_id: str) -> CorrelationRule | None:
        """Retrieve registered rule by ID."""
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self, enabled_only: bool = False) -> list[CorrelationRule]:
        """List registered correlation rules."""
        with self._lock:
            if enabled_only:
                return [r for r in self._rules.values() if r.enabled]
            return list(self._rules.values())

    def process_event(self, event: NormalizedLogEvent) -> list[CorrelatedIncident]:
        """Evaluate an ingested event against all active correlation rules."""
        incidents: list[CorrelatedIncident] = []

        with self._lock:
            active_rules = [r for r in self._rules.values() if r.enabled]

            for rule in active_rules:
                entity_key, entity_dict = self._build_entity_key(rule, event)
                if entity_key is None:
                    continue

                buffer_key = f"{rule.rule_id}::{entity_key}"
                self.buffer.add_event(
                    buffer_key, event, max_retention_seconds=rule.window_seconds * 3
                )

                # Check cooldown suppression
                last_triggered = self._cooldown_tracker.get(buffer_key)
                if (
                    last_triggered
                    and (event.timestamp - last_triggered).total_seconds() < self.cooldown_seconds
                ):
                    continue

                # Retrieve events within sliding time window
                window_events = self.buffer.get_window_events(
                    buffer_key,
                    window_seconds=rule.window_seconds,
                    reference_time=event.timestamp,
                )

                incident = self._evaluate_rule(rule, window_events, entity_dict, buffer_key)
                if incident:
                    self._cooldown_tracker[buffer_key] = event.timestamp
                    incidents.append(incident)

        return incidents

    def process_batch(self, events: list[NormalizedLogEvent]) -> list[CorrelatedIncident]:
        """Process a sequence of log events in chronological order."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        incidents: list[CorrelatedIncident] = []
        for ev in sorted_events:
            incidents.extend(self.process_event(ev))
        return incidents

    def clear(self) -> None:
        """Reset buffers, cooldowns, and rule state."""
        with self._lock:
            self.buffer.clear()
            self._cooldown_tracker.clear()

    def _build_entity_key(
        self, rule: CorrelationRule, event: NormalizedLogEvent
    ) -> tuple[str | None, dict[str, str]]:
        """Construct a unique grouping key and entity dictionary from rule.group_by_fields."""
        entity_parts: list[str] = []
        entity_dict: dict[str, str] = {}

        for field in rule.group_by_fields:
            val = event.get_entity_value(field)
            if val is None or val == "":
                return (None, {})
            entity_parts.append(f"{field}:{val}")
            entity_dict[field] = val

        return ("|".join(entity_parts), entity_dict)

    def _evaluate_rule(
        self,
        rule: CorrelationRule,
        events: list[NormalizedLogEvent],
        entity_dict: dict[str, str],
        buffer_key: str,
    ) -> CorrelatedIncident | None:
        """Route rule evaluation based on CorrelationRuleType."""
        if rule.rule_type == CorrelationRuleType.THRESHOLD:
            return self._evaluate_threshold(rule, events, entity_dict)
        if rule.rule_type == CorrelationRuleType.SEQUENCE:
            return self._evaluate_sequence(rule, events, entity_dict)
        if rule.rule_type == CorrelationRuleType.COMPOSITE:
            return self._evaluate_composite(rule, events, entity_dict)
        return None

    def _evaluate_threshold(
        self,
        rule: CorrelationRule,
        events: list[NormalizedLogEvent],
        entity_dict: dict[str, str],
    ) -> CorrelatedIncident | None:
        if rule.threshold_count is None:
            return None

        matching_events = [ev for ev in events if self._matches_filter(ev, rule.match_filter)]
        if len(matching_events) >= rule.threshold_count:
            return self._synthesize_incident(rule, matching_events, entity_dict)
        return None

    def _evaluate_sequence(
        self,
        rule: CorrelationRule,
        events: list[NormalizedLogEvent],
        entity_dict: dict[str, str],
    ) -> CorrelatedIncident | None:
        """Evaluate whether events satisfy the ordered sequence chain."""
        if len(rule.sequence_filters) < 2 or len(events) < len(rule.sequence_filters):
            return None

        matched_sequence: list[NormalizedLogEvent] = []
        current_stage_idx = 0
        last_matched_time: datetime | None = None

        for ev in events:
            if current_stage_idx >= len(rule.sequence_filters):
                break

            target_filter = rule.sequence_filters[current_stage_idx]
            if self._matches_filter(ev, target_filter) and (
                last_matched_time is None or ev.timestamp >= last_matched_time
            ):
                matched_sequence.append(ev)
                last_matched_time = ev.timestamp
                current_stage_idx += 1

        if current_stage_idx == len(rule.sequence_filters):
            return self._synthesize_incident(rule, matched_sequence, entity_dict)
        return None

    def _evaluate_composite(
        self,
        rule: CorrelationRule,
        events: list[NormalizedLogEvent],
        entity_dict: dict[str, str],
    ) -> CorrelatedIncident | None:
        """Evaluate composite correlation (e.g. multi-stage attack progression)."""
        stages_present = {
            ev.attack_stage for ev in events if ev.attack_stage != AttackStage.UNKNOWN
        }
        required_stages = set(rule.attack_stages)

        if required_stages and required_stages.issubset(stages_present):
            matching = [ev for ev in events if ev.attack_stage in required_stages]
            if len(matching) >= 2:
                return self._synthesize_incident(rule, matching, entity_dict)
        return None

    def _matches_filter(self, event: NormalizedLogEvent, filter_spec: dict[str, Any]) -> bool:
        """Determine if an event satisfies attribute filter constraints."""
        for field, expected in filter_spec.items():
            if field == "action" and event.action != expected:
                return False
            if field == "status" and event.status != expected:
                return False
            if field == "attack_stage":
                expected_stage = AttackStage(expected) if isinstance(expected, str) else expected
                if event.attack_stage != expected_stage:
                    return False
            if field == "severity" and event.severity != expected:
                return False
            if (
                field in ("source_ip", "destination_ip", "user", "source_host")
                and event.get_entity_value(field) != expected
            ):
                return False
            if field in event.metadata and event.metadata[field] != expected:
                return False
        return True

    def _synthesize_incident(
        self,
        rule: CorrelationRule,
        matched_events: list[NormalizedLogEvent],
        entity_dict: dict[str, str],
    ) -> CorrelatedIncident:
        """Create and score a CorrelatedIncident from matching events."""
        first_time = matched_events[0].timestamp
        last_time = matched_events[-1].timestamp

        all_stages = list(
            {ev.attack_stage for ev in matched_events if ev.attack_stage != AttackStage.UNKNOWN}
            | set(rule.attack_stages)
        )
        all_mitre = list(
            {ev.mitre_technique_id for ev in matched_events if ev.mitre_technique_id}
            | set(rule.mitre_attack_ids)
        )

        incident = CorrelatedIncident(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            rule_type=rule.rule_type,
            severity=rule.severity,
            entity_keys=entity_dict,
            attack_stages=all_stages,
            mitre_attack_ids=all_mitre,
            matched_events=matched_events,
            event_count=len(matched_events),
            window_seconds=rule.window_seconds,
            first_event_time=first_time,
            last_event_time=last_time,
        )
        incident.calculate_risk_score()
        return incident
