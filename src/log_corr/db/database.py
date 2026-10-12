"""Persistence engine for Security Log Correlation Engine using SQLite in WAL mode."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from log_corr.models.enums import (
    AttackStage,
    CorrelationRuleType,
    IncidentStatus,
    LogFormat,
    Severity,
)
from log_corr.models.schemas import (
    AlertNotification,
    CorrelatedIncident,
    CorrelationRule,
    NormalizedLogEvent,
)


class DatabaseManager:
    """Thread-safe SQLite Write-Ahead Logging (WAL) database manager."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = Path(db_path) if db_path != ":memory:" else ":memory:"
        self._lock = RLock()
        if isinstance(self.db_path, Path):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        else:
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)

        self._conn.row_factory = sqlite3.Row
        self._enable_wal()
        self.init_db()

    def _enable_wal(self) -> None:
        """Configure performance and data integrity PRAGMAs."""
        with self._lock:
            cur = self._conn.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.close()

    def init_db(self) -> None:
        """Initialize database schema from schema.sql."""
        schema_file = Path(__file__).parent / "schema.sql"
        schema_sql = schema_file.read_text(encoding="utf-8")
        with self._lock:
            self._conn.executescript(schema_sql)
            self._conn.commit()

    def save_event(self, event: NormalizedLogEvent) -> None:
        """Persist a single NormalizedLogEvent."""
        query = """
        INSERT OR REPLACE INTO normalized_events (
            event_id, timestamp, raw_log, format, source_host, source_ip,
            source_port, destination_ip, destination_port, user, action,
            status, severity, attack_stage, mitre_technique_id, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._lock:
            self._conn.execute(
                query,
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.raw_log,
                    event.format.value,
                    event.source_host,
                    event.source_ip,
                    event.source_port,
                    event.destination_ip,
                    event.destination_port,
                    event.user,
                    event.action,
                    event.status,
                    event.severity.value,
                    event.attack_stage.value,
                    event.mitre_technique_id,
                    json.dumps(event.metadata),
                ),
            )
            self._conn.commit()

    def save_events(self, events: list[NormalizedLogEvent]) -> int:
        """Batch persist multiple NormalizedLogEvents."""
        query = """
        INSERT OR REPLACE INTO normalized_events (
            event_id, timestamp, raw_log, format, source_host, source_ip,
            source_port, destination_ip, destination_port, user, action,
            status, severity, attack_stage, mitre_technique_id, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        rows = [
            (
                ev.event_id,
                ev.timestamp.isoformat(),
                ev.raw_log,
                ev.format.value,
                ev.source_host,
                ev.source_ip,
                ev.source_port,
                ev.destination_ip,
                ev.destination_port,
                ev.user,
                ev.action,
                ev.status,
                ev.severity.value,
                ev.attack_stage.value,
                ev.mitre_technique_id,
                json.dumps(ev.metadata),
            )
            for ev in events
        ]
        with self._lock:
            self._conn.executemany(query, rows)
            self._conn.commit()
        return len(rows)

    def get_event(self, event_id: str) -> NormalizedLogEvent | None:
        """Retrieve a stored event by ID."""
        query = "SELECT * FROM normalized_events WHERE event_id = ?;"
        with self._lock:
            row = self._conn.execute(query, (event_id,)).fetchone()
            if not row:
                return None
            return self._row_to_event(row)

    def list_events(
        self,
        limit: int = 100,
        offset: int = 0,
        source_ip: str | None = None,
        action: str | None = None,
    ) -> list[NormalizedLogEvent]:
        """List events with optional filtering."""
        query = "SELECT * FROM normalized_events WHERE 1=1"
        params: list[Any] = []
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if action:
            query += " AND action = ?"
            params.append(action)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
            return [self._row_to_event(r) for r in rows]

    def save_rule(self, rule: CorrelationRule) -> None:
        """Persist or update a CorrelationRule."""
        query = """
        INSERT OR REPLACE INTO rules (
            rule_id, name, description, rule_type, enabled, window_seconds,
            group_by_json, threshold_count, match_filter_json, sequence_filters_json,
            severity, attack_stages_json, mitre_attack_ids_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._lock:
            self._conn.execute(
                query,
                (
                    rule.rule_id,
                    rule.name,
                    rule.description,
                    rule.rule_type.value,
                    1 if rule.enabled else 0,
                    rule.window_seconds,
                    json.dumps(rule.group_by_fields),
                    rule.threshold_count,
                    json.dumps(rule.match_filter),
                    json.dumps(rule.sequence_filters),
                    rule.severity.value,
                    json.dumps([s.value for s in rule.attack_stages]),
                    json.dumps(rule.mitre_attack_ids),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()

    def get_rule(self, rule_id: str) -> CorrelationRule | None:
        """Retrieve a rule by ID."""
        query = "SELECT * FROM rules WHERE rule_id = ?;"
        with self._lock:
            row = self._conn.execute(query, (rule_id,)).fetchone()
            if not row:
                return None
            return self._row_to_rule(row)

    def list_rules(self) -> list[CorrelationRule]:
        """Retrieve all registered rules."""
        query = "SELECT * FROM rules ORDER BY rule_id ASC;"
        with self._lock:
            rows = self._conn.execute(query).fetchall()
            return [self._row_to_rule(r) for r in rows]

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule by ID. Returns True if deleted."""
        query = "DELETE FROM rules WHERE rule_id = ?;"
        with self._lock:
            cursor = self._conn.execute(query, (rule_id,))
            self._conn.commit()
            return cursor.rowcount > 0

    def save_incident(self, incident: CorrelatedIncident) -> None:
        """Persist a CorrelatedIncident and its matched events."""
        query = """
        INSERT OR REPLACE INTO incidents (
            incident_id, rule_id, rule_name, rule_type, severity, risk_score,
            status, entity_keys_json, attack_stages_json, mitre_attack_ids_json,
            event_count, window_seconds, first_event_time, last_event_time,
            created_at, summary, matched_event_ids_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        matched_ids = [ev.event_id for ev in incident.matched_events]
        with self._lock:
            if incident.matched_events:
                self.save_events(incident.matched_events)

            self._conn.execute(
                query,
                (
                    incident.incident_id,
                    incident.rule_id,
                    incident.rule_name,
                    incident.rule_type.value,
                    incident.severity.value,
                    incident.risk_score,
                    incident.status.value,
                    json.dumps(incident.entity_keys),
                    json.dumps([s.value for s in incident.attack_stages]),
                    json.dumps(incident.mitre_attack_ids),
                    incident.event_count,
                    incident.window_seconds,
                    incident.first_event_time.isoformat(),
                    incident.last_event_time.isoformat(),
                    incident.created_at.isoformat(),
                    incident.summary,
                    json.dumps(matched_ids),
                ),
            )
            self._conn.commit()

    def get_incident(self, incident_id: str) -> CorrelatedIncident | None:
        """Retrieve an incident by ID including its matched events."""
        query = "SELECT * FROM incidents WHERE incident_id = ?;"
        with self._lock:
            row = self._conn.execute(query, (incident_id,)).fetchone()
            if not row:
                return None
            return self._row_to_incident(row)

    def list_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[CorrelatedIncident]:
        """List incidents with optional filtering."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: list[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ?;"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
            return [self._row_to_incident(r) for r in rows]

    def update_incident_status(self, incident_id: str, status: IncidentStatus) -> bool:
        """Update the operational status of an incident."""
        query = "UPDATE incidents SET status = ? WHERE incident_id = ?;"
        with self._lock:
            cursor = self._conn.execute(query, (status.value, incident_id))
            self._conn.commit()
            return cursor.rowcount > 0

    def save_alert(self, alert: AlertNotification) -> None:
        """Persist an AlertNotification record."""
        query = """
        INSERT OR REPLACE INTO alerts (
            alert_id, incident_id, rule_id, rule_name, severity, risk_score,
            title, description, affected_entities_json, mitre_tactics_json,
            timestamp, channel, dispatched
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._lock:
            self._conn.execute(
                query,
                (
                    alert.alert_id,
                    alert.incident_id,
                    alert.rule_id,
                    alert.rule_name,
                    alert.severity.value,
                    alert.risk_score,
                    alert.title,
                    alert.description,
                    json.dumps(alert.affected_entities),
                    json.dumps(alert.mitre_tactics),
                    alert.timestamp.isoformat(),
                    alert.channel,
                    1 if alert.dispatched else 0,
                ),
            )
            self._conn.commit()

    def list_alerts(self, limit: int = 100) -> list[AlertNotification]:
        """Retrieve recent alerts."""
        query = "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?;"
        with self._lock:
            rows = self._conn.execute(query, (limit,)).fetchall()
            return [self._row_to_alert(r) for r in rows]

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            self._conn.close()

    def _row_to_event(self, row: sqlite3.Row) -> NormalizedLogEvent:
        metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        return NormalizedLogEvent(
            event_id=row["event_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            raw_log=row["raw_log"],
            format=LogFormat(row["format"]),
            source_host=row["source_host"],
            source_ip=row["source_ip"],
            source_port=row["source_port"],
            destination_ip=row["destination_ip"],
            destination_port=row["destination_port"],
            user=row["user"],
            action=row["action"],
            status=row["status"],
            severity=Severity(row["severity"]),
            attack_stage=AttackStage(row["attack_stage"]),
            mitre_technique_id=row["mitre_technique_id"],
            metadata=metadata,
        )

    def _row_to_rule(self, row: sqlite3.Row) -> CorrelationRule:
        stages = [AttackStage(s) for s in json.loads(row["attack_stages_json"])]
        return CorrelationRule(
            rule_id=row["rule_id"],
            name=row["name"],
            description=row["description"] or "",
            rule_type=CorrelationRuleType(row["rule_type"]),
            enabled=bool(row["enabled"]),
            window_seconds=row["window_seconds"],
            group_by_fields=json.loads(row["group_by_json"]),
            threshold_count=row["threshold_count"],
            match_filter=json.loads(row["match_filter_json"]) if row["match_filter_json"] else {},
            sequence_filters=json.loads(row["sequence_filters_json"])
            if row["sequence_filters_json"]
            else [],
            severity=Severity(row["severity"]),
            attack_stages=stages,
            mitre_attack_ids=json.loads(row["mitre_attack_ids_json"]),
        )

    def _row_to_incident(self, row: sqlite3.Row) -> CorrelatedIncident:
        stages = [AttackStage(s) for s in json.loads(row["attack_stages_json"])]
        matched_event_ids: list[str] = json.loads(row["matched_event_ids_json"])
        matched_events: list[NormalizedLogEvent] = []
        for eid in matched_event_ids:
            ev = self.get_event(eid)
            if ev:
                matched_events.append(ev)

        return CorrelatedIncident(
            incident_id=row["incident_id"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            rule_type=CorrelationRuleType(row["rule_type"]),
            severity=Severity(row["severity"]),
            risk_score=row["risk_score"],
            status=IncidentStatus(row["status"]),
            entity_keys=json.loads(row["entity_keys_json"]),
            attack_stages=stages,
            mitre_attack_ids=json.loads(row["mitre_attack_ids_json"]),
            matched_events=matched_events,
            event_count=row["event_count"],
            window_seconds=row["window_seconds"],
            first_event_time=datetime.fromisoformat(row["first_event_time"]),
            last_event_time=datetime.fromisoformat(row["last_event_time"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            summary=row["summary"],
        )

    def _row_to_alert(self, row: sqlite3.Row) -> AlertNotification:
        return AlertNotification(
            alert_id=row["alert_id"],
            incident_id=row["incident_id"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            severity=Severity(row["severity"]),
            risk_score=row["risk_score"],
            title=row["title"],
            description=row["description"],
            affected_entities=json.loads(row["affected_entities_json"]),
            mitre_tactics=json.loads(row["mitre_tactics_json"]),
            timestamp=datetime.fromisoformat(row["timestamp"]),
            channel=row["channel"],
            dispatched=bool(row["dispatched"]),
        )
