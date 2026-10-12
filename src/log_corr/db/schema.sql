-- Security Log Correlation Engine Schema (SQLite WAL mode)

CREATE TABLE IF NOT EXISTS normalized_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    raw_log TEXT NOT NULL,
    format TEXT NOT NULL,
    source_host TEXT NOT NULL,
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    user TEXT,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    attack_stage TEXT NOT NULL,
    mitre_technique_id TEXT,
    metadata_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON normalized_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON normalized_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON normalized_events(user);
CREATE INDEX IF NOT EXISTS idx_events_action ON normalized_events(action);

CREATE TABLE IF NOT EXISTS rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    rule_type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    window_seconds INTEGER NOT NULL,
    group_by_json TEXT NOT NULL,
    threshold_count INTEGER,
    match_filter_json TEXT,
    sequence_filters_json TEXT,
    severity TEXT NOT NULL,
    attack_stages_json TEXT,
    mitre_attack_ids_json TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score REAL NOT NULL,
    status TEXT NOT NULL,
    entity_keys_json TEXT NOT NULL,
    attack_stages_json TEXT NOT NULL,
    mitre_attack_ids_json TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL,
    first_event_time TEXT NOT NULL,
    last_event_time TEXT NOT NULL,
    created_at TEXT NOT NULL,
    summary TEXT NOT NULL,
    matched_event_ids_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_rule_id ON incidents(rule_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score REAL NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    affected_entities_json TEXT NOT NULL,
    mitre_tactics_json TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    channel TEXT NOT NULL,
    dispatched INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts(incident_id);
