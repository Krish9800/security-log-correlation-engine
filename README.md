# Security Log Correlation Engine

A high-performance security log correlation and detection engine for identifying multi-stage threats across distributed logs (Syslog RFC 5424, CEF, JSON, Windows Event Logs) using sliding time-window stateful correlation.

## Key Features
- **Multi-Format Ingestion**: Ingests Syslog (RFC 5424 / 3164), ArcSight CEF, structured JSON, and Windows Event Logs.
- **Unified Security Taxonomy**: ECS/OCSF-aligned normalized schema (`NormalizedLogEvent`).
- **Sliding Time-Window Engine**: Memory-bounded state tracking per entity key (source IP, target user, host).
- **Multi-Stage Threat Correlation**: Threshold detection, sequence detection, and composite MITRE ATT&CK progression.
- **Incident Synthesis & Persistence**: Risk-scored `CorrelatedIncident` entities backed by SQLite WAL persistence.
- **Interfaces**: FastAPI asynchronous control plane and Typer / Rich CLI.
