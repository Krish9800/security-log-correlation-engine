# Changelog

All notable changes to the Security Log Correlation Engine will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-12

### Added
- **Phase 1: Project Foundation & Architecture**
  - Project configuration in `pyproject.toml` with strict ruff, mypy, bandit, and pytest settings.
  - Environment-aware Pydantic v2 configuration settings (`EngineSettings`).
  - Core exception taxonomy hierarchy (`LogCorrError`, `ParsingError`, `CorrelationError`, etc.).
- **Phase 2: Domain Models & ECS/OCSF Taxonomy**
  - Typed enumerations for `SeverityLevel`, `ParserType`, `RuleType`, `MitreTactic`, `IncidentStatus`, `AlertChannelType`.
  - Normalized security event schema `NormalizedLogEvent` with network 5-tuple, host info, and MITRE mapping.
  - Correlation rule schemas (`CorrelationCriterion`, `CorrelationRule`) supporting THRESHOLD, SEQUENCE, and COMPOSITE rules.
  - Security incident entities (`CorrelatedIncident`) with automated risk scoring and alert records (`AlertNotification`).
- **Phase 3: Multi-Format Log Ingestion & Parsers**
  - Syslog parsers supporting RFC 5424 (structured data, ISO timestamps) and RFC 3164 (legacy BSD syslog).
  - ArcSight Common Event Format (CEF) header and key-value extension parser.
  - Structured JSON parser supporting Elastic Common Schema (ECS), AWS CloudTrail, and custom JSON formats.
  - Windows Event Log XML/plaintext parser with standard security Event IDs (4624, 4625, 4672, 4720).
  - Resilient `LogIngestionDispatcher` with automatic format detection and fallback to `RAW_UNPARSED`.
- **Phase 4: Sliding Time-Window Temporal Correlation Engine**
  - Thread-safe deque-backed `SlidingWindowBuffer` with bounded memory capacity and stream-relative time eviction.
  - Multi-stage correlation engine `CorrelationEngine` detecting:
    - Threshold anomalies (frequency bursts per entity key).
    - Ordered sequence attacks (stages requiring specific elapsed order).
    - Composite MITRE ATT&CK progression across tactics.
- **Phase 5: Built-in Attack Chain Rules & Dynamic YAML Loader**
  - Default detection rules covering SSH Brute Force, PrivEsc, Multi-Host Lateral Movement, and Data Exfiltration.
  - Dynamic YAML rule loader with strict schema validation.
- **Phase 6: Incident Synthesis & Multi-Channel Alert Dispatcher**
  - `IncidentSynthesizer` for aggregating related alerts, deduplicating, and computing weighted risk scores.
  - Multi-channel `AlertDispatcher` supporting Webhook (HTTP POST), Syslog output, Console logging, and In-Memory channels.
- **Phase 7: SQLite WAL Mode Persistence Engine**
  - `SQLitePersistenceEngine` with Write-Ahead Logging (WAL) and `busy_timeout` configuration.
  - Parameterized table storage for normalized events, correlation rules, correlated incidents, and incident-event mappings.
- **Phase 8: FastAPI Asynchronous Control Plane**
  - Endpoints for single event ingestion (`POST /api/v1/logs`), bulk ingestion (`POST /api/v1/logs/batch`), and raw text ingestion (`POST /api/v1/logs/raw`).
  - Incident management endpoints (`GET /api/v1/incidents`, `GET /api/v1/incidents/{id}`, `PATCH /api/v1/incidents/{id}/status`).
  - Rule management endpoints (`GET /api/v1/rules`, `POST /api/v1/rules`).
  - Liveness and readiness health checks (`GET /health`, `GET /ready`).
- **Phase 9: Typer & Rich CLI Tool**
  - CLI commands: `ingest`, `ingest-file`, `rules list`, `incidents list`, `incidents show`.
  - Colored Rich tables, formatted incident summaries, and standard stream piping.
- **Phase 10: Production Hardening & Adversarial Testbed**
  - Rootless Dockerfile with multi-stage build and non-root user `appsec` (UID 10001).
  - Docker Compose service configuration with dropped capabilities.
  - GitHub Actions CI workflow covering ruff, mypy strict, bandit, and pytest.
  - STRIDE threat model documentation (`docs/threat_model.md`).
  - Adversarial test suite validating malformed logs, SQL injection, timestamp jumps, and high-frequency flood resistance.
