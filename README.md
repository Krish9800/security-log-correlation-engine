# Security Log Correlation Engine

A high-performance security log correlation and detection engine for identifying multi-stage threats across distributed logs (Syslog RFC 5424/3164, ArcSight CEF, structured JSON, Windows Event Logs) using sliding time-window stateful correlation, MITRE ATT&CK attack chain rules, SQLite WAL persistence, and real-time alert dispatching.

---

## Key Features

- **Multi-Format Ingestion**: Ingests Syslog (RFC 5424 / RFC 3164), ArcSight CEF, structured JSON, and Windows Event Logs with resilient fallback parsing.
- **Unified Security Taxonomy**: ECS/OCSF-aligned normalized schema (`NormalizedLogEvent`) with typed timestamps, severity scoring, network 5-tuples, and MITRE tactics.
- **Sliding Time-Window Engine**: Memory-bounded deque-backed event tracking per entity key (`source_ip`, `target_user`, `host`) with stream-relative time eviction.
- **Multi-Stage Threat Correlation**:
  - **Threshold Detection**: High-frequency single-action anomalies (e.g. brute force).
  - **Sequence Detection**: Ordered, causally linked multi-stage events (e.g. Recon $\to$ Breach $\to$ Lateral Movement).
  - **Composite Attack Chains**: Cross-tactic MITRE ATT&CK progression.
- **Built-in & Custom YAML Rules**: Out-of-the-box attack chain rules (Brute Force, PrivEsc, Data Exfiltration) with dynamic YAML loader.
- **Incident Synthesis & Alert Dispatch**: Composite risk-scored `CorrelatedIncident` generation with multi-channel alert dispatcher (Webhook, Syslog, Console, In-Memory).
- **SQLite WAL Persistence**: Zero-overhead, transactional SQLite persistence running in write-ahead log (WAL) mode with busy timeouts and full query filtering.
- **FastAPI Control Plane**: Asynchronous REST API for single/bulk log ingestion, rule management, and incident queries.
- **Typer & Rich CLI**: Command-line interface with interactive table visualizations and live log streaming.
- **Production & Security Hardened**: Rootless Docker container (UID 10001), STRIDE threat model, 100% strict type hints (`mypy --strict`), PEP 8 compliance (`ruff`), and adversarial test suite.

---

## Architecture Overview

```
                      ┌─────────────────────────────────────────┐
                      │            Log Ingestion Sources        │
                      │  Syslog (5424/3164), CEF, JSON, WinEvt  │
                      └────────────────────┬────────────────────┘
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │          Parsers & Normalizer           │
                      │       ECS / OCSF Normalized Event       │
                      └────────────────────┬────────────────────┘
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │       Sliding Window Buffer (Deque)     │
                      │      Keyed by Source IP / User / Host   │
                      └────────────────────┬────────────────────┘
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │     Multi-Stage Correlation Engine      │
                      │   Threshold, Sequence, Attack Chains    │
                      └──────────────┬───────────────────┬──────┘
                                     │                   │
                                     ▼                   ▼
                      ┌──────────────────────┐   ┌──────────────────────┐
                      │ SQLite WAL Storage   │   │ Alert Dispatcher     │
                      │ Events & Incidents   │   │ Webhook, Syslog, etc │
                      └──────────────────────┘   └──────────────────────┘
```

---

## Installation & Quick Start

### 1. Local Setup with Virtual Environment

```bash
# Clone repository
git clone https://github.com/example/security-log-correlation-engine.git
cd security-log-correlation-engine

# Create virtual environment and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### 2. Using the CLI

```bash
# Ingest raw logs directly via stdin or arguments
log-corr ingest "<134>1 2026-10-12T12:00:00Z auth.corp.internal sshd 1234 - - Failed password for invalid user admin from 198.51.100.55 port 44222 ssh2"

# View current active rules
log-corr rules list

# Query detected security incidents
log-corr incidents list --severity HIGH

# Ingest and correlate a file containing mixed logs
log-corr ingest-file /var/log/auth.log
```

### 3. Running the FastAPI Server

```bash
# Start API server locally
uvicorn log_corr.api.app:app --host 0.0.0.0 --port 8000 --reload
```

Interactive OpenAPI docs will be available at `http://127.0.0.1:8000/docs`.

### 4. Running via Docker / Docker Compose

```bash
# Build and run the rootless container
docker compose up -d

# Check service health
curl -f http://localhost:8000/health
```

---

## Detection Rules & Attack Chains

Rules can be defined in YAML and loaded dynamically:

```yaml
id: "R-SSH-BRUT"
name: "SSH Password Brute Force"
description: "Detects 5 or more failed logins from a single source within 5 minutes"
rule_type: "THRESHOLD"
threshold_count: 5
window_seconds: 300
entity_key: "source_ip"
severity: "HIGH"
tactic: "CREDENTIAL_ACCESS"
technique_id: "T1110"
criteria:
  - field: "event_action"
    operator: "EQUALS"
    value: "failed_login"
```

---

## Quality Gates & Verification

The project adheres to strict production software engineering standards:

```bash
# Code formatting and style
ruff format --check src tests
ruff check src tests

# Strict static type checking
mypy --strict src tests

# Security AST vulnerability audit
bandit -r src/

# Full test suite with coverage
pytest --cov=log_corr --cov-fail-under=90 tests/
```

---

## Documentation

- [Threat Model (STRIDE)](docs/threat_model.md)
- [Architecture Blueprint](https://github.com/example/security-log-correlation-engine)
- [Changelog](CHANGELOG.md)

---

## License

Apache License 2.0
