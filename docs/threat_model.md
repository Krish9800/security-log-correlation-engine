# STRIDE Threat Model: Security Log Correlation Engine

## 1. System Overview & Scope
The **Security Log Correlation Engine** ingests heterogeneous, high-volume event logs (Syslog RFC 5424/3164, CEF, JSON, Windows Events), normalizes them into structured domain events, maintains temporal sliding windows, correlates multi-stage attack chains across MITRE ATT&CK stages, persists forensic state via SQLite WAL mode, and triggers structured alerts.

### Assets at Risk
1. **Engine Integrity & Availability**: The continuous processing pipeline must not crash or deadlock under hostile or malformed log floods.
2. **Alert & Incident Fidelity**: Detection state and incident records must not be suppressed, blinded, or altered by attackers attempting evasion.
3. **Log & Forensic Data**: Stored raw logs and correlation records in SQLite WAL database must be protected against tampering and unauthorized leakage.
4. **Host System & Execution Environment**: The host runtime must be protected against remote code execution, unauthorized process elevation, and file system traversal.

---

## 2. Threat Analysis (STRIDE Matrix)

| STRIDE Threat Category | Potential Attack Vector | Impact | Mitigation in Architecture & Implementation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker injects forged IP addresses or fake hostnames into syslog payloads to impersonate trusted hosts or frame benign systems. | High (Misattribution, false alerts, alert fatigue) | Multi-attribute correlation combines IP, host, username, and session identifiers. Ingestion records parser type and raw log hash for non-repudiation. |
| **Tampering** | Attacker injects SQL syntax (`admin' OR '1'='1'`) or format exploit strings into raw logs to manipulate the database or crash parsers. | Critical (Data corruption, forensic bypass) | Strict parameterized SQL queries (`?` binding) across SQLite repository; zero string concatenation. Pydantic schema validation rejects illegal datatypes. |
| **Repudiation** | Attacker claims an incident alert was fabricated or that malicious activities were never performed. | Medium (Lack of audit trail) | Ingestion logs raw event payloads, cryptographic hashes, deterministic nanosecond/microsecond timestamps, and persistent SQLite WAL audit history. |
| **Information Disclosure** | Sensitive authentication tokens, passwords, or internal system configurations leaked via verbose error messages or API endpoints. | High (Credential theft) | API error handlers sanitize internal exceptions. Default production logs redact sensitive parameters. Bandit AST scanning enforces absence of hardcoded secrets. |
| **Denial of Service (DoS)** | High-frequency log flooding, algorithmic complexity attacks (ReDoS), memory exhaustion via infinite sliding window retention, or disk exhaustion. | High (Engine unavailability, blind spots during attack) | Deque `maxlen` caps, stream-relative sliding window pruning, bounded regex patterns with linear complexity, and SQLite busy timeout locks. |
| **Elevation of Privilege** | Container breakout or unauthorized local root execution via unpatched system vulnerabilities. | Critical (Full host takeover) | Rootless Docker container with non-root UID 10001 (`appsec`), dropped Linux capabilities (`cap_drop: ALL`), and `no-new-privileges: true`. |

---

## 3. Detailed Component Analysis

### 3.1 Log Ingestion & Parsing
- **Threat**: Hostile payloads containing null bytes (`\x00`), ANSI terminal escapes, control characters, or oversized log messages (>1MB).
- **Mitigation**:
  - Parsers safely validate strings using typed Pydantic models.
  - Safe fallback mechanisms assign `RAW_UNPARSED` with error tags rather than failing or unhandled exception propagation.
  - ANSI escapes and control characters are preserved as inert text or stripped in CLI Rich rendering.

### 3.2 Temporal Correlation Engine
- **Threat**: Clock skew manipulation and timestamp spoofing (e.g., sending events dated in year 1970 or 2099 to evade sliding window detection or poison window boundaries).
- **Mitigation**:
  - Temporal windows use event timestamp delta bounds relative to the moving stream horizon (`newest_ts - window_duration`).
  - Pre-filter steps reject extreme future timestamps (>24 hours in the future) or clamp out-of-order logs to buffer retention bounds.

### 3.3 Storage Layer (SQLite WAL)
- **Threat**: SQL injection via search filters, incident queries, or log tags.
- **Mitigation**:
  - Full parameterization across all SQL queries in `SQLitePersistenceEngine`.
  - WAL journaling mode ensures ACID consistency with concurrent reader threads and crash resiliency.
  - Foreign key constraints enforce referential integrity between events and incident associations.

### 3.4 Control Plane & API
- **Threat**: Unauthenticated administrative changes or arbitrary payload injection via REST endpoints.
- **Mitigation**:
  - FastAPI request validation with Pydantic v2.
  - Configurable CORS and binding to explicit local interfaces.
  - Health checks provide unauthenticated liveness probes without exposing internal diagnostics.

---

## 4. Verification & Testing
The above threat model mitigations are verified by:
1. **Adversarial Security Testbed**: `tests/security/test_security_adversarial.py` covers malformed payload resilience, SQL injection resistance, timestamp jump handling, and DoS buffer overflow.
2. **Automated Static Security Scan**: `bandit -r src/` run in CI enforces zero high/medium security issues.
3. **Type Safety Verification**: `mypy --strict` guarantees no untyped boundary transitions.
