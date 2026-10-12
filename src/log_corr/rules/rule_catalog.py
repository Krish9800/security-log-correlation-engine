"""Built-in correlation rules and YAML / Sigma-style rule loader."""

import contextlib
from pathlib import Path
from typing import Any

import yaml

from log_corr.models.enums import AttackStage, CorrelationRuleType, Severity
from log_corr.models.schemas import CorrelationRule

# ============================================================================
# Built-in Detection Rules
# ============================================================================

RULE_SSH_BRUTE_FORCE = CorrelationRule(
    rule_id="R-SSH-BRUTE-01",
    name="SSH Password Brute Force",
    description="5 or more failed authentication attempts from a single source IP within 60s",
    rule_type=CorrelationRuleType.THRESHOLD,
    window_seconds=60,
    group_by_fields=["source_ip"],
    threshold_count=5,
    match_filter={"action": "auth_failure"},
    severity=Severity.HIGH,
    attack_stages=[AttackStage.CREDENTIAL_ACCESS],
    mitre_attack_ids=["T1110.001"],
)

RULE_BRUTE_FORCE_TO_SUDO = CorrelationRule(
    rule_id="R-AUTH-SUDO-02",
    name="Brute Force to Sudo Privilege Escalation",
    description="Authentication failure followed by sudo command execution from same entity",
    rule_type=CorrelationRuleType.SEQUENCE,
    window_seconds=120,
    group_by_fields=["source_ip", "user"],
    sequence_filters=[
        {"action": "auth_failure"},
        {"action": "sudo_exec"},
    ],
    severity=Severity.CRITICAL,
    attack_stages=[AttackStage.CREDENTIAL_ACCESS, AttackStage.PRIVILEGE_ESCALATION],
    mitre_attack_ids=["T1110", "T1548.003"],
)

RULE_PORT_SCAN_TO_EXPLOIT = CorrelationRule(
    rule_id="R-RECON-EXPLOIT-03",
    name="Port Reconnaissance to Web Application Exploit",
    description="Port probing followed by web application exploitation within 180s",
    rule_type=CorrelationRuleType.SEQUENCE,
    window_seconds=180,
    group_by_fields=["source_ip"],
    sequence_filters=[
        {"action": "port_probe"},
        {"action": "web_exploit"},
    ],
    severity=Severity.HIGH,
    attack_stages=[AttackStage.RECONNAISSANCE, AttackStage.INITIAL_ACCESS],
    mitre_attack_ids=["T1046", "T1190"],
)

RULE_LATERAL_MOVEMENT = CorrelationRule(
    rule_id="R-LATERAL-SSH-04",
    name="Internal Remote Service Lateral Movement",
    description="Account logon success followed by remote service connection from internal IP",
    rule_type=CorrelationRuleType.SEQUENCE,
    window_seconds=300,
    group_by_fields=["user"],
    sequence_filters=[
        {"action": "auth_success"},
        {"action": "auth_success"},
    ],
    severity=Severity.HIGH,
    attack_stages=[AttackStage.INITIAL_ACCESS, AttackStage.LATERAL_MOVEMENT],
    mitre_attack_ids=["T1078", "T1021.004"],
)

RULE_MULTI_STAGE_KILL_CHAIN = CorrelationRule(
    rule_id="R-KILL-CHAIN-05",
    name="Comprehensive Multi-Stage Attack Kill Chain",
    description="Concurrent detection of reconnaissance and initial access within 300s",
    rule_type=CorrelationRuleType.COMPOSITE,
    window_seconds=300,
    group_by_fields=["source_ip"],
    attack_stages=[AttackStage.RECONNAISSANCE, AttackStage.INITIAL_ACCESS],
    severity=Severity.CRITICAL,
    mitre_attack_ids=["T1046", "T1190"],
)

BUILTIN_RULES: list[CorrelationRule] = [
    RULE_SSH_BRUTE_FORCE,
    RULE_BRUTE_FORCE_TO_SUDO,
    RULE_PORT_SCAN_TO_EXPLOIT,
    RULE_LATERAL_MOVEMENT,
    RULE_MULTI_STAGE_KILL_CHAIN,
]


def get_default_rules() -> list[CorrelationRule]:
    """Return a fresh list of all built-in correlation rules."""
    return [rule.model_copy(deep=True) for rule in BUILTIN_RULES]


# ============================================================================
# YAML / Sigma-Style Rule Loader
# ============================================================================


class RuleLoader:
    """Parses and validates declarative YAML correlation rules."""

    @classmethod
    def load_from_yaml(cls, yaml_content: str) -> CorrelationRule:
        """Parse a single YAML string into a CorrelationRule."""
        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            raise ValueError("YAML rule document must be a dictionary")
        return cls._dict_to_rule(data)

    @classmethod
    def load_from_file(cls, file_path: Path | str) -> list[CorrelationRule]:
        """Load one or multiple YAML rules from a file."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Rule file not found: {path}")

        content = path.read_text(encoding="utf-8")
        docs = yaml.safe_load_all(content)
        rules: list[CorrelationRule] = []

        for doc in docs:
            if isinstance(doc, dict):
                rules.append(cls._dict_to_rule(doc))
        return rules

    @classmethod
    def load_from_directory(cls, dir_path: Path | str) -> list[CorrelationRule]:
        """Load all .yml and .yaml rules from a directory."""
        path = Path(dir_path)
        if not path.is_dir():
            raise NotADirectoryError(f"Rule directory not found: {path}")

        rules: list[CorrelationRule] = []
        for file in sorted(path.glob("*")):
            if file.suffix.lower() in (".yml", ".yaml") and file.is_file():
                rules.extend(cls.load_from_file(file))
        return rules

    @classmethod
    def _dict_to_rule(cls, data: dict[str, Any]) -> CorrelationRule:
        """Map YAML / Sigma dictionary to CorrelationRule."""
        rule_id = str(data.get("id") or data.get("rule_id", "R-CUSTOM"))
        name = str(data.get("title") or data.get("name", "Custom Rule"))
        description = str(data.get("description", ""))
        rule_type_str = str(data.get("rule_type", "threshold")).lower()
        rule_type = CorrelationRuleType(rule_type_str)

        window_sec = int(data.get("timeframe") or data.get("window_seconds", 60))
        group_by = data.get("group_by") or data.get("group_by_fields") or ["source_ip"]
        if isinstance(group_by, str):
            group_by = [group_by]

        sev_str = str(data.get("level") or data.get("severity", "medium")).lower()
        severity = cls._parse_severity(sev_str)

        attack_stages: list[AttackStage] = []
        raw_stages = data.get("stages") or data.get("attack_stages") or []
        for s in raw_stages:
            with contextlib.suppress(ValueError):
                attack_stages.append(AttackStage(str(s).lower()))

        mitre_ids = [str(m) for m in (data.get("tags") or data.get("mitre_attack_ids") or [])]

        threshold_count = data.get("threshold_count") or data.get("count")
        if threshold_count is not None:
            threshold_count = int(threshold_count)

        match_filter = data.get("condition") or data.get("match_filter") or {}
        if not isinstance(match_filter, dict):
            match_filter = {"action": str(match_filter)}

        seq_filters = data.get("sequence") or data.get("sequence_filters") or []
        if isinstance(seq_filters, list):
            seq_filters = [f if isinstance(f, dict) else {"action": str(f)} for f in seq_filters]

        # Ensure defaults for threshold if type is threshold
        if rule_type == CorrelationRuleType.THRESHOLD:
            if threshold_count is None:
                threshold_count = 5
            if not match_filter:
                match_filter = {"action": "auth_failure"}

        return CorrelationRule(
            rule_id=rule_id,
            name=name,
            description=description,
            rule_type=rule_type,
            enabled=bool(data.get("enabled", True)),
            window_seconds=window_sec,
            group_by_fields=group_by,
            threshold_count=threshold_count,
            match_filter=match_filter,
            sequence_filters=seq_filters,
            severity=severity,
            attack_stages=attack_stages,
            mitre_attack_ids=mitre_ids,
        )

    @classmethod
    def _parse_severity(cls, sev_str: str) -> Severity:
        sev = sev_str.lower()
        if "crit" in sev:
            return Severity.CRITICAL
        if "high" in sev:
            return Severity.HIGH
        if "med" in sev or "warn" in sev:
            return Severity.MEDIUM
        if "low" in sev:
            return Severity.LOW
        return Severity.INFO
