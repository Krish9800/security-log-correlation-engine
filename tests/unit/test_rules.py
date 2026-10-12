"""Unit tests for built-in rule catalog and YAML rule loader."""

from pathlib import Path

import pytest

from log_corr.models.enums import AttackStage, CorrelationRuleType, Severity
from log_corr.rules.rule_catalog import (
    BUILTIN_RULES,
    RULE_BRUTE_FORCE_TO_SUDO,
    RULE_SSH_BRUTE_FORCE,
    RuleLoader,
    get_default_rules,
)


def test_builtin_rules_integrity() -> None:
    """Verify built-in rule definitions and immutability of defaults."""
    assert len(BUILTIN_RULES) >= 5
    default_rules = get_default_rules()
    assert len(default_rules) == len(BUILTIN_RULES)

    # Verify deep copy
    default_rules[0].name = "Mutated Rule"
    assert RULE_SSH_BRUTE_FORCE.name == "SSH Password Brute Force"

    assert RULE_BRUTE_FORCE_TO_SUDO.rule_type == CorrelationRuleType.SEQUENCE
    assert RULE_BRUTE_FORCE_TO_SUDO.severity == Severity.CRITICAL


def test_rule_loader_from_yaml_threshold() -> None:
    """Verify loading threshold rule from YAML text."""
    yaml_text = """
    id: R-YAML-THRESH-01
    title: Multiple Failed Web Logins
    description: 10 failed logins within 60 seconds
    rule_type: threshold
    timeframe: 60
    count: 10
    group_by: source_ip
    level: high
    stages:
      - credential_access
    tags:
      - T1110
    condition:
      action: web_login_failure
    """
    rule = RuleLoader.load_from_yaml(yaml_text)
    assert rule.rule_id == "R-YAML-THRESH-01"
    assert rule.name == "Multiple Failed Web Logins"
    assert rule.threshold_count == 10
    assert rule.severity == Severity.HIGH
    assert rule.attack_stages == [AttackStage.CREDENTIAL_ACCESS]
    assert rule.mitre_attack_ids == ["T1110"]
    assert rule.match_filter == {"action": "web_login_failure"}


def test_rule_loader_from_yaml_sequence() -> None:
    """Verify loading sequence rule from YAML text."""
    yaml_text = """
    id: R-YAML-SEQ-02
    title: Port Scan Then RCE
    rule_type: sequence
    timeframe: 120
    group_by: source_ip
    level: critical
    sequence:
      - action: port_probe
      - action: rce_exploit
    stages:
      - reconnaissance
      - initial_access
    """
    rule = RuleLoader.load_from_yaml(yaml_text)
    assert rule.rule_id == "R-YAML-SEQ-02"
    assert rule.rule_type == CorrelationRuleType.SEQUENCE
    assert len(rule.sequence_filters) == 2
    assert rule.severity == Severity.CRITICAL
    assert len(rule.attack_stages) == 2


def test_rule_loader_file_and_directory(temp_dir: Path) -> None:
    """Verify loading rules from single multi-doc file and directory."""
    multi_doc_yaml = """
---
id: R-DOC-1
title: Document 1
rule_type: threshold
count: 3
condition:
  action: fail
---
id: R-DOC-2
title: Document 2
rule_type: sequence
sequence:
  - action: step1
  - action: step2
"""
    file1 = temp_dir / "rules1.yaml"
    file1.write_text(multi_doc_yaml, encoding="utf-8")

    file2 = temp_dir / "rules2.yml"
    file2.write_text(
        """
id: R-DOC-3
title: Document 3
rule_type: threshold
count: 5
condition:
  action: alert
""",
        encoding="utf-8",
    )

    # Test load from file
    loaded_file = RuleLoader.load_from_file(file1)
    assert len(loaded_file) == 2
    assert loaded_file[0].rule_id == "R-DOC-1"
    assert loaded_file[1].rule_id == "R-DOC-2"

    # Test load from directory
    loaded_dir = RuleLoader.load_from_directory(temp_dir)
    assert len(loaded_dir) == 3
    rule_ids = {r.rule_id for r in loaded_dir}
    assert rule_ids == {"R-DOC-1", "R-DOC-2", "R-DOC-3"}


def test_rule_loader_invalid_inputs(temp_dir: Path) -> None:
    """Verify error handling on invalid YAML format and missing files."""
    with pytest.raises(ValueError, match="dictionary"):
        RuleLoader.load_from_yaml("- a list instead of dict")

    with pytest.raises(FileNotFoundError):
        RuleLoader.load_from_file(temp_dir / "nonexistent.yaml")

    with pytest.raises(NotADirectoryError):
        RuleLoader.load_from_directory(temp_dir / "not_a_dir.yaml")
