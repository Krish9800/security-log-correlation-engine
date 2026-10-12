"""Rules module for Security Log Correlation Engine."""

from log_corr.rules.rule_catalog import (
    BUILTIN_RULES,
    RULE_BRUTE_FORCE_TO_SUDO,
    RULE_LATERAL_MOVEMENT,
    RULE_MULTI_STAGE_KILL_CHAIN,
    RULE_PORT_SCAN_TO_EXPLOIT,
    RULE_SSH_BRUTE_FORCE,
    RuleLoader,
    get_default_rules,
)

__all__ = [
    "BUILTIN_RULES",
    "RULE_BRUTE_FORCE_TO_SUDO",
    "RULE_LATERAL_MOVEMENT",
    "RULE_MULTI_STAGE_KILL_CHAIN",
    "RULE_PORT_SCAN_TO_EXPLOIT",
    "RULE_SSH_BRUTE_FORCE",
    "RuleLoader",
    "get_default_rules",
]
