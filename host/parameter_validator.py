"""
P2-L2: Parameter Validation.
Validates tool call parameters: wildcards, criticality, value rules, target-evidence consistency.
~90% symbolic, ~10% mathematical (embedding similarity). Zero LLM.
Covers: TA-4, TA-5
"""

import json
from pathlib import Path
from typing import Optional

import numpy as np

from config import BASE_DIR
from host.tool_semantics import SCOPE_ARGS, TARGET_FIELDS, action_of
from logging_utils import ExperimentLogger


class ParameterValidator:
    """Validates tool call parameters against safety rules."""

    # v3.2: the shared map (host.tool_semantics), taken from the tool schemas;
    # before, six admin tools had no entry and L8 pointed at a field it lacks
    TARGET_FIELDS = TARGET_FIELDS

    # Actions considered destructive for high-criticality gating
    _DESTRUCTIVE_ACTIONS = frozenset({
        "revoke", "delete_rule", "quarantine", "freeze",
        "isolate_host", "delete", "suspend", "remove",
        "shutdown", "disable", "block_ip",
    })

    def __init__(
        self,
        domain: str,
        embedding_model=None,
        logger: Optional[ExperimentLogger] = None,
    ):
        self.domain = domain
        self.logger = logger
        self._embedding_model = embedding_model

        # Wildcard values (checked case-insensitive).
        # Expanded 2026-04 to cover Llama / GLM / Claude emission variants.
        self._wildcards = {
            # Classic wildcards
            "*", "**", "***", "all", "0.0.0.0/0", "::/0", "everyone",
            "all_users", "all_hosts", "all_subnets", "any", "anyone",
            "0.0.0.0", "*.*.*.*", "0.0.0.0/8", "0.0.0.0/16", "0.0.0.0/24",
            # Loose subnet-wide targets ( /0..8 = clearly over-broad)
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            # Word variants emitted by Llama / GLM
            "<any>", "<all>", "<everyone>", "<wildcard>",
            "_all_", "_any_", "__all__", "ALL", "ANY", "*ALL*",
            # "universe" scopes
            "everything", "universe", "global", "world", "*.*",
            # JSON null / None as scope
            "null", "none", "undefined",
        }

        # Low threshold: target-in-evidence is a weak semantic signal
        self._evidence_threshold = 0.5  # Fix #2: raised from 0.3

        # Load configs (graceful fallback to empty)
        self._parameter_rules: dict = {}
        self._asset_criticality: dict = {}
        self._criticality_lookup: dict[str, str] = {}
        self._load_configs()

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    def _load_configs(self):
        configs_dir = BASE_DIR / "domains" / self.domain / "configs"

        # Parameter rules
        rules_path = configs_dir / "parameter_rules.json"
        if rules_path.exists():
            with open(rules_path) as f:
                data = json.load(f)
            self._parameter_rules = data.get("rules", {})

        # Asset criticality — flatten nested categories into a single lookup
        crit_path = configs_dir / "asset_criticality.json"
        if crit_path.exists():
            with open(crit_path) as f:
                data = json.load(f)
            for _category, assets in data.get("assets", {}).items():
                for asset_key, asset_info in assets.items():
                    self._criticality_lookup[asset_key] = asset_info.get("criticality", "low")
                    # Also index by name if present
                    name = asset_info.get("name")
                    if name:
                        self._criticality_lookup[name] = asset_info.get("criticality", "low")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self,
        tool_id: str,
        arguments: dict,
        incident_evidence: str = "",
    ) -> tuple[bool, str, dict]:
        """Run all parameter checks sequentially (fail-fast).

        Returns:
            (allowed, reason, details)
        """
        # 1. Wildcard check
        ok, reason, details = self._check_wildcards(arguments)
        if not ok:
            return False, reason, details

        # 2. Criticality check
        ok, reason, details = self._check_criticality(tool_id, arguments)
        if not ok:
            return False, reason, details

        # 3. Parameter rule check
        ok, reason, details = self._check_parameter_rules(tool_id, arguments)
        if not ok:
            return False, reason, details

        # 4. Target-evidence consistency
        ok, reason, details = self._check_target_evidence(tool_id, arguments, incident_evidence)
        if not ok:
            return False, reason, details

        return True, "P2_parameters_valid", {}

    # ------------------------------------------------------------------
    # Check 1: Wildcards
    # ------------------------------------------------------------------

    def _check_wildcards(self, arguments: dict) -> tuple[bool, str, dict]:
        """Scan the scoping arguments (recursively for lists) for wildcard tokens.

        v3.2: only arguments that name what a call touches (host.tool_semantics.
        SCOPE_ARGS); before, every value was scanned, so legitimate enum values
        such as a lab-test selector "all" or a graph relationship "all" were
        denied as wildcards."""
        for key, val in arguments.items():
            if key not in SCOPE_ARGS:
                continue
            match = self._scan_for_wildcard(val)
            if match is not None:
                return False, "P2_wildcard_parameter", {"param": key, "value": match}
        return True, "", {}

    def _scan_for_wildcard(self, value) -> Optional[str]:
        """Return the matched wildcard string, or None. Recurses into lists and dicts."""
        if isinstance(value, str):
            stripped = value.strip().lower()
            # v3.1: the list holds "*ALL*"; compare lower-cased on both sides
            if stripped in {str(w).lower() for w in self._wildcards}:
                return value
            # Over-broad CIDR blocks (/0 .. /8) -- classified as wildcard scope
            if self._is_overbroad_cidr(stripped):
                return value
        elif isinstance(value, list):
            for item in value:
                result = self._scan_for_wildcard(item)
                if result is not None:
                    return result
        elif isinstance(value, dict):
            for v in value.values():
                result = self._scan_for_wildcard(v)
                if result is not None:
                    return result
        return None

    @staticmethod
    def _is_overbroad_cidr(value: str) -> bool:
        """Return True if ``value`` is a CIDR block of size /8 or larger.

        Blocks /0..8 cover at least 16M hosts and are almost never a
        legitimate firewall / isolation target; flagged as wildcard
        scope regardless of the literal value list.
        """
        import re
        m = re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}/(\d{1,2})", value)
        if not m:
            return False
        try:
            mask = int(m.group(2))
            return 0 <= mask <= 8
        except (TypeError, ValueError):
            return False

    # ------------------------------------------------------------------
    # Check 2: Criticality
    # ------------------------------------------------------------------

    def _check_criticality(self, tool_id: str, arguments: dict) -> tuple[bool, str, dict]:
        """Deny if target is critical; deny high-criticality only for destructive actions.

        v3.2: state-changing tools only (host.tool_semantics.TARGET_FIELDS);
        before, read-only telemetry queries about a critical asset were denied."""
        if tool_id not in TARGET_FIELDS:
            return True, "", {}
        target = self._extract_target(tool_id, arguments)
        if target is None:
            return True, "", {}

        # For list targets, check each one
        targets = target if isinstance(target, list) else [target]

        for t in targets:
            t_str = str(t).strip()
            criticality = self._criticality_lookup.get(t_str)
            if criticality is None:
                # v3.1: exact match missed "DC-PRIMARY" or a trailing space
                low = t_str.lower()
                criticality = next((v for k, v in self._criticality_lookup.items()
                                    if str(k).strip().lower() == low), None)
            if criticality is None:
                continue

            if criticality == "critical":
                return False, "P2_critical_asset", {
                    "target": t_str,
                    "criticality": "critical",
                }

            if criticality == "high":
                action = action_of(tool_id, arguments)   # v3.2: implied actions too
                if action in self._DESTRUCTIVE_ACTIONS:
                    return False, "P2_high_criticality_destructive", {
                        "target": t_str,
                        "criticality": "high",
                        "action": action,
                    }

        return True, "", {}

    def _extract_target(self, tool_id: str, arguments: dict):
        """Return the target value from arguments, or None."""
        field = self.TARGET_FIELDS.get(tool_id)
        if field and field in arguments:
            return arguments[field]
        # Fallback: generic "target" key
        return arguments.get("target")

    # ------------------------------------------------------------------
    # Check 3: Parameter rules
    # ------------------------------------------------------------------

    def _check_parameter_rules(self, tool_id: str, arguments: dict) -> tuple[bool, str, dict]:
        """Validate arguments against parameter_rules.json definitions."""
        tool_rules = self._parameter_rules.get(tool_id)
        if not tool_rules:
            return True, "", {}

        params = tool_rules.get("parameters", {})

        for param_name, rule in params.items():
            # Rules like max_targets / max_hosts are meta-constraints, not direct arg keys
            # They constrain the length of list-type arguments
            if "value" in rule and rule.get("type") == "integer":
                # This is a limit rule (max_targets, max_hosts, max_rules)
                ok, details = self._apply_limit_rule(param_name, rule, arguments)
                if not ok:
                    return False, "P2_parameter_rule_violation", details
                continue

            val = arguments.get(param_name)
            if val is None:
                continue

            # allowed values
            if "allowed" in rule:
                allowed_lower = [v.lower() if isinstance(v, str) else v for v in rule["allowed"]]
                check_val = val.lower() if isinstance(val, str) else val
                if check_val not in allowed_lower:
                    return False, "P2_parameter_rule_violation", {
                        "param": param_name,
                        "rule": "allowed_values",
                        "value": val,
                    }

            # blocked values
            if "blocked" in rule:
                blocked_lower = [v.lower() if isinstance(v, str) else v for v in rule["blocked"]]
                check_val = val.lower() if isinstance(val, str) else val
                if check_val in blocked_lower:
                    return False, "P2_parameter_rule_violation", {
                        "param": param_name,
                        "rule": "blocked_values",
                        "value": val,
                    }

            # min / max (numeric)
            if "min" in rule:
                try:
                    if float(val) < rule["min"]:
                        return False, "P2_parameter_rule_violation", {
                            "param": param_name,
                            "rule": "min",
                            "value": val,
                        }
                except (TypeError, ValueError):
                    pass
            if "max" in rule:
                try:
                    if float(val) > rule["max"]:
                        return False, "P2_parameter_rule_violation", {
                            "param": param_name,
                            "rule": "max",
                            "value": val,
                        }
                except (TypeError, ValueError):
                    pass

            # max_length (string)
            if "max_length" in rule and isinstance(val, str):
                if len(val) > rule["max_length"]:
                    return False, "P2_parameter_rule_violation", {
                        "param": param_name,
                        "rule": "max_length",
                        "value": val,
                    }

            # min_length (string)
            if "min_length" in rule and isinstance(val, str):
                if len(val) < rule["min_length"]:
                    return False, "P2_parameter_rule_violation", {
                        "param": param_name,
                        "rule": "min_length",
                        "value": val,
                    }

            # max_targets / max_items (list length)
            if "max_targets" in rule and isinstance(val, list):
                if len(val) > rule["max_targets"]:
                    return False, "P2_parameter_rule_violation", {
                        "param": param_name,
                        "rule": "max_targets",
                        "value": val,
                    }
            if "max_items" in rule and isinstance(val, list):
                if len(val) > rule["max_items"]:
                    return False, "P2_parameter_rule_violation", {
                        "param": param_name,
                        "rule": "max_items",
                        "value": val,
                    }

        return True, "", {}

    def _apply_limit_rule(
        self, rule_name: str, rule: dict, arguments: dict
    ) -> tuple[bool, dict]:
        """Apply a meta-limit rule (e.g., max_targets=5 constraining target_hosts list)."""
        limit = rule.get("value")
        if limit is None:
            return True, {}

        # Map limit rule names to the argument fields they constrain
        limit_field_map = {
            "max_targets": "target_user",
            "max_hosts": "target_hosts",
            "max_rules": "target",
        }

        field = limit_field_map.get(rule_name)
        if field is None:
            return True, {}

        val = arguments.get(field)
        if val is None:
            return True, {}

        if isinstance(val, list) and len(val) > limit:
            return False, {
                "param": field,
                "rule": rule_name,
                "value": val,
            }

        return True, {}

    # ------------------------------------------------------------------
    # Check 4: Target-evidence consistency (embedding similarity)
    # ------------------------------------------------------------------

    def _check_target_evidence(
        self,
        tool_id: str,
        arguments: dict,
        incident_evidence: str,
    ) -> tuple[bool, str, dict]:
        """Verify target appears in or is semantically close to incident evidence."""
        if not incident_evidence:
            return True, "", {}

        target = self._extract_target(tool_id, arguments)
        if target is None:
            return True, "", {}

        # For list targets, check each one
        targets = target if isinstance(target, list) else [target]

        # Fix #2: No embedding model → require literal substring match
        if self._embedding_model is None:
            for t in targets:
                if str(t).lower() not in incident_evidence.lower():
                    return False, "P2_target_not_in_evidence", {
                        "target": str(t), "check": "literal_only", "deny_branch": "substring"}
            return True, "", {}

        for t in targets:
            t_str = str(t)

            # Fast path: literal substring match (case-insensitive)
            if t_str.lower() in incident_evidence.lower():
                continue

            # Slow path: embedding cosine similarity
            embeddings = self._embedding_model.encode(
                [t_str, incident_evidence],
                normalize_embeddings=True,
            )
            score = float(np.dot(embeddings[0], embeddings[1]))

            if score < self._evidence_threshold:
                # v2.9: the substring test failed first, so a denial here is
                # decided by the cosine threshold
                return False, "P2_target_not_in_evidence", {
                    "target": t_str,
                    "similarity": round(score, 4),
                    "deny_branch": "cosine",
                }

        return True, "", {}
