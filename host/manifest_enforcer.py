"""
P2: Capability Scoping via Phase Manifests.

Validates every tool call and memory access against the calling agent's
manifest. Domain-agnostic — reads manifests from domains/{domain}/configs/.
"""

import json
from pathlib import Path
from typing import Optional

from config import BASE_DIR
from logging_utils import ExperimentLogger


class ManifestEnforcer:
    """Enforces phase-scoped capability restrictions."""

    def __init__(self, domain: str, logger: Optional[ExperimentLogger] = None):
        self.domain = domain
        self.logger = logger
        self._manifests: dict[str, dict] = {}
        self._action_counts: dict[str, int] = {}
        self._load_manifests()

    def _load_manifests(self):
        configs_dir = BASE_DIR / "domains" / self.domain / "configs"
        for phase in ("monitor", "analyze", "admin", "report"):
            path = configs_dir / f"{phase}_manifest.json"
            if path.exists():
                with open(path) as f:
                    self._manifests[phase] = json.load(f)
            else:
                self._manifests[phase] = {
                    "phase": phase,
                    "allowed_tools": [],
                    "allowed_memory_read": [],
                    "allowed_memory_write": [],
                    "max_actions_per_incident": 50,
                    "requires_consensus": False,
                    "escalation_triggers": {
                        "bulk_action_threshold": 10,
                        "critical_tools": [],
                    },
                }

    def get_manifest(self, phase: str) -> dict:
        return self._manifests.get(phase, {})

    def validate_tool_call(self, agent_phase: str, tool_id: str) -> tuple[bool, str]:
        """Check if agent_phase is allowed to call tool_id.

        Returns (allowed, reason).
        """
        manifest = self._manifests.get(agent_phase)
        if not manifest:
            return False, f"Unknown phase: {agent_phase}"

        if tool_id not in manifest.get("allowed_tools", []):
            return False, f"Tool {tool_id} not in {agent_phase} manifest"

        # Check action count
        count = self._action_counts.get(agent_phase, 0)
        max_actions = manifest.get("max_actions_per_incident", 50)
        if count >= max_actions:
            return False, f"Phase {agent_phase} exceeded max actions ({max_actions})"

        return True, "allowed"

    @staticmethod
    def _store_allowed(store_id: str, allowed: list) -> bool:
        """Manifests list short store ids (``M2``); agents and payloads emit
        either form (``M2`` or ``M2_case_context``).  Compare on the short
        id, as the MMA's AccessController does."""
        short = str(store_id).split("_", 1)[0]
        return any(str(a).split("_", 1)[0] == short for a in allowed)

    def validate_memory_read(self, agent_phase: str, store_id: str) -> tuple[bool, str]:
        manifest = self._manifests.get(agent_phase)
        if not manifest:
            return False, f"Unknown phase: {agent_phase}"
        if not self._store_allowed(store_id, manifest.get("allowed_memory_read", [])):
            return False, f"Store {store_id} not readable by {agent_phase}"
        return True, "allowed"

    def validate_memory_write(self, agent_phase: str, store_id: str) -> tuple[bool, str]:
        manifest = self._manifests.get(agent_phase)
        if not manifest:
            return False, f"Unknown phase: {agent_phase}"
        if not self._store_allowed(store_id, manifest.get("allowed_memory_write", [])):
            return False, f"Store {store_id} not writable by {agent_phase}"
        return True, "allowed"

    def requires_consensus(self, agent_phase: str, tool_id: Optional[str] = None) -> bool:
        manifest = self._manifests.get(agent_phase, {})
        if manifest.get("requires_consensus", False):
            return True
        if tool_id:
            triggers = manifest.get("escalation_triggers", {})
            if tool_id in triggers.get("critical_tools", []):
                return True
        return False

    def check_bulk_action(self, agent_phase: str, action_count: int) -> bool:
        """Returns True if action_count exceeds threshold (triggers escalation)."""
        manifest = self._manifests.get(agent_phase, {})
        threshold = manifest.get("escalation_triggers", {}).get("bulk_action_threshold", 10)
        return action_count >= threshold

    def record_action(self, agent_phase: str):
        """Increment action counter for a phase."""
        self._action_counts[agent_phase] = self._action_counts.get(agent_phase, 0) + 1

    def reset_counts(self):
        """Reset action counts between incidents."""
        self._action_counts.clear()
