"""
Role-based manifest enforcer for the TAMAS benchmark.

The TAMAS benchmark models multi-agent systems in which each agent plays
a *role* (e.g. ``DiagnosisAgent``, ``PrescriptionAgent``) rather than
occupying one of the fixed NIST-IR phases used by the main
DEFER SOAR pipeline.  The existing :class:`host.manifest_enforcer.ManifestEnforcer`
loads phase manifests from ``domains/{domain}/configs/{phase}_manifest.json``;
for TAMAS we want the same enforcement semantics but against role
manifests that are supplied at runtime (e.g. from a scenario JSON file).

``DynamicManifestEnforcer`` provides that runtime-configurable version
while keeping the public signature compatible with ``ManifestEnforcer``
so that the middleware can swap between the two without branching.
"""

from typing import Optional

from logging_utils import ExperimentLogger


class DynamicManifestEnforcer:
    """Like :class:`ManifestEnforcer` but operates on role manifests loaded at runtime.

    TAMAS agents have ROLES (``DiagnosisAgent``, ``PrescriptionAgent``)
    instead of PHASES.  This wrapper accepts a ``role_manifests`` dict
    directly rather than loading from disk.

    The expected manifest format matches the on-disk phase manifests::

        {
            "role_name": {
                "allowed_tools": [...],
                "allowed_memory_read": [...],
                "allowed_memory_write": [...],
                "max_actions_per_incident": 50,
                "requires_consensus": False,
                "escalation_triggers": {
                    "bulk_action_threshold": 10,
                    "critical_tools": [...],
                },
            },
            ...
        }
    """

    def __init__(
        self,
        role_manifests: dict,
        logger: Optional[ExperimentLogger] = None,
    ):
        """
        Args:
            role_manifests: Mapping of ``{role_name: manifest_dict}``.
            logger: Optional :class:`ExperimentLogger` for structured logs.
        """
        self.role_manifests: dict = role_manifests or {}
        self.logger = logger
        self._action_counts: dict[str, int] = {}

    # ------------------------------------------------------------------ #
    #  Manifest access
    # ------------------------------------------------------------------ #

    def get_manifest(self, role: str) -> dict:
        """Return the manifest dict for *role*, or an empty dict."""
        return self.role_manifests.get(role, {})

    # ------------------------------------------------------------------ #
    #  Tool call / memory validation
    # ------------------------------------------------------------------ #

    def validate_tool_call(self, role: str, tool_id: str) -> tuple[bool, str]:
        """Check if *role* is permitted to invoke *tool_id*.

        Returns ``(allowed, reason)`` where ``reason`` is a short
        human-readable explanation on deny or ``"allowed"`` on success.
        """
        manifest = self.role_manifests.get(role)
        if manifest is None:
            return False, f"Unknown role: {role}"

        allowed = manifest.get("allowed_tools", [])
        if tool_id not in allowed:
            return False, f"Role '{role}' cannot call '{tool_id}'"

        # Enforce per-task action ceiling if configured
        max_actions = manifest.get("max_actions_per_incident")
        if max_actions is not None:
            count = self._action_counts.get(role, 0)
            if count >= max_actions:
                return False, (
                    f"Role '{role}' exceeded max actions ({max_actions})"
                )

        return True, "allowed"

    def validate_memory_write(self, role: str, store_id: str) -> tuple[bool, str]:
        """Check if *role* is allowed to write to memory *store_id*."""
        manifest = self.role_manifests.get(role)
        if manifest is None:
            return False, f"Unknown role: {role}"
        if store_id not in manifest.get("allowed_memory_write", []):
            return False, f"Role '{role}' cannot write to '{store_id}'"
        return True, "allowed"

    def validate_memory_read(self, role: str, store_id: str) -> tuple[bool, str]:
        """Check if *role* is allowed to read from memory *store_id*."""
        manifest = self.role_manifests.get(role)
        if manifest is None:
            return False, f"Unknown role: {role}"
        if store_id not in manifest.get("allowed_memory_read", []):
            return False, f"Role '{role}' cannot read from '{store_id}'"
        return True, "allowed"

    # ------------------------------------------------------------------ #
    #  Consensus / escalation decisions
    # ------------------------------------------------------------------ #

    def requires_consensus(self, role: str, tool_id: Optional[str] = None) -> bool:
        """Return True if actions by *role* (or specifically *tool_id*) require P3 consensus."""
        manifest = self.role_manifests.get(role, {})
        if manifest.get("requires_consensus", False):
            return True
        if tool_id is None:
            return False
        critical = manifest.get("escalation_triggers", {}).get("critical_tools", [])
        return tool_id in critical

    def check_bulk_action(self, role: str, action_count: int) -> bool:
        """Return True if *action_count* crosses the bulk-action threshold."""
        manifest = self.role_manifests.get(role, {})
        threshold = manifest.get("escalation_triggers", {}).get(
            "bulk_action_threshold", 10
        )
        return action_count >= threshold

    # ------------------------------------------------------------------ #
    #  Counters
    # ------------------------------------------------------------------ #

    def record_action(self, role: str) -> None:
        """Increment the per-role action counter."""
        self._action_counts[role] = self._action_counts.get(role, 0) + 1

    def reset_counts(self) -> None:
        """Reset all per-role action counters (call between tasks)."""
        self._action_counts.clear()
