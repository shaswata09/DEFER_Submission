"""
P3-L4: Cross-Incident Ledger.
Persistent accumulation detection across incidents.
Tracks same-target, same-action frequency, and total destructive actions.
Thread/async-safe via asyncio.Lock (TA-22 fix).
100% symbolic — zero LLM.
Covers: TA-7, TA-22
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional

from host.tool_semantics import TARGET_FIELDS, action_of
from logging_utils import ExperimentLogger


class CrossIncidentLedger:
    """Detects cross-incident accumulation of destructive actions."""

    # v3.2: the shared map (host.tool_semantics)
    TARGET_FIELDS = TARGET_FIELDS

    DESTRUCTIVE_ACTIONS = frozenset({
        "revoke", "delete_rule", "quarantine", "isolate_host",
        "freeze", "file", "suspend", "delete",
    })

    def __init__(
        self,
        window_hours: int = 24,
        same_target_threshold: int = 3,
        same_action_threshold: int = 10,
        destructive_threshold: int = 8,
        logger: Optional[ExperimentLogger] = None,
    ):
        self.logger = logger
        self._ledger: list[dict] = []
        self._window = timedelta(hours=window_hours)
        self._same_target_threshold = same_target_threshold
        self._same_action_threshold = same_action_threshold
        self._destructive_threshold = destructive_threshold
        self._lock = asyncio.Lock()  # TA-22: concurrency control

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, proposal: dict, context: dict) -> tuple[bool, str, dict]:
        """Check proposal against cross-incident accumulation rules.

        Returns (ok, reason, details).
        """
        now = datetime.now(timezone.utc)
        recent = [e for e in self._ledger if now - e["timestamp"] <= self._window]

        tool_id = proposal.get("tool_id", "")
        # v3.2: the hoisted or implied action (F8 "freeze", L8 "file" were empty)
        action = action_of(proposal.get("tool_id", ""), proposal.get("arguments") or {}, proposal)
        target = self._extract_target(proposal)
        incident_id = context.get("incident_id", "")

        # --- Same target across incidents --------------------------------
        if target:
            cross_entries = [
                e for e in recent
                if e["target"] == target and e["incident_id"] != incident_id
            ]
            if len(cross_entries) >= self._same_target_threshold:
                incident_ids = list({e["incident_id"] for e in cross_entries})
                details = {
                    "target": target,
                    "count": len(cross_entries),
                    "incident_count": len(incident_ids),
                    "incident_ids": incident_ids,
                }
                if self.logger:
                    self.logger.log(
                        source="cross_incident_ledger",
                        destination="host",
                        action="P3_L4_check",
                        auth_decision="escalate",
                        mechanism="P3_same_target_accumulation",
                        extra=details,
                    )
                return False, "P3_same_target_accumulation", details

        # --- Same action frequency ---------------------------------------
        combo_entries = [
            e for e in recent
            if e["tool_id"] == tool_id and e["action"] == action
        ]
        if len(combo_entries) >= self._same_action_threshold:
            details = {
                "tool_id": tool_id,
                # v2.9: not "action", which the logger's own ``action`` field
                # would be overwritten by, hiding the P3_L4_check event
                "proposal_action": action,
                "count": len(combo_entries),
            }
            if self.logger:
                self.logger.log(
                    source="cross_incident_ledger",
                    destination="host",
                    action="P3_L4_check",
                    auth_decision="escalate",
                    mechanism="P3_same_action_accumulation",
                    extra=details,
                )
            return False, "P3_same_action_accumulation", details

        # --- Total destructive actions -----------------------------------
        destructive_entries = [
            e for e in recent if e["action"] in self.DESTRUCTIVE_ACTIONS
        ]
        if len(destructive_entries) >= self._destructive_threshold:
            details = {
                "destructive_count": len(destructive_entries),
                "threshold": self._destructive_threshold,
            }
            if self.logger:
                self.logger.log(
                    source="cross_incident_ledger",
                    destination="host",
                    action="P3_L4_check",
                    auth_decision="escalate",
                    mechanism="P3_destructive_accumulation",
                    extra=details,
                )
            return False, "P3_destructive_accumulation", details

        # --- All checks passed -------------------------------------------
        if self.logger:
            self.logger.log(
                source="cross_incident_ledger",
                destination="host",
                action="P3_L4_check",
                auth_decision="allow",
                mechanism="P3_cross_incident_ok",
            )
        return True, "P3_cross_incident_ok", {}

    def record(self, proposal: dict, context: dict):
        """Append an entry to the ledger."""
        self._ledger.append({
            "incident_id": context.get("incident_id", ""),
            "tool_id": proposal.get("tool_id", ""),
            "action": action_of(proposal.get("tool_id", ""), proposal.get("arguments") or {}, proposal),
            "target": self._extract_target(proposal),
            "timestamp": datetime.now(timezone.utc),
        })

    async def check_and_record(self, proposal: dict, context: dict) -> tuple[bool, str, dict]:
        """Atomic check + record to prevent TOCTOU race (TA-22 fix).

        Acquires lock before checking, records if approved, then releases.
        Use this instead of separate check() + record() calls.
        """
        async with self._lock:
            ok, reason, details = self.check(proposal, context)
            if ok:
                self.record(proposal, context)
            return ok, reason, details

    def reset(self):
        """Forget every recorded action (per-trial isolation, H3)."""
        self._ledger = []

    def prune(self):
        """Remove entries older than the window."""
        now = datetime.now(timezone.utc)
        self._ledger = [e for e in self._ledger if now - e["timestamp"] <= self._window]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_target(self, proposal: dict):
        """Extract the target value from proposal arguments."""
        tool_id = proposal.get("tool_id", "")
        arguments = proposal.get("arguments", {})
        field = self.TARGET_FIELDS.get(tool_id)
        if field and field in arguments:
            return arguments[field]
        # Fallback: generic "target" key
        return arguments.get("target")
