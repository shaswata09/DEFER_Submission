"""
P3-L0.5: Operational Context Checker.
Change management, incident lifecycle, maintenance windows, time policies.
100% symbolic — zero LLM.
Covers: TA-10
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from config import BASE_DIR
from logging_utils import ExperimentLogger

REVERSAL_PAIRS = {
    ("T9_firewall", "block_ip"): ("T9_firewall", "unblock_ip"),
    ("T9_firewall", "unblock_ip"): ("T9_firewall", "block_ip"),
    ("T8_iam_pam", "revoke"): ("T8_iam_pam", "unlock"),
    ("T8_iam_pam", "unlock"): ("T8_iam_pam", "revoke"),
    ("F8_account_freeze", "freeze"): ("F8_account_freeze", "unfreeze"),
    ("F8_account_freeze", "unfreeze"): ("F8_account_freeze", "freeze"),
    # v3.1: the healthcare and legal reversals AP-11 v1 seeds
    ("H8_prescription_writer", "prescribe"): ("H8_prescription_writer", "discontinue"),
    ("H8_prescription_writer", "discontinue"): ("H8_prescription_writer", "prescribe"),
    ("L8_court_filing", "file"): ("L8_court_filing", "withdraw"),
    ("L8_court_filing", "withdraw"): ("L8_court_filing", "file"),
}


def tool_for_action(action: str) -> str:
    """The tool a change-log action belongs to (payloads name only the action)."""
    return next((t for t, a in REVERSAL_PAIRS if a == action), "")


class OperationalContextChecker:
    """Checks operational context: change conflicts, lifecycle, maintenance, time policies."""

    def __init__(self, domain: str, logger: Optional[ExperimentLogger] = None):
        self.domain = domain
        self.logger = logger

        self._change_log: list[dict] = []
        self._maintenance_windows: list[dict] = []
        self._time_policies: dict = {}
        self._incident_registry: dict = {}

        self._load_configs()

    def reset(self):
        """Drop payload-seeded changes, windows and incident statuses and
        reload the configured baseline (per-trial isolation, H3)."""
        self._change_log = []
        self._maintenance_windows = []
        self._time_policies = {}
        self._incident_registry = {}
        self._load_configs()

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    def _load_configs(self):
        configs_dir = BASE_DIR / "domains" / self.domain / "configs"

        # Change log
        change_path = configs_dir / "change_log.json"
        if change_path.exists():
            with open(change_path) as f:
                data = json.load(f)
            self._change_log = data if isinstance(data, list) else data.get("changes", [])

        # Maintenance windows
        maint_path = configs_dir / "maintenance_windows.json"
        if maint_path.exists():
            with open(maint_path) as f:
                data = json.load(f)
            self._maintenance_windows = (
                data if isinstance(data, list) else data.get("windows", [])
            )

        # Time policies
        time_path = configs_dir / "time_policies.json"
        if time_path.exists():
            with open(time_path) as f:
                data = json.load(f)
            self._time_policies = data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self, proposal: dict, context: dict
    ) -> tuple[bool, str, dict]:
        """Run all operational context checks sequentially (fail-fast).

        Returns:
            (ok, reason, details)
        """
        # 1. Change conflict (honours payload's claimed_time when provided)
        ok, reason, details = self._check_change_conflict(proposal, context)
        if not ok:
            self._log_check("P3_change_conflict", "escalate", details)
            return False, reason, details

        # 2. Incident lifecycle
        ok, reason, details = self._check_incident_lifecycle(context)
        if not ok:
            self._log_check("P3_incident_lifecycle", "deny", details)
            return False, reason, details

        # 3. Maintenance window (honours payload's claimed_time when provided)
        ok, reason, details = self._check_maintenance_window(proposal, context)
        if not ok:
            self._log_check("P3_maintenance_window", "escalate", details)
            return False, reason, details

        # 4. Time policy (honours payload's claimed_time when provided)
        ok, reason, details = self._check_time_policy(proposal, context)
        if not ok:
            self._log_check("P3_time_policy", "escalate", details)
            return False, reason, details

        self._log_check("P3_operational_context_ok", "allow", {})
        return True, "P3_operational_context_ok", {}

    def register_incident_status(self, incident_id: str, status: str):
        """Update incident lifecycle status."""
        self._incident_registry[incident_id] = status

    def record_change(
        self,
        tool_id: str,
        action: str,
        target: str,
        incident_id: str,
        timestamp: Optional[str] = None,
    ):
        """Record a completed change for conflict detection.

        Args:
            timestamp: ISO-8601 string. If None, uses current wall-clock time.
                Orchestrator should pass the payload's declared approval
                timestamp (e.g. ``recent_change.approved_at``) so the
                72-hour cutoff reflects the scenario's claimed timeline.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        self._change_log.append({
            "tool_id": tool_id,
            "action": action,
            "target": target,
            "incident_id": incident_id,
            "timestamp": ts,
        })

    def add_maintenance_window(
        self,
        asset: str,
        start_time: str,
        end_time: str,
        window_id: str = "payload_seeded",
        **kwargs,
    ):
        """Seed a maintenance window from an incident payload.

        Enables the P3-L0.5 maintenance-window check to fire against
        scenarios whose declared window is not in the persistent
        ``maintenance_windows.json`` config.
        """
        self._maintenance_windows.append({
            "id": window_id,
            "affected_assets": [asset],
            "start": start_time,
            "end": end_time,
            "source": "payload",
        })

    # ------------------------------------------------------------------
    # Check 1: Change conflict (reversal within 72h)
    # ------------------------------------------------------------------

    def _check_change_conflict(
        self, proposal: dict, context: Optional[dict] = None
    ) -> tuple[bool, str, dict]:
        """Detect contradictory changes on the same target within 72 hours.

        Uses ``context['claimed_time']`` (ISO-8601) as the "now" anchor
        when provided, so the 72-hour cutoff reflects the incident's
        declared timeline rather than wall-clock drift.
        """
        tool_id = proposal.get("tool_id", "")
        action = proposal.get("action", "")
        target = proposal.get("target", "")

        reversal = REVERSAL_PAIRS.get((tool_id, action))
        if reversal is None:
            return True, "", {}

        rev_tool, rev_action = reversal

        now = None
        if context:
            claimed = context.get("claimed_time")
            if claimed:
                try:
                    now = datetime.fromisoformat(claimed.replace("Z", "+00:00"))
                    if now.tzinfo is None:
                        now = now.replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    now = None
        if now is None:
            now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=72)

        for entry in self._change_log:
            if entry.get("tool_id") != rev_tool:
                continue
            if entry.get("action") != rev_action:
                continue
            if entry.get("target") != target:
                continue

            # Check timestamp
            ts_str = entry.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    return False, "P3_change_conflict", {
                        "proposed": f"{tool_id}.{action}",
                        "conflicting": f"{rev_tool}.{rev_action}",
                        "target": target,
                        "prior_timestamp": ts_str,
                    }
            except (ValueError, TypeError):
                # If timestamp is unparseable, treat as recent (conservative)
                return False, "P3_change_conflict", {
                    "proposed": f"{tool_id}.{action}",
                    "conflicting": f"{rev_tool}.{rev_action}",
                    "target": target,
                    "prior_timestamp": ts_str,
                }

        return True, "", {}

    # ------------------------------------------------------------------
    # Check 2: Incident lifecycle
    # ------------------------------------------------------------------

    def _check_incident_lifecycle(self, context: dict) -> tuple[bool, str, dict]:
        """Reject actions on resolved or closed incidents."""
        incident_id = context.get("incident_id", "")
        if not incident_id:
            return True, "", {}

        status = self._incident_registry.get(incident_id, "")
        if status in ("resolved", "closed"):
            return False, "P3_incident_closed", {
                "incident_id": incident_id,
                "status": status,
            }

        return True, "", {}

    # ------------------------------------------------------------------
    # Check 3: Maintenance window
    # ------------------------------------------------------------------

    def _check_maintenance_window(
        self, proposal: dict, context: Optional[dict] = None
    ) -> tuple[bool, str, dict]:
        """Escalate if target asset is in an active maintenance window.

        Uses ``context['claimed_time']`` (ISO-8601) when present so the
        window comparison honours the incident's declared execution time.
        Falls back to wall-clock UTC otherwise.
        """
        target = proposal.get("target", "")
        if not target:
            return True, "", {}

        # Prefer the incident's claimed execution time when provided.
        now = None
        if context:
            claimed = context.get("claimed_time")
            if claimed:
                try:
                    now = datetime.fromisoformat(claimed.replace("Z", "+00:00"))
                    if now.tzinfo is None:
                        now = now.replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    now = None
        if now is None:
            now = datetime.now(timezone.utc)

        for window in self._maintenance_windows:
            assets = window.get("affected_assets", window.get("assets", []))
            if target not in assets:
                continue

            try:
                start = datetime.fromisoformat(window.get("start", "").replace("Z", "+00:00"))
                end = datetime.fromisoformat(window.get("end", "").replace("Z", "+00:00"))
                if start.tzinfo is None:
                    start = start.replace(tzinfo=timezone.utc)
                if end.tzinfo is None:
                    end = end.replace(tzinfo=timezone.utc)
                if start <= now <= end:
                    return False, "P3_maintenance_window", {
                        "target": target,
                        "window_start": window.get("start"),
                        "window_end": window.get("end"),
                        "window_id": window.get("id", "unknown"),
                    }
            except (ValueError, TypeError):
                continue

        return True, "", {}

    # ------------------------------------------------------------------
    # Check 4: Time policy
    # ------------------------------------------------------------------

    def _check_time_policy(
        self, proposal: dict, context: Optional[dict] = None
    ) -> tuple[bool, str, dict]:
        """Escalate if effective hour is outside allowed window for tool+action.

        Uses ``context['claimed_time']`` (ISO-8601) when present so the check
        honours the incident's declared execution time (e.g., an attacker
        action proposed at 03:00 while the trial actually runs at 14:00).
        Falls back to wall-clock UTC if no claimed_time is provided.
        """
        tool_id = proposal.get("tool_id", "")
        action = proposal.get("action", "")

        # Look up policy by tool_id, then drill into action-specific sub-dict
        tool_policy = self._time_policies.get(tool_id)
        if tool_policy is None:
            tool_policy = self._time_policies.get(f"{tool_id}.{action}")
        if tool_policy is None:
            return True, "", {}

        # Support nested structure: {tool_id: {action: {allowed_start, allowed_end}}}
        if action and isinstance(tool_policy.get(action), dict):
            policy = tool_policy[action]
        else:
            policy = tool_policy

        allowed_start = policy.get("allowed_start", policy.get("allowed_start_hour", 0))
        allowed_end = policy.get("allowed_end", policy.get("allowed_end_hour", 24))

        # Prefer the incident's claimed execution time if declared.
        effective_hour = None
        source = "wall_clock"
        if context:
            claimed = context.get("claimed_time")
            if claimed:
                try:
                    dt = datetime.fromisoformat(claimed.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    effective_hour = dt.astimezone(timezone.utc).hour
                    source = "claimed_time"
                except (ValueError, TypeError):
                    effective_hour = None
        if effective_hour is None:
            effective_hour = datetime.now(timezone.utc).hour

        if not (allowed_start <= effective_hour < allowed_end):
            return False, "P3_time_policy", {
                "tool_id": tool_id,
                "action": action,
                "effective_hour_utc": effective_hour,
                "hour_source": source,
                "allowed_start_hour": allowed_start,
                "allowed_end_hour": allowed_end,
            }

        return True, "", {}

    # ------------------------------------------------------------------
    # Logging helper
    # ------------------------------------------------------------------

    def _log_check(self, mechanism: str, decision: str, details: dict):
        if self.logger:
            self.logger.log(
                source="operational_context",
                destination="host",
                action="P3_L05_check",
                auth_decision=decision,
                mechanism=mechanism,
                extra=details if details else None,
            )
