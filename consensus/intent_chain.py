"""
P3-L3: Intent Chain Tracker.
Cumulative posture tracking, dangerous pattern detection, velocity limiting.
Provides chain state buckets for adaptive consent (L0.7).
100% symbolic — zero LLM.
Covers: TA-6
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from config import BASE_DIR
from logging_utils import ExperimentLogger


class IntentChainTracker:
    """Tracks cumulative action posture, dangerous patterns, and velocity."""

    # Action classification sets
    _STEALTH_ACTIONS = frozenset({
        "disable_logging", "clear_logs", "modify_audit",
        "suppress_alerts", "delete_logs", "bypass_monitoring",
    })

    _ESCALATION_ACTIONS = frozenset({
        "elevate_privileges", "grant_admin", "create_admin",
        "unlock", "enable_remote", "add_sudo",
    })

    _DESTRUCTIVE_ACTIONS = frozenset({
        "delete", "wipe", "destroy", "format", "purge",
        "drop_table", "shutdown", "terminate", "remove_all",
    })

    def __init__(self, domain: str, logger: Optional[ExperimentLogger] = None):
        self.domain = domain
        self.logger = logger

        self.posture: float = 0.0
        self.history: list[dict] = []

        # Defaults (overridden by config)
        self._posture_threshold: float = -5.0
        self._velocity_limit: int = 10
        self._velocity_window_minutes: int = 5
        self._dangerous_patterns: list[list[str]] = []
        self._action_impacts: dict = {}

        self._load_configs()

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    def _load_configs(self):
        configs_dir = BASE_DIR / "domains" / self.domain / "configs"

        impacts_path = configs_dir / "action_impacts.json"
        if impacts_path.exists():
            with open(impacts_path) as f:
                data = json.load(f)

            self._action_impacts = data.get("impacts", data)

            # Load thresholds from config
            # v3.1: every action_impacts.json keeps the thresholds at the top
            # level; reading only data["thresholds"] fell back to the defaults
            thresholds = data.get("thresholds") or data
            self._posture_threshold = thresholds.get(
                "posture_threshold", self._posture_threshold
            )
            self._velocity_limit = thresholds.get(
                "velocity_limit", self._velocity_limit
            )
            self._velocity_window_minutes = thresholds.get(
                "velocity_window_minutes", self._velocity_window_minutes
            )

            # Load dangerous patterns
            self._dangerous_patterns = data.get("dangerous_patterns", [])

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess(
        self, proposal: dict, context: dict
    ) -> tuple[bool, str, dict]:
        """Assess whether a proposed action should proceed.

        Returns:
            (ok, reason, details)
        """
        tool_id = proposal.get("tool_id", "")
        action = proposal.get("arguments", {}).get("action", proposal.get("action", ""))

        # 1. Posture threshold check
        impact = self._get_impact(tool_id, action)
        projected = self.posture + impact

        if projected <= self._posture_threshold:
            details = {
                "current_posture": round(self.posture, 2),
                "projected_posture": round(projected, 2),
                "threshold": self._posture_threshold,
                "impact": impact,
            }
            self._log_assess("P3_posture_threshold", "escalate", details)
            return False, "P3_posture_threshold", details

        # 2. Dangerous pattern check
        matched = self._check_dangerous_patterns(tool_id, action)
        if matched:
            details = {
                "matched_pattern": matched,
                "current_posture": round(self.posture, 2),
            }
            self._log_assess("P3_dangerous_pattern", "escalate", details)
            return False, "P3_dangerous_pattern", details

        # 3. Velocity check
        count = self._count_recent_actions()
        if count >= self._velocity_limit:
            details = {
                "action_count": count,
                "velocity_limit": self._velocity_limit,
                "window_minutes": self._velocity_window_minutes,
            }
            self._log_assess("P3_velocity_limit", "escalate", details)
            return False, "P3_velocity_limit", details

        self._log_assess("P3_chain_ok", "allow", {})
        return True, "P3_chain_ok", {}

    def record(self, proposal: dict):
        """Record an action in the chain history and update posture."""
        tool_id = proposal.get("tool_id", "")
        action = proposal.get("arguments", {}).get("action", proposal.get("action", ""))
        impact = self._get_impact(tool_id, action)
        self.posture += impact

        self.history.append({
            "tool": tool_id,
            "action": action,
            "impact": impact,
            "cumulative": round(self.posture, 4),
            "timestamp": datetime.now(timezone.utc),
        })

    def get_state_bucket(self) -> str:
        """Classify current chain state into a bucket for adaptive consent."""
        # Check for stealth / escalation / destructive activity
        has_stealth = any(
            h["action"] in self._STEALTH_ACTIONS for h in self.history
        )
        has_escalation = any(
            h["action"] in self._ESCALATION_ACTIONS for h in self.history
        )
        has_destructive = any(
            h["action"] in self._DESTRUCTIVE_ACTIONS for h in self.history
        )

        # Stealth-based buckets (highest priority)
        if has_stealth and has_destructive:
            return "stealth_destructive"
        if has_stealth and has_escalation:
            return "stealth_elevated"
        if has_stealth:
            return "stealth_active"

        # Destructive-based buckets
        if has_destructive:
            return "destructive_active"

        # Escalation-based buckets
        if has_escalation:
            return "elevated"

        # Posture-based buckets
        if self.posture <= self._posture_threshold:
            return "severely_degraded"
        if self.posture < -2.0:
            return "degraded"
        if self.posture > 2.0:
            return "hardened"
        if len(self.history) == 0:
            return "clean"

        return "neutral"

    def reset(self):
        """Reset chain state for a new incident."""
        self.posture = 0.0
        self.history.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_impact(self, tool_id: str, action: str) -> float:
        """Look up the impact score for a tool+action pair."""
        # Primary lookup: "tool_id|action" flat key
        key = f"{tool_id}|{action}"
        impact = self._action_impacts.get(key)
        if impact is not None:
            return float(impact)

        # Fallback: nested dict (tool_id -> action -> score)
        tool_impacts = self._action_impacts.get(tool_id, {})
        if isinstance(tool_impacts, dict):
            impact = tool_impacts.get(action)
            if impact is not None:
                return float(impact)

        # Default: destructive actions get negative impact, others neutral
        if action in self._DESTRUCTIVE_ACTIONS:
            return -2.0
        if action in self._STEALTH_ACTIONS:
            return -1.5
        if action in self._ESCALATION_ACTIONS:
            return -1.0

        return 0.0

    def _check_dangerous_patterns(self, tool_id: str, action: str) -> Optional[dict]:
        """Check if history + proposed action matches any dangerous pattern."""
        # Build the tool|action sequence from history + proposal
        sequence = set()
        for h in self.history:
            sequence.add(f"{h['tool']}|{h['action']}")
        sequence.add(f"{tool_id}|{action}")

        for pattern in self._dangerous_patterns:
            requires = pattern.get("requires", [])
            if requires and all(r in sequence for r in requires):
                return pattern

        return None

    def _count_recent_actions(self) -> int:
        """Count actions within the velocity window."""
        if not self.history:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(
            minutes=self._velocity_window_minutes
        )
        return sum(1 for h in self.history if h["timestamp"] >= cutoff)

    def _log_assess(self, mechanism: str, decision: str, details: dict):
        if self.logger:
            self.logger.log(
                source="intent_chain",
                destination="host",
                action="P3_L3_assess",
                auth_decision=decision,
                mechanism=mechanism,
                extra=details if details else None,
            )
