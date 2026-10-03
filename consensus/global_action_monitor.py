"""
P3: Global Action Monitor.
Detects dangerous action patterns split across concurrent incidents.
Thread/async-safe via asyncio.Lock.
100% symbolic — zero LLM.
Covers: TA-22
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional

from config import BASE_DIR
from logging_utils import ExperimentLogger


class GlobalActionMonitor:
    """Monitors actions across ALL concurrent incidents.

    Catches dangerous combinations split across parallel pipelines
    that per-incident IntentChainTracker cannot see.
    """

    # Dangerous cross-incident patterns (tool|action pairs)
    DANGEROUS_PATTERNS = [
        {"name": "stealth_and_access",
         "requires": ["T10_config_manager|set", "T9_firewall|add_rule"]},
        {"name": "stealth_and_privilege",
         "requires": ["T10_config_manager|set", "T8_iam_pam|unlock"]},
        {"name": "blind_and_open",
         "requires": ["T11_epp_av|whitelist", "T9_firewall|delete_rule"]},
        {"name": "unblock_and_weaken",
         "requires": ["T9_firewall|unblock_ip", "T9_firewall|delete_rule"]},
    ]

    def __init__(
        self,
        window_minutes: int = 10,
        logger: Optional[ExperimentLogger] = None,
    ):
        self.logger = logger
        self._recent_actions: list[dict] = []
        self._window = timedelta(minutes=window_minutes)
        self._lock = asyncio.Lock()

    async def check_and_record(
        self, proposal: dict, context: dict
    ) -> tuple[bool, str, dict]:
        """Atomic check + record for cross-incident pattern detection.

        Args:
            proposal: Tool call proposal with tool_id and arguments.
            context: Incident context with incident_id.

        Returns:
            (ok, reason, details)
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            cutoff = now - self._window

            # Prune old entries
            self._recent_actions = [
                a for a in self._recent_actions if a["ts"] > cutoff
            ]

            tool_id = proposal.get("tool_id", "")
            action = proposal.get("arguments", {}).get(
                "action", proposal.get("action", "")
            )
            incident_id = context.get("incident_id", "")

            # Build the combined action set
            current_actions = set()
            for a in self._recent_actions:
                current_actions.add(f"{a['tool']}|{a['action']}")
            proposed = f"{tool_id}|{action}"
            current_actions.add(proposed)

            # Check if any dangerous pattern is formed across incidents
            for pattern in self.DANGEROUS_PATTERNS:
                requires = pattern.get("requires", [])
                if all(r in current_actions for r in requires):
                    # Check it actually spans multiple incidents
                    contributing_incidents = set()
                    contributing_incidents.add(incident_id)
                    for a in self._recent_actions:
                        action_key = f"{a['tool']}|{a['action']}"
                        if action_key in requires:
                            contributing_incidents.add(a["incident_id"])

                    if len(contributing_incidents) > 1:
                        details = {
                            "pattern": pattern["name"],
                            "incidents": sorted(contributing_incidents),
                        }
                        if self.logger:
                            self.logger.log(
                                source="global_action_monitor",
                                destination="host",
                                action="P3_global_pattern_check",
                                auth_decision="deny",
                                mechanism="P3_cross_incident_pattern",
                                extra=details,
                            )
                        return False, "P3_cross_incident_pattern", details

            # Record this action
            self._recent_actions.append({
                "tool": tool_id,
                "action": action,
                "incident_id": incident_id,
                "ts": now,
            })

            return True, "P3_global_pattern_ok", {}

    def reset(self):
        """Clear all tracked actions."""
        self._recent_actions.clear()
