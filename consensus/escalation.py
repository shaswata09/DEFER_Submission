"""
Human-in-the-loop escalation handler.

In the testbed, escalation is simulated by logging the event and
auto-rejecting (conservative default). In production, this would
route to a real analyst queue.
"""

from typing import Optional

from logging_utils import ExperimentLogger


class EscalationHandler:
    """Handles escalation when consensus fails or bulk actions are detected."""

    def __init__(self, logger: Optional[ExperimentLogger] = None):
        self.logger = logger
        self.escalation_log: list[dict] = []

    async def escalate(
        self, action: dict, reason: str, context: dict
    ) -> bool:
        """Log escalation and return False (auto-reject in testbed).

        Returns:
            False always (conservative default for experiments).
        """
        record = {
            "action": action,
            "reason": reason,
            "incident_id": context.get("incident_id"),
            "decision": "rejected_by_escalation",
        }
        self.escalation_log.append(record)

        if self.logger:
            self.logger.log_escalation(
                source=action.get("tool_id", "unknown"),
                reason=reason,
                severity="high",
            )

        return False

    def get_escalation_count(self) -> int:
        return len(self.escalation_log)

    def reset(self):
        self.escalation_log.clear()
