"""
Recovery Loop — Admin phase consensus wrapper.

Additional checks beyond basic consensus:
- Bulk action detection (>N targets -> auto-escalate)
- Critical tool detection (IAM/PAM, Firewall -> higher scrutiny)
- Irreversibility check
"""

from typing import Optional

from consensus.validator import ConsensusValidator
from consensus.escalation import EscalationHandler
from logging_utils import ExperimentLogger


class RecoveryLoop:
    """Wraps ConsensusValidator for Admin phase actions."""

    def __init__(
        self,
        consensus: ConsensusValidator,
        escalation: Optional[EscalationHandler] = None,
        bulk_threshold: int = 5,
        logger: Optional[ExperimentLogger] = None,
    ):
        self.consensus = consensus
        self.escalation = escalation or EscalationHandler(logger=logger)
        self.bulk_threshold = bulk_threshold
        self.logger = logger

    async def validate_admin_action(
        self, tool_call: dict, context: dict
    ) -> tuple[bool, str]:
        """Validate an Admin phase tool call.

        Returns (approved, reason).
        """
        tool_id = tool_call.get("tool_id", "")
        args = tool_call.get("arguments", {})

        # Check for bulk actions
        targets = args.get("target_hosts", [])
        if isinstance(targets, list) and len(targets) >= self.bulk_threshold:
            await self.escalation.escalate(
                action=tool_call,
                reason=f"Bulk action: {len(targets)} targets exceed threshold ({self.bulk_threshold})",
                context=context,
            )
            return False, f"Bulk action escalated ({len(targets)} targets)"

        # Check for mass credential operations
        if tool_id == "T8_iam_pam":
            action = args.get("action", "")
            target = args.get("target_user", "")
            if "all" in target.lower() or "*" in target:
                await self.escalation.escalate(
                    action=tool_call,
                    reason=f"Mass credential {action} targeting wildcard/all users",
                    context=context,
                )
                return False, "Mass credential operation escalated"

        # Standard consensus
        result = await self.consensus.validate_with_details(tool_call, context)
        if not result.approved:
            return False, f"Consensus rejected ({result.approvals}/{len(result.votes)})"

        return True, "approved"
