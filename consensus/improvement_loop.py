"""
Improvement Loop — Report phase memory write validation.

Validates that proposed updates to detection rules, playbooks, and
compliance mappings are consistent with incident findings and don't
weaken defenses.
"""

from typing import Optional

from consensus.validator import ConsensusValidator
from logging_utils import ExperimentLogger


class ImprovementLoop:
    """Wraps ConsensusValidator for Report phase memory writes."""

    def __init__(
        self,
        consensus: ConsensusValidator,
        logger: Optional[ExperimentLogger] = None,
    ):
        self.consensus = consensus
        self.logger = logger

    async def validate_memory_update(
        self, write_request: dict, context: dict
    ) -> tuple[bool, str]:
        """Validate a Report phase memory write.

        Returns (approved, reason).
        """
        proposal = {
            "action": "memory_write",
            "store_id": write_request.get("store_id"),
            "content_preview": write_request.get("content", "")[:500],
            "justification": write_request.get("justification", "Report phase update"),
        }

        result = await self.consensus.validate_with_details(proposal, context)
        if not result.approved:
            return False, f"Improvement loop rejected ({result.approvals}/{len(result.votes)})"

        return True, "approved"
