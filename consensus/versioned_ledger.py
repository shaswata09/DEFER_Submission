"""
P3-L5: Versioned Proposal Ledger.
Replay detection: exact hash, incident ID mismatch, structural similarity.
100% symbolic — zero LLM.
Covers: TA-8, TA-13
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from logging_utils import ExperimentLogger


class VersionedLedger:
    """Detects replayed or structurally duplicated proposals."""

    def __init__(self, logger: Optional[ExperimentLogger] = None):
        self.logger = logger
        self._ledger: dict[str, dict] = {}  # hash -> record

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_replay(self, proposal: dict, context: dict) -> tuple[bool, str, dict]:
        """Check proposal for exact replay, incident mismatch, or structural replay.

        Returns (ok, reason, details).
        """
        full_hash = self._hash_full(proposal)
        struct_hash = self._hash_structural(proposal)
        context_incident = context.get("incident_id", "")

        # --- Exact replay ------------------------------------------------
        if full_hash in self._ledger:
            prev = self._ledger[full_hash]
            details = {
                "full_hash": full_hash,
                "original_incident_id": prev["incident_id"],
                "original_timestamp": prev["timestamp"].isoformat(),
            }
            if self.logger:
                self.logger.log(
                    source="versioned_ledger",
                    destination="host",
                    action="P3_L5_check",
                    auth_decision="deny",
                    mechanism="P3_exact_replay",
                    extra=details,
                )
            return False, "P3_exact_replay", details

        # --- Incident ID mismatch ----------------------------------------
        proposal_incident = proposal.get(
            "incident_id", proposal.get("arguments", {}).get("incident_id")
        )
        # v3.2: any id the incident itself names is legitimate (nested and
        # multi-incident triggers), not only the one the context is keyed on
        known = set(map(str, context.get("incident_ids") or [])) | {str(context_incident)}
        if proposal_incident and str(proposal_incident) not in known:
            details = {
                "proposal_incident_id": proposal_incident,
                "context_incident_id": context_incident,
            }
            if self.logger:
                self.logger.log(
                    source="versioned_ledger",
                    destination="host",
                    action="P3_L5_check",
                    auth_decision="deny",
                    mechanism="P3_incident_id_mismatch",
                    extra=details,
                )
            return False, "P3_incident_id_mismatch", details

        # --- Structural replay -------------------------------------------
        for existing_hash, record in self._ledger.items():
            if record["struct_hash"] == struct_hash and record["incident_id"] != context_incident:
                details = {
                    "struct_hash": struct_hash,
                    "original_incident_id": record["incident_id"],
                    "original_timestamp": record["timestamp"].isoformat(),
                }
                if self.logger:
                    self.logger.log(
                        source="versioned_ledger",
                        destination="host",
                        action="P3_L5_check",
                        auth_decision="escalate",
                        mechanism="P3_structural_replay",
                        extra=details,
                    )
                return False, "P3_structural_replay", details

        # --- No replay detected ------------------------------------------
        if self.logger:
            self.logger.log(
                source="versioned_ledger",
                destination="host",
                action="P3_L5_check",
                auth_decision="allow",
                mechanism="P3_no_replay",
            )
        return True, "P3_no_replay", {}

    def record(self, proposal: dict, context: dict):
        """Store the proposal's hashes for future replay detection."""
        full_hash = self._hash_full(proposal)
        self._ledger[full_hash] = {
            "full_hash": full_hash,
            "struct_hash": self._hash_structural(proposal),
            "incident_id": context.get("incident_id", ""),
            "timestamp": datetime.now(timezone.utc),
            # v2.9: what was approved, so the risk scorer can count precedent
            "proposal": {"tool_id": proposal.get("tool_id", ""),
                         "action": proposal.get("action", (proposal.get("arguments") or {}).get("action", ""))},
            "decision": "approve",
        }

    def get_entries(self) -> list[dict]:
        """Approved proposals, in the shape ``ProposalScorer._score_precedent`` reads."""
        return list(self._ledger.values())

    def reset(self):
        """Clear ledger (for testing)."""
        self._ledger.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hash_full(self, proposal: dict) -> str:
        """SHA-256 of the full proposal (deterministic serialization)."""
        payload = json.dumps(proposal, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def _hash_structural(self, proposal: dict) -> str:
        """SHA-256 of structural skeleton: tool_id, sorted arg keys, action."""
        arguments = proposal.get("arguments", {})
        skeleton = {
            "tool": proposal.get("tool_id", ""),
            "keys": sorted(arguments.keys()),
            "action": arguments.get("action"),
        }
        payload = json.dumps(skeleton, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()
