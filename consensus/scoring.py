"""
P3-L1: Quantified Scoring.
Computes scope, reversibility, alignment, precedent, proportionality scores.
~70% symbolic, ~30% mathematical (embeddings). Zero LLM.
"""

import json
from pathlib import Path
from typing import Optional

import numpy as np

from config import BASE_DIR
from logging_utils import ExperimentLogger


class ProposalScorer:
    """Computes multi-dimensional scores for a proposed action."""

    # Severity weights used in proportionality calculation
    _SEVERITY_WEIGHTS = {
        "critical": 1.0,
        "high": 0.7,
        "medium": 0.4,
        "low": 0.2,
    }

    def __init__(
        self,
        domain: str,
        embedding_model=None,
        logger: Optional[ExperimentLogger] = None,
        ledger=None,
    ):
        self.domain = domain
        self.logger = logger
        self._embedding_model = embedding_model
        self._ledger = ledger

        # Load configs (graceful fallback to empty)
        self._reversibility_scores: dict[str, float] = {}
        self._criticality_lookup: dict[str, str] = {}
        self._load_configs()

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    def _load_configs(self):
        configs_dir = BASE_DIR / "domains" / self.domain / "configs"

        # Reversibility scores
        rev_path = configs_dir / "reversibility_scores.json"
        if rev_path.exists():
            with open(rev_path) as f:
                data = json.load(f)
            self._reversibility_scores = data.get("scores", {})

        # Asset criticality — flatten nested categories into a single lookup
        crit_path = configs_dir / "asset_criticality.json"
        if crit_path.exists():
            with open(crit_path) as f:
                data = json.load(f)
            for _category, assets in data.get("assets", {}).items():
                for asset_key, asset_info in assets.items():
                    self._criticality_lookup[asset_key] = asset_info.get("criticality", "low")
                    name = asset_info.get("name")
                    if name:
                        self._criticality_lookup[name] = asset_info.get("criticality", "low")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, proposal: dict, context: dict) -> dict:
        """Compute multi-dimensional scores for the proposal.

        Args:
            proposal: Dict with tool_id, action, target/target_hosts/target_users, etc.
            context: Dict with severity, incident_evidence, total_managed_assets, etc.

        Returns:
            Dict with keys: scope, reversibility, alignment, precedent, proportionality.
            All values are floats in [0, 1].
        """
        scope = self._score_scope(proposal, context)
        reversibility = self._score_reversibility(proposal)
        alignment = self._score_alignment(proposal, context)
        precedent = self._score_precedent(proposal, context)
        severity = context.get("severity", "medium").lower()
        proportionality = self._score_proportionality(
            scope, reversibility, severity,
        )

        return {
            "scope": round(scope, 4),
            "reversibility": round(reversibility, 4),
            "alignment": round(alignment, 4),
            "precedent": round(precedent, 4),
            "proportionality": round(proportionality, 4),
        }

    # ------------------------------------------------------------------
    # Individual scoring dimensions
    # ------------------------------------------------------------------

    def _score_scope(self, proposal: dict, context: dict) -> float:
        """Score scope (0-1): ratio of targets affected vs total managed.

        Single target ~ 0.01, list = len/total.
        """
        total_managed = context.get("total_managed_assets", 100)
        if total_managed <= 0:
            total_managed = 100

        target_count = 0

        # Check list-type target fields
        for field in ("target_hosts", "target_users"):
            val = proposal.get(field)
            if isinstance(val, list):
                target_count += len(val)

        # Check single-target fields (only if no list targets found)
        if target_count == 0:
            for field in ("target_user", "target"):
                if proposal.get(field) is not None:
                    target_count = 1
                    break

        if target_count == 0:
            return 0.0

        ratio = target_count / total_managed
        return min(1.0, ratio)

    def _score_reversibility(self, proposal: dict) -> float:
        """Score reversibility (0-1): lookup from reversibility_scores.json."""
        tool_id = proposal.get("tool_id", "")
        action = proposal.get("action", "")
        key = f"{tool_id}|{action}"
        return self._reversibility_scores.get(key, 0.5)

    def _score_alignment(self, proposal: dict, context: dict) -> float:
        """Score alignment (0-1): semantic similarity between proposal and evidence.

        Uses embedding model if available; otherwise returns 0.5 default.
        """
        if self._embedding_model is None:
            return 0.5

        incident_evidence = context.get("incident_evidence", "")
        if not incident_evidence:
            return 0.5

        # Build a text representation of the proposal
        tool_id = proposal.get("tool_id", "unknown")
        action = proposal.get("action", "unknown")
        target = proposal.get("target") or proposal.get("target_user") or ""
        if isinstance(target, list):
            target = ", ".join(str(t) for t in target)
        proposal_text = f"{tool_id} {action} {target}"

        embeddings = self._embedding_model.encode(
            [proposal_text, incident_evidence],
            normalize_embeddings=True,
        )
        score = float(np.dot(embeddings[0], embeddings[1]))
        return max(0.0, min(1.0, score))

    def _score_precedent(self, proposal: dict, context: dict) -> float:
        """Score precedent (0-1): how often similar actions have been approved.

        Queries the ledger for structurally similar past proposals matching
        the same tool_id + action combination.

        Returns:
            0.1  if 0 matches   (truly unprecedented)
            0.4  if 1-3 matches (somewhat precedented)
            0.7  if 4-9 matches (well precedented)
            0.9  if 10+ matches (routine)
            0.5  if no ledger is available
        """
        if self._ledger is None:
            return 0.5

        tool_id = proposal.get("tool_id", "")
        action = proposal.get("action", "")
        match_count = 0

        # Support both versioned ledger (.get_entries / .entries) and
        # cross-incident ledger (.get_all / list-like) interfaces
        entries = []
        if hasattr(self._ledger, "get_entries"):
            entries = self._ledger.get_entries()
        elif hasattr(self._ledger, "entries"):
            entries = self._ledger.entries
        elif hasattr(self._ledger, "get_all"):
            entries = self._ledger.get_all()
        elif isinstance(self._ledger, list):
            entries = self._ledger

        for entry in entries:
            entry_data = entry if isinstance(entry, dict) else {}
            proposal_data = entry_data.get("proposal", entry_data)
            if (
                proposal_data.get("tool_id") == tool_id
                and proposal_data.get("action") == action
                and entry_data.get("decision") == "approve"
            ):
                match_count += 1

        if match_count == 0:
            return 0.1
        if match_count <= 3:
            return 0.4
        if match_count <= 9:
            return 0.7
        return 0.9

    def _score_proportionality(
        self,
        scope: float,
        reversibility: float,
        severity: str,
    ) -> float:
        """Score proportionality (0-1): combines scope, reversibility, severity.

        Formula: max(0, min(1, 1.0 - max(0, scope - severity_weight*0.5) - (1-reversibility)*0.3))
        """
        severity_weight = self._SEVERITY_WEIGHTS.get(severity, 0.4)
        raw = 1.0 - max(0.0, scope - severity_weight * 0.5) - (1.0 - reversibility) * 0.3
        return max(0.0, min(1.0, raw))
