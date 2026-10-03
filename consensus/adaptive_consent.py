"""
P3-L0.7: Adaptive Consent Model.
Chain-state-aware reward profiles with time decay.
~95% symbolic, ~5% state management. Zero LLM.
Covers: TA-6 (accumulated trust), TA-12 (validator manipulation via trust poisoning)
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

from config import BASE_DIR
from logging_utils import ExperimentLogger


class AdaptiveConsentModel:
    """Chain-state-aware adaptive consent with time-decayed reward profiles."""

    # Reward deltas for each (decision, decided_by) combination
    REWARD_VALUES = {
        ("approve", "human"):       +1.0,
        ("approve", "llm"):         +0.5,
        ("approve", "auto_gate"):   +0.3,
        ("approve", "adaptive"):    +0.2,
        ("reject",  "human"):       -1.0,
        ("reject",  "llm"):         -0.5,
        ("reject",  "auto_gate"):   -0.3,
        ("reject",  "adaptive"):    -0.2,
    }

    # Chain states that should never be auto-decided
    UNSAFE_CHAIN_STATES = frozenset({
        "compromised", "under_attack", "lateral_movement",
        "privilege_escalation", "data_exfiltration", "c2_active",
    })

    # External tools that must never be auto-decided
    EXTERNAL_TOOLS = frozenset({
        "T14_isac_misp", "H12_regulatory_filing",
        "L8_court_filing", "F13_regulatory_submission",
    })

    def __init__(
        self,
        domain: str,
        approve_threshold: float = 5.0,
        reject_threshold: float = -3.0,
        decay_rate: float = 0.95,
        decay_interval_hours: float = 1.0,
        min_decisions: int = 5,
        logger: Optional[ExperimentLogger] = None,
        persist_path: Optional[Path] = None,
        persist: bool = True,
    ):
        self.domain = domain
        self.logger = logger
        self._approve_threshold = approve_threshold
        self._reject_threshold = reject_threshold
        self._decay_rate = decay_rate
        self._decay_interval_seconds = decay_interval_hours * 3600.0
        self._min_decisions = min_decisions

        self._rewards: dict[str, dict] = {}
        self._never_auto: set = set()

        # Load asset criticality for criticality checks
        self._criticality_lookup: dict[str, str] = {}
        self._load_criticality()

        # Reward profiles persist across incidents by design.  ``persist=False``
        # keeps them in memory only (isolated state mode, H3); ``persist_path``
        # relocates the file (persistent mode uses one file per group/domain).
        self._persist_enabled = bool(persist)
        self._persist_path = Path(persist_path) if persist_path else (
            BASE_DIR / "data" / "adaptive_consent.json")
        if self._persist_enabled:
            self._load()

    def reset(self):
        """Forget every reward profile (per-trial isolation, H3).

        In persistent mode the on-disk file is left alone: reset only
        affects the in-memory profiles of this process.
        """
        self._rewards = {}
        self._never_auto = set()

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    def _load_criticality(self):
        crit_path = BASE_DIR / "domains" / self.domain / "configs" / "asset_criticality.json"
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

    def check_auto_decision(
        self,
        proposal: dict,
        context: dict,
        chain_state: str = "clean",
    ) -> tuple[bool, str, dict]:
        """Check if this proposal can be auto-decided based on reward history.

        Returns:
            (decided, reason, details) where decided=True means auto-decided.
            When decided=True, check details["approved"] for direction.
        """
        profile = self._get_profile(proposal, context, chain_state)

        # Safety: never auto-decide blacklisted profiles
        if profile in self._never_auto:
            return False, "never_auto", {}

        # Safety: catastrophic criticality
        target = self._extract_target(proposal)
        if target:
            targets = target if isinstance(target, list) else [target]
            for t in targets:
                if self._criticality_lookup.get(str(t)) == "critical":
                    return False, "never_auto", {}

        # Safety: bulk scope
        scope = self._scope_bucket(proposal, context)
        if scope == "bulk":
            return False, "never_auto", {}

        # Safety: escalate action
        action = proposal.get("action", "").lower()
        if action == "escalate":
            return False, "never_auto", {}

        # Safety: unsafe chain state
        if chain_state in self.UNSAFE_CHAIN_STATES:
            return False, "never_auto", {}

        # Safety: external tools
        tool_id = proposal.get("tool_id", "")
        if tool_id in self.EXTERNAL_TOOLS:
            return False, "never_auto", {}

        # Check history
        entry = self._rewards.get(profile)
        if not entry:
            return False, "insufficient_history", {}

        total_decisions = entry.get("approves", 0) + entry.get("rejects", 0)
        if total_decisions < self._min_decisions:
            return False, "insufficient_history", {}

        # Apply time decay
        self._decay(entry)
        reward = entry["reward"]

        if reward >= self._approve_threshold:
            return True, "P3_adaptive_auto_approve", {"approved": True, "reward": reward}

        if reward <= self._reject_threshold:
            return True, "P3_adaptive_auto_reject", {"approved": False, "reward": reward}

        return False, "between_thresholds", {"reward": reward}

    def record_outcome(
        self,
        proposal: dict,
        context: dict,
        chain_state: str,
        decision: str,
        decided_by: str,
    ):
        """Record a decision outcome and update the reward profile.

        Args:
            proposal: The proposal dict.
            context: The context dict.
            chain_state: Current chain state string.
            decision: "approve" or "reject".
            decided_by: "human", "llm", "auto_gate", or "adaptive".
        """
        profile = self._get_profile(proposal, context, chain_state)

        if profile not in self._rewards:
            self._rewards[profile] = {
                "reward": 0.0,
                "last_updated": time.time(),
                "approves": 0,
                "rejects": 0,
            }

        entry = self._rewards[profile]

        # Apply time decay before adding new reward
        self._decay(entry)

        # Add reward delta
        # v3.1: callers pass "llm_consensus" / "adaptive_consent"; the table is
        # keyed on "llm" / "adaptive", so every panel decision added nothing
        decided_by = {"llm_consensus": "llm", "adaptive_consent": "adaptive"}.get(decided_by, decided_by)
        delta = self.REWARD_VALUES.get((decision, decided_by), 0.0)
        entry["reward"] += delta
        entry["last_updated"] = time.time()

        if decision == "approve":
            entry["approves"] += 1
        elif decision == "reject":
            entry["rejects"] += 1

        # Check rejection ratio: >30% over 10+ decisions → never_auto
        total = entry["approves"] + entry["rejects"]
        if total >= 10:
            rejection_ratio = entry["rejects"] / total
            if rejection_ratio > 0.30:
                self._never_auto.add(profile)

        self._persist()

    # ------------------------------------------------------------------
    # Profile construction
    # ------------------------------------------------------------------

    # Fields excluded from parameter hashing (non-security-relevant metadata only)
    # NOTE: target fields are INCLUDED in the hash to prevent trust transfer
    # between different targets of the same criticality tier (second-pass fix)
    _PARAM_HASH_EXCLUDE = frozenset({
        "justification", "reason", "description",
        "tool_id", "action", "phase",
    })

    def _get_profile(self, proposal: dict, context: dict, chain_state: str) -> str:
        """Build a profile string for reward lookup."""
        tool_id = proposal.get("tool_id", "unknown")
        action = proposal.get("action", "unknown")
        scope = self._scope_bucket(proposal, context)

        # Determine criticality from target
        criticality = "low"
        target = self._extract_target(proposal)
        if target:
            targets = target if isinstance(target, list) else [target]
            for t in targets:
                c = self._criticality_lookup.get(str(t), "low")
                if c in ("critical", "high", "medium"):
                    criticality = c
                    break

        severity = context.get("severity", "medium").lower()

        # Compute hash of security-relevant parameters to prevent trust
        # transfer between different parameter sets
        param_items = sorted(
            (k, str(v))
            for k, v in proposal.items()
            if k not in self._PARAM_HASH_EXCLUDE
        )
        param_str = json.dumps(param_items, sort_keys=True)
        param_hash = hashlib.sha256(param_str.encode()).hexdigest()[:8]

        return f"{tool_id}|{action}|{scope}|{criticality}|{severity}|{chain_state}|{param_hash}"

    def _scope_bucket(self, proposal: dict, context: dict) -> str:
        """Classify scope into single/small/large/bulk."""
        count = 0
        for field in ("target_hosts", "target_users"):
            val = proposal.get(field)
            if isinstance(val, list):
                count += len(val)
        if count == 0:
            # Check for single-target fields
            if proposal.get("target_user") or proposal.get("target"):
                count = 1
        if count <= 1:
            return "single"
        if count <= 5:
            return "small"
        if count <= 20:
            return "large"
        return "bulk"

    def _extract_target(self, proposal: dict):
        """Extract target value from proposal."""
        for field in ("target_hosts", "target_users", "target_user", "target"):
            val = proposal.get(field)
            if val is not None:
                return val
        return None

    # ------------------------------------------------------------------
    # Time decay
    # ------------------------------------------------------------------

    def _decay(self, entry: dict):
        """Apply exponential time decay to the reward."""
        now = time.time()
        elapsed = now - entry.get("last_updated", now)
        if elapsed <= 0 or self._decay_interval_seconds <= 0:
            return
        intervals = elapsed / self._decay_interval_seconds
        entry["reward"] *= self._decay_rate ** intervals
        entry["last_updated"] = now

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist(self):
        """Save reward profiles and never_auto set to disk with HMAC."""
        if not self._persist_enabled:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "rewards": self._rewards,
            "never_auto": sorted(self._never_auto),
        }
        # Compute HMAC for data integrity (P1-L3, MA-11 defense)
        hmac_key = self._get_hmac_key()
        signature = ""
        if hmac_key:
            from host.authenticated_interface import AuthenticatedInterface
            signature = AuthenticatedInterface.compute_hmac(data, hmac_key)

        state = {"data": data, "signature": signature}
        with open(self._persist_path, "w") as f:
            json.dump(state, f, indent=2)

    def _load(self):
        """Load persisted state from disk with HMAC verification."""
        if not self._persist_path.exists():
            return
        try:
            with open(self._persist_path) as f:
                state = json.load(f)

            # Verify HMAC if key is available
            hmac_key = self._get_hmac_key()
            if hmac_key and state.get("signature"):
                from host.authenticated_interface import AuthenticatedInterface
                expected = AuthenticatedInterface.compute_hmac(
                    state.get("data", state), hmac_key
                )
                if state["signature"] != expected:
                    if self.logger:
                        self.logger.log(
                            source="adaptive_consent",
                            destination="data_integrity",
                            action="load",
                            auth_decision="deny",
                            mechanism="P1_data_integrity_violation",
                        )
                    # Tampered — start fresh
                    self._rewards = {}
                    self._never_auto = set()
                    return

            data = state.get("data", state)
            self._rewards = data.get("rewards", {})
            self._never_auto = set(data.get("never_auto", []))
        except (json.JSONDecodeError, OSError):
            self._rewards = {}
            self._never_auto = set()

    @staticmethod
    def _get_hmac_key() -> str:
        """Load HMAC key from environment or file."""
        import os
        key = os.environ.get("AGENTICCYOPS_HMAC_KEY", "")
        if not key:
            key_path = BASE_DIR / "configs" / "hmac_key.txt"
            if key_path.exists():
                key = key_path.read_text().strip()
        return key
