"""
P5: Phase-Partitioned Memory Access Control

Enforces which NIST-IR phases (monitor, analyze, admin, report) can
read or write to which memory stores (M1-M12).

Policy is loaded from:
    domains/{domain}/configs/access_policy.json

Format:
    {
        "monitor": {"read": ["M1","M4"], "write": []},
        "analyze": {"read": ["M1","M2","M6","M7"], "write": ["M1","M6"]},
        ...
    }

Usage:
    from memory.access_control import AccessController

    ac = AccessController(domain="cyberops")
    ac.can_read("monitor", "M1")   # True
    ac.can_write("monitor", "M1")  # False
"""

import json
import re
from pathlib import Path

from config import BASE_DIR


# Store IDs in access_policy.json are recorded in short form ("M1", "HM2",
# "FM3", ...).  The orchestrator/agent path sometimes emits the long form
# "<id>_<collection_name>" (e.g. "M1_threat_repository") because it
# concatenates the human-readable name from memory_collections.json.
# This regex strips the suffix so policy lookups match either form.
_STORE_ID_RE = re.compile(r"^([A-Z]+\d+)(?:_.*)?$")


def _normalize_store_id(store_id: str) -> str:
    """Return the canonical short-form store_id (e.g. M1) from either
    short or long-form input.  Unknown shapes pass through unchanged
    so the caller still gets exact-string matching as a fallback."""
    if not store_id:
        return store_id
    m = _STORE_ID_RE.match(store_id)
    return m.group(1) if m else store_id


class AccessController:
    """P5: Phase-partitioned memory access.

    Reads policy from domains/{domain}/configs/access_policy.json.
    Returns False for any unknown phase or store_id.
    """

    def __init__(self, domain: str, configs_dir: str | Path | None = None):
        """
        Args:
            domain: Domain identifier (e.g. "cyberops").
            configs_dir: Override path to the configs directory.
                         Defaults to BASE_DIR / "domains" / domain / "configs".
        """
        if configs_dir is None:
            configs_dir = BASE_DIR / "domains" / domain / "configs"
        else:
            configs_dir = Path(configs_dir)

        policy_path = configs_dir / "access_policy.json"
        with open(policy_path, "r") as f:
            self._policy: dict = json.load(f)

        self.domain = domain

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def can_read(self, phase: str, store_id: str) -> bool:
        """Check if *phase* is allowed to read from *store_id*.

        Accepts either short ("M1") or long ("M1_threat_repository") form
        and matches against the policy's short-form list.

        Args:
            phase: NIST-IR phase name (monitor, analyze, admin, report).
            store_id: Memory store identifier (M1-M12) or its long-form
                      alias.

        Returns:
            True if the policy explicitly grants read access, False otherwise.
        """
        phase_policy = self._policy.get(phase)
        if phase_policy is None:
            return False
        allow = set(phase_policy.get("read", []))
        return _normalize_store_id(store_id) in allow or store_id in allow

    def can_write(self, phase: str, store_id: str) -> bool:
        """Check if *phase* is allowed to write to *store_id*.

        Accepts either short ("M1") or long ("M1_threat_repository") form.

        Args:
            phase: NIST-IR phase name (monitor, analyze, admin, report).
            store_id: Memory store identifier (M1-M12) or its long-form
                      alias.

        Returns:
            True if the policy explicitly grants write access, False otherwise.
        """
        phase_policy = self._policy.get(phase)
        if phase_policy is None:
            return False
        allow = set(phase_policy.get("write", []))
        return _normalize_store_id(store_id) in allow or store_id in allow

    def accessible_stores(self, phase: str, mode: str = "read") -> list[str]:
        """Return list of store IDs accessible to *phase* for the given mode.

        Args:
            phase: NIST-IR phase name.
            mode: "read" or "write".

        Returns:
            List of store IDs, or empty list for unknown phase/mode.
        """
        phase_policy = self._policy.get(phase)
        if phase_policy is None:
            return []
        return list(phase_policy.get(mode, []))
