"""Isolated tool loader for the ASB benchmark.

Mirror of ``benchmarks/injecagent/harness/tool_loader.py`` but for the
upstream ASB tool catalogue.  Tools are namespaced with an ``ASB_``
prefix in an in-memory registry so they cannot collide with native
domain tools (T*, H*, F*, L*) or with InjecAgent's ``IA_*`` namespace.

Returns a registry dict::

    {
        "original_name_to_asb_name": {<upstream_id>: "ASB_<scenario>_<tool>", ...},
        "asb_name_to_schema":        {ASB_id: {name, description, parameters, scenario}, ...},
        "by_scenario":               {"e_commerce": [ASB_id, ...], ...},
    }

The actual tool list is populated by the ingestion + conversion
scripts:

  ./benchmarks/asb/scripts/ingest_upstream.sh        # clone upstream
  python -m benchmarks.asb.scripts.convert_cases     # extract tools

Until those run, this loader returns an empty registry and emits a
clear SystemExit telling the user what to do.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
TOOLS_PATH = DATA_DIR / "tools.json"
NAMESPACE_PREFIX = "ASB_"

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_]")


def _safe(name: str) -> str:
    """Slug-ify a scenario / tool name to a safe identifier."""
    return _SAFE_NAME_RE.sub("_", name).strip("_")


@lru_cache(maxsize=1)
def load_asb_tools() -> dict[str, Any]:
    """Load and namespace the ASB tool catalogue.

    Returns the registry dict (see module docstring).  Cached -- repeat
    calls return the same object without re-reading disk.

    Raises SystemExit with a hint if ``data/tools.json`` is missing,
    which happens before the upstream ingest + conversion has been run.
    """
    if not TOOLS_PATH.exists():
        raise SystemExit(
            f"ASB tools.json not found at {TOOLS_PATH}.\n"
            "Run the ingest + conversion pipeline first:\n"
            "  ./benchmarks/asb/scripts/ingest_upstream.sh\n"
            "  python -m benchmarks.asb.scripts.convert_cases\n")

    with open(TOOLS_PATH) as f:
        raw = json.load(f)

    orig_to_asb: dict[str, str] = {}
    asb_to_schema: dict[str, dict] = {}
    by_scenario: dict[str, list[str]] = {}

    # Expected shape (after convert_cases.py runs):
    #   [
    #     {"scenario": "e_commerce",
    #      "tools": [{"name": "AddToCart", "description": "...",
    #                 "parameters": [...], "returns": [...]}]},
    #     ...
    #   ]
    for entry in raw:
        scenario = _safe(entry.get("scenario", "unknown"))
        for t in entry.get("tools", []):
            tool_name = _safe(t.get("name", ""))
            if not tool_name:
                continue
            original = f"{scenario}_{tool_name}"
            asb = f"{NAMESPACE_PREFIX}{scenario}_{tool_name}"
            orig_to_asb[original] = asb
            asb_to_schema[asb] = {
                "name":        asb,
                "scenario":    scenario,
                "description": t.get("description", ""),
                "parameters":  t.get("parameters", []),
                "returns":     t.get("returns", []),
            }
            by_scenario.setdefault(scenario, []).append(asb)

    return {
        "original_name_to_asb_name": orig_to_asb,
        "asb_name_to_schema":        asb_to_schema,
        "by_scenario":               by_scenario,
    }


def resolve_case_tools(case: dict) -> dict[str, Any]:
    """Given a converted ASB case (see convert_cases.py output schema),
    return its ASB_* attacker / user tool identifiers.

    Output shape mirrors :func:`benchmarks.injecagent.harness.tool_loader.resolve_case_tools`
    so a single trial driver can dispatch on benchmark type::

        {
            "user_tool":     "ASB_<scenario>_<tool>" or None,
            "attacker_tools": ["ASB_<scenario>_<tool>", ...],
            "missing":        ["any_unresolved_originals"],
        }
    """
    reg = load_asb_tools()
    o2a = reg["original_name_to_asb_name"]

    # Cases store tool names in bare form (e.g. "FinancialAnalysis" /
    # "ResourceAllocationHijack") but the registry is keyed by
    # ``<scenario>_<tool>`` to keep namespacing per-agent.  Build the
    # composite key for the lookup; fall through to the bare name as a
    # fallback for cases that already carry the prefixed form.
    scenario = case.get("scenario", "")
    user_orig = case.get("User Tool", "")
    attacker_origs = case.get("Attacker Tools", []) or []

    def _resolve(name: str) -> Optional[str]:
        if not name:
            return None
        if name in o2a:
            return o2a[name]
        if scenario:
            keyed = f"{scenario}_{name}"
            if keyed in o2a:
                return o2a[keyed]
        return None

    missing: list[str] = []
    user_resolved = _resolve(user_orig)
    if user_orig and not user_resolved:
        missing.append(user_orig)

    attacker_resolved: list[str] = []
    for orig in attacker_origs:
        a = _resolve(orig)
        if a:
            attacker_resolved.append(a)
        else:
            missing.append(orig)

    return {
        "user_tool":     user_resolved,
        "attacker_tools": attacker_resolved,
        "missing":        missing,
    }
