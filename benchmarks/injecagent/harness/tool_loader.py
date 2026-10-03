"""Isolated tool loader for the InjecAgent benchmark.

Loads the upstream ``tools.json`` into a **separate in-memory registry**
and namespaces every tool with an ``IA_`` prefix so it cannot collide
with the domain-native tools (T*, H*, F*, L*).  The registry is never
written to disk and never touches ``configs/component_registry.json``.

Key functions
=============

:func:`load_injecagent_tools` -- returns::

    {
        "original_name_to_ia_name": {"AmazonGetProductDetails": "IA_Amazon_GetProductDetails", ...},
        "ia_name_to_schema":        {"IA_Amazon_GetProductDetails": {name, description, parameters, returns}, ...},
        "by_toolkit":               {"Amazon": ["IA_Amazon_GetProductDetails", ...], ...},
    }

:func:`resolve_case_tools` -- given an InjecAgent test case, returns the
concrete ``IA_*``-prefixed identifiers for the user tool + attacker
tools.

Design notes
============

* InjecAgent tool identifiers in the test cases concatenate toolkit
  name and tool name with no separator, e.g. ``AmazonGetProductDetails``
  (toolkit ``Amazon``, tool ``GetProductDetails``).  We preserve that
  format when matching, then add a separator + ``IA_`` prefix for the
  internal namespaced form: ``IA_Amazon_GetProductDetails``.
* The loader is completely read-only; it never mutates any project
  state.  All callers must pass the loaded registry explicitly.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
TOOLS_PATH = DATA_DIR / "tools.json"
NAMESPACE_PREFIX = "IA_"

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_]")


def _safe(name: str) -> str:
    """Slug-ify a toolkit/tool name so it's safe as a tool identifier."""
    return _SAFE_NAME_RE.sub("_", name).strip("_")


@lru_cache(maxsize=1)
def load_injecagent_tools() -> dict[str, Any]:
    """Load and namespace the InjecAgent tool schemas.

    Returns a registry dict (see module docstring).  Cached — repeat
    calls return the same object without re-reading disk.
    """
    with open(TOOLS_PATH, "r") as f:
        raw = json.load(f)

    # Expected shape: list of toolkit dicts, each with:
    #   toolkit, category, name_for_model, description_for_model, tools
    # Each "tools[i]" has: name, summary, parameters, returns, exceptions
    original_to_ia: dict[str, str] = {}
    ia_to_schema: dict[str, dict] = {}
    by_toolkit: dict[str, list[str]] = {}

    for tk in raw:
        tk_name = tk.get("toolkit") or tk.get("name_for_model") or ""
        if not tk_name:
            continue
        for tool in tk.get("tools", []):
            tool_name = tool.get("name", "")
            if not tool_name:
                continue
            # Upstream identifier in test cases: f"{toolkit}{tool_name}"
            orig = f"{tk_name}{tool_name}"
            # Our namespaced identifier
            ia = f"{NAMESPACE_PREFIX}{_safe(tk_name)}_{_safe(tool_name)}"
            original_to_ia[orig] = ia
            ia_to_schema[ia] = {
                "name": ia,
                "original_name": orig,
                "toolkit": tk_name,
                "description": tool.get("summary", ""),
                "category": tk.get("category", ""),
                "parameters": tool.get("parameters", []),
                "returns": tool.get("returns", []),
                "exceptions": tool.get("exceptions", []),
            }
            by_toolkit.setdefault(tk_name, []).append(ia)

    return {
        "original_name_to_ia_name": original_to_ia,
        "ia_name_to_schema": ia_to_schema,
        "by_toolkit": by_toolkit,
    }


def resolve_case_tools(case: dict) -> dict[str, Any]:
    """Given one InjecAgent case, return the IA_-namespaced tool names
    it references + the schemas.

    Returns::

        {
            "user_tool":      "IA_Amazon_GetProductDetails",
            "attacker_tools": ["IA_AugustSmartLock_GrantGuestAccess", ...],
            "missing":        []    # any upstream tool we couldn't find
        }
    """
    reg = load_injecagent_tools()
    orig_to_ia = reg["original_name_to_ia_name"]

    user_tool = orig_to_ia.get(case.get("User Tool", ""), None)
    attacker_names = case.get("Attacker Tools", []) or []
    attacker_tools = [orig_to_ia[n] for n in attacker_names if n in orig_to_ia]

    missing = []
    if case.get("User Tool") and user_tool is None:
        missing.append(("User Tool", case["User Tool"]))
    for n in attacker_names:
        if n not in orig_to_ia:
            missing.append(("Attacker Tool", n))

    return {
        "user_tool": user_tool,
        "attacker_tools": attacker_tools,
        "missing": missing,
    }


def tool_identifier_count() -> int:
    """Total IA_-prefixed tool identifiers registered."""
    return len(load_injecagent_tools()["ia_name_to_schema"])


if __name__ == "__main__":
    reg = load_injecagent_tools()
    print(f"InjecAgent isolated registry:")
    print(f"  Toolkits:          {len(reg['by_toolkit'])}")
    print(f"  IA_* tool IDs:     {len(reg['ia_name_to_schema'])}")
    print(f"  Original -> IA map entries: {len(reg['original_name_to_ia_name'])}")
    print()
    print("  Sample toolkits:")
    for tk in list(reg["by_toolkit"].keys())[:6]:
        print(f"    {tk}: {len(reg['by_toolkit'][tk])} tools")
