"""The runs every reported number comes from, in one place.

After the 2026-10-02 audit the reported boundary is a composition:

* CyberOps: ``defense-freeze-v3.2`` (the high-severity defense fixes), every
  configuration re-run (group ``q235_local2_v32``).
* Healthcare, finance, legal: ``defense-freeze-v3.1`` (``q235_local2_v31``),
  with the cells the harness fixes of ``defense-freeze-v3.1.4`` changed re-run
  at v3.1.4 (``q235_local2_v314``): AP-9 under every configuration (its handoff
  content now reaches the next agent) and JUDGEONLY on every path (it now sees
  every tool). Their defense code is v3.1's, so each domain has one defense.

``REPORTED`` is a virtual group: :func:`analysis.runlogs.run_logs` resolves it
to the member groups' log files, oldest first, so the trial-level readers
(newest file wins) take the v3.1.4 trial wherever one exists. Every analysis
reads the reported boundary through it.

The leave-one-out arms and the two other primaries were re-run in CyberOps at
v3.2. Persistent state was not re-run (``defense-freeze-v3.1``).
"""
from __future__ import annotations

REPORTED = "q235_local2_rep"
DOMAINS = ("cyberops", "healthcare", "finance", "legal")
COMPOSITION = {
    "cyberops": ("q235_local2_v32",),
    "healthcare": ("q235_local2_v31", "q235_local2_v314"),
    "finance": ("q235_local2_v31", "q235_local2_v314"),
    "legal": ("q235_local2_v31", "q235_local2_v314"),
}
# which defense each domain's reported cells ran
FREEZE = {"cyberops": "defense-freeze-v3.2", "healthcare": "defense-freeze-v3.1",
          "finance": "defense-freeze-v3.1", "legal": "defense-freeze-v3.1"}
ABLATION = {i: f"q235_local2_disabled_P{i}_v32" for i in range(1, 6)}
PRIMARIES = {"gpt-oss-120b": "oss120_local2_v32", "Llama-3.1-8B": "llama8b_local2_v32"}
PERSIST = ("q235_local2_v31persist", "q235_local2_v31persist2")
# the boundary before the audit (every domain at v3.1), kept for comparison
PREVIOUS = "q235_local2_v31"

# groups whose runs carry the E2 rule-evading siblings next to the 75
# reported variants per domain (analyses drop the siblings except where named)
SIBLING_GROUPS_SUFFIXES = ("_v31", "_v314", "_v32", "_rep")


def carries_siblings(group: str) -> bool:
    return any(group.endswith(s) for s in SIBLING_GROUPS_SUFFIXES)


def member_for(domain: str, ap: str, config: str) -> str:
    """The actual group a reported (domain, ap, config) cell comes from."""
    if domain == "cyberops":
        return "q235_local2_v32"
    if config == "llm_judge" or ap == "ap9":
        return "q235_local2_v314"
    return "q235_local2_v31"


# the host of defense-freeze-v3.1 and later hoists implied actions and fallback
# targets onto the proposal (host.orchestrator._hoist); what a judge or a P3
# layer saw must be rebuilt the same way for these runs, the plain way before
LIVE_HOIST_SUFFIXES = ("_v31", "_v31persist", "_v31persist2", "_v314", "_v32", "_rep")


def hoists_live(group: str) -> bool:
    return any(group.endswith(s) for s in LIVE_HOIST_SUFFIXES)
