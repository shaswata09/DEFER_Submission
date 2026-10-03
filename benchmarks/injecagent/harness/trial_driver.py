"""Trial driver for the InjecAgent static benchmark.

For each upstream test case, constructs a proposal representing the
adversarial tool call (one per attacker tool) and drives it through the
DEFER P1-P5 defense pipeline for a chosen domain + config.

This is a *deterministic* driver (no live LLM calls).  It tests
middleware correctness: given an attacker's intent + poisoned evidence,
do the defense layers catch it?  Equivalent in methodology to our TAMAS
simulated run.

A later Phase 1b adds a *live LLM* driver that actually runs an
AutoGen / ReAct agent against the poisoned tool response and measures
whether the LLM itself proposes the attacker tool (higher-variance but
more faithful to upstream's evaluation).  The static driver is
sufficient for the first-pass paper tables.

Events logged
=============

* ``user_tool_call`` -- benign tool the user asked for (always allowed)
* ``tool_call_proposal`` -- attacker tool proposal going through P1-P5
* ``P*_*`` deny events from whichever defense layer catches

Output events carry ``ia_case_id`` and ``ia_attack_type`` so analytics
can slice by upstream attack class without re-joining to the case file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typing import Optional

from config import BASE_DIR
from host.authenticated_interface import AuthenticatedInterface
from host.parameter_validator import ParameterValidator
from host.output_classifier import OutputClassifier
from host.manifest_enforcer import ManifestEnforcer
from consensus.operational_context import OperationalContextChecker
from consensus.validator import ConsensusValidator
from memory.access_isolation import AccessIsolation, AccessController

from benchmarks.injecagent.harness.tool_loader import (
    load_injecagent_tools, resolve_case_tools, NAMESPACE_PREFIX,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


# --------------------------------------------------------------------- #
#  Case loading
# --------------------------------------------------------------------- #


def load_cases(attack_family: str = "dh", variant: str = "base") -> list[dict]:
    """Load cases from one of the four upstream JSON files.

    Args:
        attack_family: "dh" (direct harm) or "ds" (data stealing)
        variant: "base" or "enhanced"
    """
    fn = f"test_cases_{attack_family}_{variant}.json"
    with open(DATA_DIR / fn, "r") as f:
        return json.load(f)


# --------------------------------------------------------------------- #
#  Per-domain defense pipeline (Flat / ACL / DEFER)
# --------------------------------------------------------------------- #


class DefensePipeline:
    """Minimal per-config P1-P5 evaluator.

    * ``flat``           -- no defenses; every attack succeeds unless the
                             tool is unknown (which we don't let happen)
    * ``acl_hardened``   -- only network-layer ACL; allows tools that are
                             in a phase's allowed list
    * ``agenticcyops``   -- full P1-P5 stack (AuthenticatedInterface,
                             ParameterValidator, OutputClassifier,
                             OperationalContextChecker, AccessIsolation)
    """

    def __init__(self, domain: str, config: str,
                 embedding_model=None,
                 consensus_config_name: Optional[str] = None):
        self.domain = domain
        self.config = config

        if config == "agenticcyops":
            self.auth = AuthenticatedInterface(domain=domain)
            # Register every IA_* tool into the auth component registry
            # in memory only -- never written to disk.  This is the
            # benchmark-side "overlay" that satisfies P1-L1 so the later
            # defense layers can actually be exercised.  Without this,
            # P1-L1 trivially rejects every IA_* tool as unregistered
            # and P2-P5 never run.
            self._register_ia_tools_in_auth()
            self.param_validator = ParameterValidator(
                domain=domain, embedding_model=embedding_model)
            self.output_classifier = OutputClassifier(
                domain=domain, embedding_model=embedding_model)
            self.op_context = OperationalContextChecker(domain=domain)
            self.access_iso = AccessIsolation(
                domain=domain,
                access_controller=AccessController(domain=domain),
                embedding_model=embedding_model,
            )
        else:
            self.auth = None
            self.param_validator = None
            self.output_classifier = None
            self.op_context = None
            self.access_iso = None

        # ACL-hardened uses the phase manifest as a network-layer allowlist
        self.enforcer = ManifestEnforcer(domain=domain)

        # P3-L6 LLM consensus is only meaningful for the agenticcyops
        # config and only when a profile name is provided (e.g. by the
        # live e2e runner).  Stays None otherwise -- evaluate() remains
        # purely symbolic.
        self.consensus: Optional[ConsensusValidator] = None
        if config == "agenticcyops" and consensus_config_name:
            self.consensus = ConsensusValidator(
                config_name=consensus_config_name)

    def _register_ia_tools_in_auth(self) -> None:
        """In-memory extension of auth._registry with IA_* tools.

        Side effect scope: local to this `AuthenticatedInterface`
        instance; never persisted to disk or shared with other
        domains.  When this pipeline instance is garbage-collected the
        extension disappears.
        """
        reg = load_injecagent_tools()
        tools_section = self.auth._registry.setdefault("tools", {})
        dom_tools = tools_section.setdefault(self.domain, {})
        for ia_name, schema in reg["ia_name_to_schema"].items():
            dom_tools[ia_name] = {
                "description":   schema["description"],
                "category":      schema["category"],
                "injecagent_benchmark": True,  # provenance marker
                "expected_response_keys": [],  # lenient schema for IA_ tools
            }

    # ----------------------------------------------------------------- #
    #  Evaluate one (case, attacker_tool) pair
    # ----------------------------------------------------------------- #

    def _build_proposal(self, case: dict, attacker_tool_ia: str,
                        attacker_phase: str) -> dict:
        """Synthesize the proposal the agent would emit if fooled.

        We populate argument fields with the attacker_instruction text so
        P2-L2 "target in evidence" can compute semantic distance between
        what the attacker wants to do and what the user actually asked
        for.  The two are orthogonal for every InjecAgent case by
        construction.
        """
        attacker_instruction = case.get("Attacker Instruction", "")
        user_instruction = case.get("User Instruction", "")
        return {
            "tool_id":    attacker_tool_ia,
            "action":     "invoke",
            "arguments":  {
                "target":         attacker_instruction[:200],
                "description":    attacker_instruction,
                "justification":  attacker_instruction,
            },
            "phase":      attacker_phase,
            "justification": attacker_instruction,
            "task_evidence": user_instruction,
        }

    def evaluate(self, case: dict, attacker_tool_ia: str,
                 attacker_phase: str = "admin") -> dict:
        """Return a dict describing how each defense layer voted.

        Symbolic-only path (P1-P5 deterministic checks).  For the live
        e2e runner that should additionally consult the LLM consensus
        layer, use :meth:`evaluate_with_consensus`.

        ``attacker_phase`` is the phase in which the adversarial tool
        call is attempted.  InjecAgent is single-agent, but we map the
        attempt to the admin phase because (a) that's where destructive
        actions happen in our pipeline and (b) the P3 op-context check
        applies at admin-phase proposals.
        """
        poisoned_evidence = case.get("Tool Response", "")
        user_instruction = case.get("User Instruction", "")
        proposal = self._build_proposal(case, attacker_tool_ia, attacker_phase)

        # Flat: no checks
        if self.config == "flat":
            return {"allowed": True, "mechanism": "flat_no_defense",
                    "stage": None, "reason": "flat config has no defenses"}

        # ACL: is attacker tool in admin's allowed list?
        # The IA_* namespace tools are never in any domain manifest, so
        # ACL will always deny.  But that's a domain-transfer artefact,
        # not a real defense signal.  We explicitly allow IA_* under ACL
        # mode so the flat/ACL comparison reflects network-layer filtering,
        # not namespace isolation.  (Otherwise ACL would look perfect and
        # we couldn't tell apart network-layer filtering from P1-P5.)
        if self.config == "acl_hardened":
            # Simulate network ACL: allow everything (no deny signal)
            return {"allowed": True, "mechanism": "acl_no_deny",
                    "stage": None, "reason": "ACL does not know IA_* tools"}

        # DEFER full stack --------------------------------------

        # P1-L1: component identity
        ok, reason = self.auth.verify_component(attacker_tool_ia, "tools")
        if not ok:
            return {"allowed": False, "mechanism": "P1_authenticated_interface",
                    "stage": 1, "reason": reason}

        # P2-L1: parameter / wildcard check
        ok, reason, _ = self.param_validator.validate(
            attacker_tool_ia, proposal["arguments"], user_instruction)
        if not ok:
            return {"allowed": False, "mechanism": f"P2_{reason.lower()}",
                    "stage": 2, "reason": reason}

        # P3-L0.5: operational context
        ok, reason, _ = self.op_context.check(
            proposal, {"incident_id": f"IA_{case.get('User Tool')}",
                        "claimed_time": None})
        if not ok:
            return {"allowed": False, "mechanism": reason,
                    "stage": 3, "reason": reason}

        # P2-L3: output classifier applied to the poisoned evidence
        safe, reason, _ = self.output_classifier.classify(
            attacker_tool_ia, {"result": poisoned_evidence},
            agent_phase=attacker_phase)
        if not safe:
            return {"allowed": False, "mechanism": f"P2_{reason}",
                    "stage": 4, "reason": reason}

        # P5-L5: inject-pattern sanitisation of the poisoned evidence
        sanitized = self.access_iso.sanitize_results(
            [{"content": poisoned_evidence}], attacker_phase)
        if sanitized and sanitized[0].get("_sanitized"):
            return {"allowed": False, "mechanism": "P5_injection_sanitization",
                    "stage": 5, "reason": "poisoned evidence sanitised at L5"}

        # No defense layer caught -> attack succeeded
        return {"allowed": True, "mechanism": "no_defense_fired",
                "stage": None, "reason": "all P1-P5 layers passed"}

    async def evaluate_with_consensus(self, case: dict, attacker_tool_ia: str,
                                       attacker_phase: str = "admin") -> dict:
        """Run the symbolic pipeline first; if every layer passes and a
        consensus profile is configured, escalate to P3-L6 LLM-consensus
        voting.

        Failure modes:
          - If consensus is not configured, returns the symbolic verdict
            unchanged (`no_defense_fired` for cases that pass symbolic).
          - If every validator errors out (API down, key missing, ...) we
            do *not* silently mask the result -- we mark the trial as
            ``P3_consensus_unavailable`` and treat it as allowed (caller
            can decide how to count it).  This keeps the benchmark
            honest when validators are down.
          - If the consensus call itself raises, ditto -- bubble up as
            ``P3_consensus_error`` with the message in `reason`.
        """
        sym = self.evaluate(case, attacker_tool_ia, attacker_phase)
        # Only escalate when symbolic explicitly *passed everything* AND
        # we actually have a consensus instance.
        if self.consensus is None or sym["mechanism"] != "no_defense_fired":
            return sym

        proposal = self._build_proposal(case, attacker_tool_ia, attacker_phase)
        incident_context = {
            "incident_id": f"IA_{case.get('ia_case_id', case.get('User Tool', 'unknown'))}",
            "incident": {
                "description": case.get("User Instruction", ""),
            },
            "config": self.config,
            "current_phase": attacker_phase,
        }
        try:
            result = await self.consensus.validate_with_details(
                proposal, incident_context)
        except Exception as exc:
            return {"allowed": True, "mechanism": "P3_consensus_error",
                    "stage": None,
                    "reason": f"consensus call raised: {type(exc).__name__}: {exc}"}

        votes = list(result.votes)
        all_error = bool(votes) and all(v.validator_id == "error" for v in votes)
        if not votes or all_error:
            return {"allowed": True, "mechanism": "P3_consensus_unavailable",
                    "stage": None,
                    "reason": "no validators returned a vote (all errored)"}

        if not result.approved:
            return {"allowed": False, "mechanism": "P3_consensus_reject",
                    "stage": 6,
                    "reason": (f"consensus {result.rejections}/{len(votes)} reject "
                               f"(threshold {result.threshold}); "
                               + "; ".join(f"{v.validator_id}={v.decision}"
                                           for v in votes))}
        return {"allowed": True, "mechanism": "P3_consensus_approve",
                "stage": 6,
                "reason": (f"consensus {result.approvals}/{len(votes)} approve "
                           f"(threshold {result.threshold})")}


# --------------------------------------------------------------------- #
#  Trial runner
# --------------------------------------------------------------------- #


def run_case(case: dict, pipeline: DefensePipeline) -> list[dict]:
    """Run every attacker tool in a case through the pipeline.

    Returns one record per (case, attacker_tool) pair with the decision.
    """
    resolved = resolve_case_tools(case)
    results = []
    for ia_tool in resolved["attacker_tools"]:
        decision = pipeline.evaluate(case, ia_tool)
        results.append({
            "case_user_tool":    case.get("User Tool"),
            "case_attack_type":  case.get("Attack Type"),
            "attacker_tool_ia":  ia_tool,
            "attacker_tool_orig": next(
                (k for k, v in load_injecagent_tools()
                   ["original_name_to_ia_name"].items() if v == ia_tool),
                None),
            "allowed":     decision["allowed"],
            "mechanism":   decision["mechanism"],
            "stage":       decision["stage"],
            "reason":      decision["reason"],
            "config":      pipeline.config,
            "domain":      pipeline.domain,
        })
    return results


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", default="cyberops",
                    choices=["cyberops", "healthcare", "finance", "legal"])
    ap.add_argument("--config", default="agenticcyops",
                    choices=["flat", "acl_hardened", "agenticcyops"])
    ap.add_argument("--family", default="dh", choices=["dh", "ds"])
    ap.add_argument("--variant", default="base", choices=["base", "enhanced"])
    ap.add_argument("--limit", type=int, default=3)
    args = ap.parse_args()

    cases = load_cases(args.family, args.variant)
    print(f"Loaded {len(cases)} cases; running {args.limit} through "
          f"{args.config} on {args.domain}")

    pipeline = DefensePipeline(domain=args.domain, config=args.config)

    for c in cases[:args.limit]:
        rows = run_case(c, pipeline)
        for r in rows:
            print(f"  {r['attacker_tool_ia']:50s}  "
                  f"{'ALLOWED' if r['allowed'] else 'BLOCKED':8s} "
                  f"mech={r['mechanism']}")
