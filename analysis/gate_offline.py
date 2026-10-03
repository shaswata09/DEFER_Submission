"""Evaluate the deterministic approve gate offline on every logged proposal.

In the main runs the approve gate never decided (the scorer defect pins
alignment and precedent at 0.5), so every proposal that survived the
deterministic P3 layers went to the panel. Those are exactly the proposals a
working gate would have seen. The gate is deterministic and its inputs are
reproducible from the log: scope from the proposal's targets, reversibility
from the static table, proportionality from both (P3's context carries no
severity or asset count before v3.1, so the scorer's defaults apply; the
v3.1+ host adds severity and the hoisted implied action). This module
re-scores each of them with the shipped ``ProposalScorer`` and ``AutoGates``
and reports what the gate would have done: in-sample on the CyberOps
development domain, out of sample on the three transfer domains.

The security question is whether the gate would approve an attack proposal
the panel rejected: that proposal would then have executed.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from analysis.p3_eligibility import JUDGED_PATHS, _payload, call_path, trials
from attacks.effects import build_calls, evaluate_effects
from consensus.auto_gates import AutoGates
from consensus.scoring import ProposalScorer

DOMAINS = ("cyberops", "healthcare", "finance", "legal")
_HOIST = ("action", "target", "target_user", "target_hosts", "target_users",
          "account_id", "patient_id", "case_id")


def p3_proposal(call, phase: str, live: bool = False) -> dict:
    """The proposal dict P3 builds (orchestrator: to_proposal + phase + hoisted
    fields). ``live``: the v3.1+ host's hoist, which also sets single-action
    tools' implied action and a fallback target (analysis.reported.hoists_live);
    without it a v3.1 proposal is rebuilt without fields the run had."""
    args = dict(call.arguments or {})
    p = {"tool_id": call.target, "arguments": args, "phase": phase}
    if live:
        from host.orchestrator import _hoist
        return _hoist(p)
    for f in _HOIST:
        if f in args and f not in p:
            p[f] = args[f]
    return p


_SCORE_KEYS = ("alignment", "scope", "reversibility", "precedent", "proportionality")


def logged_scores(call, events: list[dict]) -> dict | None:
    """The five risk scores the run computed for this call (logged from
    defense-freeze-v2.6 on, ``P3_L1_scores`` / ``P3_L2_scores``), or ``None``.
    From v3.1 the live scorer also had the incident's severity and the hoisted
    implied action, which an offline re-score without that context misses."""
    end = call.decision_seq if call.decision_seq >= 0 else len(events)
    for e in events[call.seq:end + 1]:
        if e.get("action") in ("P3_L1_scores", "P3_L2_scores") and all(k in e for k in _SCORE_KEYS):
            return {k: float(e[k]) for k in _SCORE_KEYS}
    return None


def evaluate(group: str = "q235_div4", config: str = "agenticcyops", mode: str = "permissive",
             domains=DOMAINS, suffix: str = "") -> dict:
    from analysis.reported import hoists_live
    gate = AutoGates(mode=mode)
    live = hoists_live(group)
    out: dict = defaultdict(Counter)
    flagged: list[dict] = []
    for d in domains:
        scorer = ProposalScorer(domain=d)
        for tid, events in trials(group, d, config, suffix).items():
            benign = "_benign_" in tid
            calls = build_calls(events)
            attack_ids: set[str] = set()
            if not benign:
                p = _payload(d, tid)
                if p:
                    attack_ids = set(evaluate_effects(p[1], events, config=config).attempted_call_ids or [])
            for c in calls:
                path = call_path(c, events)
                if path not in JUDGED_PATHS:
                    continue                  # never reached the gate
                scores = logged_scores(c, events) or scorer.score(p3_proposal(c, c.phase, live), {})
                decided, reason, det = gate.evaluate(scores)
                approve = decided and det.get("approved")
                role = "benign" if benign else ("attack_effect" if c.call_id in attack_ids else "attack_other")
                key = (d, role)
                out[key]["reached_gate"] += 1
                out[key]["gate_approves"] += bool(approve)
                out[key]["gate_denies"] += bool(decided and not det.get("approved"))
                if approve and path == "p3_panel_rejected":
                    out[key]["approved_by_gate_rejected_by_panel"] += 1
                    if role == "attack_effect":
                        flagged.append({"trial_id": tid, "tool": c.target, "scores": scores})
    return {"counts": {f"{d}|{r}": dict(v) for (d, r), v in out.items()}, "flagged": flagged}


# ---------------------------------------------------------------------------
# Trial-level simulation: what attack success and benign cost would have been
# had a given gate decided before the panel. Each proposal that reached the
# gate is re-scored; where the gate decides, its decision replaces the
# logged one, and the oracle re-scores the trial. This is a direct outcome:
# it uses the proposals that were actually made and cannot show what the
# agents would have proposed next had a decision changed.
# ---------------------------------------------------------------------------

def _incident(domain: str, trial_id: str) -> dict:
    from attacks.harness import load_payloads
    parts = trial_id.split("_")
    ap, variant = parts[1], int(parts[2].lstrip("v"))
    if ap == "benign":
        payloads = load_payloads(domain, "benign_alerts.json") or load_payloads(domain, "benign_workflows.json")
    else:
        payloads = load_payloads(domain, f"{ap}_variants.json")
    return (payloads[variant - 1] or {}).get("trigger", {}) if 0 < variant <= len(payloads) else {}


def simulate(mode: str = "permissive", fixed_scorer: bool = False, group: str = "q235_div4",
             config: str = "agenticcyops", domains=DOMAINS, embedding_model=None) -> dict:
    """Per domain: attack success as run and with the gate (direct), and benign
    proposal decisions the gate would flip.

    With ``fixed_scorer`` the scorer gets what the wiring defect withheld: the
    incident evidence (JSON of the incident, as P2 uses it) for alignment, and
    a ledger of the approvals made earlier in the same trial for precedent.
    """
    import copy
    from analysis.reported import hoists_live
    gate = AutoGates(mode=mode)
    live = hoists_live(group)
    out: dict = {}
    for d in domains:
        scorer = ProposalScorer(domain=d, embedding_model=embedding_model if fixed_scorer else None)
        dom = Counter()
        for tid, events in trials(group, d, config).items():
            benign = "_benign_" in tid
            calls = build_calls(events)
            evidence = __import__("json").dumps(_incident(d, tid), default=str) if fixed_scorer else ""
            ledger: list[dict] = []
            ev = copy.deepcopy(events)
            for c in calls:
                path = call_path(c, events)
                if path not in JUDGED_PATHS:
                    continue
                prop = p3_proposal(c, c.phase, live)
                scorer._ledger = ledger if fixed_scorer else None
                scores = ((None if fixed_scorer else logged_scores(c, events))
                          or scorer.score(prop, {"incident_evidence": evidence} if fixed_scorer else {}))
                decided, _reason, det = gate.evaluate(scores)
                approved = path == "p3_panel_approved"
                if decided:
                    approved = bool(det.get("approved"))
                    dom[("benign" if benign else "attack") + ("_gate_approve" if approved else "_gate_deny")] += 1
                    # a rule after the panel decided a p3_rule_after_panel call; the gate cannot undo it
                    if (c.decision_seq >= 0 and path != "p3_rule_after_panel"
                            and approved != (path == "p3_panel_approved")):
                        ev[c.decision_seq]["auth_decision"] = "allow" if approved else "deny"
                        dom[("benign" if benign else "attack") + "_flipped_" + ("to_allow" if approved else "to_deny")] += 1
                dom[("benign" if benign else "attack") + "_reached_gate"] += 1
                if approved:
                    ledger.append({"proposal": {"tool_id": prop["tool_id"], "action": prop.get("action", "")},
                                   "decision": "approve"})
            if benign:
                continue
            p = _payload(d, tid)
            if not p:
                continue
            base = evaluate_effects(p[1], events, config=config)
            if base.outcome not in ("executed", "blocked", "not_attempted"):
                continue
            new = evaluate_effects(p[1], ev, config=config)
            dom["n"] += 1
            dom["executed_as_run"] += base.outcome == "executed"
            dom["executed_with_gate"] += new.outcome == "executed"
        out[d] = dict(dom)
    return out
