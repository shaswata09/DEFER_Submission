"""P2.2 (target in evidence) with the evidence restricted to trusted fields.

P2.2 allows a proposal's target when it appears in the incident evidence, or
when its embedding is within cosine 0.5 of it. The evidence is the JSON of
the whole incident, including free text the attacker writes on the
task-input channel, so an attacker who names the target in the alert
satisfies the rule. This module re-runs the shipped ``ParameterValidator``
on every logged tool call twice: with the full incident (reproducing the
logged decisions) and with only the structured fields (identifiers,
addresses, indicators, assets, timestamps, severities), and reports which
interceptions survive and what the restriction costs benign incidents.
"""
from __future__ import annotations

import json
from collections import Counter

from analysis.gate_offline import _incident
from analysis.p3_eligibility import _payload, trials
from attacks.effects import build_calls, evaluate_effects
from host.parameter_validator import ParameterValidator

DOMAINS = ("cyberops", "healthcare", "finance", "legal")
# free text, and harness-supplied proposals: content an attacker can write
UNTRUSTED_KEYS = {"description", "notes", "summary", "resolution_summary", "reason",
                  "payload", "message", "details", "narrative", "body", "comment",
                  "proposed_action", "proposed_actions"}


def trusted(obj):
    if isinstance(obj, dict):
        return {k: trusted(v) for k, v in obj.items()
                if k not in UNTRUSTED_KEYS and k != "memory_ops"}
    if isinstance(obj, list):
        return [trusted(v) for v in obj]
    return obj


def shipped_embedding_model():
    """The embedding model the harness gives P2.2 (attacks/harness.py)."""
    from sentence_transformers import SentenceTransformer
    from config import MODELS_DIR
    return SentenceTransformer(str(MODELS_DIR / "Qwen" / "Qwen3-Embedding-0.6B"), device="cpu")


def evaluate(group: str = "q235_div4", config: str = "agenticcyops", domains=DOMAINS,
             embedding_model="shipped", skip=None) -> dict:
    """``embedding_model``: the shipped model by default. Without one, P2.2 is
    substring-only and does not reproduce the logged decisions (every logged
    P2.2 denial is the cosine branch's; 2026-10-02 audit). ``skip``: trial ids
    to leave out (the E2 siblings)."""
    if embedding_model == "shipped":
        embedding_model = shipped_embedding_model()
    out: dict = {}
    for d in domains:
        pv = ParameterValidator(domain=d, embedding_model=embedding_model)
        c = Counter()
        for tid, events in trials(group, d, config).items():
            if skip and skip(tid):
                continue
            incident = _incident(d, tid)
            full_ev = json.dumps(incident, default=str)
            trusted_ev = json.dumps(trusted(incident), default=str)
            benign = "_benign_" in tid
            attack_ids: set[str] = set()
            if not benign:
                p = _payload(d, tid)
                if p:
                    attack_ids = set(evaluate_effects(p[1], events, config=config).attempted_call_ids or [])
            for call in build_calls(events):
                if call.kind != "tool":
                    continue
                # P2.2 denials are logged under the P2 mechanism with the
                # parameter check's reason in ``p2l2_reason``; a P2 denial
                # without it is the manifest (P2.1), and P1 denials never reach
                # P2.2. Denials by P2.2's earlier sub-checks (wildcard,
                # criticality, parameter rules) never reach the evidence test.
                p2l2 = (call.decision_event or {}).get("p2l2_reason")
                if call.mechanism == "P1_authenticated_interface" or (
                        call.mechanism == "P2_capability_scoping" and call.denied and not p2l2):
                    continue
                if p2l2 and p2l2 != "P2_target_not_in_evidence":
                    continue
                role = "benign" if benign else ("attack" if call.call_id in attack_ids else "other")
                args = call.arguments or {}
                ok_full, why_full, _ = pv._check_target_evidence(call.target, args, full_ev)
                ok_tr, why_tr, _ = pv._check_target_evidence(call.target, args, trusted_ev)
                logged_deny = p2l2 == "P2_target_not_in_evidence"
                c[(role, "calls")] += 1
                c[(role, "denied_full")] += not ok_full
                c[(role, "denied_trusted")] += not ok_tr
                c[(role, "logged_p2_2_denial")] += logged_deny
                c[(role, "reproduces_logged")] += (not ok_full) == logged_deny
        out[d] = {f"{r}|{k}": v for (r, k), v in c.items()}
    return out
