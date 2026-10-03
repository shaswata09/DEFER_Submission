"""Which tool calls ever reached verified execution (P3), and how they left it.

Only calls that the phase manifest marks as requiring verification, or whose
(tool, action) pair has negative impact in the static impact table, enter P3.
Every other in-manifest call that passes P1 and P2 executes with no panel
involvement: that is deterministic approval by classification, and the
judged fraction depends on it. This module attributes every logged tool call
to exactly one path, using the oracle's own call folding
(``attacks.effects.build_calls``), and traces each executed attack to the path
that let it through.

Paths
    denied_before_p3   P1 or P2 denied it
    p3_denied_rule     a deterministic P3 layer denied it
    p3_panel_approved  the panel approved it
    p3_panel_rejected  the panel rejected it
    p3_rule_after_panel  the panel approved it and a later rule denied or
                       escalated it (bulk-action cap, P1 response integrity,
                       pre-execution hash); the panel did not decide it
    allowed_no_p3      allowed without entering P3 (not consequential)
    other              no decision logged (e.g. the incident ended first)
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict

from analysis.runlogs import run_logs
from attacks.effects import Call, build_calls, evaluate_effects
from attacks.harness import load_payloads

DOMAINS = ("cyberops", "healthcare", "finance", "legal")
# the paths on which the panel judged the call
JUDGED_PATHS = ("p3_panel_approved", "p3_panel_rejected", "p3_rule_after_panel")


def trials(group: str, domain: str, config: str, suffix: str = "") -> dict[str, list[dict]]:
    """``trial_id -> events`` for one cell; the newest log carrying a trial wins."""
    per: dict[tuple[str, str], list[dict]] = defaultdict(list)
    newest: dict[str, str] = {}
    for f in run_logs(group, domain, config, suffix=suffix):
        seen = set()
        with open(f, errors="ignore") as fh:
            for ln in fh:
                try:
                    e = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                tid = e.get("trial_id")
                if not tid:
                    continue
                if tid not in seen:
                    seen.add(tid)
                    newest[tid] = str(f)
                per[(tid, str(f))].append(e)
    return {tid: per[(tid, f)] for tid, f in newest.items()}


def trial_commits(group: str, domain: str, config: str, suffix: str = "") -> dict[str, str]:
    """``trial_id -> git_sha`` of the run that produced the events ``trials``
    returns for it (same newest-log rule)."""
    out: dict[str, str] = {}
    for f in run_logs(group, domain, config, suffix=suffix):
        sha = ""
        with open(f, errors="ignore") as fh:
            for ln in fh:
                try:
                    e = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                if e.get("action") == "run_header":
                    sha = e.get("git_sha") or ""
                elif e.get("trial_id"):
                    out[e["trial_id"]] = sha
    return out


def call_path(call: Call, events: list[dict]) -> str:
    """The single path a tool call took, from the events between its
    proposal and its decision."""
    if call.kind != "tool":
        return "other"
    end = call.decision_seq if call.decision_seq >= 0 else len(events)
    window = events[call.seq:end + 1]
    entered_p3 = any(str(e.get("action", "")).startswith("P3_L") for e in window)
    panel = [e for e in window if e.get("action") == "consensus_result" and e.get("votes")]
    if call.decision in ("deny", "escalate", "denied"):
        if panel:
            if panel[-1].get("auth_decision") == "approved":
                return "p3_rule_after_panel"
            return "p3_panel_rejected"
        return "p3_denied_rule" if entered_p3 else "denied_before_p3"
    if call.allowed:
        if panel:
            return "p3_panel_approved"
        return "allowed_no_p3" if not entered_p3 else "p3_allowed_no_panel"
    return "other"


def _payload(domain: str, trial_id: str) -> tuple[str, dict] | None:
    # <domain>_<ap>_v<variant>_t<trial>_<config>
    parts = trial_id.split("_")
    ap, variant = parts[1], int(parts[2].lstrip("v"))
    if ap == "benign":
        return None
    payloads = load_payloads(domain, f"{ap}_variants.json")
    if not 0 < variant <= len(payloads):
        return None
    return ap, payloads[variant - 1]


def paths(group: str, config: str, domains=DOMAINS, suffix: str = "") -> dict:
    """Path counts of every tool call (attack and benign incidents), and the
    path of every call that executed an attack effect."""
    all_calls: dict[str, Counter] = {"attack": Counter(), "benign": Counter()}
    executed: list[dict] = []
    for d in domains:
        for tid, events in trials(group, d, config, suffix).items():
            kind = "benign" if "_benign_" in tid else "attack"
            calls = build_calls(events)
            for c in calls:
                if c.kind == "tool":
                    all_calls[kind][call_path(c, events)] += 1
            if kind != "attack":
                continue
            p = _payload(d, tid)
            if p is None:
                continue
            ap, payload = p
            verdict = evaluate_effects(payload, events, config=config)
            if verdict.outcome != "executed":
                continue
            ids = set(verdict.executed_call_ids or [])
            by_id = {c.call_id: c for c in calls}
            hit = [by_id[i] for i in ids if i in by_id] or []
            executed.append({"trial_id": tid, "domain": d, "ap": ap,
                             "calls": [(c.kind, c.target, call_path(c, events)) for c in hit]})
    return {"calls": all_calls, "executed": executed}
