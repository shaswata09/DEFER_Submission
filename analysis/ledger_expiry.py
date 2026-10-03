"""Expiry and identity policies for the stateful P3 checks, replayed offline.

Under persistent state the pipeline collapses because two deterministic,
stateful checks accumulate the attack incidents' actions:

    P3.4  cross-incident ledger: same target in >= 3 other incidents, same
          (tool, action) >= 10 times, or >= 8 destructive actions, within a
          24-hour window;
    P3.6  structural replay: a proposal whose skeleton (tool, argument
          names, action) matches one approved in any earlier incident, with
          no window at all.

A 50-incident sequence runs in about an hour, so neither window ever expires
in the experiment. This module replays the logged sequence of consequential
proposals through both checks under alternative policies and counts their
denials. Each policy is applied to the same proposals in the same order, so
the counts are exact for the first denial; what a released proposal would
have met next (the panel) is reported separately.

Policies
    window N     keep only the entries of the last N incidents (N=None: never expire)
    identity     structural replay keyed on (tool, action, target) instead of the skeleton
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter

from analysis.p3_eligibility import trials
from analysis.gate_offline import p3_proposal
from attacks.effects import build_calls

_HOIST_TARGETS = ("target", "target_user", "target_hosts", "target_users",
                  "account_id", "patient_id", "case_id")
DESTRUCTIVE = {"delete", "wipe", "terminate", "disable", "revoke", "purge", "destroy",
               "shutdown", "delete_rule", "reset", "quarantine", "isolate", "block_ip", "lock"}


def _target(p: dict):
    for f in _HOIST_TARGETS:
        v = p.get(f) or (p.get("arguments") or {}).get(f)
        if v:
            return json.dumps(v, sort_keys=True) if isinstance(v, (list, dict)) else str(v)
    return None


def _skeleton(p: dict, identity: bool) -> str:
    args = p.get("arguments") or {}
    sk = {"tool": p.get("tool_id", ""), "action": args.get("action")}
    if identity:
        sk["target"] = _target(p)
    else:
        sk["keys"] = sorted(args.keys())
    return hashlib.sha256(json.dumps(sk, sort_keys=True).encode()).hexdigest()


def sequence(group: str, domain: str, config: str = "agenticcyops") -> list[tuple]:
    """(trial_id, log file, incident_id, [item, ...]) in run order, one item per
    proposal that reached the stateful checks: the proposal as the host built
    it, its logged L4/L5 outcome, and whether P3 approved it.

    Faithful to the run (2026-10-02 audit): the ledgers are in-memory, so they
    start empty in every harness process (one per log file); the context id is
    the trigger's ``incident_id``; the proposal carries its justification and,
    for v3.1+ runs, the host's hoisted fields. The earlier version replayed one
    ledger across all processes with the trial id as incident id and agreed with
    the logged outcomes on 58 of 165 proposals."""
    from analysis.gate_offline import _incident
    from analysis.reported import hoists_live
    from analysis.runlogs import run_logs
    live = hoists_live(group)
    file_of: dict[str, str] = {}
    for f in run_logs(group, domain, config):
        with open(f, errors="ignore") as fh:
            for ln in fh:
                if '"trial_id"' in ln:
                    try:
                        file_of.setdefault(json.loads(ln)["trial_id"], str(f))
                    except (json.JSONDecodeError, KeyError):
                        pass
    ts = trials(group, domain, config)
    order = sorted(ts, key=lambda t: ts[t][0].get("timestamp", ""))
    out = []
    for tid in order:
        events = ts[tid]
        just = {e.get("call_id"): e.get("justification", "") for e in events
                if e.get("action") == "tool_proposed"}
        items = []
        for c in build_calls(events):
            if c.kind != "tool":
                continue
            end = c.decision_seq if c.decision_seq >= 0 else len(events)
            win = events[c.seq:end + 1]
            # the layer verdicts are the reliable markers: the L4 ledger's own
            # log event carries the tool's ``action`` in its details, which
            # overwrites the event's ``action`` field
            reached = any(e.get("action") == "P3_L3_assess" and e.get("auth_decision") == "allow"
                          for e in win)
            if not reached:
                continue                                    # never reached the stateful checks
            verdict = {e.get("mechanism") for e in win if e.get("action") == "consensus_result"}
            logged = ("L4" if "P3_cross_incident" in verdict else
                      "L5" if "P3_replay_detection" in verdict else "pass")
            p3ok = any(e.get("action") == "consensus_result"
                       and e.get("auth_decision") in ("approved", "allow") for e in win)
            prop = {"tool_id": c.target, "arguments": dict(c.arguments or {}),
                    "justification": just.get(c.call_id, "")}
            prop = {**prop, **{k: v for k, v in p3_proposal(c, c.phase, live).items()
                               if k not in ("tool_id", "arguments")}}
            items.append({"proposal": prop, "logged": logged, "p3ok": p3ok})
        out.append((tid, file_of.get(tid, ""), _incident(domain, tid).get("incident_id", tid), items))
    return out


def simulate(seq, window: int | None, identity: bool, upper: bool = False) -> dict:
    """Replay the sequence through the shipped ``CrossIncidentLedger`` (P3.4)
    and ``VersionedLedger`` (P3.6), in order, with fresh ledgers at every
    process boundary. Expiry prunes the entries of incidents older than
    ``window``; ``identity`` keys the replay check on (tool, action, target).

    A proposal the stateful checks release is recorded as approved when P3
    approved it in the run (a lower bound on the state a policy leaves); with
    ``upper`` also when the run denied it statefully, since it might then have
    been approved (an upper bound)."""
    import asyncio
    from consensus.cross_incident_ledger import CrossIncidentLedger
    from consensus.versioned_ledger import VersionedLedger

    c = Counter()
    index: dict[str, int] = {}
    l4 = l5 = None
    current = None
    for i, (tid, f, iid, items) in enumerate(seq):
        if f != current or l4 is None:
            l4, l5, current, index = CrossIncidentLedger(), VersionedLedger(), f, {}
            if identity:
                l5._hash_structural = lambda prop: _skeleton(prop, identity=True)
        index[iid] = i
        if window is not None:
            l4._ledger = [e for e in l4._ledger if i - index.get(e["incident_id"], i) <= window]
            for h in [h for h, r in l5._ledger.items() if i - index.get(r["incident_id"], i) > window]:
                del l5._ledger[h]
        kind = "benign" if "_benign_" in tid else "attack"
        c[kind + "_incidents"] += 1
        ctx = {"incident_id": iid}
        denied_here = 0
        for it in items:
            p, logged = it["proposal"], it["logged"]
            c[f"{kind}_consequential"] += 1
            c[f"{kind}_logged_{logged}"] += 1
            ok4, _r, _d = asyncio.run(l4.check_and_record(p, ctx))
            reason = None if ok4 else "L4"
            if reason is None:
                ok5, _r, _d = l5.check_replay(p, ctx)
                reason = None if ok5 else "L5"
            c[f"{kind}_agree"] += (reason or "pass") == logged
            if reason:
                c[f"{kind}_denied_{reason}"] += 1
                denied_here += 1
            elif it["p3ok"] or (upper and logged != "pass"):
                l5.record(p, ctx)
        c[f"{kind}_incidents_with_stateful_denial"] += denied_here > 0
    return dict(c)
