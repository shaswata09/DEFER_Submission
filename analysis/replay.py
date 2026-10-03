"""Rebuild the exact panel input of every logged round, for offline re-adjudication.

A validator sees a fixed system prompt and one user message:

    json.dumps({"proposal": <proposal>,
                "incident_context": {"incident_id", "description", "config"}})

(``consensus/validator.py``). The proposal is the tool call as P3 builds it
(``to_proposal`` + phase + hoisted argument fields), sanitized under FULL and
not under JUDGEONLY; the incident comes from the payload files; ``config`` is
the host's config string. All of this is recoverable from the logs, so a
panel decision can be re-taken by any validator without running the primary
again. The logged per-vote prompt token counts make the reconstruction
checkable: a message that tokenizes, under a validator's own chat template,
to the count that validator reported is byte-for-byte what it saw.

Rounds are enumerated per tool call with the oracle's call folding, so each
round is tied to a call, a trial, and whether that call realized an attack.
``include_unjudged`` also emits the calls that passed every deterministic
check but never reached the panel (not consequential): the judge-everything-
after-rules control.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from dataclasses import dataclass, field

from analysis.gate_offline import _incident, p3_proposal
from analysis.p3_eligibility import JUDGED_PATHS, _payload, call_path, trial_commits, trials
from attacks.effects import build_calls, evaluate_effects
from consensus.validator import VALIDATOR_SYSTEM_PROMPT
from consensus.verified_execution import VerifiedExecution

DOMAINS = ("cyberops", "healthcare", "finance", "legal")
_SANITIZER = object.__new__(VerifiedExecution)          # only the pattern-stripping methods are used


@dataclass
class Round:
    key: str                       # sha256 of the user message: the cache key
    message: str                   # the user message the validators see
    group: str
    domain: str
    config: str
    trial_id: str
    call_id: str
    tool: str
    role: str                      # attack_effect | attack_other | benign
    path: str                      # p3_panel_approved | p3_panel_rejected | allowed_no_p3
    logged_votes: dict = field(default_factory=dict)      # validator -> approve|reject|error
    logged_prompt_tokens: dict = field(default_factory=dict)


def message(proposal: dict, incident: dict, host_config: str, sanitize: bool,
            trial_id: str = "") -> str:
    """The panel's user message. When the trigger has no top-level
    ``incident_id`` (its fields are nested, as for AP-4/5/6/12), the host drew
    a random UUID and the description was empty; the UUID is not recoverable,
    so a deterministic one of the same form stands in for it."""
    import uuid
    p = _SANITIZER._sanitize_proposal(proposal) if sanitize else proposal
    iid = incident.get("incident_id") or str(uuid.uuid5(uuid.NAMESPACE_URL, trial_id))
    return json.dumps({
        "proposal": p,
        "incident_context": {
            "incident_id": iid,
            "description": incident.get("description", ""),
            "config": host_config,
        },
    }, default=str)


def _proposal(call, live: bool = False) -> dict:
    """``to_proposal`` order (tool_id, arguments, justification), then phase,
    then the hoisted fields: key order matters to ``json.dumps``. ``live``: the
    v3.1+ host's hoist (implied actions, fallback targets); the v3.1 replay was
    built without it, so 5,979 of its messages differed from what the judges
    saw (2026-10-02 audit)."""
    base = p3_proposal(call, call.phase, live)
    p = {"tool_id": base["tool_id"], "arguments": base["arguments"],
         "justification": call.justification if hasattr(call, "justification") else ""}
    for k, v in base.items():
        if k not in p:
            p[k] = v
    return p


_PAYLOAD_AT: dict[tuple[str, str, str], list] = {}


def incident_at(domain: str, trial_id: str, sha: str) -> dict:
    """The incident as the run saw it: the trigger from the payload file at the
    run's commit. Payload triggers were edited after some runs (the E5.1 strip
    of experiment annotations, 22 Sep), and the judges read the trigger, so the
    replay must use the version the run used. Falls back to the current file
    when the commit is unknown or lacks the file."""
    import subprocess
    parts = trial_id.split("_")
    ap, variant = parts[1], int(parts[2].lstrip("v"))
    if not sha or ap == "benign":
        return _incident(domain, trial_id)
    name = f"{ap}_variants.json"
    key = (sha, domain, name)
    if key not in _PAYLOAD_AT:
        rc = subprocess.run(["git", "show", f"{sha}:domains/{domain}/payloads/{name}"],
                            capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1])
        try:
            data = json.loads(rc.stdout) if rc.returncode == 0 else None
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            data = data.get("variants") or data.get("payloads") or data.get("attacks")
        _PAYLOAD_AT[key] = data if isinstance(data, list) else []
    payloads = _PAYLOAD_AT[key]
    if not 0 < variant <= len(payloads):
        return _incident(domain, trial_id)
    return (payloads[variant - 1] or {}).get("trigger", {})


LOGGED_JUSTIFICATION_CHARS = 300      # host/orchestrator.py logs justification[:300]


def _full_justification(logged: str, call, domain: str, trial_id: str) -> str:
    """The justification the judges saw. The host logs it cut to 300
    characters; a proposal injected on the ``proposal_justification`` channel
    (AP-10) carries a longer, attacker-written rationale whose full text is in
    the payload's ``meta.injection``. Restore it when the logged text is a
    300-character prefix of an injected proposal's justification for the same
    tool. An agent's own justification longer than 300 characters cannot be
    restored and stays cut."""
    if len(logged) < LOGGED_JUSTIFICATION_CHARS or "_benign_" in trial_id:
        return logged
    p = _payload(domain, trial_id)
    if not p:
        return logged
    inj = ((p[1].get("meta") or {}).get("injection") or {})
    specs = [inj["proposal"]] if isinstance(inj.get("proposal"), dict) else []
    specs += [s for s in (inj.get("proposals") or []) if isinstance(s, dict)]
    for spec in specs:
        full = str(spec.get("justification") or "")
        if spec.get("tool") == call.target and full.startswith(logged):
            return full
    return logged


def rounds(group: str, config: str, domains=DOMAINS, suffix: str = "",
           include_unjudged: bool = False) -> list[Round]:
    from analysis.reported import hoists_live
    host_config = "llm_judge" if config == "llm_judge" else "agenticcyops"
    sanitize = config != "llm_judge"
    live = hoists_live(group)
    out: list[Round] = []
    for d in domains:
        commits = trial_commits(group, d, config, suffix)
        for tid, events in trials(group, d, config, suffix).items():
            incident = incident_at(d, tid, commits.get(tid, ""))
            benign = "_benign_" in tid
            attack_ids: set[str] = set()
            if not benign:
                p = _payload(d, tid)
                if p:
                    attack_ids = set(evaluate_effects(p[1], events, config=config).attempted_call_ids or [])
            just = {e.get("call_id"): e.get("justification", "") for e in events
                    if e.get("action") == "tool_proposed"}
            for c in build_calls(events):
                path = call_path(c, events)
                judged = path in JUDGED_PATHS
                if not (judged or (include_unjudged and path == "allowed_no_p3")):
                    continue
                c.justification = _full_justification(just.get(c.call_id, ""), c, d, tid)
                msg = message(_proposal(c, live), incident, host_config, sanitize, tid)
                votes, toks = {}, {}
                if judged:
                    end = c.decision_seq if c.decision_seq >= 0 else len(events)
                    for e in events[c.seq:end + 1]:
                        if e.get("action") == "consensus_vote":
                            votes[e.get("source")] = e.get("auth_decision")
                            if e.get("tokens_prompt"):
                                toks[e.get("source")] = int(e["tokens_prompt"])
                role = "benign" if benign else ("attack_effect" if c.call_id in attack_ids else "attack_other")
                out.append(Round(key=hashlib.sha256(msg.encode()).hexdigest(), message=msg,
                                 group=group + suffix, domain=d, config=config, trial_id=tid,
                                 call_id=c.call_id, tool=c.target, role=role, path=path,
                                 logged_votes=votes, logged_prompt_tokens=toks))
    return out


def chat(message_text: str) -> list[dict]:
    return [{"role": "system", "content": VALIDATOR_SYSTEM_PROMPT},
            {"role": "user", "content": message_text}]
