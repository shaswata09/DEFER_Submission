"""What the LLM panel sees (defense-freeze-v3.0).

Up to v2.9 a validator received the sanitized proposal and three fields of
the incident: its id, its free-text description, and the configuration name.
It did not see the incident's structured fields, the calling agent's role and
allowed tools, the operating context the deterministic checks consult, or
what had already happened in the incident, although the validator prompt asks
it to judge consistency with the evidence, scope, and proportionality.

``build_panel_message`` is the single place that builds the panel's input. It
keeps the v2.9 fields and adds:

    evidence           the incident's structured fields; free text an attacker
                       can write (notes, summaries, harness proposals) is left
                       out, as in the trusted-evidence restriction of P2.2
    agent              the calling phase, its allowed tools, and whether its
                       manifest requires verification
    operating_context  for the proposal's targets: asset criticality,
                       maintenance windows, open change requests, and the time
                       policy for the (tool, action) pair
    prior_actions      the consequential proposals already decided in this
                       incident, with their outcome

Offline re-adjudication (``analysis.replay_v3``) calls the same function, so
the live and replayed inputs cannot drift apart.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

CONFIGS = Path(__file__).resolve().parents[1] / "domains"
# free text and harness-supplied content an attacker can write
UNTRUSTED_KEYS = {"description", "notes", "summary", "resolution_summary", "reason", "payload",
                  "message", "details", "narrative", "body", "comment", "proposed_action",
                  "proposed_actions", "memory_ops"}
TARGET_KEYS = ("target", "target_user", "target_hosts", "target_users", "account_id", "patient_id",
               "case_id", "hostname", "host", "ip", "ip_address", "user", "username", "asset", "account")
MAX_PRIOR = 10


def trusted(obj):
    if isinstance(obj, dict):
        return {k: trusted(v) for k, v in obj.items() if k not in UNTRUSTED_KEYS}
    if isinstance(obj, list):
        return [trusted(v) for v in obj]
    return obj


def _load(domain: str, name: str) -> dict:
    p = CONFIGS / domain / "configs" / name
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


@lru_cache(maxsize=None)
def _domain(domain: str) -> dict:
    assets = {}
    for group in (_load(domain, "asset_criticality.json").get("assets") or {}).values():
        if isinstance(group, dict):
            for key, info in group.items():
                if isinstance(info, dict):
                    assets[str(key).lower()] = info
                    if info.get("name"):
                        assets[str(info["name"]).lower()] = {**info, "address": key}
    windows = _load(domain, "maintenance_windows.json").get("windows") or []
    changes = _load(domain, "change_log.json").get("changes") or []
    times = {k: v for k, v in _load(domain, "time_policies.json").items() if isinstance(v, dict)}
    manifests = {}
    for phase in ("monitor", "analyze", "admin", "report"):
        m = _load(domain, f"{phase}_manifest.json")
        if m:
            manifests[phase] = {"allowed_tools": m.get("allowed_tools", []),
                                "requires_verification": bool(m.get("requires_consensus", False)),
                                "max_actions_per_incident": m.get("max_actions_per_incident")}
    return {"assets": assets, "windows": windows, "changes": changes, "times": times,
            "manifests": manifests}


def targets(proposal: dict) -> list[str]:
    out = []
    args = proposal.get("arguments") or {}
    for src in (proposal, args):
        for k in TARGET_KEYS:
            v = src.get(k)
            for x in (v if isinstance(v, list) else [v]):
                if isinstance(x, (str, int)) and str(x) and str(x) not in out:
                    out.append(str(x))
    return out


def operating_context(domain: str, proposal: dict) -> dict:
    d = _domain(domain)
    ts = targets(proposal)
    low = [t.lower() for t in ts]
    tool = proposal.get("tool_id", "")
    action = proposal.get("action") or (proposal.get("arguments") or {}).get("action", "")
    return {
        "targets": ts,
        "target_assets": [{"target": t, **d["assets"][t.lower()]} for t in ts if t.lower() in d["assets"]],
        "maintenance_windows": [w for w in d["windows"]
                                if any(str(a).lower() in low for a in w.get("affected_assets", []))],
        "change_requests": [c for c in d["changes"] if str(c.get("target", "")).lower() in low],
        "time_policy": (d["times"].get(tool) or {}).get(action),
    }


def agent_view(domain: str, phase: str) -> dict:
    m = _domain(domain)["manifests"].get(phase, {})
    return {"phase": phase, **m}


def build_panel_message(proposal: dict, context: dict) -> str:
    """The panel's user message for ``proposal`` (already sanitized)."""
    incident = context.get("incident") or {}
    domain = context.get("domain") or "general"
    phase = proposal.get("phase") or context.get("current_phase") or ""
    return json.dumps({
        "proposal": proposal,
        "incident_context": {
            "incident_id": context.get("incident_id") or incident.get("incident_id"),
            "description": incident.get("description", ""),
            "config": context.get("config"),
            "evidence": trusted({k: v for k, v in incident.items() if k != "incident_id"}),
        },
        "agent": agent_view(domain, phase),
        "operating_context": operating_context(domain, proposal),
        "prior_actions": list(context.get("prior_actions") or [])[-MAX_PRIOR:],
    }, default=str)


def prior_action(proposal: dict, approved: bool) -> dict:
    """The record a decided consequential proposal leaves for later rounds."""
    ts = targets(proposal)
    return {"tool": proposal.get("tool_id"),
            "action": proposal.get("action") or (proposal.get("arguments") or {}).get("action"),
            "target": ts[0] if ts else None, "outcome": "approved" if approved else "denied"}
