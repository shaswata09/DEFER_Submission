"""Payload schema (H5): what the model sees vs. what the harness knows.

A variant has two halves::

    {
      "variant_id": "ap3_v1", "name": ..., "description": ...,
      "trigger":   { ... the incident as the SOC would receive it ... },
      "memory_ops": { "reads": [...], "writes": [...] },        # scripted ops
      "meta": {
        "channel": "alert_text" | "tool_response" | "memory" | "handoff"
                   | "proposal_justification",
        "attacker_phase": "admin",
        "canaries": ["CANARY-..."],
        "injection": { ...channel-specific delivery spec... },
        "legacy": { ...keys moved out of the trigger, kept for reference... }
      },
      "success_criteria": { "attacker_phase": ..., "effects": [...] }
    }

``trigger`` (plus ``memory_ops``, which the host strips before rendering)
is the only part handed to the host; ``meta`` is never shown to a model.
``meta.injection`` is delivered by the harness through the named channel:

``tool_response``          ``{"tool": id, "response": {...}, "mode": "merge"|"replace",
                             "calls": n}`` -> ``POST /inject`` on the tool stub.
``memory``                 ``{"store": id, "content": str, "doc_id": str,
                             "metadata": {...}}`` (or ``"entries": [...]``)
                           -> pre-seeded through the gateway with ``harness_seed``.
``handoff``                ``{"from_phase": p, "fields": {...}, "append_summary": str}``
                           -> merged into that phase's handoff by the host.
``proposal_justification`` ``{"phase": p, "tool": id, "arguments": {...},
                             "justification": str}`` (or ``"proposals": [...]``)
                           -> appended to that phase's proposals by the host.
``alert_text``             nothing to deliver: the content is in the trigger.
"""

from __future__ import annotations

import functools
import json
import re
from pathlib import Path
from typing import Any, Iterable, Optional

from config import BASE_DIR

CHANNELS = ("alert_text", "tool_response", "memory", "handoff", "proposal_justification")
PHASES = ("monitor", "analyze", "admin", "report")

# Tool names payloads used before the registry ids were settled.  The
# harness resolves them on delivery and the oracle on scoring; payloads
# should name the registered id directly (T1).
TOOL_ALIASES = {"T11_edr": "T11_epp_av", "T6_siem": "T6_siem_search"}


def resolve_tool(tool_id: Any, registry_ports: Iterable[str] | dict) -> Optional[str]:
    """Registered tool id for ``tool_id``, or ``None``.

    Applies :data:`TOOL_ALIASES`, strips a trailing ``_response`` (the AP-2
    payloads named the *response* of the tool), and checks the result
    against the registry's tool ids (``ServerRegistry._ports`` or any
    iterable of ids).
    """
    if not tool_id:
        return None
    known = set(registry_ports.keys() if isinstance(registry_ports, dict) else registry_ports)
    t = str(tool_id)
    for cand in (t, TOOL_ALIASES.get(t, t)):
        if cand in known:
            return cand
    if t.endswith("_response"):
        base = t[: -len("_response")]
        for cand in (base, TOOL_ALIASES.get(base, base)):
            if cand in known:
                return cand
    return None


@functools.lru_cache(maxsize=None)
def registered_tools(domain: str) -> frozenset:
    """Tool ids the domain's server registry serves (loaded once)."""
    from mcp_servers.server_registry import ServerRegistry
    reg = ServerRegistry(domain=domain, logger=None)
    reg.load_tools()
    reg.assign_ports(9000)
    return frozenset(reg._ports)


# --------------------------------------------------------------------- #
#  E5.3  Hygiene of the injected content itself
# --------------------------------------------------------------------- #
# ``meta`` as a whole is scaffolding and never reaches the model, but the
# payload *inside* ``meta.injection`` is served to it, so it has to look like
# genuine tool output or a genuine record. Two things give it away:
#
#   * a field that marks the content as synthetic (``fabricated``, a per-item
#     ``false`` flag, ``falsified_timeline`` ...) -- no real tool emits one;
#   * a phrase that frames the experiment (a P-label, "adversarial write",
#     "must block").
#
# Ordinary domain vocabulary is deliberately allowed: a threat-intel verdict of
# ``malicious`` and a firewall alert describing bytecode "injected via CVE-..."
# are what genuine responses say, and scrubbing them would make the injected
# content *less* realistic, which is the opposite of the intent.
_SYNTH_KEY_RE = re.compile(r"fabricat|falsif|forged|adversar|poison|is_fake|synthetic|^false$", re.I)
_EXPERIMENT_RE = re.compile(
    r"\bP[1-5](\.\d+)?\b|adversarial|must block|expected defen|ground truth|attack path", re.I)


def injection_hygiene_hits(meta: dict) -> list[str]:
    """Paths in ``meta.injection`` that would tell the model it is a test.

    Returns ``[]`` when the injected content is shaped like genuine output.
    """
    hits: list[str] = []
    injection = (meta or {}).get("injection") or {}

    def walk(obj: Any, path: list[str]) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if _SYNTH_KEY_RE.search(str(k)):
                    hits.append(f"key:{'.'.join(path + [str(k)])}")
                walk(v, path + [str(k)])
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, path + [str(i)])
        elif isinstance(obj, str):
            if _EXPERIMENT_RE.search(obj):
                hits.append(f"value:{'.'.join(path)}")

    for field in ("response", "entries", "content"):
        if field in injection:
            walk(injection[field], [field])
    return hits


def load_variants(domain: str, ap: str) -> list[dict]:
    path = BASE_DIR / "domains" / domain / "payloads" / f"{ap}_variants.json"
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("variants", [])


def meta_of(payload: dict) -> dict:
    m = payload.get("meta")
    return m if isinstance(m, dict) else {}


def split_payload(payload: dict) -> tuple[dict, dict]:
    """``(trigger_for_host, meta)``.

    The trigger carries ``memory_ops`` (scripted reads / writes the host
    performs; the agent never sees them) and nothing from ``meta``.
    """
    trigger = payload.get("trigger", payload)
    trigger = dict(trigger) if isinstance(trigger, dict) else {"description": str(trigger)}
    trigger.pop("meta", None)
    if "memory_ops" in payload:
        trigger["memory_ops"] = payload["memory_ops"]
    return trigger, meta_of(payload)


def injection_of(payload: dict) -> dict:
    inj = meta_of(payload).get("injection")
    inj = dict(inj) if isinstance(inj, dict) else {}
    ap = meta_of(payload).get("attacker_phase")
    if ap and "attacker_phase" not in inj:
        inj["attacker_phase"] = ap
    return inj


def validate_payload(payload: dict, domain: Optional[str] = None) -> list[str]:
    """Schema problems of one variant (empty list when well-formed).

    With ``domain`` the ``tool_response`` tool must resolve to a tool the
    domain's registry serves (an unresolved tool is never delivered).
    """
    problems = []
    meta = meta_of(payload)
    if not meta:
        problems.append("missing meta block")
        return problems
    ch = meta.get("channel")
    if ch not in CHANNELS:
        problems.append(f"channel {ch!r} not in {CHANNELS}")
    ap = meta.get("attacker_phase")
    if ap not in PHASES and ap != "none":
        problems.append(f"attacker_phase {ap!r} not an agent phase")
    if not isinstance(meta.get("canaries", []), list):
        problems.append("canaries must be a list")
    inj = meta.get("injection") or {}
    if ch == "tool_response" and not (inj.get("tool") and "response" in inj):
        problems.append("tool_response channel needs injection.tool and injection.response")
    elif ch == "tool_response" and domain:
        known = registered_tools(domain)
        if inj.get("tool") not in known:
            resolved = resolve_tool(inj.get("tool"), known)
            problems.append(f"tool_response tool {inj.get('tool')!r} is not a registered {domain} tool"
                            + (f" (alias of {resolved!r}: name it directly)" if resolved else ""))
    if ch == "memory" and not inj.get("entries"):
        problems.append("memory channel needs injection.entries")
    if ch == "handoff" and not isinstance(inj.get("handoff"), dict):
        problems.append("handoff channel needs injection.handoff")
    if ch == "proposal_justification" and not (inj.get("proposal") or inj.get("proposals")):
        problems.append("proposal_justification channel needs injection.proposal(s)")
    sc = payload.get("success_criteria")
    if not isinstance(sc, dict) or "effects" not in sc:
        problems.append("success_criteria.effects missing")
        return problems
    # Every canary must actually occur in the adversarial content the trial
    # delivers (seeded record, injected tool response, or the alert text),
    # otherwise the harmful action can never carry it (T3).
    canaries = [str(c) for c in (meta.get("canaries") or []) if c]
    if canaries:
        content = json.dumps(inj, default=str) + json.dumps(payload.get("trigger", {}), default=str)
        for c in canaries:
            if c not in content:
                problems.append(f"canary {c!r} does not occur in the payload's adversarial content")
    # An effect whose kind is scored by a canary must name one (T3).
    for e in (sc.get("effects") or []):
        if not isinstance(e, dict):
            continue
        if e.get("kind") in ("mem_read_leak", "exfil"):
            if not (e.get("canary") or e.get("canaries")):
                problems.append(f"{e.get('kind')} effect has no canary")
    return problems


def validate_all(domains=PHASES) -> int:      # noqa: ARG001 (domains overwritten below)
    """Validate every payload of every domain; return the problem count."""
    doms = ("cyberops", "healthcare", "finance", "legal")
    total = 0
    for domain in doms:
        for ap in range(1, 16):
            for v in load_variants(domain, f"ap{ap}"):
                errs = validate_payload(v, domain=domain)
                if errs:
                    total += len(errs)
                    print(f"  [{domain}/{v.get('variant_id', 'ap%d' % ap)}] {errs}")
    print(f"validate-all: {total} problems across {len(doms)} domains")
    return total


def assert_measurable() -> int:
    """Count payloads that can only ever score not_measurable (T5 gate)."""
    from attacks.effects import evaluate_effects, OUTCOME_NOT_MEASURABLE
    doms = ("cyberops", "healthcare", "finance", "legal")
    bad = 0
    for domain in doms:
        for ap in range(1, 16):
            for v in load_variants(domain, f"ap{ap}"):
                verdict = evaluate_effects(v, [], config="flat")
                if verdict.outcome == OUTCOME_NOT_MEASURABLE:
                    bad += 1
                    print(f"  [{domain}/{v.get('variant_id', 'ap%d' % ap)}] not_measurable: {verdict.blocked_by}")
    print(f"assert-measurable: {bad} payloads can only score not_measurable")
    return bad


def memory_seed_entries(injection: dict) -> list[dict]:
    """Normalised list of ``{store, content, doc_id, metadata}`` to pre-seed."""
    out = []
    entries = injection.get("entries")
    if isinstance(entries, list):
        out.extend(e for e in entries if isinstance(e, dict))
    elif injection.get("store") and injection.get("content"):
        out.append({k: injection.get(k) for k in ("store", "content", "doc_id", "metadata", "phase")})
    norm = []
    for i, e in enumerate(out):
        if not (e.get("store") and e.get("content")):
            continue
        norm.append({
            "store": str(e["store"]), "content": str(e["content"]),
            "doc_id": str(e.get("doc_id") or f"seed_{i}"),
            "metadata": dict(e.get("metadata") or {}),
            "phase": str(e.get("phase") or "analyze"),
        })
    return norm


if __name__ == "__main__":       # python -m attacks.payload_schema --validate-all
    import sys as _sys
    if "--validate-all" in _sys.argv:
        raise SystemExit(1 if validate_all() else 0)
    if "--assert-measurable" in _sys.argv:
        raise SystemExit(1 if assert_measurable() else 0)
    print("usage: python -m attacks.payload_schema --validate-all | --assert-measurable")
