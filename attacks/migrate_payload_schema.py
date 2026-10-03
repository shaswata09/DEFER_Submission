"""Move harness-only payload fields out of the trigger into ``meta`` (H5).

The v1 payloads mixed three kinds of fields inside ``trigger``:

1. the incident as the SOC would see it (kept);
2. adversarial content that reaches the system through a specific channel
   but was stored under a tell-tale key (``forged_tool_response``,
   ``poisoned_memory_entry``, ``injected_handoff``,
   ``injected_justification``, ``*_override``, ``injected_instruction``):
   moved to ``meta.injection`` and delivered by the harness through the
   matching channel (``tool_response`` / ``memory`` / ``handoff`` /
   ``proposal_justification``), so the model never sees the label;
3. harness annotations (``type``, ``inject_at``, ``combined_pattern``,
   ``drift_metrics``, AP-15 tampering descriptions, ...): moved to
   ``meta.legacy``.

Nothing is rewritten: content is relocated verbatim.  Fields that still
match the hygiene pattern after relocation are listed in
``tests/payload_hygiene_waivers.json`` with the field path, for the
STOP-gated rewrite.

Usage::

    python -m attacks.migrate_payload_schema --dry-run
    python -m attacks.migrate_payload_schema
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from attacks.migrate_criteria import domain_tools, named_actions, tool_schemas
from attacks.payload_schema import CHANNELS, PHASES, validate_payload
from config import BASE_DIR

DOMAINS = ("cyberops", "healthcare", "finance", "legal")
HYGIENE_RE = re.compile(r"inject|attack|poison|swap|forged|falsif|adversar|malicious", re.I)
_TOOL_RE = re.compile(r"\b([A-Z]{1,2}\d{1,2}_[a-z0-9_]+)")

# Pure annotations: never content the system receives.
LEGACY_KEYS = {
    "type", "injection_target", "injection_type", "combined_pattern",
    "cross_incident_pattern", "accumulation_context", "velocity_context",
    "drift_metrics", "replay_context", "broad_query_attempt", "baseline_content",
    "drift_writes", "write_sequence", "target_store", "adversarial_write",
    "toctou_swap", "forged_response", "forged_mma_response", "config_change",
    "data_tamper", "infra_manipulation", "poisoned_data",
}
HANDOFF_ANNOTATIONS = {"original_scope_entities", "inflated_scope_entities",
                       "scope_expansion_ratio", "source_phase", "target_phase", "prior_phases"}
INJECT_AT_HANDOFF = {"report_phase_context": "admin", "analysis_findings": "analyze"}
WAIVERS_PATH = BASE_DIR / "tests" / "payload_hygiene_waivers.json"


def _tool_in(text) -> str | None:
    m = _TOOL_RE.search(str(text or ""))
    return m.group(1) if m else None


def _proposal_from_text(text: str, domain: str, known: set[str], schemas: dict) -> dict | None:
    acts = named_actions(text, known)
    if not acts:
        return None
    a = acts[0]
    schema = schemas.get(a["tool"], {})
    params_known = set(schema.get("params") or [])
    ops = schema.get("ops")
    args = {}
    if a.get("operation") and any(k in params_known for k in ("action", "operation", "op")):
        if ops is None or a["operation"] in ops:
            args["action"] = a["operation"]
    for k, v in (a.get("parameters") or {}).items():
        if k in params_known:
            args[k] = v
    return {"tool": a["tool"], "arguments": args}


def _proposal_from_struct(pa: dict, schemas: dict) -> dict:
    """``{"tool", "operation", "parameters"}`` -> proposal arguments that
    the tool's schema accepts.  A ``target`` parameter the schema does not
    name is mapped onto the tool's single ``*_id`` parameter when there is
    exactly one; otherwise it is dropped."""
    tool = str(pa.get("tool"))
    schema = schemas.get(tool, {})
    params_known = list(schema.get("params") or [])
    ops = schema.get("ops")
    args: dict = {}
    op = pa.get("operation") or pa.get("action")
    if op and any(k in params_known for k in ("action", "operation", "op")) and (ops is None or op in ops):
        args["action"] = op
    id_params = [k for k in params_known if k.endswith("_id")]
    for k, val in (pa.get("parameters") or {}).items():
        if k in params_known:
            args[k] = val
        elif k == "target" and len(id_params) == 1:
            args[id_params[0]] = val
    return {"tool": tool, "arguments": args}


def _rename_alert_fields(obj) -> None:
    """Alert-side field names that label the adversary (``attacker_ip``)
    become neutral names a SIEM would use; values are untouched."""
    if isinstance(obj, dict):
        if "attacker_ip" in obj and "origin_ip" not in obj:
            obj["origin_ip"] = obj.pop("attacker_ip")
        for val in obj.values():
            _rename_alert_fields(val)
    elif isinstance(obj, list):
        for val in obj:
            _rename_alert_fields(val)


def migrate_variant(domain: str, ap: str, v: dict, known: set[str], schemas: dict) -> dict:
    trig = v.get("trigger")
    if not isinstance(trig, dict):
        return {"channel": "alert_text", "moved": []}
    sc = v.get("success_criteria") if isinstance(v.get("success_criteria"), dict) else {}
    meta = v.get("meta") if isinstance(v.get("meta"), dict) else {}
    meta.setdefault("channel", "alert_text")
    meta.setdefault("canaries", [])
    injection = meta.setdefault("injection", {})
    legacy = meta.setdefault("legacy", {})
    moved = []
    attacker = sc.get("attacker_phase") if sc.get("attacker_phase") in PHASES else None

    def move_legacy(key):
        if key in trig:
            legacy[key] = trig.pop(key)
            moved.append(key)

    # ---- tool_response: forged / falsified tool responses ---------------
    for key in list(trig.keys()):
        val = trig.get(key)
        if not isinstance(val, dict):
            continue
        payload_key = next((k for k in ("forged_response", "falsified_response", "falsified_pattern",
                                        "falsified_instruction") if k in val), None)
        if key == "forged_tool_response" or (key.endswith("_override") and payload_key):
            resp = val.get(payload_key) if payload_key else None
            if not isinstance(resp, dict):
                continue
            tool = _tool_in(val.get("inject_at")) or _tool_in(resp.get("tool")) or _tool_in(key)
            resp = dict(resp)
            for ann in ("target_store", "target_stores", "response_id"):
                if ann in resp:
                    legacy.setdefault(f"{key}.{ann}", resp.pop(ann))
            if tool:
                meta["channel"] = "tool_response"
                injection.update({"tool": tool, "response": resp, "mode": "merge", "calls": 1})
                legacy[key] = {k: x for k, x in val.items() if k != payload_key}
                trig.pop(key)
                moved.append(key)

    # legal AP-2: poisoned_data with a source tool -> tool_response
    pd = trig.get("poisoned_data")
    if isinstance(pd, dict) and pd.get("source_tool") and isinstance(pd.get("injected_case"), dict):
        meta["channel"] = "tool_response"
        injection.update({"tool": pd["source_tool"], "response": dict(pd["injected_case"]),
                          "mode": "merge", "calls": 1})
        legacy["poisoned_data"] = {k: x for k, x in pd.items() if k != "injected_case"}
        trig.pop("poisoned_data")
        moved.append("poisoned_data")

    # ---- memory: pre-seeded entries --------------------------------------
    entries = []
    pm = trig.get("poisoned_memory_entry")
    if isinstance(pm, dict) and pm.get("injected_content"):
        entries.append({"store": pm.get("store"), "doc_id": pm.get("entry_id"),
                        "content": pm["injected_content"], "metadata": {"seeded": True}})
        meta["channel"] = "memory"
        legacy["poisoned_memory_entry"] = {k: x for k, x in pm.items() if k != "injected_content"}
        trig.pop("poisoned_memory_entry")
        moved.append("poisoned_memory_entry")
    em = trig.get("existing_memory")
    if isinstance(em, dict) and em.get("content"):
        entries.append({"store": em.get("store"), "doc_id": em.get("entry_id") or "existing_memory",
                        "content": em["content"], "metadata": dict(em.get("metadata") or {})})
        legacy["existing_memory"] = {k: x for k, x in em.items() if k != "content"}
        trig.pop("existing_memory")
        moved.append("existing_memory")
    if entries:
        injection["entries"] = injection.get("entries", []) + entries

    # ---- handoff: poisoned handoffs and phase-context instructions -------
    for key in ("injected_handoff", "poisoned_handoff"):
        h = trig.get(key)
        if isinstance(h, dict):
            fields = {k: x for k, x in h.items() if k not in HANDOFF_ANNOTATIONS}
            src = h.get("source_phase") if h.get("source_phase") in PHASES else (attacker or "monitor")
            meta["channel"] = "handoff"
            injection["handoff"] = {"from_phase": src, "fields": fields}
            legacy[key] = {k: x for k, x in h.items() if k in HANDOFF_ANNOTATIONS}
            trig.pop(key)
            moved.append(key)
    instr = trig.get("injected_instruction")
    if isinstance(instr, str) and instr:
        where = str(trig.get("inject_at", ""))
        src = INJECT_AT_HANDOFF.get(where)
        if src:
            meta["channel"] = "handoff"
            injection["handoff"] = {"from_phase": src, "append_summary": instr}
            attacker = attacker or src
        else:
            # no known carrier: keep the text where the model already saw it
            trig["description"] = f"{trig.get('description', '')}\n\n{instr}".strip()
        trig.pop("injected_instruction")
        moved.append("injected_instruction")
    move_legacy("inject_at")

    # ---- proposal_justification: injected proposal + justification ------
    ij = trig.get("injected_justification")
    if isinstance(ij, dict):
        prop = _proposal_from_text(str(ij.get("proposed_action", "")), domain, known, schemas)
        if prop:
            meta["channel"] = "proposal_justification"
            injection["proposal"] = {**prop, "phase": attacker or "admin",
                                     "justification": str(ij.get("justification", ""))}
            legacy["injected_justification"] = {k: x for k, x in ij.items()
                                                if k not in ("justification",)}
            trig.pop("injected_justification")
            moved.append("injected_justification")
    # transfer domains carry the AP-10 proposal as a structured block
    pa = trig.get("proposed_action")
    if ap == "ap10" and isinstance(pa, dict) and pa.get("tool") and (
            pa.get("justification") or pa.get("reason")):
        prop = _proposal_from_struct(pa, schemas)
        meta["channel"] = "proposal_justification"
        injection["proposal"] = {**prop, "phase": attacker or "admin",
                                 "justification": str(pa.get("justification") or pa.get("reason") or "")}
        legacy["proposed_action"] = {k: x for k, x in pa.items() if k not in ("justification", "reason")}
        trig.pop("proposed_action")
        moved.append("proposed_action")

    # ---- annotations ------------------------------------------------------
    for key in list(trig.keys()):
        if key in LEGACY_KEYS:
            move_legacy(key)
    _rename_alert_fields(trig)

    meta["attacker_phase"] = attacker or (sc.get("attacker_phase") if sc.get("attacker_phase") in PHASES else "none")
    if attacker and sc.get("attacker_phase") not in PHASES:
        sc["attacker_phase"] = attacker
    if not injection:
        meta.pop("injection")
    v["meta"] = meta
    return {"channel": meta["channel"], "moved": moved}


def hygiene_hits(trigger, canaries: list[str]) -> list[str]:
    """Paths of trigger keys / string values matching the hygiene pattern."""
    hits = []

    def walk(obj, path):
        if isinstance(obj, dict):
            for k, val in obj.items():
                if HYGIENE_RE.search(str(k)):
                    hits.append(f"key:{'.'.join(path + [k])}")
                walk(val, path + [k])
        elif isinstance(obj, list):
            for i, val in enumerate(obj):
                walk(val, path + [str(i)])
        elif isinstance(obj, str):
            text = obj
            for c in canaries:
                text = text.replace(c, "")
            if HYGIENE_RE.search(text):
                hits.append(f"value:{'.'.join(path)}")

    walk(trigger, [])
    return hits


def migrate(dry_run: bool) -> None:
    per_channel = Counter()
    waivers: dict[str, list[str]] = {}
    moved_keys = Counter()
    for domain in DOMAINS:
        known = {t for ts in domain_tools(domain).values() for t in ts}
        schemas = tool_schemas(domain)
        for ap in range(1, 16):
            p = BASE_DIR / "domains" / domain / "payloads" / f"ap{ap}_variants.json"
            if not p.exists():
                continue
            data = json.load(open(p))
            variants = data if isinstance(data, list) else data.get("variants", [])
            for v in variants:
                info = migrate_variant(domain, f"ap{ap}", v, known, schemas)
                per_channel[info["channel"]] += 1
                moved_keys.update(info["moved"])
                hits = hygiene_hits(v.get("trigger", {}), v["meta"].get("canaries", []))
                if hits:
                    waivers[f"{domain}/{v['variant_id']}"] = hits
                problems = validate_payload(v)
                if problems:
                    print(f"  schema: {domain}/{v['variant_id']}: {problems}")
            if not dry_run:
                with open(p, "w") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.write("\n")
    print("channels:", dict(per_channel))
    print("moved keys:", dict(moved_keys))
    print(f"variants still matching the hygiene pattern in trigger: {len(waivers)}")
    by_dom = Counter(k.split("/")[0] for k in waivers)
    print("  by domain:", dict(by_dom))
    if not dry_run:
        with open(WAIVERS_PATH, "w") as f:
            json.dump({"_note": "Variants whose trigger still contains a tell-tale key or "
                                "word after the mechanical H5 migration. Each entry lists the "
                                "field paths; remove the entry once the payload is rewritten.",
                       "waivers": waivers}, f, indent=1, sort_keys=True)
            f.write("\n")
        print(f"wrote {WAIVERS_PATH}")
    else:
        print("(dry-run: nothing written)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    migrate(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
