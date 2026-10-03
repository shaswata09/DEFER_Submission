"""
Load AP payloads from domains/<domain>/payloads/ and extract the
attacker-controlled (untrusted) text spans that an existing defense
would be applied to.

Untrusted-content fields are catalogued per attack-path because each AP
plants the injection in a different surface (description for AP-1,
analyst_notes for AP-1 v2, tool_response for AP-3, memory content for
AP-2/13/14, etc.).
"""

import json
from pathlib import Path

# Project root: domains/existing_defense_eval/common -> up 3
PROJECT_ROOT = Path(__file__).resolve().parents[3]


# Fields a defense would scan as "untrusted input" — they enter the
# LLM's context window from attacker-influenceable sources.
UNTRUSTED_FIELDS = {
    "description",
    "analyst_notes",
    "recommended_actions",
    "escalation_chain",
    "override_claim",
    "patient_notes",
    "clinical_notes",
    "case_notes",
    "memo_text",
    "claim_notes",
    "report_body",
    "alert_body",
    "alert_text",
    "tool_response",
    "tool_response_body",
    "memory_content",
    "memory_record",
    "handoff_context",
    "obfuscation_techniques",
    "incident_summary",
    "patient_chart",
    "transaction_note",
    "case_summary",
}


def list_aps(domain: str, payloads_subdir: str = "payloads") -> list[str]:
    """Return sorted list of AP ids that have payload files in the domain.

    payloads_subdir defaults to 'payloads'. Override to point at an alternate
    payload subdirectory under domains/<domain>/.
    """
    base = PROJECT_ROOT / "domains" / domain / payloads_subdir
    if not base.exists():
        return []
    aps = []
    for f in base.glob("ap*_variants.json"):
        ap = f.stem.replace("_variants", "")
        aps.append(ap)
    return sorted(aps, key=lambda a: int(a[2:]))


def load_attack_payloads(domain: str, ap: str | None = None,
                         payloads_subdir: str = "payloads") -> list[dict]:
    """
    Load attack-payload variants for a domain.

    Args:
        domain:          cyberops | healthcare | finance | legal
        ap:              Optional AP filter (e.g., 'ap1'). If None, load all APs.
        payloads_subdir: Which payload directory to read from. Defaults to
                         'payloads'; override to point at an alternate
                         subdirectory under domains/<domain>/.

    Returns:
        List of payload dicts. Each dict gets an injected '_ap' key.
    """
    base = PROJECT_ROOT / "domains" / domain / payloads_subdir
    if not base.exists():
        raise FileNotFoundError(f"No payloads directory '{payloads_subdir}' for domain '{domain}': {base}")

    if ap:
        files = [base / f"{ap}_variants.json"]
    else:
        files = sorted(base.glob("ap*_variants.json"),
                       key=lambda f: int(f.stem.replace("_variants", "")[2:]))

    payloads = []
    for f in files:
        if not f.exists():
            continue
        variants = json.loads(f.read_text())
        ap_id = f.stem.replace("_variants", "")
        for v in variants:
            v["_ap"] = ap_id
            payloads.append(v)
    return payloads


def extract_untrusted_spans(payload: dict) -> list[dict]:
    """
    Pull out attacker-controlled text spans from a payload.

    Returns a list of {field, text} dicts. Defenses are applied to each
    span independently; if any one is flagged, the attack is considered
    blocked at the input boundary.
    """
    trigger = payload.get("trigger", payload)
    spans: list[dict] = []
    if not isinstance(trigger, dict):
        return spans

    for k, v in trigger.items():
        if k not in UNTRUSTED_FIELDS:
            continue
        if isinstance(v, str) and v.strip():
            spans.append({"field": k, "text": v})
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, str) and item.strip():
                    spans.append({"field": f"{k}[{i}]", "text": item})
                elif isinstance(item, dict):
                    # AP-3 v3 escalation_chain etc. — flatten the dict.
                    flat = " ".join(str(x) for x in item.values() if isinstance(x, (str, int)))
                    if flat.strip():
                        spans.append({"field": f"{k}[{i}]", "text": flat})
        elif isinstance(v, dict):
            flat = " ".join(str(x) for x in v.values() if isinstance(x, (str, int)))
            if flat.strip():
                spans.append({"field": k, "text": flat})
    return spans


def build_attack_user_message(payload: dict) -> str:
    """
    For prompt-modification defenses (D4-D6) we need the attacker payload
    expressed as a single user-side message that goes to the target LLM.

    This concatenates all untrusted spans into a realistic alert/event
    message, mirroring what the Monitor agent would receive at the start
    of an incident.
    """
    trigger = payload.get("trigger", payload)
    lines = []
    if isinstance(trigger, dict):
        if "alert_type" in trigger:
            lines.append(f"Alert Type: {trigger['alert_type']}")
        if "initial_severity" in trigger:
            lines.append(f"Severity: {trigger['initial_severity']}")
        if "source_ip" in trigger and "destination_ip" in trigger:
            lines.append(f"Source: {trigger['source_ip']} -> {trigger['destination_ip']}")
        for k, v in trigger.items():
            if k in UNTRUSTED_FIELDS:
                if isinstance(v, str):
                    lines.append(f"\n{k}:\n{v}")
                elif isinstance(v, list):
                    lines.append(f"\n{k}:")
                    for item in v:
                        lines.append(f"  - {item}")
                elif isinstance(v, dict):
                    lines.append(f"\n{k}: {json.dumps(v)}")
    return "\n".join(lines)
