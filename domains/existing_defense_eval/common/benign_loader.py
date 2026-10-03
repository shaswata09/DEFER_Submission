"""
Drop-in benign payload loader for false-positive evaluation.

Returns payloads in EXACTLY the same shape as `load_attack_payloads`, so any
notebook can flip from attack to benign by swapping one import.

The only fields added are `_ap = variant_id` (each benign payload is its own
"AP" id for compatibility with `compute_per_ap_bypass` etc.) and the
attack-side `success_criteria` will be missing — that is intentional so the
exact same evaluator code path runs unchanged on benign inputs.

Benign files (canonical):
    domains/cyberops/payloads/benign_alerts.json
    domains/healthcare/payloads/benign_workflows.json
    domains/finance/payloads/benign_workflows.json
    domains/legal/payloads/benign_workflows.json
"""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]

_DEFAULT_FILES = {
    "cyberops":   "benign_alerts.json",
    "healthcare": "benign_workflows.json",
    "finance":    "benign_workflows.json",
    "legal":      "benign_workflows.json",
}


def _resolve_path(domain: str, filename: str | None) -> Path:
    fname = filename or _DEFAULT_FILES.get(domain, "benign_alerts.json")
    p = PROJECT_ROOT / "domains" / domain / "payloads" / fname
    if p.exists():
        return p
    alt = "benign_workflows.json" if fname == "benign_alerts.json" else "benign_alerts.json"
    alt_p = PROJECT_ROOT / "domains" / domain / "payloads" / alt
    if alt_p.exists():
        return alt_p
    raise FileNotFoundError(f"No benign payloads for domain '{domain}'")


def load_benign_payloads(domain: str, ap: str | None = None,
                          filename: str | None = None) -> list[dict]:
    """Drop-in for `load_attack_payloads`.

    Args:
        domain:   cyberops | healthcare | finance | legal
        ap:       Optional filter. Matches against variant_id (e.g., 'benign_01')
                  OR category (e.g., 'phishing') so existing notebook code that
                  passes an AP id still works (with no match returning empty).
        filename: Override the default benign payload filename.

    Returns:
        List of payload dicts with `_ap` injected (= variant_id) for parity
        with attack payloads.
    """
    path = _resolve_path(domain, filename)
    payloads = json.loads(path.read_text())
    for p in payloads:
        p["_ap"] = p.get("variant_id") or p.get("name", "v?")
        p.setdefault("variant_id", p["_ap"])
        # Attack payloads carry a top-level `description` (one-line summary)
        # parallel to `variant_id`. Benign payloads only have `trigger.description`
        # (the full body). Mirror it up so dry-run prints — which call
        # `sample.get('description')` — show something meaningful and the
        # dry-run output format matches the attack notebooks exactly.
        if "description" not in p:
            trig = p.get("trigger") or {}
            if isinstance(trig, dict) and isinstance(trig.get("description"), str):
                p["description"] = trig["description"]
    if ap:
        # Match against variant_id OR category for flexibility.
        payloads = [p for p in payloads
                    if p.get("variant_id") == ap or p.get("category") == ap]
    return payloads


def list_benign_variants(domain: str, filename: str | None = None) -> list[str]:
    """Return the sorted list of benign variant_ids (drop-in analog of list_aps)."""
    return sorted({p["_ap"] for p in load_benign_payloads(domain, filename=filename)})
