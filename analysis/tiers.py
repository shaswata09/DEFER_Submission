"""The one tier mapping of first-interception mechanisms.

Every table and figure that splits interceptions by tier imports this module;
no other mapping exists. The four tiers:

  content-independent rule  decides from structure alone -- identity, the
      manifest, the shape of a write, a replay. It never reads what the
      proposal says, so rewording cannot get past it.
  content-dependent rule    a deterministic rule that does read the content:
      parameter values, a handoff's claims, a sanitisation regex.
  similarity threshold      an embedding threshold. Tunable.
  LLM panel                 the validators.

P2.2 (target not in evidence) has two branches, a substring match and a cosine
match. The substring branch can only allow, so a denial is the cosine
threshold's whenever an embedding model is loaded, as in every reported run:
the label maps to the similarity tier (the paper's rule, "the tier of the rule
that actually denied"). A log whose ``deny_branch`` says "substring" (a run
without an embedding model) is mapped back to a content-dependent rule.

A mechanism that is not listed maps to ``None``. Callers that count
interceptions must treat ``None`` as an error rather than a tier
(``tests/test_tiers.py`` checks that every label in the committed logs is
mapped), so a new check can never be filed silently under a default.
"""
from __future__ import annotations

TIERS = ("content_independent", "content_dependent", "similarity", "panel")

LABEL = {
    "content_independent": "Rule (content-independent)",
    "content_dependent": "Rule (content-dependent)",
    "similarity": "Similarity threshold",
    "panel": "LLM panel",
}

COLOR = {
    "content_independent": "#0072B2",   # deep blue: the structural floor
    "content_dependent": "#56B4E9",     # light blue: still deterministic
    "similarity": "#CC79A7",            # purple: the tunable tier
    "panel": "#E69F00",                 # orange: the judges
}

# check (as the paper names it) -> the mechanism labels it emits when it denies
_CHECKS: dict[str, tuple[str, tuple[str, ...]]] = {
    # content-independent rule
    "P1 identity": ("content_independent", ("P1_unregistered", "P1_unregistered_tools")),
    "P1 response integrity": ("content_independent", (
        "P1_response_integrity", "P1_response_signature_invalid", "P1_response_unsigned",
        "P1_response_replay", "P1_response_suspiciously_fast")),
    "P1 config integrity": ("content_independent", (
        "P1_config_integrity_violation", "P1_config_tampered",
        "P1_data_integrity_violation", "P1_data_file_missing")),
    "P2 manifest / capability scoping": ("content_independent", (
        "P2_capability_scoping", "P2_manifest_enforcement", "P2_tool_not_in_manifest")),
    "P2 critical asset": ("content_independent", ("P2_critical_asset", "P2_high_criticality_destructive")),
    "P3 replay detection": ("content_independent", (
        "P3_replay_detection", "P3_exact_replay", "P3_structural_replay", "P3_incident_id_mismatch")),
    "P3 execution verification": ("content_independent", ("P3_execution_verification", "P3_toctou_mismatch")),
    "P3 bulk action": ("content_independent", ("P3_bulk_action",)),
    "P4 schema violation": ("content_independent", ("P4_schema_violation",)),
    "P4 write replay": ("content_independent", ("P4_write_replay",)),
    "P5 access control": ("content_independent", ("P5_access_control", "P5_field_filtering")),
    # content-dependent rule

    "P2 parameter rule violation": ("content_dependent", ("P2_parameter_rule_violation",)),
    "P2 wildcard parameter": ("content_dependent", ("P2_wildcard_parameter",)),
    "P2 output classifier (pattern branch)": ("content_dependent", ("P2_sensitive_pattern_detected",)),
    "P3 handoff validation": ("content_dependent", (
        "P3_handoff_validation", "P3_handoff_deflation", "P3_handoff_scope_expansion",
        "P3_handoff_severity_jump")),
    "P3 operational context": ("content_dependent", (
        "P3_operational_context", "P3_incident_lifecycle", "P3_incident_closed",
        "P3_maintenance_window", "P3_change_conflict")),
    "P3 intent chain": ("content_dependent", (
        "P3_intent_chain", "P3_dangerous_pattern", "P3_destructive_accumulation",
        "P3_same_action_accumulation", "P3_same_target_accumulation")),
    "P4 contradiction": ("content_dependent", ("P4_contradiction_detected",)),
    "P4 metadata invalid": ("content_dependent", ("P4_metadata_invalid",)),
    "P5 broad query block": ("content_dependent", ("P5_broad_query_block", "P5_query_scope")),
    "P5 injection sanitization": ("content_dependent", ("P5_injection_sanitization",)),
    # similarity threshold
    # P2.2's target-in-evidence test: the substring branch can only allow, so
    # with an embedding model loaded (every reported run, ASB included) a
    # denial is the cosine threshold's (2026-10-02 audit; the v2.9+ logs carry
    # deny_branch "cosine" on all 409 of them). A run without an embedding model
    # logs deny_branch "substring", which tier_of maps back to a rule.
    "P2 target not in evidence (cosine branch)": ("similarity", (
        "P2_target_not_in_evidence", "P2_p2_target_not_in_evidence")),
    "P4 similarity reject": ("similarity", ("P4_similarity_reject",)),
    "P4 drift outlier": ("similarity", ("P4_drift_outlier",)),
    "P4 centroid shift": ("similarity", ("P4_centroid_shift",)),
    "P2 output classifier (cosine)": ("similarity", ("P2_sensitive_content_detected",)),
    "P5 read-pattern monitor": ("similarity", (
        "P5_irrelevant_query", "P5_query_diversity_escalation", "P5_store_diversity_escalation")),
    # LLM panel
    "P3 consensus": ("panel", (
        "P3_llm_consensus_reject", "P3_llm_consensus_approve",
        "P3_consensus_reject", "P3_consensus_approve")),
    "P3 write-judge reject": ("panel", ("P3_write_judge_reject",)),
}

MECHANISM_TIER: dict[str, str] = {}
MECHANISM_CHECK: dict[str, str] = {}
for _check, (_tier, _labels) in _CHECKS.items():
    for _m in _labels:
        assert _m not in MECHANISM_TIER, f"{_m} mapped twice"
        MECHANISM_TIER[_m] = _tier
        MECHANISM_CHECK[_m] = _check

# P2.2's cosine branch, once logs record it (defense-freeze-v2.9 on)
_BRANCH_TIER = {"substring": "content_dependent", "cosine": "similarity"}
_P2_2 = {"P2_target_not_in_evidence", "P2_p2_target_not_in_evidence"}


def tier_of(mechanism: str | None, deny_branch: str | None = None) -> str | None:
    """Tier of a first-interception mechanism, or ``None`` if it is not a
    mapped interception (empty, or a label this module does not list)."""
    if not mechanism:
        return None
    m = str(mechanism).strip()
    if m in _P2_2 and deny_branch in _BRANCH_TIER:
        return _BRANCH_TIER[deny_branch]
    return MECHANISM_TIER.get(m)


def check_of(mechanism: str | None) -> str | None:
    """The check (paper name) that emits a mechanism label."""
    return MECHANISM_CHECK.get(str(mechanism or "").strip())


def shares(mechanisms: list[str]) -> tuple[dict[str, float], int, list[str]]:
    """Tier shares of a list of first-interception labels.

    Returns ``(share per tier, n mapped, unmapped labels)``. Unmapped labels are
    returned rather than dropped so the caller can refuse to report shares
    that silently exclude something.
    """
    counts = {t: 0 for t in TIERS}
    unmapped = []
    for m in mechanisms:
        t = tier_of(m)
        if t is None:
            if m and str(m).strip().lower() not in ("nan", "none"):
                unmapped.append(m)
            continue
        counts[t] += 1
    n = sum(counts.values())
    return ({t: counts[t] / n for t in TIERS} if n else {}), n, unmapped
