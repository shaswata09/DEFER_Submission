"""E1 / E9 / E16 / E17: configuration variants on the agenticcyops stack.

Each variant is a flag on the deployed stack, not a fork of the decision code.
These tests pin two things: the flags reach the right component, and no
variant can make the gate *less* safe than the deployed one.
"""
import pytest

from consensus.auto_gates import AutoGates
from host.orchestrator import SOARHost

# scores that trip each deny / escalate rule, and one that is all-green
DENY_CASES = {
    "P3_auto_reject_alignment": {"alignment": 0.1, "scope": 0.0},
    "P3_auto_escalate_scope": {"alignment": 0.9, "scope": 0.9},
    "P3_auto_escalate_irreversible": {"alignment": 0.9, "scope": 0.0,
                                      "reversibility": 0.1, "proportionality": 0.1},
    "P3_auto_escalate_unprecedented": {"alignment": 0.9, "scope": 0.1, "precedent": 0.0},
}
ALL_GREEN = {"alignment": 0.9, "precedent": 0.9, "proportionality": 0.9, "scope": 0.01}
# A benign-looking proposal as the scorer actually emits them: alignment and
# precedent are pinned at their 0.5 fallback in the deployed system (the ledger
# is never passed to the scorer and incident_evidence never reaches the P3
# context), so only scope and proportionality carry information. The deployed
# gate leaves this to the panel; the permissive gate approves it.
MIDDLING = {"alignment": 0.5, "precedent": 0.5, "proportionality": 0.95, "scope": 0.01}


def test_modes_are_validated():
    with pytest.raises(ValueError):
        AutoGates(mode="nonsense")


@pytest.mark.parametrize("mode", AutoGates.MODES)
@pytest.mark.parametrize("expected,scores", list(DENY_CASES.items()))
def test_deny_and_escalate_rules_are_identical_in_every_mode(mode, expected, scores):
    """No configuration may weaken a deny or escalate path."""
    decided, reason, details = AutoGates(mode=mode).evaluate(scores)
    assert decided is True
    assert reason == expected
    assert details["approved"] is False


def test_default_gate_approves_only_all_green():
    g = AutoGates(mode="default")
    decided, reason, details = g.evaluate(ALL_GREEN)
    assert decided and details["approved"] and reason == "P3_auto_approve_all_green"
    # middling scores are left to the panel
    assert g.evaluate(MIDDLING)[0] is False


def test_permissive_gate_fires_on_middling_scores():
    """E16: the point of the permissive gate is that it actually fires."""
    decided, reason, details = AutoGates(mode="permissive").evaluate(MIDDLING)
    assert decided and details["approved"]
    assert reason == "P3_auto_approve_permissive"


def test_permissive_rule_ignores_the_pinned_dimensions():
    """E16: alignment and precedent are structurally 0.5, so a rule that keys
    on them can never fire. The permissive rule must key on scope and
    proportionality instead."""
    g = AutoGates(mode="permissive")
    pinned = {"alignment": 0.5, "precedent": 0.5}
    # high proportionality + narrow scope -> approves despite pinned dimensions
    assert g.evaluate({**pinned, "proportionality": 0.95, "scope": 0.01})[0] is True
    # low proportionality -> still goes to the panel
    assert g.evaluate({**pinned, "proportionality": 0.80, "scope": 0.01})[0] is False


def test_noautoapprove_never_approves():
    """E1: everything not denied or escalated must reach the panel."""
    g = AutoGates(mode="noautoapprove")
    for scores in (ALL_GREEN, MIDDLING):
        decided, _reason, _d = g.evaluate(scores)
        assert decided is False, "noautoapprove must not auto-approve"


@pytest.mark.parametrize("label,gate,p3off,writejudge,disabled", [
    ("agenticcyops", "default", False, False, set()),
    ("symbolic_only", "default", False, False, set()),
    ("agenticcyops_noautoapprove", "noautoapprove", False, False, set()),
    ("agenticcyops_gate_permissive", "permissive", False, False, set()),
    ("p2_judge", "default", True, False, {"P1", "P4", "P5"}),
    ("agenticcyops_writejudge", "default", False, True, set()),
])
def test_variant_flags_reach_the_stack(label, gate, p3off, writejudge, disabled):
    h = SOARHost(domain="cyberops", config=label, consensus=object())
    assert h.config == "agenticcyops", "variants run the agenticcyops stack"
    assert h.config_label == label, "the label is kept for logs and results"
    assert h.verified_execution.gate_mode == gate
    assert h.verified_execution.p3_deterministic_off is p3off
    assert h.write_judge is writejudge
    assert h.disabled_principles == disabled


def test_deployed_config_is_unchanged():
    """The whole point: adding variants must not move the deployed config."""
    h = SOARHost(domain="cyberops", config="agenticcyops", consensus=object())
    assert h.verified_execution.gate_mode == "default"
    assert h.verified_execution.p3_deterministic_off is False
    assert h.write_judge is False
    assert h.disabled_principles == set()


def test_variants_are_registered_with_the_harness():
    from attacks.harness import CONFIGS, _PANEL_CONFIGS, _STACK_CONFIGS
    for label in ("agenticcyops_noautoapprove", "agenticcyops_gate_permissive",
                  "p2_judge", "agenticcyops_writejudge"):
        assert label in CONFIGS
        assert label in _STACK_CONFIGS
        assert label in _PANEL_CONFIGS, "every variant needs the validator panel"


def test_writejudge_loads_critical_stores_only_for_its_own_config():
    """E9: the critical-store set is empty for every other configuration, so
    the deployed write path is untouched."""
    wj = SOARHost(domain="cyberops", config="agenticcyops_writejudge", consensus=object())
    assert wj.write_judge is True
    assert wj.critical_stores, "writejudge must load the marked stores"
    base = SOARHost(domain="cyberops", config="agenticcyops", consensus=object())
    assert base.write_judge is False
    assert base.critical_stores == set()


@pytest.mark.parametrize("domain", ["cyberops", "finance", "healthcare", "legal"])
def test_every_domain_marks_critical_stores(domain):
    """E9 needs a marking in each domain, and it must name real collections."""
    import json
    from config import BASE_DIR
    cfg = json.loads((BASE_DIR / "domains" / domain / "configs"
                      / "memory_collections.json").read_text())
    ids = {c["id"] for c in cfg["collections"]}
    crit = {c["id"] for c in cfg["collections"] if c.get("critical")}
    assert crit, f"{domain}: no critical stores marked"
    assert crit <= ids
