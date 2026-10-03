"""defense-freeze-v3.2: the high-severity defects of the 2026-10-02 audit."""
import asyncio

from consensus.cross_incident_ledger import CrossIncidentLedger
from consensus.handoff_validator import HandoffValidator
from consensus.versioned_ledger import VersionedLedger
from host.orchestrator import _incident_ids
from host.parameter_validator import ParameterValidator

HIGH = {"initial_severity": "high"}


def test_deflation_reads_claims_not_evidence():
    hv = HandoffValidator()
    # a sandbox verdict "benign" in the tool results is evidence, not a claim
    ok, _, _ = hv._check_deflation_phrases(
        {"phase_summary": "Lateral movement confirmed.",
         "tool_results": [{"result": '{"category": "benign"}'}]}, HIGH)
    assert ok
    # the phase itself calling it a false positive is a claim
    ok, _, d = hv._check_deflation_phrases({"phase_summary": "This is a false positive."}, HIGH)
    assert not ok and "false positive" in d["deflation_phrases"]


def test_deflation_matches_words_and_skips_negation():
    hv = HandoffValidator()
    assert hv._check_deflation_phrases({"phase_summary": "illegitimate access"}, HIGH)[0]
    assert hv._check_deflation_phrases({"phase_summary": "this is not benign"}, HIGH)[0]
    assert not hv._check_deflation_phrases({"phase_summary": "activity looks benign"}, HIGH)[0]


def test_deflation_reads_severity_under_every_field_name():
    hv = HandoffValidator()
    claim = {"phase_summary": "benign, close incident"}
    assert not hv._check_deflation_phrases(claim, {"severity": "critical"})[0]
    assert not hv._check_deflation_phrases(claim, {"incident_context": {"severity": "high"}})[0]
    assert hv._check_deflation_phrases(claim, {"severity": "low"})[0]


def test_nested_incident_ids_are_legitimate():
    inc = {"incident_context": {"incident_id": "INC-2026-0505", "severity": "high"}}
    assert _incident_ids(inc) == ["INC-2026-0505"]
    led = VersionedLedger()
    ok, _, _ = led.check_replay({"tool_id": "T8_iam_pam", "arguments": {"incident_id": "INC-2026-0505"}},
                                {"incident_id": "INC-2026-0505", "incident_ids": ["INC-2026-0505"]})
    assert ok
    ok, reason, _ = led.check_replay({"tool_id": "T8_iam_pam", "arguments": {"incident_id": "INC-9"}},
                                     {"incident_id": "INC-2026-0505", "incident_ids": ["INC-2026-0505"]})
    assert not ok and reason == "P3_incident_id_mismatch"


def test_parameter_rules_follow_the_tool_schemas():
    cy = ParameterValidator("cyberops")
    assert cy._check_parameter_rules("T8_iam_pam", {"action": "reset", "target_user": "j.doe"})[0]
    assert not cy._check_parameter_rules("T8_iam_pam", {"action": "escalate", "target_user": "j.doe"})[0]
    assert cy._check_parameter_rules("T10_config_manager", {"action": "push"})[0]
    fi = ParameterValidator("finance")
    assert fi._check_parameter_rules("F8_account_freeze", {"account_id": "ACC-1", "reason": "aml_hold"})[0]
    assert fi._check_parameter_rules("F10_wire_recall", {"wire_id": "W-1", "reason": "fraud"})[0]


def test_wildcards_only_in_scoping_arguments():
    hc = ParameterValidator("healthcare")
    assert hc._check_wildcards({"patient_id": "PAT-1", "test_type": "all"})[0]
    assert not hc._check_wildcards({"patient_id": "all"})[0]


def test_criticality_only_for_state_changing_tools():
    cy = ParameterValidator("cyberops")
    crit = next((k for k, v in cy._criticality_lookup.items() if v == "critical"), None)
    assert crit is not None
    assert cy._check_criticality("T3_edr_ndr", {"target": crit})[0]          # a read
    assert not cy._check_criticality("T9_firewall", {"action": "block_ip", "target": crit})[0]


def test_admin_tools_have_targets_and_actions_in_the_ledger():
    pv = ParameterValidator("legal")
    assert pv._extract_target("L8_court_filing", {"case_number": "CASE-1"}) == "CASE-1"
    led = CrossIncidentLedger()
    asyncio.run(led.check_and_record({"tool_id": "L8_court_filing", "arguments": {"case_number": "CASE-1"}},
                                     {"incident_id": "INC-1"}))
    entry = led._ledger[-1]
    assert entry["action"] == "file" and entry["target"] == "CASE-1"
