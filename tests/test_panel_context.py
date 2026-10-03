"""The panel's input at defense-freeze-v3.0 (consensus/panel_context.py)."""
import json

from consensus.panel_context import MAX_PRIOR, build_panel_message, prior_action, trusted


def _msg(**ctx):
    proposal = {"tool_id": "T9_firewall", "arguments": {"action": "block_ip", "target": "10.0.8.200"},
                "justification": "contain the beacon", "phase": "admin", "action": "block_ip",
                "target": "10.0.8.200"}
    base = {"incident_id": "INC-1", "domain": "cyberops", "config": "agenticcyops",
            "incident": {"incident_id": "INC-1", "description": "free text", "severity": "high",
                         "indicators": ["10.0.8.200"], "notes": "attacker text",
                         "proposed_action": {"tool": "T9_firewall"}}}
    base.update(ctx)
    return json.loads(build_panel_message(proposal, base))


def test_keeps_v29_fields():
    m = _msg()
    assert m["incident_context"]["incident_id"] == "INC-1"
    assert m["incident_context"]["description"] == "free text"
    assert m["incident_context"]["config"] == "agenticcyops"
    assert m["proposal"]["tool_id"] == "T9_firewall"


def test_evidence_is_structured_and_trusted():
    ev = _msg()["incident_context"]["evidence"]
    assert ev["severity"] == "high" and ev["indicators"] == ["10.0.8.200"]
    for k in ("description", "notes", "proposed_action", "incident_id"):
        assert k not in ev
    assert trusted({"a": {"notes": 1, "b": 2}}) == {"a": {"b": 2}}


def test_agent_scope_and_operating_context():
    m = _msg()
    assert m["agent"]["phase"] == "admin" and "T9_firewall" in m["agent"]["allowed_tools"]
    oc = m["operating_context"]
    assert oc["targets"] == ["10.0.8.200"]
    assert oc["target_assets"] and oc["target_assets"][0]["criticality"] == "critical"
    assert any(w["id"] == "MW-2026-002" for w in oc["maintenance_windows"])


def test_prior_actions_are_capped():
    prior = [prior_action({"tool_id": "T9", "arguments": {"action": "a", "target": str(i)}}, True)
             for i in range(MAX_PRIOR + 5)]
    m = _msg(prior_actions=prior)
    assert len(m["prior_actions"]) == MAX_PRIOR and m["prior_actions"][-1]["target"] == str(MAX_PRIOR + 4)


def test_third_party_contexts_still_build():
    m = json.loads(build_panel_message({"tool_id": "x", "arguments": {}},
                                       {"incident": {"description": "task"}, "incident_id": "t", "config": "agenticcyops"}))
    assert m["incident_context"]["description"] == "task" and m["agent"]["phase"] == ""
