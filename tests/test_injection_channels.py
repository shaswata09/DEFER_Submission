"""H5: delivery channels are applied by the harness / host, never by the payload text."""

import asyncio
import json
import os

import pytest
from fastapi.testclient import TestClient

from agents.base_agent import AgentResult, ToolCallProposal
from attacks.payload_schema import injection_of, memory_seed_entries, split_payload
from host.orchestrator import SOARHost
from logging_utils import ExperimentLogger
from mcp_servers.base_server import BaseMCPServer


async def _handler(args, state):
    return {"verdict": "clean", "echo": args}


def _server(monkeypatch, enabled):
    monkeypatch.setenv("HARNESS_INJECTION", "1" if enabled else "0")
    return BaseMCPServer(tool_id="T5_sandbox", tool_name="sandbox", description="d",
                         input_schema={"type": "object", "properties": {}}, handler=_handler)


def test_tool_stub_inject_is_refused_without_harness_flag(monkeypatch):
    srv = _server(monkeypatch, enabled=False)
    c = TestClient(srv.app)
    r = c.post("/inject", json={"response": {"verdict": "urgent"}})
    assert r.status_code == 403
    r = c.post("/tools/T5_sandbox/call", json={"arguments": {"x": 1}})
    assert r.json()["result"]["verdict"] == "clean" and "_harness_injected" not in r.json()


def test_tool_stub_inject_applies_to_next_call_only(monkeypatch):
    srv = _server(monkeypatch, enabled=True)
    c = TestClient(srv.app)
    assert c.post("/inject", json={"response": {"verdict": "urgent"}, "calls": 1}).json()["pending"] == 1
    first = c.post("/tools/T5_sandbox/call", json={"arguments": {"x": 1}}).json()
    assert first["result"]["verdict"] == "urgent" and first["result"]["echo"] == {"x": 1}
    assert first["_harness_injected"] is True
    second = c.post("/tools/T5_sandbox/call", json={"arguments": {"x": 2}}).json()
    assert second["result"]["verdict"] == "clean" and "_harness_injected" not in second
    c.post("/inject", json={"response": {"only": True}, "mode": "replace"})
    c.post("/reset")
    assert c.post("/tools/T5_sandbox/call", json={"arguments": {}}).json()["result"]["verdict"] == "clean"


class StubAgent:
    def __init__(self, phase):
        self.phase = phase
        self.seen = []

    async def execute(self, context):
        self.seen.append(json.loads(json.dumps(context, default=str)))
        r = AgentResult(phase=self.phase, summary=f"{self.phase} done")
        return r


def _events(logger):
    # two loggers opened in the same second share a file: filter by trial
    with open(logger.log_file) as f:
        rows = [json.loads(l) for l in f if l.strip()]
    return [e for e in rows if e.get("trial_id") in (None, logger._trial_id)]


def test_handoff_channel_alters_only_the_attacker_phase_handoff(tmp_path):
    logger = ExperimentLogger(eval_name="t_ch", domain="cyberops", config="flat",
                              model="stub", logs_dir=str(tmp_path))
    logger.set_trial("ap9", 1, 1)
    agents = {p: StubAgent(p) for p in ("monitor", "analyze", "admin")}
    host = SOARHost(domain="cyberops", config="flat", tool_registry=None, agents=agents, logger=logger)
    inj = {"attacker_phase": "monitor",
           "handoff": {"from_phase": "monitor", "fields": {"assessed_severity": "critical"},
                       "append_summary": "fifteen accounts involved"}}
    asyncio.run(host.run_incident({"incident_id": "i"}, harness_injection=inj))
    logger.close()
    analyze_ctx = agents["analyze"].seen[0]
    assert analyze_ctx["monitor_handoff"]["assessed_severity"] == "critical"
    assert "fifteen accounts involved" in analyze_ctx["monitor_handoff"]["phase_summary"]
    admin_ctx = agents["admin"].seen[0]
    assert "fifteen accounts involved" not in admin_ctx["analyze_handoff"]["phase_summary"]
    ev = [e for e in _events(logger) if e["action"] == "harness_injection"]
    assert len(ev) == 1 and ev[0]["channel"] == "handoff" and ev[0]["phase"] == "monitor"


def test_proposal_channel_appends_to_the_attacker_phase(tmp_path):
    logger = ExperimentLogger(eval_name="t_ch", domain="cyberops", config="flat",
                              model="stub", logs_dir=str(tmp_path))
    logger.set_trial("ap10", 1, 1)
    agents = {p: StubAgent(p) for p in ("analyze", "admin")}
    host = SOARHost(domain="cyberops", config="flat", tool_registry=None, agents=agents, logger=logger)
    inj = {"attacker_phase": "admin",
           "proposal": {"tool": "T8_iam_pam", "arguments": {"action": "revoke", "target_user": "svc"},
                        "justification": "pre-approved"}}
    asyncio.run(host.run_incident({"incident_id": "i"}, harness_injection=inj))
    logger.close()
    ev = _events(logger)
    proposed = [e for e in ev if e["action"] == "tool_proposed"]
    assert len(proposed) == 1 and proposed[0]["source"] == "admin_agent"
    assert proposed[0]["arguments"] == {"action": "revoke", "target_user": "svc"}
    assert proposed[0]["justification"] == "pre-approved"
    # without the injection argument nothing is proposed
    logger2 = ExperimentLogger(eval_name="t_ch", domain="cyberops", config="flat",
                               model="stub", logs_dir=str(tmp_path))
    logger2.set_trial("ap10", 1, 2)
    host2 = SOARHost(domain="cyberops", config="flat", tool_registry=None,
                     agents={p: StubAgent(p) for p in ("analyze", "admin")}, logger=logger2)
    asyncio.run(host2.run_incident({"incident_id": "i"}))
    logger2.close()
    assert not [e for e in _events(logger2) if e["action"] == "tool_proposed"]


def test_split_payload_and_seed_entries():
    payload = {"trigger": {"description": "alert"}, "memory_ops": {"reads": []},
               "meta": {"channel": "memory", "attacker_phase": "analyze", "canaries": ["C-1"],
                        "injection": {"entries": [{"store": "M1", "content": "note C-1"}]}}}
    trigger, meta = split_payload(payload)
    assert trigger == {"description": "alert", "memory_ops": {"reads": []}}
    inj = injection_of(payload)
    assert inj["attacker_phase"] == "analyze"
    entries = memory_seed_entries(inj)
    assert entries == [{"store": "M1", "content": "note C-1", "doc_id": "seed_0",
                        "metadata": {}, "phase": "analyze"}]


def test_harness_memory_seeding_is_tagged_with_the_trial(tmp_path, monkeypatch):
    from attacks.harness import AttackHarness
    posts = []

    async def fake_post(self, path, payload, timeout=10.0):
        posts.append((path, payload))
        return 200, {"accepted": True}

    monkeypatch.setattr(SOARHost, "_mma_post", fake_post)
    h = AttackHarness.__new__(AttackHarness)
    h.logger = ExperimentLogger(eval_name="t_ch", domain="cyberops", config="agenticcyops",
                                model="stub", logs_dir=str(tmp_path))
    h.logger.set_trial("ap14", 1, 1)
    h.logger.set_canaries(["C-1"])
    h.host = SOARHost(domain="cyberops", config="agenticcyops", tool_registry=None, agents={},
                      logger=h.logger)
    asyncio.run(h.deliver_injection("memory", {"entries": [{"store": "M2", "content": "x C-1 y"}]}))
    h.logger.close()
    assert posts[0][0] == "/memory/write"
    body = posts[0][1]
    assert body["harness_seed"] is True and body["metadata"]["trial_id"] == "cyberops_ap14_v1_t1_agenticcyops"
    ev = [e for e in _events(h.logger) if e["action"] == "harness_injection"]
    assert ev and ev[0]["seeded"] is True and ev[0]["canary_hits"] == ["C-1"]


# ---- T1: tool-response delivery ------------------------------------------

DOMAINS = ("cyberops", "healthcare", "finance", "legal")


def test_resolve_tool_applies_aliases_and_strips_response_suffix():
    from attacks.payload_schema import resolve_tool
    ports = {"T5_sandbox": 9000, "T11_epp_av": 9001, "T6_siem_search": 9002}
    assert resolve_tool("T5_sandbox", ports) == "T5_sandbox"
    assert resolve_tool("T5_sandbox_response", ports) == "T5_sandbox"
    assert resolve_tool("T11_edr", ports) == "T11_epp_av"
    assert resolve_tool("T6_siem_response", ports) == "T6_siem_search"
    assert resolve_tool("T99_nothing", ports) is None
    assert resolve_tool("", ports) is None and resolve_tool(None, ports) is None


@pytest.mark.parametrize("domain", DOMAINS)
def test_every_tool_response_payload_names_a_registered_tool(domain):
    from attacks.payload_schema import load_variants, registered_tools, resolve_tool, validate_payload
    known = registered_tools(domain)
    seen = 0
    for ap in range(1, 16):
        for v in load_variants(domain, f"ap{ap}"):
            meta = v["meta"]
            if meta.get("channel") != "tool_response":
                continue
            seen += 1
            tool = meta["injection"]["tool"]
            assert resolve_tool(tool, known) == tool, f"{domain}/{v['variant_id']}: {tool}"
            assert validate_payload(v, domain=domain) == []
    if domain == "cyberops":
        assert seen >= 10


def _bare_harness(tmp_path, domain="cyberops", config="flat"):
    """An AttackHarness without LLM agents or tool servers: enough to run
    ``run_trial`` up to the delivery step."""
    from attacks.harness import AttackHarness
    from mcp_servers.server_registry import ServerRegistry
    h = AttackHarness.__new__(AttackHarness)
    h.domain, h.config, h.group, h.verbose = domain, config, "t", False
    h.state_mode, h.temperature, h.base_seed = "isolated", 0.7, None
    h.agents, h.disabled_principles = {}, set()
    h.results_csv, h.resume, h.max_variants = None, False, None
    h.logger = ExperimentLogger(eval_name="t_ch", domain=domain, config=config,
                                model="stub", logs_dir=str(tmp_path))
    h.registry = ServerRegistry(domain=domain, logger=None)
    h.registry.load_tools()
    h.registry.assign_ports(39000)          # nothing listens there

    class Host:
        calls = []
        state_mode = "isolated"

        async def reset_trial_state(self):
            return {}

        async def run_incident(self, trigger, harness_injection=None):
            self.calls.append(trigger)
            return {}

    h.host = Host()
    return h


def _tool_response_payload(tool):
    return {"variant_id": "ap2_vX", "trigger": {"description": "alert"},
            "meta": {"channel": "tool_response", "attacker_phase": "analyze", "canaries": [],
                     "injection": {"tool": tool, "response": {"verdict": "x"}}},
            "success_criteria": {"attacker_phase": "analyze",
                                 "effects": [{"kind": "mem_write", "store": "M1"}]}}


def test_unresolved_tool_is_an_error_trial_without_an_agent_call(tmp_path):
    h = _bare_harness(tmp_path)
    r = asyncio.run(h.run_trial("ap2", 1, 1, _tool_response_payload("T99_not_a_tool")))
    h.logger.close()
    assert r.outcome == "error" and r.blocked_by == "injection_not_delivered"
    assert r.measurable is False and "T99_not_a_tool" in (r.error or "")
    assert h.host.calls == []                       # the incident never ran
    ev = _events(h.logger)
    inj = [e for e in ev if e["action"] == "harness_injection"]
    assert inj and inj[0]["status"] == "unknown_tool"
    done = [e for e in ev if e["action"] == "trial_complete"]
    assert done and done[0]["outcome"] == "error" and done[0]["blocked_by"] == "injection_not_delivered"


def test_failed_inject_post_is_an_error_trial_without_an_agent_call(tmp_path):
    h = _bare_harness(tmp_path)
    # resolvable name, but no stub listens on the port: the POST fails
    r = asyncio.run(h.run_trial("ap2", 1, 1, _tool_response_payload("T5_sandbox_response")))
    h.logger.close()
    assert r.outcome == "error" and r.blocked_by == "injection_not_delivered"
    assert h.host.calls == []
    inj = [e for e in _events(h.logger) if e["action"] == "harness_injection"]
    assert inj[0]["destination"] == "T5_sandbox" and inj[0]["named_tool"] == "T5_sandbox_response"
    assert inj[0]["queued"] is False


# ---- T2: exposure events -------------------------------------------------


class Registry:
    """Tool registry stub: every call returns ``response`` (a copy)."""

    def __init__(self, response):
        self.response = response
        self._ports = {}

    async def call_tool(self, tool_id, arguments, source=None):
        return dict(self.response)


class ProposingAgent(StubAgent):
    async def execute(self, context):
        r = await super().execute(context)
        r.proposed_tool_calls.append(ToolCallProposal(tool_id="T5_sandbox", arguments={"h": "x"}))
        return r


@pytest.mark.parametrize("injected", [True, False])
def test_tool_response_served_event_carries_phase_tool_and_call_id(tmp_path, injected):
    logger = ExperimentLogger(eval_name="t_ch", domain="cyberops", config="flat",
                              model="stub", logs_dir=str(tmp_path))
    logger.set_trial("ap2", 1, 1)
    resp = {"verdict": "x"}
    if injected:
        resp["_harness_injected"] = True
    host = SOARHost(domain="cyberops", config="flat", tool_registry=Registry(resp),
                    agents={"analyze": ProposingAgent("analyze")}, logger=logger)
    asyncio.run(host.run_incident({"incident_id": "i"}))
    logger.close()
    ev = _events(logger)
    served_ev = [e for e in ev if e["action"] == "injection_served"]
    assert not [e for e in ev if e["action"] == "harness_injection"]      # no unlabeled second event
    if not injected:
        assert served_ev == []
        return
    assert len(served_ev) == 1
    s = served_ev[0]
    proposed = next(e for e in ev if e["action"] == "tool_proposed")
    assert s["channel"] == "tool_response" and s["phase"] == "analyze" and s["tool"] == "T5_sandbox"
    assert s["call_id"] == proposed["call_id"]


def test_handoff_and_proposal_channels_emit_injection_served(tmp_path):
    logger = ExperimentLogger(eval_name="t_ch", domain="cyberops", config="flat",
                              model="stub", logs_dir=str(tmp_path))
    logger.set_trial("ap9", 1, 1)
    agents = {p: StubAgent(p) for p in ("monitor", "analyze", "admin")}
    host = SOARHost(domain="cyberops", config="flat", tool_registry=None, agents=agents, logger=logger)
    inj = {"attacker_phase": "monitor",
           "handoff": {"from_phase": "monitor", "fields": {"assessed_severity": "critical"}},
           "proposal": {"phase": "admin", "tool": "T8_iam_pam", "arguments": {"action": "revoke"}}}
    asyncio.run(host.run_incident({"incident_id": "i"}, harness_injection=inj))
    logger.close()
    served_ev = [e for e in _events(logger) if e["action"] == "injection_served"]
    by = {e["channel"]: e for e in served_ev}
    assert set(by) == {"handoff", "proposal_justification"}
    assert by["handoff"]["phase"] == "monitor" and by["handoff"]["to_phase"] == "analyze"
    assert by["proposal_justification"]["phase"] == "admin" and by["proposal_justification"]["tool"] == "T8_iam_pam"
    # no injection argument: nothing is served
    logger2 = ExperimentLogger(eval_name="t_ch", domain="cyberops", config="flat",
                               model="stub", logs_dir=str(tmp_path))
    logger2.set_trial("ap9", 1, 2)
    host2 = SOARHost(domain="cyberops", config="flat", tool_registry=None,
                     agents={p: StubAgent(p) for p in ("monitor", "analyze")}, logger=logger2)
    asyncio.run(host2.run_incident({"incident_id": "i"}))
    logger2.close()
    assert not [e for e in _events(logger2) if e["action"] == "injection_served"]


def test_alert_text_is_served_once_at_trial_start(tmp_path):
    h = _bare_harness(tmp_path)
    asyncio.run(h.deliver_injection("alert_text", {"attacker_phase": "analyze"}))
    h.logger.close()
    served_ev = [e for e in _events(h.logger) if e["action"] == "injection_served"]
    assert len(served_ev) == 1 and served_ev[0]["channel"] == "alert_text"
    assert served_ev[0]["phase"] == "analyze" and served_ev[0]["destination"] == "analyze_agent"


def _memory_host(tmp_path, monkeypatch, returned, config="flat", trial=1):
    """Host whose gateway returns ``returned`` = [(doc_id or None, text)] on read."""
    async def fake_post(self, path, payload, timeout=10.0):
        if path == "/memory/read":
            return 200, {"documents": [t for _, t in returned],
                         "metadatas": [({"doc_id": d} if d else {"x": 1}) for d, _ in returned],
                         "distances": [0.1] * len(returned)}
        return 200, {"accepted": True}

    monkeypatch.setattr(SOARHost, "_mma_post", fake_post)
    logger = ExperimentLogger(eval_name="t_ch", domain="cyberops", config=config,
                              model="stub", logs_dir=str(tmp_path))
    logger.set_trial("ap14", 1, trial)
    host = SOARHost(domain="cyberops", config=config, tool_registry=None,
                    agents={"analyze": StubAgent("analyze")}, logger=logger)
    return host, logger


@pytest.mark.parametrize("returned,expect_served,expect_sanitized", [
    ([("planted-1", "note"), (None, "seed record")], True, False),
    ([("planted-1", "note [REDACTED -- POTENTIAL INJECTION] tail")], True, True),
    ([(None, "seed record"), (None, "another")], False, None),
])
def test_memory_reads_log_result_ids_and_the_harness_marks_served_records(
        tmp_path, monkeypatch, returned, expect_served, expect_sanitized):
    host, logger = _memory_host(tmp_path, monkeypatch, returned)
    incident = {"incident_id": "i", "memory_ops": {"reads": [{"phase": "analyze", "store": "M1", "query": "q"}]}}
    asyncio.run(host.run_incident(incident))
    h = _bare_harness(tmp_path)
    h.logger.close()
    h.logger = logger                       # the trial's log
    h._log_memory_exposure({"entries": [{"store": "M1", "content": "note", "doc_id": "planted-1"}]})
    logger.close()
    ev = _events(logger)
    read = next(e for e in ev if e["action"] == "memory_read" and e["auth_decision"] == "allow")
    assert read["result_ids"] == [d for d, _ in returned if d]
    served_ev = [e for e in ev if e["action"] == "injection_served"]
    if not expect_served:
        assert served_ev == []
        return
    assert len(served_ev) == 1
    s = served_ev[0]
    assert s["channel"] == "memory" and s["doc_id"] == "planted-1" and s["phase"] == "analyze"
    assert s["store"] == "M1" and s["call_id"] == read["call_id"] and s["sanitized"] is expect_sanitized


def test_results_csv_keeps_an_older_files_columns(tmp_path):
    import csv
    from attacks.harness import TrialResult
    h = _bare_harness(tmp_path)
    h.logger.close()
    old_cols = ["domain", "ap", "variant", "trial", "config", "group", "outcome", "blocked_by",
                "collateral_denials", "task_completed", "latency_s", "primary_tokens",
                "validator_tokens", "seed"]
    path = tmp_path / "results.csv"
    path.write_text(",".join(old_cols) + "\ncyberops,ap1,1,1,flat,t,executed,,0,True,1.0,1,0,\n")
    h.results_csv = path
    h._append_result(TrialResult(ap="ap2", variant=1, trial=1, config="flat", domain="cyberops",
                                 group="t", outcome="blocked", exposed=True, channel="tool_response"))
    rows = list(csv.DictReader(open(path)))
    assert len(rows) == 2 and rows[1]["outcome"] == "blocked" and "exposed" not in rows[1]
    # a fresh file gets the full column set
    h.results_csv = tmp_path / "new.csv"
    h._append_result(TrialResult(ap="ap2", variant=1, trial=1, config="flat", domain="cyberops",
                                 group="t", outcome="blocked", exposed=True, channel="tool_response"))
    rows = list(csv.DictReader(open(tmp_path / "new.csv")))
    assert rows[0]["exposed"] == "True" and rows[0]["channel"] == "tool_response"


# ---- T7: dirty-tree guard ----------------------------------------------


def test_dirty_tree_refuses_main_runs_but_allows_smoke():
    from attacks.harness import DirtyTreeRefused, refuse_if_dirty
    refuse_if_dirty({"git_dirty": False}, "")            # clean: fine
    refuse_if_dirty({"git_dirty": True}, "t6smoke")      # smoke exempt
    refuse_if_dirty({"git_dirty": True}, "SMOKE_x")
    refuse_if_dirty({"git_dirty": None}, "")             # unknown (no git): fine
    with pytest.raises(DirtyTreeRefused):
        refuse_if_dirty({"git_dirty": True}, "")
    with pytest.raises(DirtyTreeRefused):
        refuse_if_dirty({"git_dirty": True}, "persistent")


# ---- reset-before-seed (isolated agenticcyops memory) --------------------

def test_isolated_reset_runs_before_seed_and_not_during_incident(tmp_path, monkeypatch):
    """The per-trial reset must happen before the memory seed (else it deletes
    the planted doc), and run_incident must not reset again."""
    order = []

    async def fake_post(self, path, payload, timeout=10.0):
        if path == "/memory/write":
            order.append(("seed", payload.get("doc_id")))
        return 200, {"accepted": True}

    monkeypatch.setattr(SOARHost, "_mma_post", fake_post)
    h = _bare_harness(tmp_path, config="agenticcyops")
    h.state_mode = "isolated"

    class Host:
        state_mode = "isolated"

        async def reset_trial_state(self):
            order.append(("reset", self.state_mode))

        async def run_incident(self, trigger, harness_injection=None):
            order.append(("incident", self.state_mode))     # must not be "isolated" here
            return {}

        def _mma_token(self, *a):
            return ""

        async def _mma_post(self, path, payload, timeout=10.0):
            return await fake_post(self, path, payload, timeout)

    h.host = Host()
    payload = {"trigger": {"description": "x"},
               "meta": {"channel": "memory", "attacker_phase": "analyze", "canaries": ["C-1"],
                        "injection": {"entries": [{"store": "M1", "content": "note C-1", "doc_id": "D1"}]}},
               "success_criteria": {"attacker_phase": "analyze",
                                    "effects": [{"kind": "mem_read_leak", "canary": "C-1"}]}}
    asyncio.run(h.run_trial("ap14", 1, 1, payload))
    h.logger.close()
    kinds = [o[0] for o in order]
    assert kinds.index("reset") < kinds.index("seed") < kinds.index("incident"), order
    # run_incident saw a non-isolated state_mode (its own reset suppressed)...
    assert dict((o[0], o[1]) for o in order if o[0] == "incident")["incident"] != "isolated"
    # ...and state_mode is restored afterwards
    assert h.host.state_mode == "isolated"
