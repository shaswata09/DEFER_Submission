"""H4: scripted memory reads / writes run in every configuration.

A fake gateway replaces ``SOARHost._mma_post`` so the host can be
exercised offline.  Checks: reads run before the LLM call and their
results reach the agent's context; flat / acl_hardened write to the same
store with the P4 / P5 layers bypassed; the ACL manifest still denies
stores the phase may not touch; event shapes are identical across configs.
"""

import asyncio
import json

import pytest

from agents.base_agent import AgentResult, BaseAgent
from host.orchestrator import SOARHost
from logging_utils import ExperimentLogger

SEEDED = "prior note: host 10.0.8.200 is the domain controller"


class FakeMMA:
    def __init__(self):
        self.docs: dict[str, dict] = {"seed": {"store": "M2_case_context", "document": SEEDED}}
        self.calls: list[tuple[str, dict]] = []

    async def post(self, path, payload, timeout=10.0):
        self.calls.append((path, payload))
        if path == "/memory/read":
            docs = [d["document"] for d in self.docs.values()
                    if d["store"].split("_")[0] == payload["store_id"].split("_")[0]]
            return 200, {"documents": docs, "metadatas": [{} for _ in docs]}
        if path == "/memory/write":
            self.docs[payload["doc_id"]] = {"store": payload["store_id"],
                                            "document": payload["document"],
                                            "metadata": payload["metadata"]}
            return 200, {"accepted": True, "similarity_score": 0.9}
        if path == "/admin/reset":
            return 200, {"deleted_documents": 0}
        return 404, {}


class RecordingAgent:
    """Records the context it was given; proposes nothing."""

    def __init__(self, phase):
        self.phase = phase
        self.seen = []

    async def execute(self, context):
        self.seen.append(json.loads(json.dumps(context, default=str)))
        return AgentResult(phase=self.phase)


INCIDENT = {
    "incident_id": "INC-MEM-1", "description": "test",
    "memory_ops": {
        "reads": [{"phase": "analyze", "store": "M2_case_context", "query": "domain controller"}],
        "writes": [{"phase": "analyze", "store": "M1_threat_repository",
                    "content": "analysis note", "metadata": {"k": "v"}},
                   {"phase": "analyze", "store": "M4_audit_log", "content": "not mine"}],
    },
}


def _run(config, tmp_path, monkeypatch):
    mma = FakeMMA()
    monkeypatch.setattr(SOARHost, "_mma_post", lambda self, path, payload, timeout=10.0: mma.post(path, payload))
    logger = ExperimentLogger(eval_name="t_mem", domain="cyberops", config=config,
                              model="stub", logs_dir=str(tmp_path))
    logger.set_trial("ap14", 1, 1)
    agent = RecordingAgent("analyze")
    host = SOARHost(domain="cyberops", config=config, tool_registry=None,
                    agents={"analyze": agent}, logger=logger)
    asyncio.run(host.run_incident(json.loads(json.dumps(INCIDENT))))
    logger.close()
    with open(logger.log_file) as f:
        events = [json.loads(l) for l in f if l.strip()]
    return mma, agent, events


@pytest.mark.parametrize("config", ["flat", "acl_hardened", "agenticcyops"])
def test_reads_run_before_the_llm_call_and_reach_the_agent(config, tmp_path, monkeypatch):
    mma, agent, events = _run(config, tmp_path, monkeypatch)
    read_calls = [c for c in mma.calls if c[0] == "/memory/read"]
    assert len(read_calls) == 1
    ctx = agent.seen[0]
    assert ctx["memory_context"]["analyze"][0]["documents"] == [SEEDED]
    actions = [e["action"] for e in events]
    assert actions.index("memory_read_proposed") < actions.index("memory_read")
    read = next(e for e in events if e["action"] == "memory_read")
    assert read["auth_decision"] == "allow"
    assert read["mechanism"] == {"flat": "none", "acl_hardened": "acl_network_layer",
                                 "agenticcyops": "P5_access_control"}[config]
    assert read["call_id"] == next(e for e in events if e["action"] == "memory_read_proposed")["call_id"]


@pytest.mark.parametrize("config", ["flat", "acl_hardened", "agenticcyops"])
def test_scripted_writes_reach_the_store_with_config_appropriate_bypass(config, tmp_path, monkeypatch):
    mma, agent, events = _run(config, tmp_path, monkeypatch)
    writes = [p for path, p in mma.calls if path == "/memory/write"]
    stores = sorted(w["store_id"] for w in writes)
    bypass = config != "agenticcyops"
    assert all(w["skip_p4"] is bypass and w["skip_p5"] is bypass for w in writes)
    assert all(w["metadata"]["trial_id"] == "cyberops_ap14_v1_t1_" + config for w in writes)
    if config == "acl_hardened":
        # the manifest does not let analyze write to M4: denied host-side
        assert stores == ["M1_threat_repository"]
        denied = [e for e in events if e["action"] == "memory_write" and e["auth_decision"] == "deny"]
        assert denied and denied[0]["mechanism"] == "acl_network_layer" and denied[0]["destination"] == "M4_audit_log"
    else:
        assert stores == ["M1_threat_repository", "M4_audit_log"]
    ok = [e for e in events if e["action"] == "memory_write" and e["auth_decision"] == "allow"]
    assert ok and ok[0]["mechanism"] == {"flat": "none", "acl_hardened": "acl_network_layer",
                                         "agenticcyops": "P4_memory_integrity"}[config]
    proposed = [e for e in events if e["action"] == "memory_write_proposed"]
    assert len(proposed) == 2 and all(p["scripted"] for p in proposed)


def test_agent_context_renders_memory_and_hides_memory_ops():
    class A(BaseAgent):
        def __init__(self):
            self.phase = "analyze"
    a = A()
    ctx = {"incident": {"incident_id": "x", "memory_ops": {"reads": []}},
           "memory_context": {"analyze": [{"store": "M2", "documents": [SEEDED]}]}}
    text = BaseAgent._format_context(a, ctx)
    assert "memory_ops" not in text
    assert "## Memory Context" in text and SEEDED in text


def test_unreachable_gateway_is_logged_as_error(tmp_path):
    logger = ExperimentLogger(eval_name="t_mem", domain="cyberops", config="flat",
                              model="stub", logs_dir=str(tmp_path))
    logger.set_trial("ap14", 1, 1)
    host = SOARHost(domain="cyberops", config="flat", mma_url="http://127.0.0.1:1",
                    tool_registry=None, agents={"analyze": RecordingAgent("analyze")}, logger=logger)
    asyncio.run(host.run_incident(json.loads(json.dumps(INCIDENT))))
    logger.close()
    with open(logger.log_file) as f:
        events = [json.loads(l) for l in f if l.strip()]
    errs = [e for e in events if e["action"] in ("memory_read", "memory_write")]
    assert errs and all(e["auth_decision"] == "error" and e["mechanism"] == "mma_unreachable" for e in errs)
