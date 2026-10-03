"""H1: every proposal is recorded before any check, in every config.

Runs the host offline (no LLM, no tool servers, no MMA) with a stub agent
that proposes one tool call and one memory write, and checks the flat
trial log:

* a ``tool_proposed`` event with the full arguments and a ``call_id``
  precedes the ``tool_call`` event for the same call;
* every ``tool_call`` event carries ``arguments`` and the same ``call_id``;
* a ``memory_write_proposed`` event precedes the ``memory_write`` event and
  they share a ``call_id``.
"""

import asyncio
import json

import pytest

from agents.base_agent import AgentResult, ToolCallProposal
from host.orchestrator import SOARHost
from logging_utils import ExperimentLogger

ARGS = {"action": "disable_user", "target_user": "svc-backup",
        "reason": "x" * 700}          # long enough to be truncated on tool_call
WRITE = {"store_id": "M2_incident_history", "content": "benign incident note"}


class StubAgent:
    def __init__(self, phase):
        self.phase = phase

    async def execute(self, context):
        r = AgentResult(phase=self.phase)
        r.proposed_tool_calls.append(ToolCallProposal(
            tool_id="T8_iam_pam", arguments=dict(ARGS), justification="cleanup"))
        r.memory_writes.append(dict(WRITE))
        return r


def _run(config, tmp_path):
    logger = ExperimentLogger(eval_name="t_events", domain="cyberops", config=config,
                              model="stub", logs_dir=str(tmp_path))
    logger.set_trial("ap1", 1, 1)
    host = SOARHost(domain="cyberops", config=config, llm_url="http://127.0.0.1:1/v1",
                    mma_url="http://127.0.0.1:1", tool_registry=None,
                    agents={"admin": StubAgent("admin")}, logger=logger)
    asyncio.run(host.run_incident({"incident_id": "inc-1", "description": "test"}))
    logger.close()
    with open(logger.log_file) as f:
        return [json.loads(l) for l in f if l.strip()]


@pytest.mark.parametrize("config", ["flat", "acl_hardened", "agenticcyops"])
def test_tool_proposed_precedes_tool_call_with_arguments(config, tmp_path):
    events = _run(config, tmp_path)
    proposed = [e for e in events if e["action"] == "tool_proposed"]
    calls = [e for e in events if e["action"] == "tool_call"]
    assert len(proposed) == 1
    assert proposed[0]["destination"] == "T8_iam_pam"
    assert proposed[0]["arguments"] == ARGS                    # full, untruncated
    call_id = proposed[0]["call_id"]
    assert call_id.startswith("admin:tool:")
    assert calls, "no tool_call event was written"
    for c in calls:
        assert c["call_id"] == call_id
        assert "arguments" in c and c["arguments"]["action"] == "disable_user"
    assert events.index(proposed[0]) < events.index(calls[0])


@pytest.mark.parametrize("config", ["flat", "acl_hardened", "agenticcyops"])
def test_memory_write_proposed_precedes_memory_write(config, tmp_path):
    events = _run(config, tmp_path)
    proposed = [e for e in events if e["action"] == "memory_write_proposed"]
    assert len(proposed) == 1
    assert proposed[0]["destination"] == WRITE["store_id"]
    assert proposed[0]["call_id"].startswith("admin:mem_write:")
    assert proposed[0]["content_len"] == len(WRITE["content"])
    writes = [e for e in events if e["action"] == "memory_write"]
    if config == "agenticcyops":
        # MMA is unreachable offline: the proposal is still on record.
        return
    assert len(writes) == 1 and writes[0]["call_id"] == proposed[0]["call_id"]
    assert events.index(proposed[0]) < events.index(writes[0])


def test_call_ids_are_unique_within_an_incident(tmp_path):
    class TwoCalls(StubAgent):
        async def execute(self, context):
            r = AgentResult(phase=self.phase)
            for _ in range(2):
                r.proposed_tool_calls.append(ToolCallProposal(
                    tool_id="T8_iam_pam", arguments=dict(ARGS)))
            return r

    logger = ExperimentLogger(eval_name="t_events", domain="cyberops", config="flat",
                              model="stub", logs_dir=str(tmp_path))
    logger.set_trial("ap1", 1, 1)
    host = SOARHost(domain="cyberops", config="flat", tool_registry=None,
                    agents={"admin": TwoCalls("admin")}, logger=logger)
    asyncio.run(host.run_incident({"incident_id": "inc-2"}))
    logger.close()
    with open(logger.log_file) as f:
        ids = [json.loads(l)["call_id"] for l in f if '"tool_proposed"' in l]
    assert len(ids) == 2 and len(set(ids)) == 2
    # same content -> same hash suffix, different sequence number
    assert ids[0].split(":")[-1] == ids[1].split(":")[-1]


def test_tool_port_map_is_the_same_for_servers_and_clients():
    """Regression (found in E0): servers were numbered in discovery order,
    clients in sorted order, so most tool calls hit the wrong server (404)."""
    from mcp_servers.server_registry import ServerRegistry
    serving = ServerRegistry(domain="cyberops", logger=None)
    serving.load_tools()
    serving.assign_ports(9000)            # what start_all does before serving
    client = ServerRegistry(domain="cyberops", logger=None)
    client.load_tools()
    client.assign_ports(9000)             # what the harness does
    assert serving._ports == client._ports
    assert list(serving._ports.values()) == list(range(9000, 9000 + len(serving._ports)))
    assert sorted(serving._ports, key=serving._ports.get) == sorted(serving._servers)
