"""H3: per-trial state isolation.

The same incident is run five times through the full agenticcyops host
(offline: no LLM, no tool servers, no MMA).  In ``isolated`` mode every
trial must produce the identical decision sequence and every
cross-incident store must be empty when the trial starts.  In
``persistent`` mode the cross-incident ledger keeps growing, which is the
replay confound the mode switch exists to remove.
"""

import asyncio
import json

import pytest

from agents.base_agent import AgentResult, ToolCallProposal
from consensus.adaptive_consent import AdaptiveConsentModel
from host.orchestrator import SOARHost
from logging_utils import ExperimentLogger

INCIDENT = {"incident_id": "INC-ISO-1", "alert_type": "credential_compromise",
            "source_ip": "10.0.5.14", "description": "credential stuffing from 10.0.5.14"}


class StubAdmin:
    phase = "admin"

    async def execute(self, context):
        r = AgentResult(phase="admin")
        r.proposed_tool_calls.append(ToolCallProposal(
            tool_id="T9_firewall",
            arguments={"action": "block_ip", "target": "10.0.5.14", "direction": "inbound"},
            justification="contain the source"))
        r.proposed_tool_calls.append(ToolCallProposal(
            tool_id="T8_iam_pam",
            arguments={"action": "revoke", "target_user": "j.martinez", "reason": "compromised"}))
        r.memory_writes.append({"store_id": "M2_case_context", "content": "blocked 10.0.5.14"})
        return r


def _host(state_mode, tmp_path, config="agenticcyops"):
    logger = ExperimentLogger(eval_name="t_state", domain="cyberops", config=config,
                              model="stub", logs_dir=str(tmp_path))
    host = SOARHost(domain="cyberops", config=config, llm_url="http://127.0.0.1:1/v1",
                    mma_url="http://127.0.0.1:1", tool_registry=None,
                    agents={"admin": StubAdmin()}, logger=logger, state_mode=state_mode,
                    adaptive_consent_path=None)
    return host, logger


def _decisions(logger, trial_id):
    with open(logger.log_file) as f:
        rows = [json.loads(l) for l in f if l.strip()]
    return [(e["action"], e.get("destination"), e.get("auth_decision"), e.get("mechanism"))
            for e in rows if e.get("trial_id") == trial_id
            and e["action"] in ("tool_call", "memory_write", "consensus_result", "escalation")]


def test_isolated_mode_reproduces_the_same_decisions_five_times(tmp_path):
    host, logger = _host("isolated", tmp_path)
    ve = host.verified_execution
    seqs = []
    for t in range(1, 6):
        logger.set_trial("benign", 1, t)
        asyncio.run(host.run_incident(dict(INCIDENT)))
        seqs.append(_decisions(logger, logger._trial_id))
    assert all(s == seqs[0] for s in seqs), seqs
    assert seqs[0], "the stub proposals produced no decisions"
    # after a fresh reset the cross-incident stores are empty
    asyncio.run(host.reset_trial_state())
    logger.close()
    assert ve.cross_incident_ledger._ledger == []
    assert ve.adaptive_consent._rewards == {}
    assert host.enforcer._action_counts == {} or all(v == 0 for v in host.enforcer._action_counts.values())


def test_persistent_mode_accumulates_cross_incident_state(tmp_path):
    host, logger = _host("persistent", tmp_path)
    ve = host.verified_execution
    sizes = []
    for t in range(1, 4):
        logger.set_trial("benign", 1, t)
        asyncio.run(host.run_incident({**INCIDENT, "incident_id": f"INC-P-{t}"}))
        sizes.append(len(ve.cross_incident_ledger._ledger)
                     + sum(len(v) if hasattr(v, "__len__") else 1
                           for v in ve.adaptive_consent._rewards.values()))
    logger.close()
    assert sizes == sorted(sizes) and sizes[-1] > 0, sizes


def test_reset_event_is_logged_with_state_mode(tmp_path):
    host, logger = _host("isolated", tmp_path)
    logger.set_trial("benign", 1, 1)
    asyncio.run(host.run_incident(dict(INCIDENT)))
    logger.close()
    with open(logger.log_file) as f:
        rows = [json.loads(l) for l in f if l.strip()]
    resets = [e for e in rows if e["action"] == "trial_reset"]
    assert resets and resets[0]["state_mode"] == "isolated"
    assert rows[0]["action"] == "run_header"
    # in isolated mode the MMA reset is attempted (and fails offline)
    assert "mma" in resets[0]


def test_adaptive_consent_in_memory_mode_never_touches_disk(tmp_path):
    path = tmp_path / "ac.json"
    m = AdaptiveConsentModel(domain="cyberops", persist_path=path, persist=False)
    m._rewards["k"] = {"score": 1.0}
    m._persist()
    assert not path.exists()
    m.reset()
    assert m._rewards == {}
    p = AdaptiveConsentModel(domain="cyberops", persist_path=path, persist=True)
    p._rewards["k"] = {"score": 1.0}
    p._persist()
    assert path.exists()


def test_invalid_state_mode_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        SOARHost(domain="cyberops", config="flat", agents={}, state_mode="sticky")


def test_symbolic_only_runs_the_stack_without_llm_consensus(tmp_path):
    from consensus.validator import ConsensusValidator
    logger = ExperimentLogger(eval_name="t_sym", domain="cyberops", config="symbolic_only",
                              model="stub", logs_dir=str(tmp_path))
    host = SOARHost(domain="cyberops", config="symbolic_only", tool_registry=None,
                    consensus=ConsensusValidator(config_name="div4"),
                    agents={"admin": StubAdmin()}, logger=logger)
    assert host.config == "agenticcyops" and host.config_label == "symbolic_only"
    assert host.consensus is None and host.verified_execution.llm_consensus is None
    assert host.verified_execution.symbolic_only is True
    logger.set_trial("ap1", 1, 1)
    asyncio.run(host.run_incident(dict(INCIDENT)))
    logger.close()
    with open(logger.log_file) as f:
        rows = [json.loads(l) for l in f if l.strip()]
    assert rows[0]["config"] == "symbolic_only"
    mechs = {e.get("mechanism") for e in rows}
    assert "P3_no_consensus" not in mechs


def test_access_isolation_is_fully_constructed_without_a_reset():
    """Found in E0: the H3 reset() was inserted in the middle of __init__, so
    the L5 sanitisation patterns only existed after the first reset and the
    ASB / InjecAgent pipelines (which never reset) crashed."""
    from memory.access_isolation import AccessIsolation
    ai = AccessIsolation(domain="cyberops", embedding_model=None)
    out = ai.sanitize_results([{"content": "normal note about 10.0.5.14"}], "analyze")
    assert isinstance(out, list) and len(out) == 1
    ai.reset()
    assert ai.sanitize_results([{"content": "x"}], "analyze")


def test_l0_scope_expansion_counts_claims_not_tool_evidence():
    """Found in E0: entities in verified tool results were counted as scope
    expansion, so every P3-gated action after a telemetry lookup was denied."""
    from consensus.handoff_validator import HandoffValidator
    hv = HandoffValidator()
    incident = {"description": "credential stuffing from 10.0.5.14 against 10.0.8.200", "initial_severity": "high"}
    telemetry = [{"result": {"hosts": [f"10.0.9.{i}" for i in range(20)], "user": "CORP\\\\jsmith"}}]
    ok, reason, _ = hv._check_scope_expansion(
        {"phase_summary": "Blocked 10.0.5.14 after review.", "tool_results": telemetry}, incident)
    assert ok, reason
    inflated = {"phase_summary": "Compromise confirmed on " + ", ".join(f"10.0.7.{i}" for i in range(15)),
                "tool_results": telemetry}
    ok, reason, _ = hv._check_scope_expansion(inflated, incident)
    assert not ok and reason == "P3_scope_expansion"


def test_git_state_ignores_run_outputs_for_dirty(tmp_path, monkeypatch):
    """git_dirty reflects source, not results/logs/data written by a run."""
    import logging_utils.run_metadata as rm
    # only output-dir changes -> not dirty
    # _git strips the whole output, so the first porcelain line loses its
    # leading status space ("D logs/..."); later lines keep it (" M logs/...").
    monkeypatch.setattr(rm, "_git", lambda *a: (
        "D logs/cyberops/x.jsonl\n M results/eval_attacks/all_trials.csv\n M data/chromadb/y"
        if a[:1] == ("status",) else "abc123" if a[:2] == ("rev-parse", "HEAD") else None))
    assert rm.git_state()["git_dirty"] is False
    # a source change -> dirty
    monkeypatch.setattr(rm, "_git", lambda *a: (
        " M results/eval_attacks/all_trials.csv\n M attacks/harness.py"
        if a[:1] == ("status",) else "abc123" if a[:2] == ("rev-parse", "HEAD") else None))
    assert rm.git_state()["git_dirty"] is True


def test_scrubbed_command_redacts_secrets_and_repo_path(monkeypatch):
    """The logged command must never carry a remote endpoint, an API key, or an
    absolute repo path (regression: REMOTE_5090_URL leaked via --model-url)."""
    import logging_utils.run_metadata as rm
    monkeypatch.setenv("REMOTE_5090_URL", "http://10.9.8.7:8008/v1")
    monkeypatch.setenv("REMOTE_5090_API_KEY", "sk-super-secret-key-value")
    monkeypatch.setenv("VALIDATOR_URL_V1", "http://localhost:8002/v1")   # not secret
    monkeypatch.setattr(rm.sys, "argv", [
        f"{rm.BASE_DIR}/attacks/harness.py",
        "--model-url", "http://10.9.8.7:8008/v1",
        "--api-key", "sk-super-secret-key-value",
        "--validator-url", "http://localhost:8002/v1",
    ])
    out = rm._scrubbed_command()
    assert "10.9.8.7" not in out and "sk-super-secret-key-value" not in out
    assert "<REMOTE_5090_URL>" in out and "<REMOTE_5090_API_KEY>" in out
    assert str(rm.BASE_DIR) not in out and "<repo>" in out
    assert "http://localhost:8002/v1" in out          # localhost URL kept as-is
