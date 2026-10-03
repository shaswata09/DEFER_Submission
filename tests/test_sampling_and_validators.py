"""H7 / H8: sampling settings and validator instrumentation."""

import asyncio
import json

import pytest

from agents.base_agent import BaseAgent
from consensus.validator import ConsensusValidator, ValidatorVote, _parse_vote
from logging_utils import ExperimentLogger


class _Resp:
    class _U:
        prompt_tokens, completion_tokens = 120, 30
    usage = _U()

    def __init__(self, content):
        self.choices = [type("C", (), {"message": type("M", (), {"content": content, "tool_calls": None})()})()]


def test_agent_temperature_and_seed_are_passed_and_logged(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIMARY_TEMPERATURE", "0.7")
    a = BaseAgent.__new__(BaseAgent)
    a.phase, a.config, a.domain = "admin", "flat", "cyberops"
    a._model_name, a._system_prompt, a.llm_url, a._extra_body = "m", "s", "http://127.0.0.1:1/v1", None
    a.temperature, a.seed = 0.7, None
    seen = {}

    class Client:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    seen.update(kw)
                    return _Resp('{"summary": "ok"}')
    a._client = Client()
    a.set_seed(41)
    monkeypatch.setattr("utils.rate_limiter.throttle_for_url", lambda url: None)
    monkeypatch.setattr("utils.rate_limiter.call_with_retry", lambda f: f())
    result, tp, tc = a._call_openai("hello", None)
    assert seen["temperature"] == 0.7 and seen["seed"] == 41
    assert (tp, tc) == (120, 30)


def test_parse_vote_handles_prose_and_garbage():
    assert _parse_vote('{"decision": "approve", "confidence": 0.9}')["decision"] == "approve"
    assert _parse_vote('Sure. {"decision": "reject", "reason": "x"} thanks')["decision"] == "reject"
    assert _parse_vote("no json here")["decision"] == "reject"
    assert _parse_vote("[1,2]")["decision"] == "reject"


def test_validator_error_is_a_logged_error_vote(tmp_path, monkeypatch):
    logger = ExperimentLogger(eval_name="t_val", domain="cyberops", config="agenticcyops",
                              model="stub", logs_dir=str(tmp_path))
    logger.set_trial("ap1", 1, 1)
    cv = ConsensusValidator(config_name="default_consensus", logger=logger)

    async def boom(config, msg):
        raise ConnectionError("validator down")

    async def fine(config, msg):
        return {"decision": "approve", "confidence": 0.8, "reason": "ok",
                "_usage": {"prompt": 50, "completion": 10}}

    monkeypatch.setattr(cv, "_call_openai", boom)
    monkeypatch.setattr(cv, "_call_openai_api", fine)
    monkeypatch.setattr(cv, "_call_anthropic", fine)
    res = asyncio.run(cv.validate_with_details({"tool_id": "T9_firewall", "arguments": {}}, {}))
    logger.close()
    by_id = {v.validator_id: v for v in res.votes}
    assert by_id["V1_qwen"].decision == "error" and by_id["V2_deepseek"].decision == "error"
    assert by_id["V6_gpt4o"].decision == "approve" and by_id["V6_gpt4o"].tokens_used == 60
    assert res.approvals == 2 and res.rejections == 2 and res.approved is False   # 3/4 needed
    with open(logger.log_file) as f:
        votes = [json.loads(l) for l in f if '"consensus_vote"' in l]
    assert sorted(v["auth_decision"] for v in votes) == ["approve", "approve", "error", "error"]
    ok = [v for v in votes if v["auth_decision"] == "approve"]
    assert all(v["tokens_used"] == 60 for v in ok)


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_every_agent_class_constructs_for_real(provider, monkeypatch):
    """Regression: a function-local `import os` shadowed the module import and
    made every agent constructor raise UnboundLocalError (found in E0)."""
    from agents.admin_agent import AdminAgent
    from agents.analyze_agent import AnalyzeAgent
    from agents.monitor_agent import MonitorAgent
    from agents.report_agent import ReportAgent
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("PRIMARY_TEMPERATURE", "0.7")
    for cls in (MonitorAgent, AnalyzeAgent, AdminAgent, ReportAgent):
        kw = dict(domain="cyberops", config="agenticcyops", manifest={"allowed_tools": []},
                  tool_schemas=[], all_tool_schemas=[], logger=None)
        if provider == "anthropic":
            kw["llm_provider"] = "anthropic"
        else:
            kw["llm_url"] = "http://127.0.0.1:1/v1"
        a = cls(**kw)
        assert a.temperature == 0.7 and a.seed is None
        a.set_seed(5); a.set_temperature(0.2)
        assert a.seed == 5 and a.temperature == 0.2


@pytest.mark.parametrize("content", ['["a", "b"]', "42", '"just a string"', "null", "not json"])
def test_non_object_json_content_does_not_void_the_trial(content):
    """Found in the Scout run: a JSON array answer raised AttributeError in
    _parse_response, which the host recorded as agent_error (39 trials)."""
    a = BaseAgent.__new__(BaseAgent)
    a.phase = "admin"
    resp = _Resp(content)
    result = a._parse_response(resp)
    assert result.summary and result.proposed_tool_calls == [] and result.memory_writes == []
