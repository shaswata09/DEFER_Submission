"""Log hygiene: every log starts with a run_header and never carries host paths."""

import json

from logging_utils import ExperimentLogger
from logging_utils.run_metadata import HEADER_FIELDS, build_run_header


def _lines(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def test_first_line_is_run_header_with_full_schema(tmp_path):
    lg = ExperimentLogger(eval_name="t_eval", domain="cyberops", config="flat",
                          model="/mnt/vol/models/Qwen/Qwen3-32B", logs_dir=str(tmp_path))
    lg.set_trial("ap1", 1, 1)
    lg.log(source="a", destination="b", action="x")
    lg.close()
    rows = _lines(lg.log_file)
    assert rows[0]["action"] == "run_header"
    for k in HEADER_FIELDS:
        assert k in rows[0], k
    assert rows[0]["primary_model"] == "Qwen/Qwen3-32B"
    assert rows[0]["git_sha"] is None or len(rows[0]["git_sha"]) == 40
    assert rows[1]["action"] == "x"


def test_model_field_never_contains_a_host_path(tmp_path):
    lg = ExperimentLogger(eval_name="t_eval", domain="cyberops", config="flat",
                          model="/srv/models/Qwen/Qwen3-235B-A22B-Instruct-2507",
                          logs_dir=str(tmp_path))
    lg.set_trial("ap1", 1, 1)
    lg.log(source="monitor_agent", destination="llm", action="llm_call",
           extra={"model": "/srv/models/meta-llama/Llama-4-Scout-17B-16E-Instruct"})
    lg.log(source="monitor_agent", destination="llm", action="llm_call",
           extra={"model": "claude-sonnet-4-5-20250929"})
    lg.close()
    rows = _lines(lg.log_file)
    assert rows[0]["primary_model"] == "Qwen/Qwen3-235B-A22B-Instruct-2507"
    assert rows[1]["model"] == "meta-llama/Llama-4-Scout-17B-16E-Instruct"
    assert rows[2]["model"] == "claude-sonnet-4-5-20250929"
    text = open(lg.log_file).read()
    assert "/srv/" not in text and "/mnt/" not in text


def test_build_run_header_fills_panel_and_quantization():
    h = build_run_header(group="A", config="agenticcyops", domain="cyberops",
                         primary_model="/x/models/zai-org/GLM-4.7-FP8",
                         consensus_config="default_consensus", probe=False)
    assert h["primary_model"] == "zai-org/GLM-4.7-FP8"
    assert h["primary_quantization"] == "fp8"
    assert set(h["validator_models"]) == {"V1_qwen", "V2_deepseek", "V4_claude", "V6_gpt4o"}
    assert h["consensus_threshold"] == 3
    assert h["disabled_principles"] == []
    assert h["command"]


def test_update_header_records_late_fields(tmp_path):
    lg = ExperimentLogger(eval_name="t_eval", domain="legal", config="agenticcyops",
                          model="Group_A", logs_dir=str(tmp_path))
    lg.update_header(primary_model="/a/models/Qwen/Qwen3-32B", seed=7)
    lg.close()
    rows = _lines(lg.log_file)
    assert rows[1]["action"] == "run_header_update"
    assert rows[1]["primary_model"] == "Qwen/Qwen3-32B" and rows[1]["seed"] == 7
    assert lg.header["seed"] == 7


def test_no_event_field_carries_the_checkout_path(tmp_path):
    """Paths inside the checkout (e.g. a config-integrity event's changed_files)
    are written repo-relative, so no log carries the machine's absolute path."""
    from config import BASE_DIR
    lg = ExperimentLogger(eval_name="t_eval", domain="cyberops", config="agenticcyops",
                          model="Qwen/Qwen3-32B", logs_dir=str(tmp_path))
    lg.set_trial("ap15", 3, 1)
    changed = str(BASE_DIR / "domains" / "cyberops" / "configs" / "asset_criticality.json")
    lg.log(source="host", destination="configs", action="config_verification",
           auth_decision="deny", extra={"changed_files": [changed]})
    lg.close()
    text = open(lg.log_file).read()
    assert str(BASE_DIR) not in text
    assert _lines(lg.log_file)[-1]["changed_files"] == ["./domains/cyberops/configs/asset_criticality.json"]
