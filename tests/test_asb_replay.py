"""E6: the replayed ASB rows must have the same shape as live rows."""

import csv

from benchmarks.asb.run_e2e import load_replay, write_results


def test_replay_rows_write_like_live_rows(tmp_path):
    src = tmp_path / "legacy.csv"
    with open(src, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["asb_case_id", "config", "trial_id", "emitted_action", "emitted_args",
                                          "user_tool", "refused_with_final_answer", "attack_succeeded_llm",
                                          "prompt_tokens", "completion_tokens", "model", "temperature", "error"])
        w.writeheader()
        w.writerow({"asb_case_id": "c1", "config": "agenticcyops", "trial_id": "0", "emitted_action": "ToolX",
                    "emitted_args": '{"a": 1}', "user_tool": "u", "refused_with_final_answer": "False",
                    "attack_succeeded_llm": "True", "prompt_tokens": "10", "completion_tokens": "5",
                    "model": "/x/models/Qwen/Qwen3-235B-A22B-Instruct-2507", "temperature": "0.7", "error": ""})
    rec = load_replay(src)[("c1", "agenticcyops", "0")]
    assert rec["emitted_action"] == "ToolX" and rec["emitted_args"] == {"a": 1}
    assert rec["attack_succeeded_llm"] is True and rec["model"] == "Qwen/Qwen3-235B-A22B-Instruct-2507"
    # what one_cell() builds in replay mode, plus a defense verdict
    case = {"asb_case_id": "c1", "scenario": "s", "agent_name": "a", "attack_type": "DPI", "attack_subtype": "naive"}
    row = {"group": "q235_div4", **{k: case[k] for k in case}, "config": "agenticcyops", **rec,
           "emitted_args": '{"a": 1}', "trial_id": 0, "defense_evaluated": True, "defense_blocked": True,
           "defense_mechanism": "P2_x", "defense_stage": "P2", "attack_succeeded_end_to_end": False}
    write_results([row], "q235_div4", tmp_path, tag="div4")
    out = tmp_path / "e2e_validator_group_q235_div4_div4" / "general"
    rows = list(csv.DictReader(open(out / "results.csv")))
    assert rows[0]["config"] == "agenticcyops" and rows[0]["attack_subtype"] == "naive"
    summ = list(csv.DictReader(open(out / "summary.csv")))
    assert summ[0]["llm_asr_pct"] == "100.0" and summ[0]["defended_asr_pct"] == "0.0"
