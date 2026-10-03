"""H12: parse_logs -> statistical_tests -> generate_tables on synthetic data."""

import csv
import json
import math
from pathlib import Path

from analysis.generate_tables import build
from analysis.parse_logs import discover_runs, parse_run_dir, write_run
from analysis.statistical_tests import (cluster_bootstrap, compute_stats, holm, paired_diff, wilson)


def test_wilson_and_holm():
    p, lo, hi = wilson(0, 10)
    assert p == 0 and lo == 0 and 0 < hi < 0.35
    p, lo, hi = wilson(9, 10)
    assert 0.55 < lo < 0.9 < hi <= 1.0
    assert all(math.isnan(x) for x in wilson(0, 0))
    adj = holm([0.01, 0.04, 0.03, float("nan")])
    assert adj[0] == 0.03 and adj[2] == 0.06 and adj[1] == 0.06 and math.isnan(adj[3])


def _trials(cfg, per_variant_exec, n_trials=3, ap="ap1"):
    out = []
    for v, k in enumerate(per_variant_exec, 1):
        for t in range(1, n_trials + 1):
            out.append({"group": "g", "domain": "cyberops", "ap": ap, "variant": str(v), "trial": str(t),
                        "config": cfg, "outcome": "executed" if t <= k else "blocked", "suffix": ""})
    return out


def test_cluster_bootstrap_and_paired_diff():
    flat = _trials("flat", [3, 3, 2, 3, 3])
    aco = _trials("agenticcyops", [0, 0, 1, 0, 0])
    ind = lambda t: t["outcome"] == "executed"
    key = lambda t: t["variant"]
    p, lo, hi = cluster_bootstrap(flat, ind, key, B=500, seed=1)
    assert abs(p - 14 / 15) < 1e-9 and lo <= p <= hi
    d = paired_diff(flat, aco, ind, key, B=2000, seed=1)
    assert d["clusters"] == 5 and abs(d["diff"] - (14 / 15 - 1 / 15)) < 1e-9
    assert d["low"] > 0 and d["p"] < 0.05
    same = paired_diff(flat, flat, ind, key, B=200, seed=1)
    assert same["diff"] == 0 and same["p"] == 1.0


def test_compute_stats_has_holm_per_family():
    trials = []
    for ap in ("ap1", "ap2"):
        trials += _trials("flat", [3, 3, 3], ap=ap) + _trials("acl_hardened", [2, 1, 3], ap=ap) + _trials("agenticcyops", [0, 0, 0], ap=ap)
    rows = compute_stats(trials, B=300, seed=2)
    scopes = {(r["domain"], r["ap"]) for r in rows}
    assert ("all", "all") in scopes and ("cyberops", "ap1") in scopes
    ap_rows = [r for r in rows if r["ap"] != "all"]
    assert all("flat_minus_aco_p_holm" in r for r in ap_rows)
    assert all(r["flat_minus_aco_p_holm"] >= r["flat_minus_aco_p"] for r in ap_rows)


def test_compute_stats_pools_attack_paths_over_domains():
    """T2a: per-AP rows with domain == "all" pool every domain and keep
    (domain, ap, variant) clusters distinct."""
    trials = []
    for dom in ("cyberops", "finance"):
        for cfg, execs in (("flat", [3, 3, 3]), ("acl_hardened", [1, 1, 1]), ("agenticcyops", [0, 0, 0])):
            for t in _trials(cfg, execs):
                trials.append({**t, "domain": dom})
    rows = compute_stats(trials, B=200, seed=3)
    pooled = [r for r in rows if r["domain"] == "all" and r["ap"] == "ap1"]
    assert len(pooled) == 1
    assert pooled[0]["flat_n"] == 18 and pooled[0]["flat_minus_aco_clusters"] == 6
    assert "flat_minus_aco_p_holm" in pooled[0]


def _write_log(dirpath: Path, config: str, rows: list[dict]):
    dirpath.mkdir(parents=True, exist_ok=True)
    with open(dirpath / f"{config}_20260919_000000.jsonl", "w") as f:
        f.write(json.dumps({"action": "run_header", "git_sha": "a" * 40, "freeze_tag": "defense-freeze-v2",
                            "group": "g1", "config": config, "primary_model": "Qwen/Qwen3-32B",
                            "consensus_config": "div4", "primary_temperature": 0.7, "state_mode": "isolated"}) + "\n")
        for r in rows:
            f.write(json.dumps({"action": "trial_complete", "trial_id": f"cyberops_{r['ap']}_v{r['variant']}_t{r['trial']}_{config}",
                                "config": config, **r}) + "\n")


def test_parse_logs_roundtrip_and_tables(tmp_path):
    logs = tmp_path / "logs"
    res = tmp_path / "results"
    rows = []
    for cfg, execs in (("flat", 1), ("acl_hardened", 1), ("agenticcyops", 0)):
        r = [{"ap": "ap1", "variant": 1, "trial": t, "outcome": "executed" if t <= execs else "blocked",
              "blocked_by": "" if t <= execs else "P2_manifest_enforcement", "collateral_denials": 0,
              "task_completed": True, "latency_s": 12.5, "primary_tokens": 900, "validator_tokens": 300, "seed": t,
              "exposed": t != 3, "channel": "tool_response"}
             for t in (1, 2, 3)]
        r.append({"ap": "benign", "variant": 1, "trial": 1, "outcome": "benign", "blocked_by": "",
                  "collateral_denials": 1 if cfg == "agenticcyops" else 0, "task_completed": True,
                  "latency_s": 9.0, "primary_tokens": 800, "validator_tokens": 100, "seed": 1})
        _write_log(logs / "cyberops_eval_attacks_g1", cfg, r)
    _write_log(logs / "cyberops_eval_attacks_g1_disabled_P3", "agenticcyops",
               [{"ap": "ap1", "variant": 1, "trial": 1, "outcome": "executed", "blocked_by": "", "collateral_denials": 0,
                 "task_completed": True, "latency_s": 1, "primary_tokens": 1, "validator_tokens": 0, "seed": 1}])
    # a run-tagged directory (E1b persistent) whose header still says group g1
    _write_log(logs / "cyberops_eval_attacks_g1_persistent", "agenticcyops",
               [{"ap": "benign", "variant": 1, "trial": 1, "outcome": "benign", "blocked_by": "", "collateral_denials": 2,
                 "task_completed": False, "latency_s": 1, "primary_tokens": 1, "validator_tokens": 0, "seed": 1}])
    runs = discover_runs(logs)
    assert [(d, g, s) for d, g, s, _ in runs] == [("cyberops", "g1", ""), ("cyberops", "g1", "_disabled_P3"),
                                                  ("cyberops", "g1_persistent", "")]
    # exposed / channel (T2) come from the event; a pre-T2 event (the P3 run
    # above has neither) gets the payload's channel and an empty exposed
    main_rows, _, _ = parse_run_dir("cyberops", "g1", "", logs / "cyberops_eval_attacks_g1")
    flat = [r for r in main_rows if r["config"] == "flat" and r["ap"] == "ap1"]
    assert [r["exposed"] for r in sorted(flat, key=lambda r: r["trial"])] == [True, True, False]
    assert all(r["channel"] == "tool_response" for r in flat)
    p3_rows, _, _ = parse_run_dir("cyberops", "g1", "_disabled_P3", logs / "cyberops_eval_attacks_g1_disabled_P3")
    assert p3_rows[0]["exposed"] == "" and p3_rows[0]["channel"] == "alert_text"   # cyberops ap1 v1 payload
    _, _, hdr = parse_run_dir("cyberops", "g1_persistent", "", logs / "cyberops_eval_attacks_g1_persistent")
    assert hdr[0]["group"] == "g1_persistent" and hdr[0]["primary_model"] == "Qwen/Qwen3-32B"
    all_rows, all_runs = [], []
    for domain, group, suffix, d in runs:
        r, details, hdr = parse_run_dir(domain, group, suffix, d)
        path = write_run(domain, group, suffix, r, details, res)
        assert path.exists()
        all_rows += [{**x, "suffix": suffix} for x in r]
        all_runs += hdr
    base = res / "eval_attacks"
    with open(base / "all_trials.csv", "w", newline="") as f:
        cols = list(all_rows[0].keys())
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(all_rows)
    stats = compute_stats([{k: str(v) for k, v in r.items()} for r in all_rows], B=200, seed=1)
    with open(base / "stats.csv", "w", newline="") as f:
        cols = sorted({k for r in stats for k in r})
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(stats)
    with open(base / "runs.csv", "w", newline="") as f:
        cols = sorted({k for r in all_runs for k in r})
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(all_runs)
    md = build(res, "g1")
    assert "## T1." in md and "DEFER" in md and "Flat" in md
    assert "T3. Benign utility" in md and "T4. Ablations" in md and "-P3" in md
    assert "P2_manifest_enforcement" in md
    assert "defense-freeze-v2" in md
    # T1 is one row per (group, config): the pooled per-AP rows (T2a) stay out of it
    t1 = md.split("## T1.")[1].split("## T2a.")[0]
    assert sum(1 for l in t1.splitlines() if l.startswith("| g1 |")) == 3
    assert "| AP-1" in md.split("## T2a.")[1].split("## T2b.")[0]

    # PDF reports from the same files: one per run directory plus the consolidated one
    from analysis.generate_reports import consolidated_report, parse_paper_tables, per_run_reports
    (res / "paper_tables.md").write_text(md)
    sections = {s[0]: s for s in parse_paper_tables(res / "paper_tables.md")}
    assert len(sections["T1"][3]) == 3 and sections["T1"][2][0] == "Group"
    written = per_run_reports(base, all_runs)
    assert sorted(p.parent.parent.name for p in written) == ["group_g1", "group_g1_disabled_P3", "group_g1_persistent"]
    names = {p.parent.parent.name: p.name for p in written}
    assert names["group_g1"] == "attack_report.pdf" and names["group_g1_persistent"] == "benign_report.pdf"
    assert all(p.stat().st_size > 1000 for p in written)
    assert (base / "group_g1" / "cyberops" / "asr_by_ap.png").exists()
    pdf = consolidated_report(res, "g1")
    assert pdf.exists() and pdf.stat().st_size > 10000
