"""
TAMAS baseline-vs-defended comparison.

Consumes ``baseline_results.json`` and ``defended_results.json`` from
``results/tamas/`` and produces:

  - a per-cell (scenario x attack_type) summary with ASR / TSR / ERS
    for both sides, ASR reduction, and a paired McNemar's p-value
  - a paper-ready CSV
  - a JSON summary
  - (optional) a markdown table

The comparison is paired on ``trial_id`` within each cell.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any, Optional

from benchmarks._unused_tamas.attacks.tamas_payloads import (
    TAMAS_ATTACKS,
    get_attack_payload,
)
from benchmarks._unused_tamas.eval_runner import load_results, load_scenario
from benchmarks._unused_tamas.metrics.asr import make_asr_evaluator
from benchmarks._unused_tamas.metrics.ers import compute_ers
from benchmarks._unused_tamas.metrics.tsr import make_tsr_evaluator

HERE = Path(__file__).resolve().parent
SCENARIOS_DIR = HERE / "scenarios"
DEFAULT_RESULTS_DIR = HERE.parents[1] / "results" / "tamas"


# --------------------------------------------------------------------- #
#  McNemar's test
# --------------------------------------------------------------------- #


def _mcnemar_exact(b: int, c: int) -> float:
    """Exact McNemar's test (binomial) for small samples.

    ``b`` is the count of pairs where condition A=1, B=0 (baseline success,
    defended failure).  ``c`` is the reverse.  Returns two-sided p-value.
    """
    from math import comb

    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    # two-sided exact: P(X <= k) + P(X >= n - k) with p=0.5
    p = 0.0
    for i in range(0, k + 1):
        p += comb(n, i) * (0.5 ** n)
    p *= 2
    return min(p, 1.0)


def _mcnemar(baseline_success: list[int], defended_success: list[int]) -> dict:
    """Compute McNemar's test from paired 0/1 outcomes."""
    assert len(baseline_success) == len(defended_success)
    b = sum(1 for bb, dd in zip(baseline_success, defended_success) if bb == 1 and dd == 0)
    c = sum(1 for bb, dd in zip(baseline_success, defended_success) if bb == 0 and dd == 1)
    p_value = _mcnemar_exact(b, c)
    return {"b": b, "c": c, "n_pairs": len(baseline_success), "p_value": p_value}


# --------------------------------------------------------------------- #
#  Cell computation
# --------------------------------------------------------------------- #


def _index_by_cell(results: list[dict]) -> dict[tuple[str, Optional[str]], dict[int, dict]]:
    """Return ``{(scenario, attack_type): {trial_id: result_dict}}``."""
    out: dict[tuple[str, Optional[str]], dict[int, dict]] = defaultdict(dict)
    for r in results:
        meta = r["meta"]
        key = (meta["scenario"], meta.get("attack_type"))
        out[key][meta["trial_id"]] = r
    return out


def _evaluate_cell(
    scenario: str,
    attack_type: Optional[str],
    trials: dict[int, dict],
) -> dict:
    """Compute ASR/TSR/ERS for one (scenario, attack_type) cell."""
    if attack_type is None:
        asr_oracle = lambda _log: False  # benign has no attack to succeed
    else:
        payload = get_attack_payload(attack_type, scenario)
        if payload is None:
            raise KeyError(f"No payload for ({attack_type}, {scenario})")
        asr_oracle = make_asr_evaluator(attack_type, payload)

    scenario_config = load_scenario(SCENARIOS_DIR / f"{scenario}_config.json")
    tsr_oracle = make_tsr_evaluator(scenario_config)

    per_trial: list[dict] = []
    for trial_id in sorted(trials):
        log = trials[trial_id]["run_log"]
        per_trial.append({
            "trial_id": trial_id,
            "asr_success": int(bool(asr_oracle(log))),
            "tsr_success": int(bool(tsr_oracle(log))),
        })
    asr = mean(p["asr_success"] for p in per_trial) if per_trial else 0.0
    tsr = mean(p["tsr_success"] for p in per_trial) if per_trial else 0.0
    return {
        "asr": asr,
        "tsr": tsr,
        "ers": compute_ers(tsr, asr),
        "n": len(per_trial),
        "trials": per_trial,
    }


# --------------------------------------------------------------------- #
#  Top-level compare
# --------------------------------------------------------------------- #


def compare(
    baseline_path: Path,
    defended_path: Path,
    out_dir: Path,
) -> dict:
    baseline = load_results(baseline_path)
    defended = load_results(defended_path)

    base_by_cell = _index_by_cell(baseline)
    def_by_cell = _index_by_cell(defended)

    all_keys = sorted(set(base_by_cell) | set(def_by_cell), key=lambda k: (k[0], k[1] or ""))

    summary: dict[str, Any] = {"cells": [], "aggregate": {}}
    rows_csv: list[dict] = []

    for (scenario, attack_type) in all_keys:
        b_cell = _evaluate_cell(scenario, attack_type, base_by_cell.get((scenario, attack_type), {}))
        d_cell = _evaluate_cell(scenario, attack_type, def_by_cell.get((scenario, attack_type), {}))

        # Pair on trial_id -> McNemar on attack cells only.
        # The simulated driver is deterministic: repeated trials of a cell
        # produce identical outcomes, so a paired test over trial replicates
        # is pseudo-replication.  McNemar is only reported when the cell
        # shows within-cell variance on at least one side; otherwise the
        # cell is flagged ``deterministic`` and no p-value is claimed.
        mcnemar = None
        deterministic = None
        if attack_type is not None:
            paired_ids = sorted(set(t["trial_id"] for t in b_cell["trials"]) &
                                set(t["trial_id"] for t in d_cell["trials"]))
            b_vec = [next(t["asr_success"] for t in b_cell["trials"] if t["trial_id"] == tid)
                     for tid in paired_ids]
            d_vec = [next(t["asr_success"] for t in d_cell["trials"] if t["trial_id"] == tid)
                     for tid in paired_ids]
            deterministic = (len(set(b_vec)) <= 1 and len(set(d_vec)) <= 1)
            if not deterministic:
                mcnemar = _mcnemar(b_vec, d_vec)

        cell = {
            "scenario": scenario,
            "attack_type": attack_type or "benign",
            "baseline": {"asr": b_cell["asr"], "tsr": b_cell["tsr"], "ers": b_cell["ers"], "n": b_cell["n"]},
            "defended": {"asr": d_cell["asr"], "tsr": d_cell["tsr"], "ers": d_cell["ers"], "n": d_cell["n"]},
            "asr_reduction": b_cell["asr"] - d_cell["asr"],
            "mcnemar": mcnemar,
            "deterministic": deterministic,
        }
        summary["cells"].append(cell)
        rows_csv.append({
            "scenario": scenario,
            "attack_type": attack_type or "benign",
            "baseline_n": b_cell["n"],
            "baseline_asr": round(b_cell["asr"], 4),
            "baseline_tsr": round(b_cell["tsr"], 4),
            "baseline_ers": round(b_cell["ers"], 4),
            "defended_n": d_cell["n"],
            "defended_asr": round(d_cell["asr"], 4),
            "defended_tsr": round(d_cell["tsr"], 4),
            "defended_ers": round(d_cell["ers"], 4),
            "asr_reduction": round(b_cell["asr"] - d_cell["asr"], 4),
            "mcnemar_b": (mcnemar or {}).get("b", ""),
            "mcnemar_c": (mcnemar or {}).get("c", ""),
            "mcnemar_n_pairs": (mcnemar or {}).get("n_pairs", ""),
            "mcnemar_p_value": round((mcnemar or {}).get("p_value", 1.0), 6)
                               if mcnemar else "",
            "deterministic": "" if deterministic is None else deterministic,
        })

    # --- aggregate (only on attack cells) -------------------------------
    attack_cells = [c for c in summary["cells"] if c["attack_type"] != "benign"]
    if attack_cells:
        summary["aggregate"] = {
            "n_cells": len(attack_cells),
            "n_cells_fully_blocked": sum(1 for c in attack_cells if c["defended"]["asr"] == 0.0),
            "n_cells_deterministic": sum(1 for c in attack_cells if c.get("deterministic")),
            "n_cells_with_mcnemar": sum(1 for c in attack_cells if c.get("mcnemar")),
            "mean_baseline_asr": round(mean(c["baseline"]["asr"] for c in attack_cells), 4),
            "mean_defended_asr": round(mean(c["defended"]["asr"] for c in attack_cells), 4),
            "mean_asr_reduction": round(mean(c["asr_reduction"] for c in attack_cells), 4),
            "mean_baseline_tsr": round(mean(c["baseline"]["tsr"] for c in attack_cells), 4),
            "mean_defended_tsr": round(mean(c["defended"]["tsr"] for c in attack_cells), 4),
            "mean_baseline_ers": round(mean(c["baseline"]["ers"] for c in attack_cells), 4),
            "mean_defended_ers": round(mean(c["defended"]["ers"] for c in attack_cells), 4),
        }

    # --- write outputs --------------------------------------------------
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "tamas_compare_summary.json"
    csv_path = out_dir / "tamas_compare_summary.csv"
    md_path = out_dir / "tamas_compare_summary.md"

    with open(json_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)

    if rows_csv:
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows_csv[0].keys()))
            w.writeheader()
            w.writerows(rows_csv)

    _write_markdown(summary, md_path)

    return summary


def _write_markdown(summary: dict, path: Path) -> None:
    lines: list[str] = []
    lines.append("# TAMAS -- P1-P5 Defense Evaluation\n")
    agg = summary.get("aggregate") or {}
    if agg:
        lines.append("## Aggregate (attack cells only)\n")
        lines.append(f"- Cells evaluated: **{agg['n_cells']}**")
        lines.append(f"- Mean ASR (baseline):  **{agg['mean_baseline_asr']:.2%}**")
        lines.append(f"- Mean ASR (defended):  **{agg['mean_defended_asr']:.2%}**")
        lines.append(f"- Mean ASR reduction:   **{agg['mean_asr_reduction']:.2%}**")
        lines.append(f"- Mean TSR (baseline):  **{agg['mean_baseline_tsr']:.2%}**")
        lines.append(f"- Mean TSR (defended):  **{agg['mean_defended_tsr']:.2%}**")
        lines.append(f"- Mean ERS (baseline):  **{agg['mean_baseline_ers']:.2%}**")
        lines.append(f"- Mean ERS (defended):  **{agg['mean_defended_ers']:.2%}**")
        lines.append(f"- Cells fully blocked (defended ASR = 0): **{agg['n_cells_fully_blocked']} / {agg['n_cells']}**")
        lines.append(f"- Deterministic cells (identical outcome on every trial): "
                     f"**{agg['n_cells_deterministic']} / {agg['n_cells']}**")
        lines.append("- McNemar p-values are reported only for cells with within-cell "
                     "variance; the simulated driver is deterministic, so trial "
                     "replication is not a source of statistical power.\n")

    lines.append("## Per-cell results\n")
    lines.append("| Scenario | Attack | n | ASR_base | ASR_def | TSR_base | TSR_def | ERS_base | ERS_def | McNemar_p |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for c in summary["cells"]:
        p = ""
        if c.get("mcnemar"):
            p = f"{c['mcnemar']['p_value']:.4f}"
        elif c.get("deterministic"):
            p = "n/a (deterministic)"
        lines.append(
            f"| {c['scenario']} | {c['attack_type']} | {c['baseline']['n']} | "
            f"{c['baseline']['asr']:.2%} | {c['defended']['asr']:.2%} | "
            f"{c['baseline']['tsr']:.2%} | {c['defended']['tsr']:.2%} | "
            f"{c['baseline']['ers']:.2%} | {c['defended']['ers']:.2%} | {p} |"
        )
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", type=Path,
                    default=DEFAULT_RESULTS_DIR / "baseline_results.json")
    ap.add_argument("--defended", type=Path,
                    default=DEFAULT_RESULTS_DIR / "defended_results.json")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    args = ap.parse_args()

    summary = compare(args.baseline, args.defended, args.out_dir)
    agg = summary.get("aggregate") or {}
    if agg:
        print(f"[compare] cells: {agg['n_cells']}  "
              f"ASR {agg['mean_baseline_asr']:.2%} -> "
              f"{agg['mean_defended_asr']:.2%} "
              f"(reduction {agg['mean_asr_reduction']:.2%})")
    print(f"[compare] wrote {args.out_dir}/tamas_compare_summary.{{json,csv,md}}")


if __name__ == "__main__":
    main()
