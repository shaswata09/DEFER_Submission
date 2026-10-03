"""
Cross-defense tables for one domain, rebuilt from the JSONL logs.

Replaces the aggregation cell that every per-defense notebook used to carry.
Loads the latest log per defense id from ``domains/<domain>/existing_defense_eval/logs``,
applies the measurability rule for prompt-modification defenses (old logs
predate the ``measurable`` field, so it is derived from the payload), and
writes::

    cross_defense_summary_<domain>.csv           per-AP bypass % per defense (blank = not measurable)
    cross_defense_category_summary_<domain>.csv  IPI / Structural means over measurable APs
    cross_defense_measurability_<domain>.csv     which (defense, AP) cells are measurable
    cross_defense_heatmap_<domain>.png
    cross_defense_bars_<domain>.png

Usage::

    python domains/existing_defense_eval/common/cross_defense_tables.py --domain cyberops
    python domains/existing_defense_eval/common/cross_defense_tables.py --domain all
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # so `import common` works when run as a file

from common.attack_categories import AP_NAMES, category            # noqa: E402
from common.attack_loader import load_attack_payloads              # noqa: E402
from common.measurability import is_prompt_mod_defense, prompt_defense_measurable  # noqa: E402
from common.metrics import compute_per_ap_bypass                   # noqa: E402
from common.plotting import plot_defense_comparison                # noqa: E402

PROJECT_ROOT = HERE.parents[2]
DOMAINS = ("cyberops", "healthcare", "finance", "legal")


def _short(d: str) -> str:
    return (d.replace("_finetuned_detector", "_ft_det")
             .replace("_llm_detector", "_llm_det")
             .replace("_perplexity_filter", "_ppl")
             .replace("_instructional_prevention", "_instr")
             .replace("_data_prompt_isolation", "_isol")
             .replace("_sandwich_prevention", "_sand")
             .replace("_paraphrasing", "_para")
             .replace("_adversarial_finetuning_secalign", "_secalign")
             .replace("_llama8b", "_L")
             .replace("_gpt2", "_G2"))


def latest_logs(log_dir: Path, domain: str) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for p in sorted(log_dir.glob("d*.jsonl")):
        m = re.match(r"(d\d_[\w_]+?)_" + domain + r"_\d+_\d+\.jsonl", p.name)
        if m:
            out[m.group(1)] = p  # sorted -> last write wins
    return out


def load_trials(path: Path, domain: str, measurable_by_key: dict[tuple, bool]) -> list[dict]:
    """Trial records with the measurability rule applied for prompt-mod defenses."""
    trials = []
    for line in path.read_text().splitlines():
        ev = json.loads(line)
        if ev.get("action") != "trial":
            continue
        did = ev.get("defense", "")
        blocked = ev.get("blocked")
        measurable = ev.get("measurable")
        if measurable is None and is_prompt_mod_defense(did):
            measurable = measurable_by_key.get((ev["ap"], ev.get("variant")), True)
        if measurable is None:
            measurable = True
        if not measurable:
            blocked = None
        trials.append({
            "ap": ev["ap"], "variant": ev.get("variant"), "trial": ev.get("trial"),
            "blocked": blocked, "category": ev.get("category") or category(ev["ap"]),
            "measurable": bool(measurable),
        })
    return trials


def build_tables(domain: str) -> None:
    log_dir = PROJECT_ROOT / "domains" / domain / "existing_defense_eval" / "logs"
    payloads = load_attack_payloads(domain)
    measurable_by_key = {
        (p["_ap"], p.get("variant_id") or p.get("name", "v?")): prompt_defense_measurable(p)
        for p in payloads
    }

    per_defense_logs = {did: load_trials(p, domain, measurable_by_key)
                        for did, p in latest_logs(log_dir, domain).items()}
    if len(per_defense_logs) < 2:
        print(f"[{domain}] fewer than two defenses logged; nothing to do")
        return

    per_defense_per_ap = {d: compute_per_ap_bypass(ev) for d, ev in per_defense_logs.items()}
    defenses = sorted(per_defense_per_ap)
    aps = sorted({ap for d in per_defense_per_ap.values() for ap in d},
                 key=lambda a: int(a[2:]))
    short = [_short(d) for d in defenses]

    # ---- per-AP summary (blank = not measurable) ---------------------------
    rows, meas_rows = [], []
    for ap in aps:
        row = {"AP": ap.upper(), "Cat": category(ap)[0], "Name": AP_NAMES.get(ap, "")[:22]}
        mrow = {"AP": ap.upper()}
        for d, sd in zip(defenses, short):
            cell = per_defense_per_ap[d].get(ap, {})
            br = cell.get("bypass_rate")
            n = cell.get("total", 0)
            row[sd] = round(br * 100, 1) if (br is not None and n > 0) else None
            mrow[sd] = "measurable" if n > 0 else "not_measurable"
        rows.append(row)
        meas_rows.append(mrow)
    summary_df = pd.DataFrame(rows)
    summary_df.to_csv(log_dir / f"cross_defense_summary_{domain}.csv", index=False)
    pd.DataFrame(meas_rows).to_csv(log_dir / f"cross_defense_measurability_{domain}.csv", index=False)
    print(f"\n=== {domain}: per-AP bypass rate per defense (%) -- blank = not measurable ===")
    print(summary_df.to_string(index=False))

    # ---- heatmap --------------------------------------------------------
    matrix = np.full((len(aps), len(defenses)), np.nan)
    for i, ap in enumerate(aps):
        for j, d in enumerate(defenses):
            cell = per_defense_per_ap[d].get(ap, {})
            if cell.get("total", 0) > 0 and cell.get("bypass_rate") is not None:
                matrix[i, j] = cell["bypass_rate"] * 100
    fig, ax = plt.subplots(figsize=(max(8, len(defenses) * 1.4), 0.5 * len(aps) + 2.5))
    im = ax.imshow(matrix, cmap="RdYlGn_r", vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(len(defenses))); ax.set_xticklabels(short, rotation=45, ha="right", fontsize=9)
    ax.set_yticks(range(len(aps)))
    ax.set_yticklabels([f'{a.upper()} ({category(a)[0]}) {AP_NAMES.get(a, "")[:22]}' for a in aps], fontsize=9)
    for i in range(len(aps)):
        for j in range(len(defenses)):
            v = matrix[i, j]
            ax.text(j, i, "n/a" if np.isnan(v) else f"{v:.0f}", ha="center", va="center",
                    fontsize=8, color="#7f8c8d" if np.isnan(v) else ("white" if v > 50 else "black"))
    plt.colorbar(im, ax=ax, label="Bypass Rate (%)")
    ax.set_title(f"Cross-Defense x Cross-AP Bypass Heatmap -- {domain}\n"
                 "(I = IPI AP, S = Structural AP; red = weak defense; n/a = not measurable)", fontsize=11)
    plt.tight_layout()
    fig.savefig(log_dir / f"cross_defense_heatmap_{domain}.png", dpi=150, bbox_inches="tight")
    plt.close(fig)

    # ---- grouped bars ---------------------------------------------------
    fig = plot_defense_comparison(per_defense_per_ap, domain=domain)
    fig.savefig(log_dir / f"cross_defense_bars_{domain}.png", dpi=130, bbox_inches="tight")
    plt.close(fig)

    # ---- IPI vs Structural per defense (measurable APs only) -------------
    cat_rows = []
    for d, per_ap in per_defense_per_ap.items():
        ipi = [v["bypass_rate"] * 100 for k, v in per_ap.items()
               if category(k) == "IPI" and v.get("total", 0) > 0]
        struct = [v["bypass_rate"] * 100 for k, v in per_ap.items()
                  if category(k) == "Structural" and v.get("total", 0) > 0]
        n_ipi_all = sum(1 for k in per_ap if category(k) == "IPI")
        n_struct_all = sum(1 for k in per_ap if category(k) == "Structural")
        cat_rows.append({
            "Defense": d,
            "mode": "prompt_modification" if is_prompt_mod_defense(d) else "static_filter",
            "IPI_n_APs_measured": len(ipi), "IPI_n_APs_total": n_ipi_all,
            "IPI_mean_bypass_%": round(float(np.mean(ipi)), 1) if ipi else None,
            "Struct_n_APs_measured": len(struct), "Struct_n_APs_total": n_struct_all,
            "Struct_mean_bypass_%": round(float(np.mean(struct)), 1) if struct else None,
            "Overall_mean_bypass_%": round(float(np.mean(ipi + struct)), 1) if (ipi or struct) else None,
        })
    cat_df = pd.DataFrame(cat_rows).sort_values("Overall_mean_bypass_%", na_position="last")
    cat_df.to_csv(log_dir / f"cross_defense_category_summary_{domain}.csv", index=False)
    print(f"\n=== {domain}: defense effectiveness by attack category (measurable APs only) ===")
    print(cat_df.to_string(index=False))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--domain", default="cyberops")
    args = ap.parse_args()
    for d in (DOMAINS if args.domain == "all" else [args.domain]):
        build_tables(d)


if __name__ == "__main__":
    main()
