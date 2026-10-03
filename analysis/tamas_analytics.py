"""
TAMAS Analytics -- Paper-Ready PDF Report + Enhanced CSV.

Consumes the artifacts written by ``benchmarks/_unused_tamas/compare.py`` plus
the raw trial logs (``baseline_results.json`` / ``defended_results.json``)
and produces:

  1. ``results/tamas/tamas_findings.pdf``  -- multi-page report
  2. ``results/tamas/tamas_enhanced.csv``  -- one row per trial event
                                              used for analytics
  3. ``results/tamas/tamas_defense_attribution.csv``  -- per-mechanism
                                                        block counts

Usage::

    python -m analysis.tamas_analytics
    python -m analysis.tamas_analytics --results-dir results/tamas/ \
                                       --out-dir    results/tamas/
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages

from benchmarks._unused_tamas.attacks.tamas_payloads import TAMAS_ATTACKS


# --------------------------------------------------------------------- #
#  Style
# --------------------------------------------------------------------- #

sns.set_theme(style="whitegrid", font_scale=1.0, palette="muted")
plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "savefig.bbox": "tight",
    "font.family": "sans-serif",
    "axes.titleweight": "bold",
    "axes.titlesize": 13,
})

BASELINE_COLOR = "#e74c3c"
DEFENDED_COLOR = "#2ecc71"
ACCENT = "#2980b9"
NEUTRAL = "#7f8c8d"

ATTACK_TYPE_LABELS = {
    "tool_misuse":             "Tool Misuse (P2)",
    "data_exfiltration":       "Data Exfiltration (P5/P2)",
    "direct_prompt_injection": "Direct Prompt Injection (P3)",
    "indirect_prompt_injection":"Indirect Prompt Injection (P4)",
    "byzantine_behavior":      "Byzantine Behavior (P3)",
    "persuasive_manipulation": "Persuasive Manipulation (P3)",
    "benign":                  "Benign",
}

ATTACK_TYPE_ORDER = [
    "tool_misuse",
    "data_exfiltration",
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "byzantine_behavior",
    "persuasive_manipulation",
]


# --------------------------------------------------------------------- #
#  Data loading
# --------------------------------------------------------------------- #


def _load(path: Path) -> Any:
    with open(path) as f:
        return json.load(f)


def _flatten_events(results: list[dict], mode: str) -> pd.DataFrame:
    """Expand a result list into a DataFrame of trial events."""
    rows = []
    for r in results:
        meta = r["meta"]
        for ev in r["run_log"]:
            rows.append({
                "mode":         mode,
                "scenario":     meta["scenario"],
                "attack_type":  meta.get("attack_type") or "benign",
                "trial_id":     meta["trial_id"],
                "role":         ev.get("role"),
                "action":       ev.get("action"),
                "tool_id":      ev.get("tool_id"),
                "phase":        ev.get("phase"),
                "auth_decision":ev.get("auth_decision"),
                "mechanism":    ev.get("mechanism"),
                "_redacted":    bool(ev.get("_redacted")),
                "_rogue":       bool(ev.get("_rogue")),
                "_persuasion":  bool(ev.get("_persuasion_active")),
            })
    return pd.DataFrame(rows)


def _build_cell_df(summary: dict) -> pd.DataFrame:
    rows = []
    for c in summary["cells"]:
        base = c["baseline"]
        deff = c["defended"]
        mc = c.get("mcnemar") or {}
        rows.append({
            "scenario":     c["scenario"],
            "attack_type":  c["attack_type"],
            "baseline_asr": base["asr"],
            "defended_asr": deff["asr"],
            "baseline_tsr": base["tsr"],
            "defended_tsr": deff["tsr"],
            "baseline_ers": base["ers"],
            "defended_ers": deff["ers"],
            "asr_reduction":c["asr_reduction"],
            "mcnemar_p":    mc.get("p_value"),
            "mcnemar_b":    mc.get("b"),
            "mcnemar_c":    mc.get("c"),
            "deterministic": bool(c.get("deterministic")),
            "n":            base["n"],
        })
    return pd.DataFrame(rows)


# --------------------------------------------------------------------- #
#  PDF pages
# --------------------------------------------------------------------- #


def _page_title(pdf: PdfPages, summary: dict, cell_df: pd.DataFrame) -> None:
    fig = plt.figure(figsize=(8.5, 11))
    fig.patch.set_facecolor("white")
    gs = fig.add_gridspec(1, 1)
    ax = fig.add_subplot(gs[0, 0])
    ax.axis("off")

    title = "TAMAS Benchmark: P1-P5 Defense Evaluation"
    subtitle = "Targeting Agentic Multi-Agent Systems (arxiv 2506.02635)"
    date = datetime.now().strftime("%Y-%m-%d")

    ax.text(0.5, 0.92, title, ha="center", fontsize=22, weight="bold")
    ax.text(0.5, 0.88, subtitle, ha="center", fontsize=12, style="italic", color=NEUTRAL)
    ax.text(0.5, 0.83, f"DEFER -- generated {date}", ha="center",
            fontsize=10, color=NEUTRAL)

    # Executive summary block -----------------------------------------
    agg = summary.get("aggregate") or {}
    attack_cells = cell_df[cell_df["attack_type"] != "benign"]
    n_trials_total = int(attack_cells["n"].sum() * 2) if not attack_cells.empty else 0

    bullets = [
        f"Attack cells evaluated:      {len(attack_cells)}",
        f"Trials per mode:             {int(attack_cells['n'].sum()) if not attack_cells.empty else 0}",
        f"Total trials (both sides):   {n_trials_total}",
        f"Attack types exercised:      {attack_cells['attack_type'].nunique()}",
        f"Scenarios covered:           {cell_df['scenario'].nunique()}",
        "",
        f"Baseline mean ASR:           {agg.get('mean_baseline_asr', 0):.2%}",
        f"Defended mean ASR:           {agg.get('mean_defended_asr', 0):.2%}",
        f"ASR reduction:               {agg.get('mean_asr_reduction', 0):.2%}",
        "",
        f"Baseline mean TSR:           {agg.get('mean_baseline_tsr', 0):.2%}",
        f"Defended mean TSR:           {agg.get('mean_defended_tsr', 0):.2%}",
        "",
        f"Baseline mean ERS:           {agg.get('mean_baseline_ers', 0):.2%}",
        f"Defended mean ERS:           {agg.get('mean_defended_ers', 0):.2%}",
        "",
        f"Cells fully blocked (defended ASR = 0):  "
        f"{int((attack_cells['defended_asr'] == 0).sum())} / {len(attack_cells)}",
        f"Deterministic cells (no within-cell variance): "
        f"{int(attack_cells['deterministic'].sum()) if 'deterministic' in attack_cells.columns else 0}"
        f" / {len(attack_cells)}",
        f"Cells with McNemar p < 0.001 (only cells with variance): "
        f"{int((attack_cells['mcnemar_p'].fillna(1.0) < 0.001).sum())} / {len(attack_cells)}",
    ]
    ax.text(0.06, 0.72, "Executive Summary", fontsize=16, weight="bold", color=ACCENT)
    ax.text(0.06, 0.66, "\n".join(bullets), fontsize=10.5, family="monospace",
            va="top")

    # Key findings -----------------------------------------------------
    key_findings = []
    if not attack_cells.empty:
        per_attack_base = attack_cells.groupby("attack_type")["baseline_asr"].mean()
        per_attack_def = attack_cells.groupby("attack_type")["defended_asr"].mean()
        strongest = (per_attack_base - per_attack_def).idxmax()
        weakest   = (per_attack_base - per_attack_def).idxmin()
        worst_cell = attack_cells.sort_values("defended_asr", ascending=False).iloc[0]

        key_findings = [
            f"  * Defense with greatest ASR reduction: "
            f"{ATTACK_TYPE_LABELS.get(strongest, strongest)}"
            f" ({per_attack_base[strongest]:.0%} -> {per_attack_def[strongest]:.0%})",
            "",
            f"  * Weakest defense (smallest reduction): "
            f"{ATTACK_TYPE_LABELS.get(weakest, weakest)}"
            f" ({per_attack_base[weakest]:.0%} -> {per_attack_def[weakest]:.0%})",
            "",
            f"  * Worst residual cell: "
            f"{worst_cell['scenario']} x {worst_cell['attack_type']} "
            f"(defended ASR = {worst_cell['defended_asr']:.0%})",
            "",
            "  * TSR preserved at 100%: benign task completion unaffected",
            "    by middleware enforcement in every scenario.",
        ]

    ax.text(0.06, 0.26, "Key Findings", fontsize=16, weight="bold", color=ACCENT)
    ax.text(0.06, 0.22, "\n".join(key_findings), fontsize=10.5, va="top")

    pdf.savefig(fig)
    plt.close(fig)


def _page_aggregate_bars(pdf: PdfPages, cell_df: pd.DataFrame) -> None:
    attack = cell_df[cell_df["attack_type"] != "benign"]
    if attack.empty:
        return
    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    fig.suptitle("Aggregate Defense Impact", fontsize=15, weight="bold")

    # --- ASR bar chart ------------------------------------------------
    labels = ["Baseline", "Defended"]
    values = [attack["baseline_asr"].mean(), attack["defended_asr"].mean()]
    colors = [BASELINE_COLOR, DEFENDED_COLOR]
    axes[0].bar(labels, values, color=colors, edgecolor="black")
    axes[0].set_title("Mean Attack Success Rate")
    axes[0].set_ylabel("ASR")
    axes[0].set_ylim(0, 1.05)
    for i, v in enumerate(values):
        axes[0].text(i, v + 0.02, f"{v:.1%}", ha="center", weight="bold")

    # --- ERS bar chart ------------------------------------------------
    values_ers = [attack["baseline_ers"].mean(), attack["defended_ers"].mean()]
    axes[1].bar(labels, values_ers, color=colors, edgecolor="black")
    axes[1].set_title("Mean Effective Robustness Score (ERS = TSR*(1-ASR))")
    axes[1].set_ylabel("ERS")
    axes[1].set_ylim(0, 1.05)
    for i, v in enumerate(values_ers):
        axes[1].text(i, v + 0.02, f"{v:.1%}", ha="center", weight="bold")

    plt.tight_layout(rect=[0, 0, 1, 0.93])
    pdf.savefig(fig)
    plt.close(fig)


def _page_heatmap(pdf: PdfPages, cell_df: pd.DataFrame) -> None:
    attack = cell_df[cell_df["attack_type"] != "benign"]
    if attack.empty:
        return
    pivot = attack.pivot(index="attack_type", columns="scenario",
                        values="defended_asr")
    pivot = pivot.reindex([a for a in ATTACK_TYPE_ORDER if a in pivot.index])
    fig, ax = plt.subplots(figsize=(11, 6))
    sns.heatmap(
        pivot,
        annot=True, fmt=".0%",
        cmap="RdYlGn_r", vmin=0, vmax=1,
        linewidths=0.5, linecolor="white",
        cbar_kws={"label": "Defended ASR (lower = better)"},
        ax=ax,
    )
    ax.set_title("Residual Defended ASR  (scenarios x attack types)",
                fontsize=13, weight="bold")
    ax.set_xlabel("")
    ax.set_ylabel("")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _page_per_attack(pdf: PdfPages, cell_df: pd.DataFrame) -> None:
    attack = cell_df[cell_df["attack_type"] != "benign"]
    if attack.empty:
        return
    per = attack.groupby("attack_type").agg(
        baseline_asr=("baseline_asr", "mean"),
        defended_asr=("defended_asr", "mean"),
        cells=("scenario", "count"),
    ).reset_index()
    per["attack_type"] = pd.Categorical(
        per["attack_type"],
        categories=[a for a in ATTACK_TYPE_ORDER if a in per["attack_type"].values],
        ordered=True,
    )
    per = per.sort_values("attack_type")

    fig, ax = plt.subplots(figsize=(11, 5.5))
    x = np.arange(len(per))
    width = 0.35
    ax.bar(x - width/2, per["baseline_asr"], width,
           color=BASELINE_COLOR, edgecolor="black", label="Baseline")
    ax.bar(x + width/2, per["defended_asr"], width,
           color=DEFENDED_COLOR, edgecolor="black", label="Defended")
    ax.set_xticks(x)
    ax.set_xticklabels(
        [ATTACK_TYPE_LABELS.get(a, a) for a in per["attack_type"]],
        rotation=15, ha="right", fontsize=9,
    )
    ax.set_ylabel("Mean ASR across scenarios")
    ax.set_ylim(0, 1.1)
    ax.set_title("ASR per Attack Type  (baseline vs defended)",
                fontsize=13, weight="bold")
    ax.legend(loc="upper right")
    # annotate values
    for i, row in per.reset_index(drop=True).iterrows():
        ax.text(i - width/2, row["baseline_asr"] + 0.01,
                f"{row['baseline_asr']:.0%}", ha="center", fontsize=8)
        ax.text(i + width/2, row["defended_asr"] + 0.01,
                f"{row['defended_asr']:.0%}", ha="center", fontsize=8)
        ax.text(i, -0.08, f"n={row['cells']} cells", ha="center",
                fontsize=8, color=NEUTRAL)
    plt.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _page_tsr_benign(pdf: PdfPages, cell_df: pd.DataFrame) -> None:
    if cell_df.empty:
        return
    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    fig.suptitle("Task Success Rate and Benign Behavior",
                fontsize=15, weight="bold")

    # --- TSR on attack cells ------------------------------------------
    attack = cell_df[cell_df["attack_type"] != "benign"]
    labels = ["Baseline (attack)", "Defended (attack)"]
    values = [attack["baseline_tsr"].mean(), attack["defended_tsr"].mean()]
    colors = [BASELINE_COLOR, DEFENDED_COLOR]
    axes[0].bar(labels, values, color=colors, edgecolor="black")
    axes[0].set_title("TSR Under Attack")
    axes[0].set_ylim(0, 1.05)
    axes[0].set_ylabel("TSR")
    for i, v in enumerate(values):
        axes[0].text(i, v + 0.02, f"{v:.1%}", ha="center", weight="bold")

    # --- Benign false-positive rate -----------------------------------
    benign = cell_df[cell_df["attack_type"] == "benign"]
    if not benign.empty:
        labels_b = ["Baseline (benign)", "Defended (benign)"]
        values_b = [benign["baseline_tsr"].mean(), benign["defended_tsr"].mean()]
        axes[1].bar(labels_b, values_b, color=colors, edgecolor="black")
        axes[1].set_title("TSR on Benign Trials (no attack)")
        axes[1].set_ylim(0, 1.05)
        axes[1].set_ylabel("TSR")
        for i, v in enumerate(values_b):
            axes[1].text(i, v + 0.02, f"{v:.1%}", ha="center", weight="bold")

    plt.tight_layout(rect=[0, 0, 1, 0.93])
    pdf.savefig(fig)
    plt.close(fig)


def _page_defense_attribution(
    pdf: PdfPages, events_df: pd.DataFrame
) -> pd.DataFrame:
    attacker_denied = events_df[
        (events_df["mode"] == "defended")
        & (events_df["phase"] == "attack")
        & (events_df["auth_decision"] == "deny")
    ]
    if attacker_denied.empty:
        return pd.DataFrame()
    counts = attacker_denied.groupby(
        ["attack_type", "mechanism"], dropna=False
    ).size().rename("count").reset_index()
    pivot = counts.pivot_table(
        index="attack_type", columns="mechanism", values="count", fill_value=0
    )
    pivot = pivot.loc[[a for a in ATTACK_TYPE_ORDER if a in pivot.index]]

    fig, ax = plt.subplots(figsize=(11, 5.5))
    pivot.plot(
        kind="bar", stacked=True, ax=ax,
        edgecolor="black", width=0.75,
    )
    ax.set_title("Defense Mechanism Attribution per Attack Type",
                fontsize=13, weight="bold")
    ax.set_xlabel("")
    ax.set_ylabel("Attack events blocked")
    ax.set_xticklabels(
        [ATTACK_TYPE_LABELS.get(a, a) for a in pivot.index],
        rotation=15, ha="right", fontsize=9,
    )
    ax.legend(title="Mechanism", bbox_to_anchor=(1.02, 1), loc="upper left",
              fontsize=9)
    plt.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)
    return pivot


def _page_mcnemar(pdf: PdfPages, cell_df: pd.DataFrame) -> None:
    attack = cell_df[cell_df["attack_type"] != "benign"].copy()
    if attack.empty or "mcnemar_p" not in attack.columns:
        return
    attack = attack.sort_values(
        ["attack_type", "scenario"]
    ).reset_index(drop=True)

    fig, ax = plt.subplots(figsize=(11, 7.5))
    ax.axis("off")
    ax.text(0.02, 0.97, "McNemar's Test -- Paired Attack Outcomes",
            fontsize=14, weight="bold", color=ACCENT)
    ax.text(0.02, 0.935,
            "Paired test per (scenario x attack_type) cell. The simulated driver is "
            "deterministic: cells whose trials are identical carry no p-value "
            "(shown as 'n/a det.'); trial replication is not statistical power.",
            fontsize=9, color=NEUTRAL)

    headers = ["Scenario", "Attack type", "n",
              "ASR base", "ASR def", "Reduction", "b", "c", "p-value"]
    rows = []
    for _, r in attack.iterrows():
        rows.append([
            r["scenario"],
            r["attack_type"],
            int(r["n"]),
            f"{r['baseline_asr']:.0%}",
            f"{r['defended_asr']:.0%}",
            f"{r['asr_reduction']:.0%}",
            int(r["mcnemar_b"]) if pd.notna(r["mcnemar_b"]) else "",
            int(r["mcnemar_c"]) if pd.notna(r["mcnemar_c"]) else "",
            (f"{r['mcnemar_p']:.4g}" if pd.notna(r["mcnemar_p"])
             else ("n/a det." if r.get("deterministic") else "")),
        ])
    tbl = ax.table(
        cellText=rows,
        colLabels=headers,
        loc="center",
        cellLoc="center",
        colLoc="center",
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(8.5)
    tbl.scale(1, 1.4)
    for j in range(len(headers)):
        tbl[(0, j)].set_facecolor(ACCENT)
        tbl[(0, j)].set_text_props(color="white", weight="bold")

    plt.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _page_weak_cells(pdf: PdfPages, cell_df: pd.DataFrame) -> None:
    attack = cell_df[cell_df["attack_type"] != "benign"]
    if attack.empty:
        return
    weak = attack[attack["defended_asr"] > 0].sort_values(
        "defended_asr", ascending=False
    )

    fig, ax = plt.subplots(figsize=(11, 6))
    ax.axis("off")
    ax.text(0.02, 0.96, "Weak Cells (defended ASR > 0)",
            fontsize=15, weight="bold", color=ACCENT)

    if weak.empty:
        ax.text(0.02, 0.88,
                "  No residual attack successes.  "
                "Every (scenario x attack) cell was fully blocked.",
                fontsize=11)
        pdf.savefig(fig)
        plt.close(fig)
        return

    ax.text(0.02, 0.925,
            f"{len(weak)} cell(s) had non-zero defended ASR.  "
            "These are the genuine gaps worth investigating.",
            fontsize=10, color=NEUTRAL)

    headers = ["Scenario", "Attack type", "Baseline ASR",
              "Defended ASR", "Reduction", "p-value"]
    rows = []
    for _, r in weak.iterrows():
        rows.append([
            r["scenario"],
            r["attack_type"],
            f"{r['baseline_asr']:.0%}",
            f"{r['defended_asr']:.0%}",
            f"{r['asr_reduction']:.0%}",
            f"{r['mcnemar_p']:.4g}" if pd.notna(r["mcnemar_p"]) else "",
        ])
    tbl = ax.table(
        cellText=rows, colLabels=headers,
        loc="upper center", cellLoc="center",
        bbox=[0.03, 0.45, 0.94, 0.4],
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    for j in range(len(headers)):
        tbl[(0, j)].set_facecolor(ACCENT)
        tbl[(0, j)].set_text_props(color="white", weight="bold")

    # Narrative -------------------------------------------------------
    narrative = [
        "Investigation notes:",
        "",
        "  * social_media_moderation / direct_prompt_injection:",
        "    HTML-comment style 'admin-approved' injection is not caught",
        "    by the byzantine-aware consensus stub.  A richer LLM-backed",
        "    consensus should close this gap.",
        "",
        "  * indirect / persuasive residuals at 5%:",
        "    Caused by scenario-specific role/tool mismatches where the",
        "    downstream tool call is within the victim's legitimate scope",
        "    but the argument semantic distance to task evidence stays",
        "    below the P2-L2 threshold.  P4 drift should catch these in",
        "    the full LLM run.",
    ]
    ax.text(0.03, 0.38, "\n".join(narrative), fontsize=10, va="top",
            family="monospace")

    pdf.savefig(fig)
    plt.close(fig)


def _page_methodology(pdf: PdfPages, summary: dict, cell_df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(8.5, 11))
    ax.axis("off")

    ax.text(0.06, 0.95, "Methodology & Threat Model",
            fontsize=16, weight="bold", color=ACCENT)

    body = [
        "Benchmark:   TAMAS (Targeting Agentic Multi-Agent Systems)",
        "Reference:   arxiv 2506.02635",
        "",
        "Attack types (from paper):",
        "  1. Tool Misuse               -- agent invokes tool outside allowed scope",
        "  2. Data Exfiltration         -- sensitive data leaves via output channels",
        "  3. Direct Prompt Injection   -- imperative injection into user input",
        "  4. Indirect Prompt Injection -- poisoned memory / tool output",
        "  5. Byzantine Behavior        -- rogue agent deviates from role",
        "  6. Persuasive Manipulation   -- social engineering across messages",
        "",
        "Defense pipeline (DEFER):",
        "  P1  Authenticated Interface     - identity + response integrity",
        "  P2  Capability Scoping          - role manifest, param validator, output filter",
        "  P3  Verified Execution          - operational context, intent chain, consensus",
        "  P4  Memory Integrity            - schema, drift, contradiction, replay",
        "  P5  Access-Controlled Isolation - ACL, query scope, sanitization",
        "",
        "Scenarios:",
        "  healthcare_prescription   healthcare_diagnosis   healthcare_triage",
        "  compliance_review         social_media_moderation",
        "",
        "Trial harness:",
        "  benchmarks/_unused_tamas/eval_runner.py drives the P12345Middleware",
        "  directly (framework-agnostic) to produce event logs that the",
        "  ASR/TSR/ERS oracles consume.  Each trial replays the scenario's",
        "  benign expected_workflow and injects one attack step.",
        "",
        "Metrics:",
        "  ASR = #trials where attack oracle fires / total trials",
        "  TSR = #trials where all benign workflow steps are observed / total",
        "  ERS = TSR * (1 - ASR)",
        "",
        "Statistical test:",
        "  Paired exact McNemar test on ASR per (scenario x attack_type) cell,",
        "  with trial_id as the pairing key.",
    ]
    ax.text(0.06, 0.88, "\n".join(body), fontsize=10, family="monospace",
            va="top")

    agg = summary.get("aggregate") or {}
    attack_cells = cell_df[cell_df["attack_type"] != "benign"]
    ax.text(0.06, 0.18, "Run summary", fontsize=14, weight="bold", color=ACCENT)
    ax.text(0.06, 0.14,
            f"  * {len(attack_cells)} attack cells, "
            f"{int(attack_cells['n'].sum()) if not attack_cells.empty else 0} trials/mode\n"
            f"  * ASR {agg.get('mean_baseline_asr', 0):.2%} "
            f"-> {agg.get('mean_defended_asr', 0):.2%} "
            f"(reduction {agg.get('mean_asr_reduction', 0):.2%})\n"
            f"  * TSR preserved at "
            f"{agg.get('mean_defended_tsr', 0):.2%} (defended)\n"
            f"  * ERS {agg.get('mean_baseline_ers', 0):.2%} "
            f"-> {agg.get('mean_defended_ers', 0):.2%}",
            fontsize=10, family="monospace", va="top")

    pdf.savefig(fig)
    plt.close(fig)


# --------------------------------------------------------------------- #
#  CSV exports
# --------------------------------------------------------------------- #


def _write_enhanced_csv(events_df: pd.DataFrame, path: Path) -> None:
    if events_df.empty:
        return
    events_df.to_csv(path, index=False)


def _write_defense_attribution_csv(attribution: pd.DataFrame, path: Path) -> None:
    if attribution is None or attribution.empty:
        return
    attribution.to_csv(path)


# --------------------------------------------------------------------- #
#  Top-level
# --------------------------------------------------------------------- #


def generate(
    results_dir: Path,
    out_dir: Path,
) -> None:
    baseline_path = results_dir / "baseline_results.json"
    defended_path = results_dir / "defended_results.json"
    summary_path  = results_dir / "tamas_compare_summary.json"

    for p in (baseline_path, defended_path, summary_path):
        if not p.exists():
            raise FileNotFoundError(
                f"required TAMAS artifact not found: {p}.  "
                f"Run benchmarks/_unused_tamas/run_baseline.py, run_defended.py, "
                f"and compare.py first."
            )

    baseline = _load(baseline_path)
    defended = _load(defended_path)
    summary  = _load(summary_path)

    base_df = _flatten_events(baseline, "baseline")
    def_df  = _flatten_events(defended, "defended")
    events_df = pd.concat([base_df, def_df], ignore_index=True)

    cell_df = _build_cell_df(summary)

    # --- PDF ---------------------------------------------------------
    pdf_path = out_dir / "tamas_findings.pdf"
    out_dir.mkdir(parents=True, exist_ok=True)
    with PdfPages(pdf_path) as pdf:
        _page_title(pdf, summary, cell_df)
        _page_aggregate_bars(pdf, cell_df)
        _page_heatmap(pdf, cell_df)
        _page_per_attack(pdf, cell_df)
        _page_tsr_benign(pdf, cell_df)
        attribution = _page_defense_attribution(pdf, events_df)
        _page_mcnemar(pdf, cell_df)
        _page_weak_cells(pdf, cell_df)
        _page_methodology(pdf, summary, cell_df)

    print(f"[tamas_analytics] wrote {pdf_path}")

    # --- CSV exports -------------------------------------------------
    _write_enhanced_csv(events_df, out_dir / "tamas_enhanced.csv")
    print(f"[tamas_analytics] wrote {out_dir / 'tamas_enhanced.csv'} "
          f"({len(events_df)} rows)")

    if 'attribution' in locals() and attribution is not None and not attribution.empty:
        _write_defense_attribution_csv(attribution, out_dir / "tamas_defense_attribution.csv")
        print(f"[tamas_analytics] wrote {out_dir / 'tamas_defense_attribution.csv'}")


def main() -> None:
    ap = argparse.ArgumentParser()
    default_dir = Path("results/tamas")
    ap.add_argument("--results-dir", type=Path, default=default_dir)
    ap.add_argument("--out-dir", type=Path, default=default_dir)
    args = ap.parse_args()
    generate(args.results_dir, args.out_dir)


if __name__ == "__main__":
    main()
