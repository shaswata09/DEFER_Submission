"""InjecAgent benchmark analytics -- paper-ready PDF + CSV.

Consumes:
  results/injecagent/injecagent_static_results.csv    (one row per trial)
  results/injecagent/injecagent_static_summary.csv    (pivoted ASR)

Produces:
  results/injecagent/injecagent_findings.pdf          (multi-page report)
  results/injecagent/injecagent_enhanced.csv          (wide per-case table)
  results/injecagent/injecagent_principle_attribution.csv
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages
from config import RESULTS_DIR

sns.set_theme(style="whitegrid", font_scale=1.0, palette="muted")
plt.rcParams.update({
    "figure.dpi": 150, "savefig.dpi": 150, "savefig.bbox": "tight",
    "font.family": "sans-serif",
    "axes.titleweight": "bold", "axes.titlesize": 13,
})

CONFIG_COLOR = {"flat": "#e74c3c", "acl_hardened": "#f39c12",
                "agenticcyops": "#2ecc71"}
CONFIG_LABEL = {"flat": "Flat MAS", "acl_hardened": "ACL-Hardened",
                "agenticcyops": "DEFER (P1-P5)"}
CONFIG_ORDER = ["flat", "acl_hardened", "agenticcyops"]
DOMAIN_ORDER = ["cyberops", "healthcare", "finance", "legal"]
DOMAIN_LABEL = {d: d.title() for d in DOMAIN_ORDER}
FAMILY_LABEL = {"dh": "Direct Harm", "ds": "Data Stealing"}
ACCENT = "#2980b9"
HEADER = "#2c3e50"


# --------------------------------------------------------------------- #
#  Data loading
# --------------------------------------------------------------------- #


def load(results_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    det = pd.read_csv(results_dir / "injecagent_static_results.csv")
    det["allowed"] = det["allowed"].astype(bool)
    summ = pd.read_csv(results_dir / "injecagent_static_summary.csv")
    return det, summ


# --------------------------------------------------------------------- #
#  Pages
# --------------------------------------------------------------------- #


def page_title(pdf: PdfPages, det: pd.DataFrame, summ: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(8.5, 11))
    ax.axis("off")
    ax.text(0.5, 0.93, "InjecAgent Benchmark — Findings",
            ha="center", fontsize=22, fontweight="bold")
    ax.text(0.5, 0.89,
            "Independent third-party prompt-injection benchmark (UIUC Kang Lab)",
            ha="center", fontsize=11, style="italic", color="#7f8c8d")
    ax.text(0.5, 0.85, f"Generated {datetime.now():%Y-%m-%d}",
            ha="center", fontsize=10, color="#7f8c8d")

    # Aggregate ASR per config (across every case/family/variant/domain)
    agg = det.groupby("config")["allowed"].agg(["sum", "count"])
    agg["asr"] = 100 * agg["sum"] / agg["count"]
    lines = ["Headline -- static InjecAgent benchmark\n"]
    for cfg in CONFIG_ORDER:
        if cfg not in agg.index:
            continue
        a = agg.loc[cfg]
        lines.append(f"  {CONFIG_LABEL[cfg]:<22s}  ASR = {a['asr']:5.2f}%  "
                     f"({int(a['sum']):>5d} / {int(a['count']):>5d})")
    lines.append("")
    lines.append(f"  Total attack evaluations: {len(det):,d}")
    lines.append(f"  Cases (base + enhanced):  2,108")
    lines.append(f"  Domains:                  {det['domain'].nunique()}")
    lines.append(f"  Configs:                  {det['config'].nunique()}")
    ax.text(0.06, 0.78, "\n".join(lines), fontsize=10.5,
            family="monospace", va="top")

    # Per-domain defended ASR
    acy = det[det.config == "agenticcyops"]
    d_agg = acy.groupby("domain")["allowed"].agg(["sum", "count"]).reset_index()
    d_agg["asr"] = 100 * d_agg["sum"] / d_agg["count"]
    ax.text(0.06, 0.45, "Defended ASR per domain  (DEFER only)",
            fontsize=14, fontweight="bold", color=ACCENT)
    rows = []
    for _, r in d_agg.iterrows():
        rows.append([DOMAIN_LABEL[r["domain"]], f"{int(r['count']):,d}",
                    f"{r['asr']:.2f}%"])
    tbl = ax.table(
        cellText=rows, colLabels=["Domain", "Trials", "ASR"],
        loc="center", bbox=[0.08, 0.24, 0.84, 0.18], cellLoc="center")
    tbl.auto_set_font_size(False); tbl.set_fontsize(10); tbl.scale(1, 1.4)
    for j in range(3):
        tbl[(0, j)].set_facecolor(ACCENT)
        tbl[(0, j)].set_text_props(color="white", weight="bold")

    ax.text(0.5, 0.08,
            "Source: AdaptiveAttackAgent (NAACL 2025) / InjecAgent (ACL 2024).  "
            "MIT-licensed, vendored unmodified.",
            ha="center", fontsize=9, style="italic", color="#7f8c8d")
    pdf.savefig(fig); plt.close(fig)


def page_aggregate_bars(pdf: PdfPages, det: pd.DataFrame) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.5))
    fig.suptitle("Aggregate ASR vs defense configuration",
                 fontsize=14, fontweight="bold")

    # Left: overall ASR per config
    ax = axes[0]
    agg = det.groupby("config")["allowed"].agg(["sum", "count"])
    agg["asr"] = 100 * agg["sum"] / agg["count"]
    agg = agg.reindex(CONFIG_ORDER)
    bars = ax.bar([CONFIG_LABEL[c] for c in agg.index], agg["asr"],
                  color=[CONFIG_COLOR[c] for c in agg.index],
                  edgecolor="black", width=0.55)
    ax.set_ylim(0, 110); ax.set_ylabel("ASR (%)")
    ax.set_title("All domains / families / variants pooled")
    for b, v in zip(bars, agg["asr"]):
        ax.text(b.get_x() + b.get_width() / 2, v + 2,
                f"{v:.1f}%", ha="center", fontweight="bold")

    # Right: per-family, defended only
    ax = axes[1]
    df = det[det.config == "agenticcyops"].copy()
    df["fv"] = df["family"] + "-" + df["variant"]
    agg2 = df.groupby("fv")["allowed"].agg(["sum", "count"])
    agg2["asr"] = 100 * agg2["sum"] / agg2["count"]
    bars = ax.bar(agg2.index, agg2["asr"], color=CONFIG_COLOR["agenticcyops"],
                  edgecolor="black", width=0.6)
    ax.set_ylim(0, max(agg2["asr"].max() * 1.4, 10))
    ax.set_ylabel("Defended ASR (%)")
    ax.set_title("DEFER by attack family × variant")
    for b, v in zip(bars, agg2["asr"]):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.3,
                f"{v:.1f}%", ha="center", fontweight="bold", fontsize=9)

    plt.tight_layout(rect=[0, 0, 1, 0.94])
    pdf.savefig(fig); plt.close(fig)


def page_heatmap(pdf: PdfPages, det: pd.DataFrame) -> None:
    """Defended ASR per (domain × family-variant)."""
    df = det[det.config == "agenticcyops"].copy()
    df["fv"] = df["family"] + "-" + df["variant"]
    pivot = (df.groupby(["fv", "domain"])["allowed"]
             .mean()
             .unstack("domain") * 100).reindex(columns=DOMAIN_ORDER)

    fig, ax = plt.subplots(figsize=(11, 4.5))
    sns.heatmap(
        pivot, annot=True, fmt=".1f", cmap="RdYlGn_r", vmin=0, vmax=50,
        linewidths=0.4, linecolor="white", ax=ax,
        cbar_kws={"label": "ASR (%) — lower is better"})
    ax.set_title("Residual ASR — DEFER across 4 domains",
                 fontsize=13, fontweight="bold")
    ax.set_xlabel(""); ax.set_ylabel("attack family × variant")
    plt.tight_layout()
    pdf.savefig(fig); plt.close(fig)


def page_principle_attribution(pdf: PdfPages, det: pd.DataFrame) -> None:
    """Stacked bar: which P-layer blocked each attack family."""
    df = det[det.config == "agenticcyops"].copy()
    df["fv"] = df["family"] + "-" + df["variant"]

    def primary_principle(mech: str) -> str:
        m = (mech or "").upper()
        if m.startswith("P1"): return "P1"
        if m.startswith("P2"): return "P2"
        if m.startswith("P3"): return "P3"
        if m.startswith("P4"): return "P4"
        if m.startswith("P5"): return "P5"
        return "none"

    df["principle"] = df["mechanism"].apply(primary_principle)
    counts = (df[~df.allowed]
              .groupby(["fv", "principle"]).size()
              .unstack(fill_value=0))
    # Keep only active principles to avoid empty columns
    active = [p for p in ["P1", "P2", "P3", "P4", "P5"] if p in counts.columns]
    counts = counts[active]

    fig, ax = plt.subplots(figsize=(12, 5))
    palette = {"P1": "#3498db", "P2": "#e67e22", "P3": "#9b59b6",
               "P4": "#1abc9c", "P5": "#e74c3c"}
    counts.plot(kind="bar", stacked=True, ax=ax,
                color=[palette[p] for p in counts.columns],
                edgecolor="white", width=0.7)
    ax.set_title("Which defense layer blocked each attack family "
                 "(DEFER, all 4 domains)",
                 fontsize=13, fontweight="bold")
    ax.set_xlabel(""); ax.set_ylabel("Blocked attack-tool evaluations")
    ax.tick_params(axis="x", labelrotation=0)
    ax.legend(title="Principle", loc="upper right")
    plt.tight_layout()
    pdf.savefig(fig); plt.close(fig)


def page_attack_type_breakdown(pdf: PdfPages, det: pd.DataFrame) -> None:
    """Per-attack-type ASR (cyberops domain, across configs)."""
    df = det[det.domain == "cyberops"].copy()
    if df.empty:
        return
    grp = df.groupby(["case_attack_type", "config"])["allowed"].agg(
        ["sum", "count"]).reset_index()
    grp["asr"] = 100 * grp["sum"] / grp["count"]
    pivot = grp.pivot(index="case_attack_type", columns="config",
                      values="asr").reindex(columns=CONFIG_ORDER)
    pivot = pivot.sort_values("agenticcyops", ascending=False)

    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(pivot))
    width = 0.27
    for i, cfg in enumerate(CONFIG_ORDER):
        if cfg not in pivot.columns:
            continue
        ax.bar(x + (i - 1) * width, pivot[cfg].fillna(0), width,
               color=CONFIG_COLOR[cfg], edgecolor="black",
               label=CONFIG_LABEL[cfg])
    ax.set_xticks(x)
    ax.set_xticklabels(list(pivot.index), rotation=30, ha="right", fontsize=9)
    ax.set_ylabel("ASR (%)")
    ax.set_ylim(0, 110)
    ax.set_title("ASR by InjecAgent attack category (cyberops pipeline)",
                 fontsize=13, fontweight="bold")
    ax.legend(loc="upper right")
    plt.tight_layout()
    pdf.savefig(fig); plt.close(fig)


def page_methodology(pdf: PdfPages, det: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(8.5, 11))
    ax.axis("off")
    ax.text(0.06, 0.95, "Methodology", fontsize=16, fontweight="bold",
            color=ACCENT)
    body = [
        "Benchmark:   InjecAgent static (Zhan et al. ACL 2024)",
        "             vendored by AdaptiveAttackAgent (Zhan et al. NAACL 2025)",
        "             License: MIT  (see data/LICENSE_InjecAgent)",
        "",
        "Attack families:",
        "  * direct_harm (dh, 510 cases) -- single destructive tool call",
        "  * data_stealing (ds, 544 cases) -- two-step read-then-send chain",
        "",
        "Variants per family:",
        "  * base      -- attacker instruction embedded in tool response as-is",
        "  * enhanced  -- generic 'IGNORE ALL PREVIOUS INSTRUCTIONS' wrapper",
        "",
        "Tool universe:  38 fabricated consumer / enterprise toolkits",
        "                (GitHub, AugustSmartLock, Amazon, Gmail, ...),",
        "                330 individual tool actions.  Tools registered under",
        "                the IA_* namespace in an in-memory registry only;",
        "                never written to disk; never collide with domain tools.",
        "",
        "Evaluation:",
        "  Deterministic per-case drive of the P1-P5 defense pipeline:",
        "    P1-L1  identity verification on the attacker tool",
        "    P2-L1  parameter / wildcard check",
        "    P2-L2  target-in-evidence semantic similarity",
        "    P3-L0.5 operational context (time / maintenance / incident)",
        "    P2-L3  output classifier on poisoned tool response",
        "    P5-L5  injection sanitisation of poisoned evidence",
        "  ASR per cell = fraction of attacker-tool calls that slip through",
        "  all five checks.  No live LLM calls -- tests middleware",
        "  correctness independent of agent-level reasoning variability.",
        "",
        "Cross-domain scope:",
        "  Same 2,108 cases replayed through each of four separate",
        "  domain orchestrators (cyberops, healthcare, finance, legal).",
        "  Each domain has independent access policies, sensitive",
        "  patterns, operational-context configs driving P1-P5.",
        "",
        "Configurations:",
        "  flat           -- no defenses; every attack succeeds.",
        "  acl_hardened   -- network-layer allowlist only; no IA_* tools",
        "                     in domain manifests (explicitly allowed to",
        "                     avoid masking ACL's true coverage).",
        "  agenticcyops   -- full P1-P5 stack.",
        "",
        "Caveats for paper framing:",
        "  * This is the STATIC InjecAgent score.  The upstream paper's",
        "    main contribution is adaptive GCG attacks which we evaluate",
        "    separately (Phase 2).",
        "  * Tool universe is consumer / general-purpose; domain transfer",
        "    means semantic-similarity checks (P2-L2) carry more weight",
        "    than parameter-rule / sensitive-pattern checks.",
        "  * No comparison with upstream paper numbers is claimed -- they",
        "    evaluated Llama-3.1-8B / Vicuna-7B single-agent ReAct; we",
        "    evaluate the DEFER middleware only (no live LLM).",
    ]
    ax.text(0.06, 0.88, "\n".join(body), fontsize=9,
            family="monospace", va="top")
    pdf.savefig(fig); plt.close(fig)


# --------------------------------------------------------------------- #
#  Top-level
# --------------------------------------------------------------------- #


def generate(results_dir: Path, out_dir: Path) -> None:
    det, summ = load(results_dir)

    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / "injecagent_findings.pdf"
    with PdfPages(pdf_path) as pdf:
        page_title(pdf, det, summ)
        page_aggregate_bars(pdf, det)
        page_heatmap(pdf, det)
        page_principle_attribution(pdf, det)
        page_attack_type_breakdown(pdf, det)
        page_methodology(pdf, det)
    print(f"wrote {pdf_path}")

    # Enhanced CSV: per-case, per-domain, one row
    piv = (det.groupby(["family", "variant", "case_idx",
                         "case_user_tool", "case_attack_type",
                         "domain", "config"])
           ["allowed"]
           .any().astype(int)
           .reset_index()
           .rename(columns={"allowed": "attack_succeeded"}))
    p2 = piv.pivot_table(
        index=["family", "variant", "case_idx", "case_user_tool",
               "case_attack_type"],
        columns=["domain", "config"], values="attack_succeeded", fill_value=0)
    p2.columns = ["_".join(c) for c in p2.columns]
    enh_path = out_dir / "injecagent_enhanced.csv"
    p2.reset_index().to_csv(enh_path, index=False)
    print(f"wrote {enh_path}")

    # Principle attribution CSV
    def primary(mech):
        m = (mech or "").upper()
        for p in ("P1", "P2", "P3", "P4", "P5"):
            if m.startswith(p): return p
        return "none"

    det["principle"] = det["mechanism"].apply(primary)
    attr = (det[det.config == "agenticcyops"]
            .groupby(["family", "variant", "principle"]).size()
            .unstack(fill_value=0))
    attr_path = out_dir / "injecagent_principle_attribution.csv"
    attr.reset_index().to_csv(attr_path, index=False)
    print(f"wrote {attr_path}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir",
                    default=str(RESULTS_DIR / "injecagent" / "static"))
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()
    results_dir = Path(args.results_dir)
    out_dir = Path(args.out_dir) if args.out_dir else results_dir
    generate(results_dir, out_dir)


if __name__ == "__main__":
    main()
