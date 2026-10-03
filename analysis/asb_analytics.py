"""ASB (Agent Security Bench) E2E analytics.

Scans ``results/asb/e2e_validator_group_<G>/general/results.csv`` for the
requested groups, then produces:

  * ``asb_analytics.pdf``           -- multi-page paper-ready report
  * ``asb_headline_asr.csv``        -- ASR by (config, attack_type)
  * ``asb_by_subtype.csv``          -- ASR by (config, attack_type, subtype)
  * ``asb_by_scenario.csv``         -- ASR by (config, scenario)
  * ``asb_mechanisms.csv``          -- mechanism distribution under agenticcyops

ASB has a single neutral domain ("general"). The script supports one or
several groups; when given a list, the headline tables are averaged.

CLI::

    python -m analysis.asb_analytics --groups A
    python -m analysis.asb_analytics --groups A,C,D,E
"""

from __future__ import annotations

import argparse
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

CONFIG_LABEL = {"flat": "Flat MAS", "acl_hardened": "ACL-Hardened",
                "agenticcyops": "DEFER (P1-P5)"}
CONFIG_COLOR = {"flat": "#e74c3c", "acl_hardened": "#f39c12",
                "agenticcyops": "#2ecc71"}
CONFIG_ORDER = ["flat", "acl_hardened", "agenticcyops"]
ATTACK_ORDER = ["DPI", "IPI", "MP", "PoT"]
ATTACK_LABEL = {"DPI": "Direct Prompt Injection",
                "IPI": "Indirect Prompt Injection",
                "MP":  "Memory Poisoning",
                "PoT": "Backdoor (Plan-of-Thought)"}
ACCENT = "#2980b9"

ASB_ROOT = RESULTS_DIR / "asb"


def load_group_csv(group: str) -> pd.DataFrame:
    p = ASB_ROOT / f"e2e_validator_group_{group}" / "general" / "results.csv"
    if not p.exists():
        return pd.DataFrame()
    df = pd.read_csv(p)
    # normalise PoT vs POT
    df["attack_type"] = df["attack_type"].replace({"POT": "PoT"})
    df["group"] = group
    if "flat" not in set(df.config):
        # paired panel replays only re-run the defense; the flat arm is the
        # primary output itself (attack_succeeded_llm), as in the live runs
        flat = df[df.config == "agenticcyops"].copy()
        flat["config"] = "flat"
        flat["attack_succeeded_end_to_end"] = flat["attack_succeeded_llm"]
        flat[["defense_evaluated", "defense_blocked"]] = False
        flat[["defense_mechanism", "defense_stage"]] = ""
        df = pd.concat([flat, df], ignore_index=True)
    return df


def headline_table(df: pd.DataFrame) -> pd.DataFrame:
    g = df.groupby(["attack_type", "config"]).agg(
        n=("attack_succeeded_end_to_end", "size"),
        succ=("attack_succeeded_end_to_end", "sum"),
    )
    g["asr_pct"] = (100 * g["succ"] / g["n"]).round(2)
    return g.reset_index()


def by_subtype(df: pd.DataFrame) -> pd.DataFrame:
    g = df.groupby(["attack_type", "attack_subtype", "config"]).agg(
        n=("attack_succeeded_end_to_end", "size"),
        succ=("attack_succeeded_end_to_end", "sum"),
    )
    g["asr_pct"] = (100 * g["succ"] / g["n"]).round(2)
    return g.reset_index()


def by_scenario(df: pd.DataFrame) -> pd.DataFrame:
    g = df.groupby(["scenario", "config"]).agg(
        n=("attack_succeeded_end_to_end", "size"),
        succ=("attack_succeeded_end_to_end", "sum"),
    )
    g["asr_pct"] = (100 * g["succ"] / g["n"]).round(2)
    return g.reset_index()


def mech_table(df: pd.DataFrame) -> pd.DataFrame:
    acy = df[df.config == "agenticcyops"].copy()
    acy["bucket"] = "not blocked (no mechanism)"
    blocked = acy.defense_blocked.fillna(False).astype(bool)
    acy.loc[blocked, "bucket"] = acy.loc[blocked, "defense_mechanism"].fillna("blocked_unknown")
    refused = acy.refused_with_final_answer.fillna(False).astype(bool) & ~blocked
    acy.loc[refused, "bucket"] = "agent_refused"
    return acy.bucket.value_counts().rename_axis("mechanism").reset_index(name="count")


def _draw_title(pdf, groups, df):
    fig, ax = plt.subplots(figsize=(8.5, 11))
    ax.axis("off")
    n_trials = len(df)
    n_cases = df.asb_case_id.nunique()
    n_scen = df.scenario.nunique()
    groups_str = ", ".join(groups)
    text = (
        f"ASB End-to-End Analytics\n"
        f"========================\n\n"
        f"Groups:           {groups_str}\n"
        f"Domain:           general (ASB single neutral domain)\n"
        f"Total trials:     {n_trials:,}\n"
        f"Unique cases:     {n_cases}\n"
        f"Unique scenarios: {n_scen}\n"
        f"Attack families:  {', '.join(ATTACK_ORDER)}\n"
        f"Configs:          {', '.join(CONFIG_ORDER)}\n\n"
        f"Source: results/asb/e2e_validator_group_<G>/general/results.csv\n"
    )
    ax.text(0.05, 0.95, text, family="monospace", fontsize=10, va="top")
    headline = headline_table(df)
    ax.text(0.05, 0.55, "Headline ASR (per attack family, all groups pooled)\n",
            fontsize=11, fontweight="bold", va="top")
    rows = []
    rows.append("  Attack    " + "".join(f"{CONFIG_LABEL[c]:>22}" for c in CONFIG_ORDER))
    rows.append("  " + "-"*8 + "  " + "-"*(22*len(CONFIG_ORDER)))
    for a in ATTACK_ORDER:
        line = f"  {a:<8}"
        for c in CONFIG_ORDER:
            r = headline[(headline.attack_type==a) & (headline.config==c)]
            line += f"{(str(r.asr_pct.iloc[0]) + '%') if len(r) else '--':>22}"
        rows.append(line)
    ax.text(0.05, 0.50, "\n".join(rows), family="monospace", fontsize=9, va="top")
    pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)


def _draw_attack_bars(pdf, df):
    fig, ax = plt.subplots(figsize=(10, 5.5))
    h = headline_table(df)
    pivot = h.pivot(index="attack_type", columns="config", values="asr_pct").reindex(ATTACK_ORDER)
    pivot = pivot.reindex(columns=CONFIG_ORDER).dropna(axis=0, how="all")
    x = np.arange(len(pivot)); w = 0.27
    for i, c in enumerate(CONFIG_ORDER):
        ax.bar(x + (i-1)*w, pivot[c].fillna(0).values, w, label=CONFIG_LABEL[c], color=CONFIG_COLOR[c])
    ax.set_xticks(x); ax.set_xticklabels([ATTACK_LABEL[a] for a in pivot.index], rotation=20, ha="right")
    ax.set_ylabel("ASR (%)"); ax.set_title("ASR by attack family")
    ax.legend(loc="upper right")
    for i, c in enumerate(CONFIG_ORDER):
        for j, v in enumerate(pivot[c].values):
            if not np.isnan(v):
                ax.text(j + (i-1)*w, v + 0.5, f"{v:.1f}", ha="center", fontsize=8)
    pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)


def _draw_subtype_table(pdf, df):
    sub = by_subtype(df)
    fig, ax = plt.subplots(figsize=(11, 7))
    ax.axis("off")
    ax.set_title("ASR by attack subtype", loc="left", fontsize=13)
    rows = [["Attack", "Subtype", "n",
              CONFIG_LABEL["flat"], CONFIG_LABEL["acl_hardened"], CONFIG_LABEL["agenticcyops"]]]
    for (a, s), grp in sub.groupby(["attack_type","attack_subtype"]):
        n = int(grp.n.iloc[0])
        cells = [a, s, f"{n}"]
        for c in CONFIG_ORDER:
            r = grp[grp.config==c]
            cells.append(f"{r.asr_pct.iloc[0]:.2f}%" if len(r) else "--")
        rows.append(cells)
    tab = ax.table(cellText=rows[1:], colLabels=rows[0], loc="center", cellLoc="center")
    tab.auto_set_font_size(False); tab.set_fontsize(9); tab.scale(1, 1.4)
    pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)


def _draw_scenario_heatmap(pdf, df):
    sc = by_scenario(df)
    pivot = sc.pivot(index="scenario", columns="config", values="asr_pct")
    present = [c for c in CONFIG_ORDER if c in pivot.columns]
    pivot = pivot[present]
    fig, ax = plt.subplots(figsize=(8.5, 6))
    sns.heatmap(pivot, annot=True, fmt=".1f", cmap="RdYlGn_r",
                vmin=0, vmax=max(60, pivot.values.max()), ax=ax,
                cbar_kws={"label":"ASR (%)"})
    ax.set_title("ASR by scenario × config")
    ax.set_xticklabels([CONFIG_LABEL[c] for c in present], rotation=15, ha="right")
    pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)


def _draw_mechanism_bars(pdf, df):
    mt = mech_table(df).head(12)
    fig, ax = plt.subplots(figsize=(10, 5.5))
    colors = ["#27ae60" if not r.startswith(("not blocked", "succeeded", "blocked_unknown")) else "#7f8c8d" for r in mt.mechanism]
    ax.barh(mt.mechanism[::-1], mt["count"][::-1], color=colors[::-1])
    ax.set_xlabel("count")
    ax.set_title("DEFER mechanism distribution (top 12)")
    for i, (m, n) in enumerate(zip(mt.mechanism[::-1], mt["count"][::-1])):
        ax.text(n + max(mt["count"])*0.01, i, str(n), va="center", fontsize=9)
    pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)


def _draw_per_group_bars(pdf, df):
    if df.group.nunique() < 2:
        return
    g = df.groupby(["group", "config"]).agg(
        n=("attack_succeeded_end_to_end", "size"),
        succ=("attack_succeeded_end_to_end", "sum"),
    )
    g["asr_pct"] = 100 * g["succ"] / g["n"]
    pivot = g.reset_index().pivot(index="group", columns="config", values="asr_pct").reindex(columns=CONFIG_ORDER)
    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(pivot)); w = 0.27
    for i, c in enumerate(CONFIG_ORDER):
        ax.bar(x + (i-1)*w, pivot[c].fillna(0).values, w, label=CONFIG_LABEL[c], color=CONFIG_COLOR[c])
        for j, v in enumerate(pivot[c].values):
            if not np.isnan(v):
                ax.text(j + (i-1)*w, v + 0.5, f"{v:.2f}", ha="center", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels(pivot.index)
    ax.set_ylabel("ASR (%)"); ax.set_title("Overall ASR by validator group")
    ax.legend(loc="upper right")
    pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)


def generate(groups: list[str], out_dir: Path) -> None:
    frames = []
    for g in groups:
        d = load_group_csv(g)
        if d.empty:
            print(f"[skip] group {g}: no results.csv")
            continue
        frames.append(d)
    if not frames:
        raise SystemExit("[fail] no ASB results found for the requested groups")
    df = pd.concat(frames, ignore_index=True)

    out_dir.mkdir(parents=True, exist_ok=True)
    headline_table(df).to_csv(out_dir / "asb_headline_asr.csv", index=False)
    by_subtype(df).to_csv(out_dir / "asb_by_subtype.csv", index=False)
    by_scenario(df).to_csv(out_dir / "asb_by_scenario.csv", index=False)
    mech_table(df).to_csv(out_dir / "asb_mechanisms.csv", index=False)

    pdf_path = out_dir / "asb_analytics.pdf"
    with PdfPages(pdf_path) as pdf:
        _draw_title(pdf, groups, df)
        _draw_attack_bars(pdf, df)
        _draw_subtype_table(pdf, df)
        _draw_scenario_heatmap(pdf, df)
        _draw_mechanism_bars(pdf, df)
        _draw_per_group_bars(pdf, df)

    print(f"[wrote] {pdf_path}")
    print(f"[wrote] {out_dir / 'asb_headline_asr.csv'}")
    print(f"[wrote] {out_dir / 'asb_by_subtype.csv'}")
    print(f"[wrote] {out_dir / 'asb_by_scenario.csv'}")
    print(f"[wrote] {out_dir / 'asb_mechanisms.csv'}")

    print()
    print("=" * 70)
    print(f"  ASB Analytics  (groups: {', '.join(groups)},  n={len(df):,} trials)")
    print("=" * 70)
    h = headline_table(df)
    for a in ATTACK_ORDER:
        line = f"  {a:<4} ({ATTACK_LABEL[a]:<32})"
        for c in CONFIG_ORDER:
            r = h[(h.attack_type==a) & (h.config==c)]
            line += f"  {CONFIG_LABEL[c][:6]}={r.asr_pct.iloc[0]:>6.2f}%" if len(r) else "  -- "
        print(line)
    print("=" * 70)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--groups", default="A",
                    help="Comma-separated groups: legacy letters (A..F) or replay "
                         "panels such as q235_div4_div4,q235_div4_lin3")
    ap.add_argument("--out-dir", default=None,
                    help="Output dir. Default = "
                         "results/asb/e2e_validator_group_<G>/asb_analytics/ "
                         "for a single group, or results/asb/asb_analytics/ "
                         "when multiple groups are requested.")
    args = ap.parse_args()
    groups = [g.strip().upper() if len(g.strip()) == 1 else g.strip()
              for g in args.groups.split(",") if g.strip()]
    if args.out_dir:
        out_dir = Path(args.out_dir)
    elif len(groups) == 1:
        out_dir = ASB_ROOT / f"e2e_validator_group_{groups[0]}" / "asb_analytics"
    else:
        out_dir = ASB_ROOT / f"asb_analytics_{'_'.join(groups)}"
    generate(groups, out_dir)


if __name__ == "__main__":
    main()
