"""InjecAgent E2E analytics -- multi-page PDF covering live-LLM sweeps.

Scans ``results/injecagent/`` for every ``e2e_validator_group_<G>/``
directory, unions their per-domain ``results.csv`` files, and produces:

  * ``injecagent_e2e_findings.pdf``       -- multi-page report
  * ``injecagent_e2e_two_tier_asr.csv``   -- headline tier table
  * ``injecagent_e2e_combined.csv``       -- every live-LLM trial (master)
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages
from config import BASE_DIR, RESULTS_DIR

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
GROUP_ORDER = ["A", "B", "C", "D", "E", "F"]
ACCENT = "#2980b9"

DIR_RE = re.compile(r"^e2e_validator_group_(?P<grp>[A-F])$")

TOOLS_JSON = Path(
    str(BASE_DIR / "benchmarks" / "injecagent" / "data" / "tools.json"))


def load_toolkit_lookup(path: Path = TOOLS_JSON) -> dict[str, str]:
    """Build {action_name: toolkit_name} from InjecAgent's tools.json.

    Upstream tools are named ``<toolkit><action>`` (e.g. ``TerminalExecute``,
    ``AugustSmartLockGrantGuestAccess``).  tools.json is the authoritative
    source -- we concatenate toolkit + each tool's ``name`` field.
    """
    import json
    lookup: dict[str, str] = {}
    if not path.exists():
        return lookup
    with open(path) as f:
        data = json.load(f)
    for tk in data:
        kit = tk.get("toolkit") or tk.get("name_for_model") or ""
        for t in tk.get("tools", []):
            action = t.get("name", "")
            if kit and action:
                lookup[f"{kit}{action}"] = kit
    return lookup

# --------------------------------------------------------------------- #
#  Discovery + loading
# --------------------------------------------------------------------- #


def discover_runs(root: Path) -> list[dict]:
    runs = []
    if not root.exists():
        return runs
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        m = DIR_RE.match(d.name)
        if not m:
            continue
        runs.append({"group": m.group("grp"), "path": d})
    return runs


def load_run_rows(run: dict) -> pd.DataFrame:
    parts = []
    for dom_dir in sorted(run["path"].iterdir()):
        if not dom_dir.is_dir():
            continue
        csv_path = dom_dir / "results.csv"
        if not csv_path.exists():
            continue
        df = pd.read_csv(csv_path)
        parts.append(df)
    if not parts:
        return pd.DataFrame()
    out = pd.concat(parts, ignore_index=True)
    # Coerce booleans that CSV round-tripped as strings
    for col in ("attack_succeeded_llm", "attack_succeeded_end_to_end",
                "defense_blocked", "refused_with_final_answer",
                "defense_evaluated"):
        if col in out.columns:
            out[col] = out[col].map(
                {"True": True, "False": False, True: True, False: False,
                 "": False}).fillna(False).astype(bool)
    return out


def load_static_symbolic(root: Path) -> Optional[pd.DataFrame]:
    """Find the Tier-1 symbolic CSV produced by the benchmark's
    ``run_static.py``.  InjecAgent writes
    ``static/injecagent_static_results.csv``; ASB writes
    ``asb_static_results.csv`` directly under the results-root."""
    candidates = [
        root / "static" / "injecagent_static_results.csv",
        root / "asb_static_results.csv",
        root / "static" / "asb_static_results.csv",
    ]
    p = next((c for c in candidates if c.exists()), None)
    if p is None:
        return None
    df = pd.read_csv(p)
    df["attack_succeeded"] = df["allowed"].astype(bool).astype(int)
    return df


# --------------------------------------------------------------------- #
#  Tier aggregation helpers
# --------------------------------------------------------------------- #


def two_tier_table(static_sym: Optional[pd.DataFrame],
                   live: pd.DataFrame) -> pd.DataFrame:
    """One row per config, columns: tier1_symbolic, tier2_live_llm_asr,
    tier2_live_defended.  Values are percentages (float, NaN if missing)."""
    rows = []
    for cfg in CONFIG_ORDER:
        r = {"config": cfg}
        if static_sym is not None:
            s = static_sym[static_sym.config == cfg]
            r["tier1_symbolic"] = 100 * s["attack_succeeded"].mean() if len(s) else np.nan
        else:
            r["tier1_symbolic"] = np.nan
        live_s = live[live.config == cfg]
        r["tier2_live_llm_asr"] = (100 * live_s["attack_succeeded_llm"].mean()
                                    if len(live_s) else np.nan)
        r["tier2_live_defended"] = (100 * live_s["attack_succeeded_end_to_end"].mean()
                                     if len(live_s) else np.nan)
        rows.append(r)
    return pd.DataFrame(rows)


# --------------------------------------------------------------------- #
#  Pages
# --------------------------------------------------------------------- #


def page_title(pdf, static_sym, live, tier_tbl):
    fig, ax = plt.subplots(figsize=(8.5, 11))
    ax.axis("off")
    ax.text(0.5, 0.95, "InjecAgent End-to-End Findings",
            ha="center", fontsize=22, fontweight="bold")
    ax.text(0.5, 0.915,
            "Live-LLM evaluation across validator groups",
            ha="center", fontsize=11, style="italic", color="#7f8c8d")
    ax.text(0.5, 0.88, f"Generated {datetime.now():%Y-%m-%d}",
            ha="center", fontsize=10, color="#7f8c8d")

    ax.text(0.06, 0.83, "Two-tier ASR headline  (lower is better)",
            fontsize=13, fontweight="bold", color=ACCENT)
    cols = ["Tier-1\nsymbolic",
             "Tier-2\nlive LLM\n(no defense)",
             "Tier-2\nlive LLM\n(defended)"]
    rows = []
    for _, r in tier_tbl.iterrows():
        def fmt(v):
            return f"{v:.2f}%" if pd.notna(v) else "--"
        rows.append([CONFIG_LABEL[r["config"]],
                     fmt(r["tier1_symbolic"]),
                     fmt(r["tier2_live_llm_asr"]),
                     fmt(r["tier2_live_defended"])])
    tbl = ax.table(cellText=rows, colLabels=["Config"] + cols,
                    loc="center",
                    bbox=[0.10, 0.58, 0.80, 0.20], cellLoc="center")
    tbl.auto_set_font_size(False); tbl.set_fontsize(9); tbl.scale(1, 1.7)
    for j in range(len(cols) + 1):
        tbl[(0, j)].set_facecolor(ACCENT)
        tbl[(0, j)].set_text_props(color="white", weight="bold")

    groups = sorted(live.group.unique()) if len(live) else []
    scope = [
        "Scope",
        f"  validator groups:  {', '.join(groups) if groups else '(none)'}",
        f"  configs:           {', '.join(CONFIG_ORDER)}",
        f"  domains:           {', '.join(DOMAIN_ORDER)}",
        f"  live-LLM trials:   {len(live):,}",
        f"  symbolic trials:   {len(static_sym):,}" if static_sym is not None else
        "  symbolic trials:   (not available)",
    ]
    ax.text(0.06, 0.50, "\n".join(scope), fontsize=10,
            family="monospace", va="top")
    ax.text(0.5, 0.06,
            "Tier-1: deterministic P1-P5 middleware on attacker proposals (no LLM).  "
            "Tier-2: live LLM sees the InjecAgent prompt.",
            ha="center", fontsize=8, style="italic",
            color="#7f8c8d", wrap=True)
    pdf.savefig(fig); plt.close(fig)


def page_per_group_bars(pdf, live):
    """Grouped bars of defended ASR per (group, config)."""
    if live.empty:
        return
    agg = (live.groupby(["group", "config"])["attack_succeeded_end_to_end"]
              .mean()
              .mul(100)
              .unstack("config")
              .reindex(columns=CONFIG_ORDER))
    groups = [g for g in GROUP_ORDER if g in agg.index]
    agg = agg.reindex(groups)

    fig, ax = plt.subplots(figsize=(12, 5))
    x = np.arange(len(groups))
    width = 0.27
    for i, cfg in enumerate(CONFIG_ORDER):
        if cfg not in agg.columns:
            continue
        vals = agg[cfg].fillna(0).values
        bars = ax.bar(x + (i - 1) * width, vals, width,
                      color=CONFIG_COLOR[cfg], edgecolor="black",
                      label=CONFIG_LABEL[cfg])
        for b, v in zip(bars, vals):
            if not np.isnan(v):
                ax.text(b.get_x() + b.get_width() / 2, v + 1,
                        f"{v:.1f}", ha="center", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels([f"Group {g}" for g in groups])
    ax.set_ylabel("Defended ASR (%)"); ax.set_ylim(0, 110)
    ax.set_title("Defended ASR per validator group",
                 fontsize=13, fontweight="bold")
    ax.legend(loc="upper right")
    plt.tight_layout()
    pdf.savefig(fig); plt.close(fig)


def page_principle_attribution(pdf, live):
    """Stacked bar: which P-layer blocked live-LLM attacks (DEFER)."""
    df = live[(live.config == "agenticcyops") &
               (live.defense_evaluated) & (live.defense_blocked)]
    if df.empty:
        return
    def primary(m: str) -> str:
        mu = (str(m) or "").upper()
        for p in ("P1", "P2", "P3", "P4", "P5"):
            if mu.startswith(p):
                return p
        return "none"
    df = df.copy()
    df["principle"] = df["defense_mechanism"].apply(primary)
    counts = (df.groupby(["group", "principle"]).size()
              .unstack(fill_value=0))
    active = [p for p in ["P1", "P2", "P3", "P4", "P5"] if p in counts.columns]
    counts = counts[active]
    groups = [g for g in GROUP_ORDER if g in counts.index]
    counts = counts.reindex(groups)

    fig, ax = plt.subplots(figsize=(12, 5))
    palette = {"P1": "#3498db", "P2": "#e67e22", "P3": "#9b59b6",
                "P4": "#1abc9c", "P5": "#e74c3c"}
    counts.plot(kind="bar", stacked=True, ax=ax,
                color=[palette[p] for p in counts.columns],
                edgecolor="white", width=0.7)
    ax.set_title("Which defense layer blocked live-LLM attacks per group "
                 "(DEFER)", fontsize=13, fontweight="bold")
    ax.set_xlabel(""); ax.set_ylabel("Blocked trials")
    ax.tick_params(axis="x", labelrotation=0)
    ax.legend(title="Principle", loc="upper right")
    plt.tight_layout()
    pdf.savefig(fig); plt.close(fig)


def page_hygiene(pdf, live):
    """Per-group LLM hygiene: refusal, error, mean tokens."""
    if live.empty:
        return
    hyg = (live.groupby("group")
               .agg(trials=("attack_succeeded_llm", "size"),
                    refused_pct=("refused_with_final_answer",
                                  lambda s: 100 * s.mean()),
                    error_pct=("error", lambda s: 100 * s.notna().mean()),
                    prompt_tok=("prompt_tokens", "mean"),
                    completion_tok=("completion_tokens", "mean"))
               .reindex([g for g in GROUP_ORDER if g in live.group.unique()]))

    fig, ax = plt.subplots(figsize=(8.5, 11))
    ax.axis("off")
    ax.text(0.5, 0.95, "Live-LLM hygiene (per group)",
            ha="center", fontsize=16, fontweight="bold", color=ACCENT)
    ax.text(0.5, 0.915,
            "Quality signals orthogonal to defense effectiveness",
            ha="center", fontsize=10, style="italic", color="#7f8c8d")
    cells = []
    for g, r in hyg.iterrows():
        cells.append([g, f"{int(r['trials']):,}",
                       f"{r['refused_pct']:.1f}%",
                       f"{r['error_pct']:.1f}%",
                       f"{r['prompt_tok']:.0f}",
                       f"{r['completion_tok']:.0f}"])
    tbl = ax.table(
        cellText=cells,
        colLabels=["Group", "Trials", "Refused", "LLM error",
                    "Avg prompt tok", "Avg compl. tok"],
        loc="center", bbox=[0.07, 0.55, 0.86, 0.3], cellLoc="center")
    tbl.auto_set_font_size(False); tbl.set_fontsize(10); tbl.scale(1, 1.5)
    for j in range(6):
        tbl[(0, j)].set_facecolor(ACCENT)
        tbl[(0, j)].set_text_props(color="white", weight="bold")

    ax.text(0.06, 0.48,
            "Refused  = model emitted 'Final Answer:' instead of a tool call.\n"
            "LLM error = non-empty 'error' column (timeout / auth / parse).\n"
            "Token counts come from the vLLM/OpenAI/Anthropic usage field.",
            fontsize=9.5, family="monospace", va="top")
    pdf.savefig(fig); plt.close(fig)


def _attach_toolkit(live: pd.DataFrame, lookup: dict[str, str]) -> pd.DataFrame:
    """Add `user_toolkit` column (attribution by the benign user tool)."""
    if "user_tool" not in live.columns or not lookup:
        return live
    out = live.copy()
    out["user_toolkit"] = out["user_tool"].map(lookup).fillna("unknown")
    return out


def page_per_toolkit(pdf, live, lookup):
    """Defended ASR per InjecAgent user-toolkit (DEFER, static live)."""
    if not lookup:
        return
    df = _attach_toolkit(live, lookup)
    df = df[df.config == "agenticcyops"]
    if df.empty:
        return
    agg = (df.groupby("user_toolkit")
              .agg(n=("attack_succeeded_end_to_end", "size"),
                    llm_asr=("attack_succeeded_llm",
                              lambda s: 100 * s.mean()),
                    def_asr=("attack_succeeded_end_to_end",
                              lambda s: 100 * s.mean()))
              .sort_values("def_asr", ascending=False))

    # Cap at 20 rows for readability; lump tail into "other"
    if len(agg) > 20:
        head = agg.iloc[:20]
        tail = agg.iloc[20:]
        tail_row = pd.DataFrame([{
            "n": tail["n"].sum(),
            "llm_asr": (tail["llm_asr"] * tail["n"]).sum() / tail["n"].sum(),
            "def_asr": (tail["def_asr"] * tail["n"]).sum() / tail["n"].sum(),
        }], index=[f"other ({len(tail)} toolkits)"])
        agg = pd.concat([head, tail_row])

    fig, ax = plt.subplots(figsize=(12, max(5, 0.3 * len(agg) + 2)))
    y = np.arange(len(agg))
    ax.barh(y, agg["llm_asr"].values, height=0.4,
             color="#bdc3c7", edgecolor="black", label="LLM compliance ASR")
    ax.barh(y + 0.4, agg["def_asr"].values, height=0.4,
             color=CONFIG_COLOR["agenticcyops"], edgecolor="black",
             label="Defended ASR (DEFER)")
    ax.set_yticks(y + 0.2); ax.set_yticklabels(agg.index, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("ASR (%)"); ax.set_xlim(0, 110)
    for i, r in enumerate(agg.itertuples()):
        ax.text(r.llm_asr + 1, i, f"{r.llm_asr:.0f}  (n={int(r.n)})",
                 fontsize=7, va="center")
        ax.text(r.def_asr + 1, i + 0.4, f"{r.def_asr:.1f}",
                 fontsize=7, va="center")
    ax.set_title("Per-toolkit ASR: LLM compliance vs defended "
                  "(DEFER, all groups pooled)",
                  fontsize=12, fontweight="bold")
    ax.legend(loc="lower right")
    plt.tight_layout()
    pdf.savefig(fig); plt.close(fig)


def page_methodology(pdf):
    fig, ax = plt.subplots(figsize=(8.5, 11))
    ax.axis("off")
    ax.text(0.06, 0.95, "Methodology", fontsize=16, fontweight="bold",
            color=ACCENT)
    body = [
        "Benchmark:   InjecAgent representative subset (50 cases)",
        "             vendored by AdaptiveAttackAgent (NAACL 2025)",
        "",
        "Runner:      benchmarks/injecagent/run_e2e.py",
        "             representative cases sent to the live primary LLM,",
        "             unmodified.  Adaptive (GCG) attacks are out of scope",
        "             for this benchmark.",
        "",
        "Live-LLM flow (per case):",
        "  1. build ReAct conversation ending in poisoned tool response",
        "  2. call group's primary LLM",
        "  3. parse generation for Action:/Action Input:",
        "  4. attack_succeeded_llm = parsed action matches an attacker tool",
        "  5. defense pipeline (P1-P5) evaluates the parsed action on the",
        "     domain's manifest; defense_blocked flips succ->blocked",
        "  6. attack_succeeded_end_to_end = LLM succeeded AND defense didn't block",
        "",
        "Validator groups (primary + consensus mix):",
        "  A: Qwen3-235B   + V1(Qwen) + V2(DeepSeek) + V4(Claude) + V6(GPT-4o)",
        "  B: GLM-4.7-FP8  + V1 + V2 + V4 + V6",
        "  C: Qwen3-235B   + V1 x3 (same-family)",
        "  D: Llama-4      + V1 + V2 + V4 + V6",
        "  E: Qwen3-235B   + V1 + V5(Mistral) + V4 + V6",
        "  F: Claude (API) + V1 + V2 + V3(Llama) + V6",
        "",
        "Two tiers:",
        "  Tier 1  symbolic     P1-P5 middleware only; no live LLM",
        "  Tier 2  live static  live LLM + defense; unmodified prompts",
        "",
        "Caveats:",
        "  * Defended ASR depends on the group's consensus layer firing;",
        "    if LLM validators are down, P3-L6 silently falls back to the",
        "    deterministic pipeline (matches Tier-1 behavior).",
        "  * Refusal rate is informational, not success/failure: a refused",
        "    trial cannot succeed at the LLM stage, so it's effectively a",
        "    model-alignment win independent of our middleware.",
    ]
    ax.text(0.06, 0.88, "\n".join(body), fontsize=8.5,
            family="monospace", va="top")
    pdf.savefig(fig); plt.close(fig)


# --------------------------------------------------------------------- #
#  Top-level
# --------------------------------------------------------------------- #


def _write_artifacts(live: pd.DataFrame,
                     static_sym: Optional[pd.DataFrame],
                     toolkit_lookup: dict,
                     out_dir: Path) -> None:
    """Write the PDF + 3 CSVs from a (possibly per-group) live DataFrame."""
    tier_tbl = two_tier_table(static_sym, live)
    out_dir.mkdir(parents=True, exist_ok=True)

    live.to_csv(out_dir / "injecagent_e2e_combined.csv", index=False)
    tier_tbl.to_csv(out_dir / "injecagent_e2e_two_tier_asr.csv",
                     index=False, float_format="%.3f")

    toolkit_csv_path = None
    if toolkit_lookup:
        tk_df = _attach_toolkit(live, toolkit_lookup)
        if not tk_df.empty:
            tk_asr = (tk_df.groupby(["user_toolkit", "config"])
                           .agg(n=("attack_succeeded_end_to_end", "size"),
                                 llm_asr_pct=("attack_succeeded_llm",
                                               lambda s: 100 * s.mean()),
                                 defended_asr_pct=("attack_succeeded_end_to_end",
                                                    lambda s: 100 * s.mean()))
                           .reset_index()
                           .sort_values(["config", "defended_asr_pct"],
                                         ascending=[True, False]))
            toolkit_csv_path = out_dir / "injecagent_e2e_toolkit_asr.csv"
            tk_asr.to_csv(toolkit_csv_path, index=False, float_format="%.3f")

    pdf_path = out_dir / "injecagent_e2e_findings.pdf"
    with PdfPages(pdf_path) as pdf:
        page_title(pdf, static_sym, live, tier_tbl)
        page_per_group_bars(pdf, live)
        page_principle_attribution(pdf, live)
        page_per_toolkit(pdf, live, toolkit_lookup)
        page_hygiene(pdf, live)
        page_methodology(pdf)

    print(f"  wrote {pdf_path}")
    print(f"  wrote {out_dir / 'injecagent_e2e_two_tier_asr.csv'}")
    print(f"  wrote {out_dir / 'injecagent_e2e_combined.csv'}")
    if toolkit_csv_path:
        print(f"  wrote {toolkit_csv_path}")


def generate(root: Path,
              groups: Optional[list[str]] = None,
              cross_group_out_dir: Optional[Path] = None) -> None:
    """Per-group analytics by default.  Each group's PDF + CSVs land
    inside that group's run directory at
    ``e2e_validator_group_<G>/e2e_analytics/``.

    If ``cross_group_out_dir`` is provided, also emit a combined
    cross-group report (every run pooled) into that path -- useful
    once multiple groups have run.

    ``groups`` filters the run set to a subset (e.g. ``["A"]``).
    """
    runs = discover_runs(root)
    if groups:
        wanted = {g.upper() for g in groups}
        runs = [r for r in runs if r["group"].upper() in wanted]
    if not runs:
        raise SystemExit(
            f"No matching e2e_*_validator_group_*/ directories under {root}.\n"
            "Run ./scripts/run_injecagent_e2e.sh <GROUP> first.")

    print(f"Found {len(runs)} e2e run director{'y' if len(runs)==1 else 'ies'}:")
    for r in runs:
        print(f"  group={r['group']}  path={r['path'].name}")

    static_sym = load_static_symbolic(root)
    toolkit_lookup = load_toolkit_lookup()

    # --- Per-group artifacts (always emitted) -------------------------
    per_group_frames: list[pd.DataFrame] = []
    for r in runs:
        df = load_run_rows(r)
        if df.empty:
            print(f"\n[skip] group={r['group']}  empty run directory")
            continue
        out_dir = r["path"] / "e2e_analytics"
        print(f"\n[group {r['group']}] -> {out_dir}")
        _write_artifacts(df, static_sym, toolkit_lookup, out_dir)
        per_group_frames.append(df)

    # --- Optional cross-group rollup ----------------------------------
    if cross_group_out_dir is not None and per_group_frames:
        live_all = pd.concat(per_group_frames, ignore_index=True)
        print(f"\n[cross-group rollup] -> {cross_group_out_dir}")
        _write_artifacts(live_all, static_sym, toolkit_lookup,
                          cross_group_out_dir)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Per-group InjecAgent E2E analytics. "
                    "Each group's PDF+CSVs land in its own run directory.")
    ap.add_argument("--results-root",
                    default=str(RESULTS_DIR / "injecagent"))
    ap.add_argument("--groups", default="",
                    help="Comma-separated subset to process, e.g. 'A,C'. "
                         "Default: every group with results on disk.")
    ap.add_argument("--cross-group-out-dir", type=Path, default=None,
                    help="If set, also emit a combined cross-group report "
                         "to this directory (in addition to the per-group "
                         "artifacts).")
    args = ap.parse_args()

    root = Path(args.results_root)
    groups = [g.strip() for g in args.groups.split(",") if g.strip()] or None
    generate(root, groups=groups,
              cross_group_out_dir=args.cross_group_out_dir)


if __name__ == "__main__":
    main()
