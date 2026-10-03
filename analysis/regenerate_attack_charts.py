"""Regenerate the per-run attack charts and short PDF from ``results.csv``.

The runner script (``scripts/run_attack_paths.sh``) draws these charts from
the ``trial_complete`` events it just logged.  After an offline re-score
(``analysis.reevaluate_logs``) the verdicts in ``results.csv`` are the
authoritative ones, so the charts must be redrawn from the CSV.

Outputs into the same directory as ``results.csv``::

    asr_by_ap.png            grouped bars, one bar per config per AP
    interception_heatmap.png AP x config interception rate
    mechanism_breakdown.png  blocking mechanisms under DEFER
    attack_report.pdf        title + R1 table + the three charts + summary

Trials whose outcome is ``not_measurable`` are excluded from every rate and
the AP is labelled ``N/A`` when no measurable trial remains.

Usage::

    python -m analysis.regenerate_attack_charts --group A --domain cyberops
    python -m analysis.regenerate_attack_charts --all
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages

from config import BASE_DIR

sns.set_theme(style="whitegrid", font_scale=1.0, palette="muted")

CONFIGS = ["flat", "acl_hardened", "agenticcyops"]
CONFIG_LABELS = {"flat": "Flat MAS", "acl_hardened": "ACL-Hardened",
                 "agenticcyops": "DEFER"}
CONFIG_COLORS = {"flat": "#e74c3c", "acl_hardened": "#f39c12",
                 "agenticcyops": "#2ecc71"}
HEADER_COLOR = "#2c3e50"
AP_LABELS = {
    "ap1": "AP-1 Tool Redir.", "ap2": "AP-2 Mem Poison", "ap3": "AP-3 Confused Dep.",
    "ap4": "AP-4 Cross-Phase", "ap5": "AP-5 Irreversible", "ap6": "AP-6 Replay",
    "ap7": "AP-7 Action Chain", "ap8": "AP-8 Param Manip.", "ap9": "AP-9 Handoff Poison",
    "ap10": "AP-10 Validator Manip.", "ap11": "AP-11 Op Context", "ap12": "AP-12 Concurrent",
    "ap13": "AP-13 Adv Memory", "ap14": "AP-14 Read Inject", "ap15": "AP-15 Infra Integrity",
}
NON_DEFENSE_MECHANISMS = {"none", "agent_refused", "", None}


def _ap_num(ap: str) -> int:
    try:
        return int(ap.replace("ap", ""))
    except ValueError:
        return 0


def load_rows(csv_path: Path) -> list[dict]:
    rows = []
    with open(csv_path, newline="") as f:
        for r in csv.DictReader(f):
            r["Succeeded"] = str(r.get("Succeeded", "")).strip() == "True"
            mech = r.get("Mechanism", "") or ""
            outcome = r.get("Outcome") or (
                "succeeded" if r["Succeeded"]
                else "not_measurable" if mech.startswith("not_measurable")
                else "agent_refused" if mech == "agent_refused"
                else "blocked")
            r["Outcome"] = outcome
            r["Measurable"] = outcome not in ("not_measurable", "error")
            rows.append(r)
    return rows


def _rate(trials: list[dict]) -> float | None:
    meas = [t for t in trials if t["Measurable"]]
    if not meas:
        return None
    return 100.0 * sum(1 for t in meas if t["Succeeded"]) / len(meas)


def regenerate(group: str, domain: str, suffix: str = "") -> None:
    result_dir = BASE_DIR / "results" / "eval_attacks" / f"group_{group}{suffix}" / domain
    csv_path = result_dir / "results.csv"
    if not csv_path.exists():
        print(f"[skip] {csv_path} not found")
        return
    rows = load_rows(csv_path)
    attack = [r for r in rows if r["AP"].startswith("ap")]
    aps = sorted({r["AP"] for r in attack}, key=_ap_num)
    if not aps:
        print(f"[skip] no attack rows in {csv_path}")
        return

    by = defaultdict(list)
    for r in attack:
        by[(r["AP"], r["Config"])].append(r)
    asr = {k: _rate(v) for k, v in by.items()}

    # ---- Chart 1: ASR bars -------------------------------------------
    fig, ax = plt.subplots(figsize=(max(10, len(aps) * 2), 6))
    x = np.arange(len(aps))
    width = 0.25
    for i, cfg in enumerate(CONFIGS):
        vals = [asr.get((ap, cfg)) for ap in aps]
        heights = [v if v is not None else 0 for v in vals]
        bars = ax.bar(x + i * width, heights, width, label=CONFIG_LABELS[cfg],
                      color=CONFIG_COLORS[cfg], edgecolor="white", linewidth=1.5)
        for bar, val in zip(bars, vals):
            if val is None:
                ax.text(bar.get_x() + bar.get_width() / 2, 1, "N/A", ha="center",
                        va="bottom", fontsize=7, color="#7f8c8d")
            elif val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                        f"{val:.0f}%", ha="center", va="bottom", fontsize=8,
                        fontweight="bold")
    ax.set_xticks(x + width)
    ax.set_xticklabels([AP_LABELS.get(ap, ap) for ap in aps], fontsize=9)
    ax.set_ylabel("Attack Success Rate (%) -- measurable trials")
    ax.set_title(f"Attack Success Rate -- {domain.title()} / Group {group}{suffix}",
                 fontsize=14, fontweight="bold")
    ax.set_ylim(0, 110)
    ax.legend(title="Configuration", frameon=True)
    sns.despine(ax=ax)
    plt.tight_layout()
    plt.savefig(result_dir / "asr_by_ap.png", dpi=150)
    plt.close()

    # ---- Chart 2: interception heatmap --------------------------------
    matrix = np.full((len(aps), len(CONFIGS)), np.nan)
    annot = np.empty((len(aps), len(CONFIGS)), dtype=object)
    for i, ap in enumerate(aps):
        for j, cfg in enumerate(CONFIGS):
            v = asr.get((ap, cfg))
            if v is None:
                annot[i, j] = "N/A"
            else:
                matrix[i, j] = 100.0 - v
                annot[i, j] = f"{100.0 - v:.0f}"
    fig, ax = plt.subplots(figsize=(8, max(4, len(aps) * 0.8)))
    sns.heatmap(matrix, annot=annot, fmt="", cmap="RdYlGn",
                xticklabels=[CONFIG_LABELS[c] for c in CONFIGS],
                yticklabels=[AP_LABELS.get(ap, ap) for ap in aps],
                vmin=0, vmax=100, linewidths=1, linecolor="white",
                cbar_kws={"label": "Interception Rate (%)"}, ax=ax)
    ax.set_title(f"Interception Rate -- {domain.title()} / Group {group}{suffix}",
                 fontsize=14, fontweight="bold")
    plt.tight_layout()
    plt.savefig(result_dir / "interception_heatmap.png", dpi=150)
    plt.close()

    # ---- Chart 3: mechanism breakdown (agenticcyops) -------------------
    aco = [r for r in attack if r["Config"] == "agenticcyops"]
    mechs: dict[str, int] = defaultdict(int)
    refused = 0
    for r in aco:
        if r["Outcome"] == "blocked":
            mechs[r.get("Mechanism") or "unknown"] += 1
        elif r["Outcome"] == "agent_refused":
            refused += 1
    if mechs or refused:
        labels = sorted(mechs, key=mechs.get, reverse=True)
        values = [mechs[m] for m in labels]
        colors = list(sns.color_palette("Set2", max(1, len(labels))))
        if refused:
            labels.append("agent_refused (not a defense)")
            values.append(refused)
            colors.append("#bdc3c7")
        fig, ax = plt.subplots(figsize=(9, max(4, 0.4 * len(labels) + 2)))
        bars = ax.barh(labels, values, color=colors, edgecolor="white")
        for bar, val in zip(bars, values):
            ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                    str(val), va="center", fontweight="bold")
        ax.invert_yaxis()
        ax.set_xlabel("Trials")
        ax.set_title(f"Blocking Mechanisms -- {domain.title()} / Group {group}{suffix}",
                     fontsize=14, fontweight="bold")
        sns.despine(ax=ax)
        plt.tight_layout()
        plt.savefig(result_dir / "mechanism_breakdown.png", dpi=150)
        plt.close()

    # ---- PDF ------------------------------------------------------------
    with PdfPages(str(result_dir / "attack_report.pdf")) as pdf:
        fig, ax = plt.subplots(figsize=(11, 8.5)); ax.axis("off")
        ax.text(0.5, 0.72, "DEFER", transform=ax.transAxes, ha="center",
                fontsize=36, fontweight="bold", color=HEADER_COLOR)
        ax.text(0.5, 0.62, "Attack Path Evaluation Report", transform=ax.transAxes,
                ha="center", fontsize=22, color="#7f8c8d")
        ax.text(0.5, 0.52, f"Domain: {domain.title()} | Group {group}{suffix}",
                transform=ax.transAxes, ha="center", fontsize=16, color="#2980b9")
        ax.text(0.5, 0.44, f"{len(rows)} trials across {len(aps)} attack paths "
                "(scoring v2: attributable interceptions only)",
                transform=ax.transAxes, ha="center", fontsize=12, color="#2980b9")
        ax.text(0.5, 0.35, datetime.now().strftime("%B %d, %Y %H:%M"),
                transform=ax.transAxes, ha="center", fontsize=12, color="#95a5a6")
        pdf.savefig(fig, bbox_inches="tight"); plt.close()

        fig, ax = plt.subplots(figsize=(11, 8.5)); ax.axis("off")
        ax.set_title("Attack Interception Results (measurable trials)", fontsize=18,
                     fontweight="bold", color=HEADER_COLOR, pad=30)
        headers = ["Attack Path"] + [CONFIG_LABELS[c] for c in CONFIGS]
        cell_data = []
        for ap in aps:
            row = [AP_LABELS.get(ap, ap)]
            for cfg in CONFIGS:
                trials = by.get((ap, cfg), [])
                meas = [t for t in trials if t["Measurable"]]
                if not trials:
                    row.append("--")
                elif not meas:
                    row.append(f"N/A ({len(trials)} not measurable)")
                else:
                    s = sum(1 for t in meas if t["Succeeded"])
                    row.append(f"{len(meas) - s}/{len(meas)} blocked ({100 * s / len(meas):.0f}% ASR)")
            cell_data.append(row)
        table = ax.table(cellText=cell_data, colLabels=headers, cellLoc="center",
                         loc="center", bbox=[0.05, 0.1, 0.9, 0.75])
        table.auto_set_font_size(False); table.set_fontsize(9); table.scale(1, 2.0)
        for j in range(len(headers)):
            table[0, j].set_facecolor(HEADER_COLOR)
            table[0, j].set_text_props(color="white", fontweight="bold")
        pdf.savefig(fig, bbox_inches="tight"); plt.close()

        for name in ("asr_by_ap.png", "interception_heatmap.png", "mechanism_breakdown.png"):
            path = result_dir / name
            if path.exists():
                img = plt.imread(str(path))
                fig, ax = plt.subplots(figsize=(11, 8.5)); ax.axis("off"); ax.imshow(img)
                pdf.savefig(fig, bbox_inches="tight"); plt.close()

        fig, ax = plt.subplots(figsize=(11, 8.5)); ax.axis("off")
        ax.set_title("Key Findings", fontsize=18, fontweight="bold",
                     color=HEADER_COLOR, pad=30)
        y = 0.8
        for cfg in CONFIGS:
            ct = [t for t in attack if t["Config"] == cfg]
            meas = [t for t in ct if t["Measurable"]]
            if not ct:
                continue
            s = sum(1 for t in meas if t["Succeeded"])
            nm = len(ct) - len(meas)
            refused_c = sum(1 for t in meas if t["Outcome"] == "agent_refused")
            line = (f"{CONFIG_LABELS[cfg]}: {100 * s / len(meas):.1f}% ASR "
                    f"({s}/{len(meas)} succeeded, {len(meas) - s} not succeeded, "
                    f"of which {refused_c} agent refusals; {nm} not measurable)"
                    if meas else f"{CONFIG_LABELS[cfg]}: no measurable trials")
            ax.text(0.06, y, line, transform=ax.transAxes, fontsize=12,
                    color=CONFIG_COLORS[cfg], fontweight="bold")
            y -= 0.07
        ax.text(0.06, y - 0.05, f"Domain: {domain.title()} | Group: {group}{suffix} | "
                f"Trials: {len(rows)}", transform=ax.transAxes, fontsize=11, color="#7f8c8d")
        pdf.savefig(fig, bbox_inches="tight"); plt.close()

    print(f"[ok] {result_dir}: charts + attack_report.pdf regenerated")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--group", default=None)
    ap.add_argument("--domain", default=None, help="domain or 'all'")
    ap.add_argument("--suffix-dir", default="")
    ap.add_argument("--all", action="store_true",
                    help="every results/eval_attacks/group_*/<domain>/results.csv")
    args = ap.parse_args()

    if args.all:
        root = BASE_DIR / "results" / "eval_attacks"
        for gdir in sorted(root.glob("group_*")):
            name = gdir.name[len("group_"):]
            group, suffix = name[0], name[1:]
            for ddir in sorted(gdir.iterdir()):
                if ddir.is_dir() and (ddir / "results.csv").exists():
                    regenerate(group, ddir.name, suffix)
        return
    if not args.group:
        raise SystemExit("--group required unless --all")
    domains = (["cyberops", "healthcare", "finance", "legal"]
               if args.domain in (None, "all") else [args.domain])
    for d in domains:
        regenerate(args.group.upper(), d, args.suffix_dir)


if __name__ == "__main__":
    main()
