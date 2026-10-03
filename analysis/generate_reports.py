"""PDF result reports from the v3 results (no LLM calls).

Runs after ``make paper-tables`` (parse_logs -> statistical_tests ->
generate_tables) and reads only what those wrote:

  results/eval_attacks/group_<G>[<suffix>]/<domain>/results.csv   per run
  results/eval_attacks/all_trials.csv, stats.csv, runs.csv
  results/paper_tables.md
  results/asb/e2e_validator_group_<G>_<panel>/general/summary.csv

Per run (one PDF next to each results.csv)::

  attack_report.pdf        title, per-AP interception table with Wilson
                           CIs, ASR bars, interception heatmap, blocking
                           mechanisms, benign utility, key findings
  asr_by_ap.png, interception_heatmap.png, mechanism_breakdown.png

Runs without attack trials (E1b persistent benign) get ``benign_report.pdf``.
Smoke/debug runs are skipped: they are not experiments.

Consolidated (``results/revision_report.pdf``): every table in
``paper_tables.md`` rendered as pages, interleaved with cross-group figures
(headline ASR with CIs, per-AP heatmaps, benign utility, ablations,
blocking layers, ASB panel replay, cost), a models/provenance page and the
scope notes.  Numbers in the PDF are the numbers in paper_tables.md.

Usage::

    python -m analysis.generate_reports              # per-run + consolidated
    python -m analysis.generate_reports --per-run
    python -m analysis.generate_reports --consolidated [--main-group q235_div4]
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt          # noqa: E402
import numpy as np                       # noqa: E402
from matplotlib.backends.backend_pdf import PdfPages  # noqa: E402

from analysis.generate_tables import AP_LABEL, CONFIG_LABEL, _ap_sort, _is_tagged, _read  # noqa: E402
from analysis.statistical_tests import MEASURABLE, SYSTEM_CONFIGS, wilson  # noqa: E402
from config import BASE_DIR, RESULTS_DIR  # noqa: E402

CONFIG_COLOR = {"flat": "#e74c3c", "acl_hardened": "#f39c12", "agenticcyops": "#2ecc71",
                "llm_judge": "#3498db", "symbolic_only": "#9b59b6"}
HEADER = "#2c3e50"
ACCENT = "#2980b9"
GREY = "#7f8c8d"
LANDSCAPE = (11, 8.5)
CONFIG_ORDER = ["flat", "acl_hardened", "agenticcyops", "llm_judge", "symbolic_only"]

# scope notes for the consolidated report: what the numbers do and do not cover
SCOPE_NOTES = [
    "ASR = executed / measurable trials. Trials scored not_measurable (no canary for the "
    "attack's effect) or error are excluded from every rate; attempt = executed + blocked.",
    "AP-4 and AP-14 have no measurable canary in CyberOps, finance and legal and are "
    "reported only where the oracle scores them (healthcare AP-4).",
    "Every (domain, config) ran as its own stream with its own tool servers, memory "
    "gateway and vector store; per-trial state isolation (isolated mode) except the E1b "
    "persistent runs.",
    "Latency and token figures were measured under 12-19 concurrent streams sharing the "
    "primary model server, so absolute latencies are load-dependent; ratios between "
    "configs within a group are comparable.",
    "Tool servers return scripted responses; the primary model sees one storyline per "
    "incident, which bounds the attempt rate.",
    "ASB panels are a paired replay of the same primary outputs through each validator "
    "panel; the drift check (live vs replayed, 50 cases) is in T6 as *_drift.",
    "Held-out variants (E4) and the adaptive attacker (E5) were not run.",
    "Defense code is frozen at defense-freeze-v2.1 (v2 plus an agent-output parser fix; "
    "the frozen directories are identical between the two tags).",
]


# ---------------------------------------------------------------- helpers
def _num(x, default=float("nan")) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def _pct(x, digits=1) -> str:
    v = _num(x)
    return "–" if math.isnan(v) else f"{100 * v:.{digits}f}"


def _git_head() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=BASE_DIR,
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return path.name


def _wrap(text: str, width: int) -> str:
    import textwrap
    return "\n".join(textwrap.wrap(text, width)) if text else ""


def _text_page(pdf: PdfPages, title: str, lines: list[str], size=11, wrap=110) -> None:
    fig, ax = plt.subplots(figsize=LANDSCAPE)
    fig.subplots_adjust(left=0.04, right=0.96, top=0.92, bottom=0.04)
    ax.axis("off")
    ax.set_title(title, fontsize=18, fontweight="bold", color=HEADER, pad=24, loc="left")
    y = 0.95
    for line in lines:
        wrapped = _wrap(line, wrap) if line else ""
        n = wrapped.count("\n") + 1
        ax.text(0.02, y, wrapped, transform=ax.transAxes, fontsize=size, va="top",
                family="DejaVu Sans")
        y -= 0.022 * size / 11 * (n + 0.6)
        if y < 0.03:
            break
    pdf.savefig(fig, bbox_inches="tight")
    plt.close(fig)


def _table_pages(pdf: PdfPages, title: str, headers: list[str], rows: list[list[str]],
                 note: str = "", rows_per_page: int = 26) -> None:
    """Render a table over as many landscape pages as it needs.

    Cells wrap at a per-column character budget, columns are sized by their
    longest line and pages are cut by line count, so wide tables (provenance,
    model names) stay inside the page."""
    if not rows:
        _text_page(pdf, title, ["(no rows)"])
        return
    ncol = len(headers)
    cap = max(12, min(36, int(260 / ncol)))                    # characters per line per column
    wrap = lambda s: _wrap(str(s), cap) if len(str(s)) > cap else str(s)   # noqa: E731
    head = [wrap(h) for h in headers]
    body = [[wrap(c) for c in r] for r in rows]
    longest = lambda s: max((len(l) for l in s.split("\n")), default=1)     # noqa: E731
    widths = [max(1.2 * longest(head[j]), *(longest(r[j]) for r in body), 3) + 2 for j in range(ncol)]  # bold header
    # font that fits the summed line lengths into the 10.6 in text width (0.65 em per char)
    font = max(6.0, min(9.0, 10.6 * 72 / (sum(widths) * 0.65)))
    widths = [w / sum(widths) for w in widths]
    n_lines = lambda cells: max(c.count("\n") + 1 for c in cells)          # noqa: E731
    head_lines = n_lines(head)
    line_budget = int(rows_per_page * 1.3 * 9 / font)

    pages: list[list[list[str]]] = [[]]
    used = head_lines
    for r in body:
        n = n_lines(r)
        if pages[-1] and used + n > line_budget:
            pages.append([])
            used = head_lines
        pages[-1].append(r)
        used += n

    for k, chunk in enumerate(pages):
        fig, ax = plt.subplots(figsize=LANDSCAPE)
        fig.subplots_adjust(left=0.02, right=0.98, top=0.92, bottom=0.04)   # axes = the page
        ax.axis("off")
        t = title if len(pages) == 1 else f"{title}  ({k + 1}/{len(pages)})"
        ax.set_title(t, fontsize=16, fontweight="bold", color=HEADER, pad=18, loc="left")
        row_lines = [head_lines] + [n_lines(r) for r in chunk]
        height = min(0.86, 0.02 * font / 9 * (sum(row_lines) + len(row_lines) * 0.6))
        table = ax.table(cellText=chunk, colLabels=head, colWidths=widths, cellLoc="center",
                         loc="upper center", bbox=[0.0, 0.9 - height, 1.0, height])
        table.auto_set_font_size(False)
        table.set_fontsize(font)
        for i, n in enumerate(row_lines):
            for j in range(ncol):
                cell = table[i, j]
                cell.set_height(n + 0.6)                  # relative; the bbox rescales
                if i == 0:
                    cell.set_facecolor(HEADER)
                    cell.set_text_props(color="white", fontweight="bold")
                else:
                    cell.set_facecolor("#f4f6f7" if i % 2 else "white")
        if note and k == len(pages) - 1:
            ax.text(0.0, max(0.0, 0.88 - height - 0.04), _wrap(note, 150), transform=ax.transAxes,
                    fontsize=8, color=GREY, va="top")
        pdf.savefig(fig, bbox_inches="tight")
        plt.close(fig)


def _image_page(pdf: PdfPages, png: Path) -> None:
    if not png.exists():
        return
    img = plt.imread(str(png))
    fig, ax = plt.subplots(figsize=LANDSCAPE)
    ax.axis("off")
    ax.imshow(img)
    pdf.savefig(fig, bbox_inches="tight")
    plt.close(fig)


def _fig_page(pdf: PdfPages, fig) -> None:
    pdf.savefig(fig, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------- markdown tables
def parse_paper_tables(path: Path) -> list[tuple[str, str, list[str], list[list[str]]]]:
    """[(id, title, headers, rows)] for every ``## Tn.`` section of paper_tables.md."""
    if not path.exists():
        return []
    out = []
    section = None
    for line in path.read_text().splitlines():
        m = re.match(r"^## (T\w+)\.\s*(.*)$", line)
        if m:
            section = [m.group(1), m.group(2).strip(), [], []]
            out.append(section)
            continue
        if section is None or not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-+:?", c) for c in cells):
            continue
        if not section[2]:
            section[2] = cells
        else:
            section[3].append(cells)
    return [tuple(s) for s in out]


# ---------------------------------------------------------------- per-run report
def _measurable(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r.get("outcome") in MEASURABLE]


def _run_meta(runs: list[dict], group_dir: str, domain: str) -> dict:
    """Primary model / panel / freeze tag for the run directory, from runs.csv."""
    seen: dict[str, list[str]] = defaultdict(list)
    for r in runs:
        if r.get("domain") != domain or f"{r.get('group')}{r.get('suffix') or ''}" != group_dir:
            continue
        for k in ("primary_model", "primary_quantization", "consensus_config", "freeze_tag",
                  "git_sha", "vllm_version", "primary_temperature", "state_mode", "disabled_principles"):
            v = str(r.get(k) or "")
            if k == "git_sha":
                v = v[:10]
            if v and v not in seen[k]:
                seen[k].append(v)
    # a resumed run may span several commits / freeze tags: list every one seen
    return {k: ", ".join(v) for k, v in seen.items()}


def _charts(result_dir: Path, attack: list[dict], label: str, configs: list[str]) -> None:
    aps = sorted({r["ap"] for r in attack}, key=_ap_sort)
    by: dict[tuple, list[dict]] = defaultdict(list)
    for r in attack:
        by[(r["ap"], r["config"])].append(r)

    def asr(ap, cfg):
        m = _measurable(by.get((ap, cfg), []))
        return None if not m else 100.0 * sum(r["outcome"] == "executed" for r in m) / len(m)

    # ASR bars
    fig, ax = plt.subplots(figsize=(13, 6.5))
    x = np.arange(len(aps))
    width = 0.8 / max(1, len(configs))
    for i, cfg in enumerate(configs):
        vals = [asr(ap, cfg) for ap in aps]
        bars = ax.bar(x + i * width, [v or 0 for v in vals], width, label=CONFIG_LABEL.get(cfg, cfg),
                      color=CONFIG_COLOR.get(cfg, "#95a5a6"), edgecolor="white", linewidth=1.2)
        for bar, v in zip(bars, vals):
            if v is None:
                ax.text(bar.get_x() + bar.get_width() / 2, 1, "N/A", ha="center", va="bottom",
                        fontsize=6, color=GREY)
            elif v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, f"{v:.0f}",
                        ha="center", va="bottom", fontsize=7, fontweight="bold")
    ax.set_xticks(x + width * (len(configs) - 1) / 2)
    ax.set_xticklabels([AP_LABEL.get(ap, ap) for ap in aps], fontsize=9, rotation=35, ha="right")
    ax.set_ylabel("Attack success rate (%), measurable trials")
    ax.set_ylim(0, 110)
    ax.set_title(f"Attack success rate — {label}", fontsize=14, fontweight="bold")
    ax.legend(title="Configuration", frameon=True)
    fig.tight_layout()
    fig.savefig(result_dir / "asr_by_ap.png", dpi=150)
    plt.close(fig)

    # interception heatmap (100 - ASR)
    mat = np.full((len(aps), len(configs)), np.nan)
    annot = np.empty(mat.shape, dtype=object)
    for i, ap in enumerate(aps):
        for j, cfg in enumerate(configs):
            v = asr(ap, cfg)
            annot[i, j] = "N/A" if v is None else f"{100 - v:.0f}"
            if v is not None:
                mat[i, j] = 100 - v
    fig, ax = plt.subplots(figsize=(2.2 + 1.8 * len(configs), max(4, 0.45 * len(aps) + 1.5)))
    cmap = matplotlib.colormaps["RdYlGn"].copy()
    cmap.set_bad("#ecf0f1")
    im = ax.imshow(np.ma.masked_invalid(mat), cmap=cmap, vmin=0, vmax=100, aspect="auto")
    for i in range(len(aps)):
        for j in range(len(configs)):
            ax.text(j, i, annot[i, j], ha="center", va="center", fontsize=8,
                    color="black" if np.isnan(mat[i, j]) or 25 < mat[i, j] < 80 else "white")
    ax.set_xticks(range(len(configs)))
    ax.set_xticklabels([CONFIG_LABEL.get(c, c) for c in configs], fontsize=8)
    ax.set_yticks(range(len(aps)))
    ax.set_yticklabels([AP_LABEL.get(ap, ap) for ap in aps], fontsize=8)
    fig.colorbar(im, ax=ax, label="Interception rate (%)")
    ax.set_title(f"Interception rate — {label}", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(result_dir / "interception_heatmap.png", dpi=150)
    plt.close(fig)

    # blocking mechanisms under the DEFER stack
    stack = [r for r in attack if r["config"] in ("agenticcyops", "symbolic_only", "llm_judge")]
    mechs = Counter((r.get("blocked_by") or "unknown") for r in stack if r["outcome"] == "blocked")
    if mechs:
        labels = [m for m, _ in mechs.most_common()]
        vals = [mechs[m] for m in labels]
        fig, ax = plt.subplots(figsize=(9, max(4, 0.4 * len(labels) + 2)))
        ax.barh(labels, vals, color=ACCENT, edgecolor="white")
        for i, v in enumerate(vals):
            ax.text(v + 0.3, i, str(v), va="center", fontweight="bold", fontsize=9)
        ax.invert_yaxis()
        ax.set_xlabel("Blocked trials")
        ax.set_title(f"Blocking mechanisms — {label}", fontsize=13, fontweight="bold")
        fig.tight_layout()
        fig.savefig(result_dir / "mechanism_breakdown.png", dpi=150)
        plt.close(fig)


def _benign_rows(rows: list[dict], configs: list[str]) -> list[list[str]]:
    out = []
    for cfg in configs:
        ts = [r for r in rows if r["ap"] == "benign" and r["config"] == cfg and r["outcome"] == "benign"]
        if not ts:
            continue
        n = len(ts)
        task = [t for t in ts if t.get("task_completed") not in ("", None)]
        tc = sum(str(t["task_completed"]).lower() == "true" for t in task)
        p, lo, hi = wilson(tc, len(task))
        any_den = sum(int(_num(t.get("collateral_denials"), 0)) > 0 for t in ts)
        q, qlo, qhi = wilson(any_den, n)
        den = sum(int(_num(t.get("collateral_denials"), 0)) for t in ts)
        lat = sorted(_num(t.get("latency_s"), 0) for t in ts)
        ptok = sum(_num(t.get("primary_tokens"), 0) for t in ts) / n
        vtok = sum(_num(t.get("validator_tokens"), 0) for t in ts) / n
        out.append([CONFIG_LABEL.get(cfg, cfg), n, f"{_pct(p)} [{_pct(lo)}, {_pct(hi)}]",
                    f"{_pct(q)} [{_pct(qlo)}, {_pct(qhi)}]", f"{den / n:.2f}",
                    f"{lat[n // 2]:.1f} / {lat[int(0.95 * (n - 1))]:.1f}", f"{ptok:.0f} / {vtok:.0f}"])
    return out


def per_run_report(result_dir: Path, runs: list[dict]) -> Path | None:
    rows = _read(result_dir / "results.csv")
    if not rows:
        print(f"[skip] {_rel(result_dir)}: no results.csv rows")
        return None
    group_dir = result_dir.parent.name[len("group_"):]
    domain = result_dir.name
    label = f"{domain.title()} / {group_dir}"
    meta = _run_meta(runs, group_dir, domain)
    configs = [c for c in CONFIG_ORDER if any(r["config"] == c for r in rows)]
    attack = [r for r in rows if r["ap"].startswith("ap")]
    benign = [r for r in rows if r["ap"] == "benign"]
    errors = sum(r["outcome"] == "error" for r in rows)
    aps = sorted({r["ap"] for r in attack}, key=_ap_sort)

    if attack:
        _charts(result_dir, attack, label, configs)
    out = result_dir / ("attack_report.pdf" if attack else "benign_report.pdf")
    with PdfPages(str(out)) as pdf:
        # title
        fig, ax = plt.subplots(figsize=LANDSCAPE)
        ax.axis("off")
        ax.text(0.5, 0.78, "DEFER", transform=ax.transAxes, ha="center", fontsize=34,
                fontweight="bold", color=HEADER)
        ax.text(0.5, 0.69, "Attack-path evaluation report" if attack else "Benign utility report",
                transform=ax.transAxes, ha="center", fontsize=20, color=GREY)
        ax.text(0.5, 0.60, f"Domain: {domain.title()}   |   Run: {group_dir}", transform=ax.transAxes,
                ha="center", fontsize=15, color=ACCENT)
        ax.plot([0.2, 0.8], [0.56, 0.56], transform=ax.transAxes, color=ACCENT, linewidth=2)
        facts = [f"{len(rows)} trials: {len(attack)} attack across {len(aps)} attack paths, "
                 f"{len(benign)} benign, {errors} errors",
                 "Configurations: " + ", ".join(CONFIG_LABEL.get(c, c) for c in configs)]
        if meta:
            facts.append(f"Primary: {meta.get('primary_model', '?')} ({meta.get('primary_quantization', '?')})"
                         f"   panel: {meta.get('consensus_config') or '–'}   T={meta.get('primary_temperature', '?')}"
                         f"   state: {meta.get('state_mode', '?')}")
            facts.append(f"Freeze: {meta.get('freeze_tag', '?')}   git: {meta.get('git_sha', '?')}"
                         f"   vLLM: {meta.get('vllm_version', '?')}"
                         + (f"   disabled: {meta['disabled_principles']}"
                            if meta.get("disabled_principles") not in (None, "", "[]") else ""))
        y = 0.49
        for line in facts:
            ax.text(0.5, y, line, transform=ax.transAxes, ha="center", fontsize=11, color=HEADER)
            y -= 0.055
        ax.text(0.5, 0.12, f"Scoring v3 (effects oracle)   |   generated {datetime.now():%Y-%m-%d %H:%M}",
                transform=ax.transAxes, ha="center", fontsize=10, color="#95a5a6")
        _fig_page(pdf, fig)

        if attack:
            by: dict[tuple, list[dict]] = defaultdict(list)
            for r in attack:
                by[(r["ap"], r["config"])].append(r)
            table = []
            for ap in aps:
                row = [AP_LABEL.get(ap, ap)]
                for cfg in configs:
                    ts = by.get((ap, cfg), [])
                    m = _measurable(ts)
                    if not ts:
                        row.append("–")
                    elif not m:
                        row.append(f"N/A ({len(ts)} not measurable)")
                    else:
                        k = sum(r["outcome"] == "executed" for r in m)
                        p, lo, hi = wilson(k, len(m))
                        row.append(f"{k}/{len(m)}  {_pct(p, 0)}% [{_pct(lo, 0)}, {_pct(hi, 0)}]")
                table.append(row)
            _table_pages(pdf, f"Attack interception by path — {label}",
                         ["Attack path"] + [CONFIG_LABEL.get(c, c) for c in configs], table,
                         note="executed / measurable trials, ASR % [Wilson 95% interval]; "
                              "not-measurable and error trials excluded.")
            for png in ("asr_by_ap.png", "interception_heatmap.png", "mechanism_breakdown.png"):
                _image_page(pdf, result_dir / png)

        if benign:
            _table_pages(pdf, f"Benign utility (E1) — {label}",
                         ["Config", "N", "Task completed % [95%]", "Any denial % [95%]",
                          "Denials / incident", "Latency s median / p95", "Tokens primary / validator"],
                         _benign_rows(rows, configs))

        # key findings
        lines = []
        for cfg in configs:
            ct = [r for r in attack if r["config"] == cfg]
            if not ct:
                continue
            m = _measurable(ct)
            ex = sum(r["outcome"] == "executed" for r in m)
            bl = sum(r["outcome"] == "blocked" for r in m)
            att = ex + bl
            nm = sum(r["outcome"] == "not_measurable" for r in ct)
            er = sum(r["outcome"] == "error" for r in ct)
            asr = f"{100 * ex / len(m):.1f}%" if m else "n/a"
            bga = f"{100 * bl / att:.1f}%" if att else "n/a"
            lines.append(f"{CONFIG_LABEL.get(cfg, cfg)}: ASR {asr} ({ex}/{len(m)} executed), attempt rate "
                         f"{100 * att / len(m) if m else 0:.1f}%, block given attempt {bga}; "
                         f"{nm} not measurable, {er} errors.")
        for cfg in configs:
            ts = [r for r in benign if r["config"] == cfg and r["outcome"] == "benign"]
            if ts:
                tc = sum(str(r.get("task_completed")).lower() == "true" for r in ts)
                den = sum(int(_num(r.get("collateral_denials"), 0)) > 0 for r in ts)
                lines.append(f"{CONFIG_LABEL.get(cfg, cfg)} benign: {tc}/{len(ts)} tasks completed, "
                             f"{den}/{len(ts)} incidents with at least one denial.")
        lines.append("")
        lines.append(f"Source: {_rel(result_dir / 'results.csv')}  (rebuilt from the JSONL logs by analysis.parse_logs)")
        _text_page(pdf, f"Key findings — {label}", lines)
    print(f"[ok] {_rel(out)}")
    return out


def per_run_reports(root: Path, runs: list[dict]) -> list[Path]:
    written = []
    for csv_path in sorted(root.glob("group_*/*/results.csv")):
        group_dir = csv_path.parent.parent.name[len("group_"):]
        if re.search(r"_(smoke|debug)\w*$", group_dir):
            print(f"[skip] {_rel(csv_path.parent)}: smoke/debug run")
            continue
        p = per_run_report(csv_path.parent, runs)
        if p:
            written.append(p)
    return written


# ---------------------------------------------------------------- consolidated report
def _stats_row(stats: list[dict], group: str, domain: str, ap: str) -> dict | None:
    for r in stats:
        if r["group"] == group and r["domain"] == domain and r["ap"] == ap:
            return r
    return None


def fig_headline(stats: list[dict], groups: list[str]):
    fig, ax = plt.subplots(figsize=(10, 5.5))
    x = np.arange(len(groups))
    w = 0.26
    for i, cfg in enumerate(SYSTEM_CONFIGS):
        vals, err_lo, err_hi = [], [], []
        for g in groups:
            r = _stats_row(stats, g, "all", "all") or {}
            p = 100 * _num(r.get(f"{cfg}_asr"))
            vals.append(p)
            err_lo.append(p - 100 * _num(r.get(f"{cfg}_wilson_low")))
            err_hi.append(100 * _num(r.get(f"{cfg}_wilson_high")) - p)
        bars = ax.bar(x + (i - 1) * w, vals, w, yerr=[err_lo, err_hi], capsize=3,
                      label=CONFIG_LABEL[cfg], color=CONFIG_COLOR[cfg], edgecolor="white")
        for b, v in zip(bars, vals):
            if not math.isnan(v):
                ax.text(b.get_x() + b.get_width() / 2, v + 2.5, f"{v:.1f}", ha="center", fontsize=8,
                        fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(groups)
    ax.set_ylabel("Attack success rate (%), Wilson 95% CI")
    ax.set_title("T1. Headline attack success by primary model group", fontsize=13, fontweight="bold")
    ax.legend(frameon=True)
    ax.set_ylim(0, max(60, ax.get_ylim()[1]))
    fig.tight_layout()
    return fig


def fig_ap_heatmap(stats: list[dict], group: str, domain: str, title: str):
    rows = sorted((r for r in stats if r["group"] == group and r["domain"] == domain and r["ap"] != "all"),
                  key=lambda r: _ap_sort(r["ap"]))
    if not rows:
        return None
    mat = np.full((len(rows), len(SYSTEM_CONFIGS)), np.nan)
    for i, r in enumerate(rows):
        for j, cfg in enumerate(SYSTEM_CONFIGS):
            if int(_num(r.get(f"{cfg}_n"), 0)) > 0:
                mat[i, j] = 100 * _num(r.get(f"{cfg}_asr"))
    fig, ax = plt.subplots(figsize=(8, max(4.5, 0.42 * len(rows) + 1.8)))
    cmap = matplotlib.colormaps["Reds"].copy()
    cmap.set_bad("#ecf0f1")
    im = ax.imshow(np.ma.masked_invalid(mat), cmap=cmap, vmin=0, vmax=100, aspect="auto")
    for i, r in enumerate(rows):
        for j, cfg in enumerate(SYSTEM_CONFIGS):
            v = mat[i, j]
            n = int(_num(r.get(f"{cfg}_n"), 0))
            txt = "N/A" if np.isnan(v) else f"{v:.0f}\n(n={n})"
            ax.text(j, i, txt, ha="center", va="center", fontsize=7.5,
                    color="white" if not np.isnan(v) and v > 60 else "black")
    ax.set_xticks(range(len(SYSTEM_CONFIGS)))
    ax.set_xticklabels([CONFIG_LABEL[c] for c in SYSTEM_CONFIGS])
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([AP_LABEL.get(r["ap"], r["ap"]) for r in rows], fontsize=8)
    fig.colorbar(im, ax=ax, label="ASR (%)")
    ax.set_title(title, fontsize=12, fontweight="bold")
    fig.tight_layout()
    return fig


def fig_benign(trials: list[dict], groups: list[str]):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    x = np.arange(len(groups))
    w = 0.26
    for i, cfg in enumerate(SYSTEM_CONFIGS):
        tcs, dens = [], []
        for g in groups:
            ts = [t for t in trials if t["group"] == g and t["config"] == cfg and t["ap"] == "benign"
                  and t["outcome"] == "benign" and not t.get("suffix")]
            task = [t for t in ts if t.get("task_completed") not in ("", None)]
            tcs.append(100 * sum(str(t["task_completed"]).lower() == "true" for t in task) / len(task) if task else np.nan)
            dens.append(100 * sum(int(_num(t.get("collateral_denials"), 0)) > 0 for t in ts) / len(ts) if ts else np.nan)
        axes[0].bar(x + (i - 1) * w, tcs, w, label=CONFIG_LABEL[cfg], color=CONFIG_COLOR[cfg], edgecolor="white")
        axes[1].bar(x + (i - 1) * w, dens, w, label=CONFIG_LABEL[cfg], color=CONFIG_COLOR[cfg], edgecolor="white")
    for ax, ttl, yl in ((axes[0], "Benign task completed", "%"), (axes[1], "Benign incidents with any denial", "%")):
        ax.set_xticks(x)
        ax.set_xticklabels(groups, fontsize=9)
        ax.set_ylim(0, 105)
        ax.set_ylabel(yl)
        ax.set_title(ttl, fontsize=12, fontweight="bold")
    axes[0].legend(frameon=True, fontsize=8)
    fig.suptitle("T3. Benign utility (E1)", fontsize=13, fontweight="bold")
    fig.tight_layout()
    return fig


def fig_ablations(section):
    """Bars from the T4 rows: [config, attack N, ASR [ci], benign N, denial [ci]]."""
    if not section:
        return None
    _, _, headers, rows = section
    labels = [r[0] for r in rows]
    asr = [_num(re.match(r"[\d.]+", r[2]).group()) if re.match(r"[\d.]+", r[2]) else np.nan for r in rows]
    den = [_num(re.match(r"[\d.]+", r[4]).group()) if re.match(r"[\d.]+", r[4]) else np.nan for r in rows]
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    y = np.arange(len(labels))
    axes[0].barh(y, asr, color="#c0392b", edgecolor="white")
    axes[0].set_title("Attack success rate (%)", fontsize=12, fontweight="bold")
    axes[1].barh(y, den, color="#f39c12", edgecolor="white")
    axes[1].set_title("Benign incidents with any denial (%)", fontsize=12, fontweight="bold")
    for ax, vals in ((axes[0], asr), (axes[1], den)):
        ax.set_yticks(y)
        ax.set_yticklabels(labels, fontsize=9)
        ax.invert_yaxis()
        for i, v in enumerate(vals):
            if not math.isnan(v):
                ax.text(v + 0.5, i, f"{v:.1f}", va="center", fontsize=8)
    axes[0].set_xlim(0, np.nanmax(asr) * 1.3 + 2)
    axes[1].set_xlim(0, 105)
    fig.suptitle("T4. Ablations (E3): removing one principle at a time", fontsize=13, fontweight="bold")
    fig.tight_layout()
    return fig


def fig_blocked_by(section):
    if not section:
        return None
    _, _, _, rows = section
    labels = [r[0] for r in rows]
    vals = [_num(r[1], 0) for r in rows]
    fig, ax = plt.subplots(figsize=(10, max(4.5, 0.38 * len(labels) + 1.5)))
    colours = {"P1": "#1abc9c", "P2": "#3498db", "P3": "#9b59b6", "P4": "#e67e22", "P5": "#e74c3c"}
    ax.barh(labels, vals, color=[colours.get(l[:2], ACCENT) for l in labels], edgecolor="white")
    for i, v in enumerate(vals):
        ax.text(v + 0.5, i, f"{v:.0f}", va="center", fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Blocked attack trials")
    ax.set_title("T5. Which layer blocked the attacks (DEFER)", fontsize=13, fontweight="bold")
    fig.tight_layout()
    return fig


def fig_asb(section):
    """Defended ASR per panel and subtype from the T6 rows."""
    if not section:
        return None
    _, _, _, rows = section
    data: dict[str, dict[str, float]] = defaultdict(dict)
    llm: dict[str, float] = {}
    for run, sub, cfg, n, llm_asr, def_asr in rows:
        if cfg != "agenticcyops" or run.endswith("_drift"):
            continue
        panel = run.rsplit("_", 1)[-1]
        data[panel][sub] = _num(def_asr)
        llm[sub] = _num(llm_asr)
    if not data:
        return None
    panels = sorted(data, key=lambda p: np.nanmean(list(data[p].values())))
    subs = sorted({s for p in data.values() for s in p})
    fig, axes = plt.subplots(1, 2, figsize=(12, 5), gridspec_kw={"width_ratios": [1, 1.4]})
    overall = [np.average([data[p].get(s, np.nan) for s in subs],
                          weights=[_num(r[3]) for r in rows if r[0].endswith("_" + p) and r[2] == "agenticcyops"])
               for p in panels]
    axes[0].bar(panels, overall, color=ACCENT, edgecolor="white")
    for i, v in enumerate(overall):
        axes[0].text(i, v + 0.15, f"{v:.2f}", ha="center", fontsize=9, fontweight="bold")
    axes[0].set_ylabel("Defended ASR (%)")
    axes[0].set_title("ASB defended ASR by validator panel", fontsize=11, fontweight="bold")
    axes[0].set_ylim(0, max(10, max(overall) * 1.3))
    mat = np.array([[data[p].get(s, np.nan) for s in subs] for p in panels])
    im = axes[1].imshow(mat, cmap="Reds", vmin=0, vmax=max(15, np.nanmax(mat)), aspect="auto")
    for i in range(len(panels)):
        for j in range(len(subs)):
            axes[1].text(j, i, f"{mat[i, j]:.1f}", ha="center", va="center", fontsize=8)
    axes[1].set_xticks(range(len(subs)))
    axes[1].set_xticklabels([f"{s.replace('_', chr(10))}\n(LLM {llm[s]:.0f}%)" for s in subs], fontsize=7.5)
    axes[1].set_yticks(range(len(panels)))
    axes[1].set_yticklabels(panels)
    axes[1].set_title("Defended ASR (%) by attack subtype; LLM ASR without defense in brackets",
                      fontsize=10, fontweight="bold")
    fig.colorbar(im, ax=axes[1])
    fig.suptitle("T6. ASB paired panel replay (same primary outputs, different validator panels)",
                 fontsize=12, fontweight="bold")
    fig.tight_layout()
    return fig


def fig_cost(section):
    if not section:
        return None
    _, _, _, rows = section
    groups = sorted({r[0] for r in rows})
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    x = np.arange(len(groups))
    w = 0.26
    label_to_cfg = {v: k for k, v in CONFIG_LABEL.items()}
    for i, cfg in enumerate(SYSTEM_CONFIGS):
        lat, tok = [], []
        for g in groups:
            r = next((r for r in rows if r[0] == g and label_to_cfg.get(r[1]) == cfg), None)
            lat.append(_num(r[5].split("/")[0]) if r else np.nan)
            tok.append((_num(r[3]) + _num(r[4])) / 1000 if r else np.nan)
        axes[0].bar(x + (i - 1) * w, lat, w, label=CONFIG_LABEL[cfg], color=CONFIG_COLOR[cfg], edgecolor="white")
        axes[1].bar(x + (i - 1) * w, tok, w, label=CONFIG_LABEL[cfg], color=CONFIG_COLOR[cfg], edgecolor="white")
    axes[0].set_title("Median latency per incident (s)", fontsize=12, fontweight="bold")
    axes[1].set_title("Tokens per incident, primary + validators (k)", fontsize=12, fontweight="bold")
    for ax in axes:
        ax.set_xticks(x)
        ax.set_xticklabels(groups, fontsize=9)
    axes[0].legend(frameon=True, fontsize=8)
    fig.suptitle("T7. Cost (attack trials; measured under concurrent load)", fontsize=13, fontweight="bold")
    fig.tight_layout()
    return fig


def _models_rows(runs: list[dict]) -> list[list[str]]:
    seen: dict[tuple, dict] = {}
    for r in runs:
        if _is_tagged(r.get("group", "")):
            continue
        key = (r.get("group"), r.get("primary_model"), r.get("consensus_config") or "–")
        seen.setdefault(key, r)
    rows = []
    for (g, model, panel), r in sorted(seen.items(), key=lambda kv: (kv[0][0], kv[0][2])):
        validators = r.get("validator_models") or ""
        try:
            parsed = json.loads(validators)
            validators = "; ".join(f"{k.split('_')[0]} {v}" for k, v in parsed.items())
        except (ValueError, AttributeError):
            pass
        if validators and r.get("consensus_threshold"):
            validators += f"  (threshold {r['consensus_threshold']})"
        rows.append([g, model, r.get("primary_quantization", ""), panel, validators or "–",
                     r.get("vllm_version", ""), r.get("freeze_tag", "")])
    return rows


def consolidated_report(results_dir: Path, main_group: str) -> Path:
    trials = _read(results_dir / "eval_attacks" / "all_trials.csv")
    stats = _read(results_dir / "eval_attacks" / "stats.csv")
    runs = _read(results_dir / "eval_attacks" / "runs.csv")
    sections = {s[0]: s for s in parse_paper_tables(results_dir / "paper_tables.md")}
    groups = sorted({t["group"] for t in trials if not _is_tagged(t["group"])})
    main = [t for t in trials if not _is_tagged(t["group"]) and not t.get("suffix")]
    out = results_dir / "revision_report.pdf"

    with PdfPages(str(out)) as pdf:
        # cover
        fig, ax = plt.subplots(figsize=LANDSCAPE)
        ax.axis("off")
        ax.text(0.5, 0.80, "DEFER", transform=ax.transAxes, ha="center", fontsize=36,
                fontweight="bold", color=HEADER)
        ax.text(0.5, 0.71, "Revision results report", transform=ax.transAxes, ha="center",
                fontsize=22, color=GREY)
        ax.plot([0.2, 0.8], [0.66, 0.66], transform=ax.transAxes, color=ACCENT, linewidth=2)
        n_att = sum(t["ap"].startswith("ap") for t in trials)
        n_ben = sum(t["ap"] == "benign" for t in trials)
        n_err = sum(t["outcome"] == "error" for t in trials)
        facts = [f"{len(trials)} trials ({n_att} attack, {n_ben} benign, {n_err} errors) in "
                 f"{len(groups)} primary-model groups: " + ", ".join(groups),
                 f"Main group {main_group}: 4 domains, 3 configurations, 7 ablation configurations, "
                 f"persistent-state benign runs, 4 ASB validator panels",
                 "Scoring v3 effects oracle; Wilson and cluster-bootstrap intervals; Holm-corrected "
                 "paired differences",
                 f"Code: git {_git_head()}   |   defense freeze: defense-freeze-v2.1",
                 f"Generated {datetime.now():%Y-%m-%d %H:%M} from {_rel(results_dir / 'paper_tables.md')}"]
        y = 0.58
        for line in facts:
            ax.text(0.5, y, _wrap(line, 110), transform=ax.transAxes, ha="center", fontsize=11, color=HEADER)
            y -= 0.075
        _fig_page(pdf, fig)

        # models & provenance summary
        _table_pages(pdf, "Models and validator panels per group",
                     ["Group", "Primary model", "Quant", "Panel", "Validators", "vLLM", "Freeze tag"],
                     _models_rows(runs),
                     note="One row per (group, primary, panel) seen in runs.csv; flat and ACL-hardened "
                          "runs have no panel.")

        # T1
        _fig_page(pdf, fig_headline(stats, groups))
        if "T1" in sections:
            _table_pages(pdf, "T1. " + sections["T1"][1], sections["T1"][2], sections["T1"][3],
                         note="ASR = executed / measurable; attempt = executed + blocked; Δ = paired "
                              "difference vs DEFER with cluster-bootstrap CI over variants.")

        # T2
        f = fig_ap_heatmap(stats, main_group, "all", f"T2a. ASR per attack path, {main_group}, all domains pooled")
        if f:
            _fig_page(pdf, f)
        f = fig_ap_heatmap(stats, main_group, "cyberops", f"T2b. ASR per attack path, {main_group}, CyberOps")
        if f:
            _fig_page(pdf, f)
        for tid in ("T2a", "T2b"):
            if tid in sections:
                _table_pages(pdf, f"{tid}. " + sections[tid][1], sections[tid][2], sections[tid][3],
                             note="Wilson 95% intervals; p_holm = Holm-corrected paired p-value within the "
                                  "family of attack paths.")

        # T3
        _fig_page(pdf, fig_benign(main, groups))
        for tid in ("T3", "T3b"):
            if tid in sections:
                _table_pages(pdf, f"{tid}. " + sections[tid][1], sections[tid][2], sections[tid][3])

        # T4
        f = fig_ablations(sections.get("T4"))
        if f:
            _fig_page(pdf, f)
        if "T4" in sections:
            _table_pages(pdf, "T4. " + sections["T4"][1], sections["T4"][2], sections["T4"][3])

        # T5
        f = fig_blocked_by(sections.get("T5"))
        if f:
            _fig_page(pdf, f)
        if "T5" in sections:
            _table_pages(pdf, "T5. " + sections["T5"][1], sections["T5"][2], sections["T5"][3])

        # T6
        f = fig_asb(sections.get("T6"))
        if f:
            _fig_page(pdf, f)
        if "T6" in sections:
            _table_pages(pdf, "T6. " + sections["T6"][1], sections["T6"][2], sections["T6"][3], rows_per_page=30)

        # T7
        f = fig_cost(sections.get("T7"))
        if f:
            _fig_page(pdf, f)
        if "T7" in sections:
            _table_pages(pdf, "T7. " + sections["T7"][1], sections["T7"][2], sections["T7"][3])

        # T8
        if "T8" in sections:
            _table_pages(pdf, "T8. " + sections["T8"][1], sections["T8"][2], sections["T8"][3], rows_per_page=32)

        _text_page(pdf, "Scope and notes", [f"• {n}" for n in SCOPE_NOTES] + [
            "", "Per-run reports: results/eval_attacks/group_<G>/<domain>/attack_report.pdf; "
            "ASB panel analytics: results/asb/**/asb_analytics.pdf."], size=10.5, wrap=125)

    print(f"[ok] {_rel(out)}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--per-run", action="store_true")
    ap.add_argument("--consolidated", action="store_true")
    ap.add_argument("--main-group", default="q235_div4")
    ap.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    args = ap.parse_args()
    both = not (args.per_run or args.consolidated)
    runs = _read(args.results_dir / "eval_attacks" / "runs.csv")
    if args.per_run or both:
        per_run_reports(args.results_dir / "eval_attacks", runs)
    if args.consolidated or both:
        consolidated_report(args.results_dir, args.main_group)


if __name__ == "__main__":
    main()
