"""Figures for the DEFER paper.

One script produces every figure: ``make figures`` (= ``python -m
analysis.make_figures --out paper/figs``). Each ``fig_*`` function writes
``paper/figs/<name>.pdf`` plus a 200 dpi PNG preview and returns the PDF path;
``main`` collects a manifest (``paper/figs/figures.json``) carrying the reader
takeaway, data sources and n for every figure.

No number is typed into this file. Everything is read from
``results/eval_attacks/all_trials.csv``, the JSONL logs under ``logs/``,
``results/asb/``, ``results_legacy_v1/`` or ``results/benign_panel_rejection.csv``.
Intervals are 95% cluster-bootstrap intervals over variants at seed 0, reusing
:func:`analysis.statistical_tests.cluster_bootstrap`.

Usage:
    python -m analysis.make_figures --out paper/figs
    python -m analysis.make_figures --out paper/figs --only judgment_boundary
"""
from __future__ import annotations

import argparse
import glob
import json
import math
from collections import defaultdict
from pathlib import Path

import numpy as np

from analysis import figstyle as fs
from analysis import tiers
from analysis.statistical_tests import (MEASURABLE, _clusters, _CLUSTER, _EXEC,
                                        cluster_bootstrap, load_trials)
from config import BASE_DIR
from analysis.runlogs import run_logs

# DEFER_PANEL=local4 builds every figure under the all-local main panel: the
# panel-using configurations from their Local4 replay (analysis/replay_tables.py),
# the validator figure from the cached local votes, the panel figure from the
# local panels. Without it, figures show the runs as recorded (Div4).
import os as _os
LOCAL4 = _os.environ.get("DEFER_PANEL", "") == "local4"
ALL_TRIALS = BASE_DIR / "results" / "eval_attacks" / ("all_trials_local4.csv" if LOCAL4 else "all_trials.csv")
LOGS = BASE_DIR / "logs"

# the earlier runs (v2.2 code): the ablation, P5, carry-over and judge figures,
# which need arms the v3.1 runs do not have
DEV_GROUP = "q235_div4"
# the reported configuration (defense-freeze-v3.1): every figure the v3.1 runs
# can feed (all five configurations in four domains)
from analysis.reported import (ABLATION as _ABL, PERSIST as _PERSIST, PREVIOUS as _PREVIOUS,  # noqa: E402
                               PRIMARIES as _PRIM, REPORTED, carries_siblings)
REPORTED_GROUP = REPORTED          # the post-audit composition (analysis.reported)
BOUNDARY_GROUP = REPORTED_GROUP
# (domain, ap, variant) of the reported variants; the v3.1 runs also carry the
# E2 siblings, which main() drops. Filled by main().
ORIGINAL: set = set()


def _original_tid(tid: str) -> bool:
    """Whether an attack trial_id is one of the reported variants."""
    p = tid.split("_")
    return not ORIGINAL or p[1] == "benign" or (p[0], p[1], p[2].lstrip("v")) in ORIGINAL
DEV_DOMAIN = "cyberops"

# CSV config -> paper label, in the judgment-boundary order
CFG_BY_LABEL = {v: k for k, v in fs.CONFIG_LABEL.items()}


# --------------------------------------------------------------------- #
#  Selection helpers -- same filters as the tables
# --------------------------------------------------------------------- #
# the five configurations of the judgment boundary; targeted arms (permissive
# gate, judged writes, ...) share the group but carry their own config names
MAIN_CONFIGS = {"flat", "acl_hardened", "llm_judge", "symbolic_only", "agenticcyops"}


def dev_attacks(trials: list[dict], group: str = BOUNDARY_GROUP,
                domain: str = DEV_DOMAIN) -> list[dict]:
    """Measurable attack trials on the development split, main arms only."""
    return [t for t in trials
            if t["group"] == group and t["domain"] == domain
            and t["ap"] != "benign" and not t.get("suffix")
            and t["config"] in MAIN_CONFIGS
            and t.get("outcome") in MEASURABLE]


def benign_trials(trials: list[dict], group: str = BOUNDARY_GROUP,
                  domain: str = DEV_DOMAIN) -> list[dict]:
    """Benign incidents, main arms only (matches generate_tables.t3_benign)."""
    return [t for t in trials
            if t["group"] == group and t["domain"] == domain
            and t["ap"] == "benign" and t["outcome"] == "benign"
            and not t.get("suffix") and t["config"] in MAIN_CONFIGS]


def by_config(trials: list[dict]) -> dict[str, list[dict]]:
    return _clusters(trials, lambda t: t["config"])


def trial_id(t: dict) -> str:
    """The log ``trial_id`` for a CSV row (all_trials.csv does not carry it)."""
    return f"{t['domain']}_{t['ap']}_v{t['variant']}_t{t['trial']}_{t['config']}"


def asr_ci(trials: list[dict], seed: int = 0) -> tuple[float, float, float]:
    """(point, low, high) attack success, cluster bootstrap over variants."""
    if not trials:
        return (float("nan"),) * 3
    point, lo, hi = cluster_bootstrap(trials, _EXEC, _CLUSTER, seed=seed)
    return point, lo, hi


def rate_ci(trials: list[dict], indicator, seed: int = 0) -> tuple[float, float, float]:
    if not trials:
        return (float("nan"),) * 3
    return cluster_bootstrap(trials, indicator, _CLUSTER, seed=seed)


def _ratio_bootstrap(units: list[tuple[str, float, float]], B: int = 10000,
                     seed: int = 0, alpha: float = 0.05) -> tuple[float, float, float]:
    """Cluster bootstrap for a ratio of sums (e.g. denied proposals / proposals).

    ``units`` is ``(cluster_key, numerator, denominator)`` per trial. The
    resampling mirrors :func:`analysis.statistical_tests.cluster_bootstrap`
    exactly -- clusters (variants) are resampled with the same seeded generator
    -- but the statistic is ``sum(num)/sum(den)`` rather than a mean of a
    per-trial indicator, which a proposal-level rate requires.
    """
    groups: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for key, num, den in units:
        groups[key].append((num, den))
    gs = list(groups.values())
    if not gs:
        return (float("nan"),) * 3
    tot_n = sum(n for g in gs for n, _ in g)
    tot_d = sum(d for g in gs for _, d in g)
    point = tot_n / tot_d if tot_d else float("nan")
    gn = np.array([sum(n for n, _ in g) for g in gs], dtype=float)
    gd = np.array([sum(d for _, d in g) for g in gs], dtype=float)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(gs), size=(B, len(gs)))
    num = gn[idx].sum(axis=1)
    den = gd[idx].sum(axis=1)
    with np.errstate(invalid="ignore", divide="ignore"):
        draws = np.where(den > 0, num / den, np.nan)
    lo, hi = np.nanpercentile(draws, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return point, float(lo), float(hi)


# --------------------------------------------------------------------- #
#  Log-derived quantities
# --------------------------------------------------------------------- #
def scan_proposals(group: str, domain: str, configs: list[str],
                   benign: bool = False) -> dict[str, dict[str, tuple[int, int]]]:
    """Per-trial ``(tool_proposed, judged)`` counts from the JSONL logs.

    ``judged`` counts ``consensus_result`` events carrying a non-empty ``votes``
    list, i.e. proposals that actually reached the LLM panel. Resumed runs are
    deduped the way ``parse_logs`` dedupes trial outcomes: for each trial the
    newest log file that carries it wins.
    """
    out: dict[str, dict[str, tuple[int, int]]] = {}
    for cfg in configs:
        per_tf: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
        newest: dict[str, str] = {}
        for f in map(str, run_logs(group, domain, cfg)):
            with open(f, errors="ignore") as fh:
                for ln in fh:
                    if not ln.strip():
                        continue
                    try:
                        e = json.loads(ln)
                    except json.JSONDecodeError:
                        continue
                    tid, ap, act = e.get("trial_id"), e.get("ap"), e.get("action")
                    if not tid:
                        continue
                    if benign != (ap == "benign"):
                        continue
                    if not _original_tid(tid):
                        continue
                    if act == "tool_proposed":
                        per_tf[(tid, f)][0] += 1
                    elif act == "consensus_result" and (e.get("votes") or []):
                        per_tf[(tid, f)][1] += 1
                    else:
                        continue
                    newest[tid] = f
        per_trial: dict[str, tuple[int, int]] = {}
        for (tid, f), (prop, judged) in per_tf.items():
            if newest.get(tid) == f:
                per_trial[tid] = (prop, judged)
        out[cfg] = per_trial
    return out


def judged_fraction(group: str, domain: str, configs: list[str]) -> dict[str, float]:
    """Share of tool proposals that reached the LLM panel, per config."""
    scan = scan_proposals(group, domain, configs, benign=False)
    frac = {}
    for cfg, per_trial in scan.items():
        prop = sum(p for p, _ in per_trial.values())
        judged = sum(j for _, j in per_trial.values())
        frac[cfg] = judged / prop if prop else float("nan")
    return frac


# --------------------------------------------------------------------- #
#  F1. The judgment boundary
# --------------------------------------------------------------------- #
# Takeaway: never judging is the safest and the least usable; judging everything
# is neither safe nor cheap; DEFER sits near the safety of NoJudge at the
# usability of JudgeOnly.
def fig_judgment_boundary(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt

    labels = list(fs.CONFIG_ORDER)                     # Flat ACL NoJudge DEFER JudgeOnly
    cfgs = [CFG_BY_LABEL[c] for c in labels]

    att = by_config(dev_attacks(trials))
    ben = by_config(benign_trials(trials))
    judged = judged_fraction(BOUNDARY_GROUP, DEV_DOMAIN, cfgs)
    ben_scan = scan_proposals(BOUNDARY_GROUP, DEV_DOMAIN, cfgs, benign=True)

    # (a) attack success
    asr = [asr_ci(att.get(c, [])) for c in cfgs]
    # (b) legitimate tool proposals denied -- E7: the same definition the T11
    # table uses (denied tool proposals / all tool proposals, matched on
    # call_id), so figure and table cannot disagree. The interval still
    # resamples benign variants, with the per-variant (denied, proposed) pairs
    # taken from the shared counter.
    from analysis.benign_cost import proposal_denials_by_variant

    denied, completed = [], []
    for c in cfgs:
        ts = ben.get(c, [])
        by_var = proposal_denials_by_variant(BOUNDARY_GROUP, DEV_DOMAIN, c)
        if LOCAL4 and c in ("agenticcyops", "llm_judge"):
            by_var = _local4_benign_by_scenario(c)
        units = [(k, float(d), float(p)) for k, (d, p) in by_var.items() if p]
        denied.append(_ratio_bootstrap(units))
        done = [t for t in ts if str(t.get("task_completed", "")).strip() != ""]
        completed.append(rate_ci(done, lambda t: str(t["task_completed"]).lower() == "true"))

    fig, (axa, axb) = plt.subplots(
        1, 2, figsize=(fs.WIDTH_2COL, 3.1), sharex=True,
        gridspec_kw={"wspace": 0.28})
    x = np.arange(len(labels))
    colors = [fs.CONFIG_COLOR[c] for c in labels]

    def _band(ax):
        """Light band over the arms that involve judgment (NoJudge..JudgeOnly)."""
        ax.axvspan(x[labels.index("NoJudge")] - 0.5, x[labels.index("JudgeOnly")] + 0.5,
                   color=tiers.COLOR["panel"], alpha=0.07, zorder=0, lw=0)

    def _bars(ax, vals, ylab, headroom):
        _band(ax)
        pts = [100 * v[0] for v in vals]
        lo = [100 * (v[0] - v[1]) for v in vals]
        hi = [100 * (v[2] - v[0]) for v in vals]
        ax.bar(x, pts, width=0.62, color=colors, zorder=2)
        ax.errorbar(x, pts, yerr=[lo, hi], fmt="none", zorder=3, **fs.ERRORBAR_KW)
        for xi, p, h in zip(x, pts, hi):
            ax.text(xi, p + h + 1.0, f"{p:.1f}", ha="center", va="bottom", fontsize=7)
        ax.set_ylabel(ylab)
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.set_ylim(0, max(p + h for p, h in zip(pts, hi)) * headroom)
        fs.style_axes(ax)

    _bars(axa, asr, "Attack success (%)", 1.32)
    _bars(axb, denied, "Legitimate proposals denied (%)", 1.22)

    # (b) right axis: benign tasks completed, hollow markers in the cost colour
    axr = axb.twinx()
    axr.plot(x, [100 * p for p, _l, _h in completed], linestyle="none", marker="D",
             markerfacecolor="none", markeredgecolor=fs.BENIGN_COLOR,
             markeredgewidth=1.1, markersize=4.5, zorder=5, clip_on=False)
    axr.set_ylabel("Benign tasks completed (%)", color=fs.BENIGN_COLOR)
    axr.set_ylim(0, 105)
    axr.grid(False)
    axr.spines["top"].set_visible(False)
    axr.spines["right"].set_visible(True)
    axr.spines["right"].set_linewidth(0.6)
    axr.spines["right"].set_color(fs.BENIGN_COLOR)
    axr.tick_params(axis="y", colors=fs.BENIGN_COLOR, width=0.6)

    # DEFER marked on both panels
    for ax in (axa, axb):
        for tick in ax.get_xticklabels():
            if tick.get_text() == "DEFER":
                tick.set_fontweight("bold")
                tick.set_color(fs.CONFIG_COLOR["DEFER"])

    # "judgment boundary" label on panel (a)
    axa.text(x[labels.index("DEFER")], axa.get_ylim()[1] * 0.985, "judgment boundary",
             ha="center", va="top", fontsize=7, color=tiers.COLOR["panel"])

    # judged fraction under the x labels of panel (a)
    for xi, c in zip(x, cfgs):
        axa.annotate(f"{100 * judged[c]:.0f}", xy=(xi, 0), xycoords=("data", "axes fraction"),
                     xytext=(0, -22), textcoords="offset points", ha="center",
                     va="top", fontsize=6, color=tiers.COLOR["panel"])
    axa.annotate("judged (%)", xy=(0, 0), xycoords=("axes fraction", "axes fraction"),
                 xytext=(-4, -22), textcoords="offset points", ha="right", va="top",
                 fontsize=6, color=tiers.COLOR["panel"])

    fs.panel_label(axa, "(a)")
    fs.panel_label(axb, "(b)")

    path = fs.save(fig, "judgment_boundary", outdir, fs.WIDTH_2COL)
    meta = {
        "name": "judgment_boundary",
        "file": path.name,
        "takeaway": ("Never judging is the safest and escalates half of the legitimate work; "
                     "the judges without the rules barely beat no checks; DEFER sits between "
                     "them, at a cost set mostly by its rules."),
        "data_sources": ["results/eval_attacks/all_trials.csv",
                         f"logs/{DEV_DOMAIN}_eval_attacks_{BOUNDARY_GROUP}/*.jsonl"],
        "n": {
            "attack_trials": {fs.CONFIG_LABEL[c]: len(att.get(c, [])) for c in cfgs},
            "attack_variants": len({_CLUSTER(t) for t in dev_attacks(trials)}),
            "benign_incidents": {fs.CONFIG_LABEL[c]: len(ben.get(c, [])) for c in cfgs},
            "benign_scenarios": len({_CLUSTER(t) for t in benign_trials(trials)}),
            "judged_pct": {fs.CONFIG_LABEL[c]: round(100 * judged[c], 1) for c in cfgs},
            # E7: same definition as table T11 (analysis/benign_cost.py)
            "benign_denied_pct": {fs.CONFIG_LABEL[c]: round(100 * d[0], 1)
                                  for c, d in zip(cfgs, denied)},
            "benign_tasks_completed_pct": {fs.CONFIG_LABEL[c]: (None if math.isnan(v[0]) else round(100 * v[0], 1))
                                           for c, v in zip(cfgs, completed)},
        },
    }
    return path, meta


# --------------------------------------------------------------------- #
#  Shared selectors for the remaining figures
# --------------------------------------------------------------------- #
# Attack paths whose adversarial content arrives as a proposal the harness
# supplies (a handoff or a proposal justification) rather than as content the
# model must first read and then act on.
HARNESS_CHANNELS = ("handoff", "proposal_justification")


def ap_sort_key(ap: str) -> int:
    return int(ap.replace("ap", "")) if ap.startswith("ap") and ap[2:].isdigit() else 99


def ap_channel(trials: list[dict], ap: str) -> str:
    """The dominant injection channel of an attack path."""
    c = defaultdict(int)
    for t in trials:
        if t["ap"] == ap and t.get("channel"):
            c[t["channel"]] += 1
    return max(c, key=c.get) if c else ""


def asb_mechanisms(path: Path) -> list[str]:
    """``defense_mechanism`` of every blocked injected action under the defence."""
    import csv
    if not Path(path).exists():
        return []
    out = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            if r.get("config") != "agenticcyops":
                continue
            if str(r.get("defense_blocked", "")).strip().lower() == "true":
                out.append(r.get("defense_mechanism") or "")
    return out


def tier_shares(mechs: list[str]) -> tuple[dict[str, float], int]:
    """Shares over the four tiers of analysis/tiers.py. Refuses to report
    shares that would silently leave an unmapped interception out."""
    s, n, unmapped = tiers.shares(mechs)
    if unmapped:
        raise ValueError(f"unmapped first-interception labels: {sorted(set(unmapped))}")
    return s, n


# --------------------------------------------------------------------- #
#  F2. Who stops the attack: first interception by tier
# --------------------------------------------------------------------- #
# Takeaway: deterministic checks decide most interceptions on policy and
# structure attacks, and well under half on semantic third-party ones.
def fig_interception_tiers(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    def blocked_mechs(domains):
        return [t["blocked_by"] for t in trials
                if t["group"] == BOUNDARY_GROUP and t["domain"] in domains
                and t["ap"] != "benign" and not t.get("suffix")
                and t["config"] == "agenticcyops" and t["outcome"] == "blocked"]

    # ASB: the live run the paper reports (the frozen pipeline, 1,530 trials).
    # Its logged panel rejected every round; under Local4 the rounds it approves
    # are let through and leave the blocked set.
    live = asb_mechanisms(BASE_DIR / "results" / "asb" / "e2e_validator_group_q235_div4_frozen_full"
                          / "general" / "results.csv")
    if LOCAL4:
        from analysis.replay_panels import decide, load_all_votes, load_rounds, panel_for
        V, R = load_all_votes(), load_rounds()
        mem, q = panel_for("Local4", "asb")
        let = sum(bool(decide(r["key"], mem, q, V)) for r in R["asb_frozen"])
        panel = [m for m in live if tiers.tier_of(m) == "panel"]
        live = [m for m in live if tiers.tier_of(m) != "panel"] + panel[:len(panel) - let]
    sources = [
        ("CyberOps", blocked_mechs({DEV_DOMAIN})),
        ("Other three domains", blocked_mechs({"finance", "healthcare", "legal"})),
        ("ASB (live)", live),
    ]

    fig, ax = plt.subplots(figsize=(fs.WIDTH_1COL, 2.3))
    ns, shares = [], []
    for _lbl, mechs in sources:
        s, n = tier_shares(mechs)
        shares.append(s)
        ns.append(n)
    y = np.arange(len(sources))[::-1]        # first source at the top
    left = np.zeros(len(sources))
    for tier in tiers.TIERS:
        vals = np.array([100 * s.get(tier, 0.0) for s in shares])
        ax.barh(y, vals, left=left, height=0.62, color=tiers.COLOR[tier],
                label=tiers.LABEL[tier], zorder=2)
        for yi, v, l in zip(y, vals, left):
            if v >= 7:
                ax.text(l + v / 2, yi, f"{v:.0f}", ha="center", va="center",
                        fontsize=6, color="white", fontweight="bold")
        left += vals
    for yi, n in zip(y, ns):
        ax.text(103, yi, f"n={n:,}", ha="left", va="center", fontsize=6)

    ax.set_yticks(y)
    ax.set_yticklabels([s[0] for s in sources])
    ax.set_xlabel("First interception (%)")
    ax.set_xlim(0, 126)
    ax.set_xticks([0, 20, 40, 60, 80, 100])
    ax.set_ylim(-0.6, len(sources) - 0.4)
    fs.style_axes(ax, ygrid=False, xgrid=True)
    ax.legend(handles=[Patch(facecolor=tiers.COLOR[t], label=tiers.LABEL[t])
                       for t in tiers.TIERS],
              loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=2,
              handlelength=1.1, columnspacing=0.9, borderpad=0.2)

    path = fs.save(fig, "interception_tiers", outdir, fs.WIDTH_1COL)
    meta = {
        "name": "interception_tiers", "file": path.name,
        "takeaway": ("Deterministic checks decide most interceptions on policy and structure "
                     "attacks, and well under half on the semantic third-party benchmark, "
                     "there only through content-dependent rules."),
        "data_sources": ["results/eval_attacks/all_trials.csv",
                         "results/asb/e2e_validator_group_q235_div4_frozen_full/general/results.csv"],
        "n": {lbl: n for (lbl, _m), n in zip(sources, ns)}
        | {f"{lbl} tier %": {t: round(100 * s.get(t, 0), 1) for t in tiers.TIERS}
           for (lbl, _m), s in zip(sources, shares)},
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F3. Per-attack-path heatmap
# --------------------------------------------------------------------- #
# Takeaway: JudgeOnly leaves whole attack paths red that DEFER clears; what
# survives DEFER is a short list -- the two harness-proposed paths and two
# alert-text paths -- and none of it above ~22%.
def fig_ap_heatmap(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap
    from analysis.generate_tables import AP_LABEL

    dev = dev_attacks(trials)
    cols = ["Flat", "ACL", "JudgeOnly", "NoJudge", "DEFER"]
    ccfg = [CFG_BY_LABEL[c] for c in cols]
    aps = sorted({t["ap"] for t in dev}, key=ap_sort_key)
    # model-mediated first, harness-proposed last, each in AP order
    harness = [a for a in aps if ap_channel(dev, a) in HARNESS_CHANNELS]
    model = [a for a in aps if a not in harness]
    SEP = "__sep__"                       # blank row carrying the group label
    ordered = model + ([SEP] + harness if harness else [])

    grid = np.full((len(ordered), len(cols)), np.nan)
    nvar = {}
    for i, ap in enumerate(ordered):
        if ap == SEP:
            continue                      # stays NaN -> renders blank
        rows_ap = [t for t in dev if t["ap"] == ap]
        nvar[ap] = len({_CLUSTER(t) for t in rows_ap})
        for j, cfg in enumerate(ccfg):
            ts = [t for t in rows_ap if t["config"] == cfg]
            if ts:
                grid[i, j] = 100 * sum(1 for t in ts if _EXEC(t)) / len(ts)

    # modal first interceptor under DEFER
    modal = {}
    for ap in ordered:
        c = defaultdict(int)
        for t in dev:
            if t["ap"] == ap and t["config"] == "agenticcyops" and t["outcome"] == "blocked":
                c[t["blocked_by"]] += 1
        modal[ap] = max(c, key=c.get) if c else None

    cmap = LinearSegmentedColormap.from_list("wr", ["#ffffff", fs.OUTCOME_COLOR["executed"]])
    fig, (ax, axm) = plt.subplots(
        1, 2, figsize=(fs.WIDTH_2COL, 3.2),
        gridspec_kw={"width_ratios": [5.0, 1.45], "wspace": 0.02})
    ax.imshow(grid, cmap=cmap, vmin=0, vmax=100, aspect="auto")
    for i in range(len(ordered)):
        for j in range(len(cols)):
            v = grid[i, j]
            if not np.isnan(v):
                ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=6,
                        color="white" if v > 55 else "black")
    ax.set_xticks(range(len(cols)))
    ax.set_xticklabels(cols)
    ax.set_yticks(range(len(ordered)))
    ax.set_yticklabels(["harness-proposed" if a == SEP
                        else f"{AP_LABEL.get(a, a)}  (n={nvar[a]})" for a in ordered], fontsize=6)
    for lbl, a in zip(ax.get_yticklabels(), ordered):
        if a == SEP:
            lbl.set_fontweight("bold")
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.grid(False)
    if harness:                            # rule through the blank spacer row
        ax.axhline(len(model), color=fs.EMPHASIS, linewidth=0.7)

    # right strip: modal first interceptor chip
    axm.set_xlim(0, 1)
    axm.set_ylim(len(ordered) - 0.5, -0.5)
    axm.axis("off")
    for i, ap in enumerate(ordered):
        m = modal[ap]
        tier = tiers.tier_of(m)
        if not tier:
            continue
        axm.add_patch(plt.Rectangle((0.02, i - 0.34), 0.1, 0.68,
                                    color=tiers.COLOR[tier], lw=0))
        axm.text(0.16, i, str(m).replace("_", " "), fontsize=5.2, va="center", ha="left")
    axm.set_title("first interceptor (DEFER)", fontsize=6, loc="left", pad=4)

    path = fs.save(fig, "ap_heatmap", outdir, fs.WIDTH_2COL)
    meta = {
        "name": "ap_heatmap", "file": path.name,
        "takeaway": ("JudgeOnly leaves whole attack paths red that DEFER clears; what "
                     "survives DEFER is concentrated on a few paths, led by persuasion of "
                     "the judges through the proposal's rationale (AP-10)."),
        "data_sources": ["results/eval_attacks/all_trials.csv"],
        "n": {"variants": {a: nvar[a] for a in ordered if a != SEP},
              "harness_proposed": harness,
              "defer_nonzero": [a for i, a in enumerate(ordered)
                                if grid[i, cols.index("DEFER")] > 0]},
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F4. Paired outcome per variant: JudgeOnly versus DEFER
# --------------------------------------------------------------------- #
# Takeaway: the cascade dominates the judge-only pipeline almost variant by
# variant.
def fig_paired_variants(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt
    from matplotlib.patches import Polygon, Patch

    dev = dev_attacks(trials)

    def verdict(ap, var, cfg):
        ts = [t for t in dev if t["ap"] == ap and t["variant"] == var and t["config"] == cfg]
        if not ts:
            return None
        if any(_EXEC(t) for t in ts):
            return "executed"
        if any(t["outcome"] == "blocked" for t in ts):
            return "blocked"
        return "not_attempted"

    aps = sorted({t["ap"] for t in dev}, key=ap_sort_key)
    vars_by_ap = {a: sorted({t["variant"] for t in dev if t["ap"] == a},
                            key=lambda v: int(v)) for a in aps}
    width = max(len(v) for v in vars_by_ap.values())

    counts = defaultdict(int)
    fig, ax = plt.subplots(figsize=(fs.WIDTH_1COL, 2.95))
    for i, ap in enumerate(aps):
        for j, var in enumerate(vars_by_ap[ap]):
            jo, de = verdict(ap, var, "llm_judge"), verdict(ap, var, "agenticcyops")
            if jo is None or de is None:
                continue
            # upper-left triangle = JudgeOnly, lower-right = DEFER
            ax.add_patch(Polygon([(j - .45, i - .45), (j + .45, i - .45), (j - .45, i + .45)],
                                 closed=True, color=fs.OUTCOME_COLOR[jo], lw=0))
            ax.add_patch(Polygon([(j + .45, i - .45), (j + .45, i + .45), (j - .45, i + .45)],
                                 closed=True, color=fs.OUTCOME_COLOR[de], lw=0))
            if jo == "executed" and de != "executed":
                counts["JudgeOnly fails, DEFER holds"] += 1
            elif de == "executed" and jo != "executed":
                counts["DEFER fails, JudgeOnly holds"] += 1
            elif de == "executed" and jo == "executed":
                counts["both fail"] += 1

    ax.set_xlim(-0.6, width - 0.4)
    ax.set_ylim(len(aps) - 0.5, -0.5)
    ax.set_xticks(range(width))
    ax.set_xticklabels([f"v{i + 1}" for i in range(width)], fontsize=6)
    ax.set_yticks(range(len(aps)))
    ax.set_yticklabels([a.replace("ap", "AP-") for a in aps], fontsize=6)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.grid(False)
    ax.set_xlabel("variant")

    handles = [Patch(facecolor=fs.OUTCOME_COLOR[k], label=lbl) for k, lbl in
               (("executed", "executed"), ("blocked", "always blocked"),
                ("not_attempted", "never attempted"))]
    # the key and the counts sit below the grid, clear of every cell: the
    # grid is as wide as the longest path (AP-4, seven variants)
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.135), ncol=3,
              handlelength=0.9, borderpad=0.2, columnspacing=1.2, handletextpad=0.4,
              fontsize=5.6, frameon=False)
    order = ("JudgeOnly fails, DEFER holds", "DEFER fails, JudgeOnly holds", "both fail")
    ax.text(0.5, -0.225, "    ".join(f"{k}: {counts.get(k, 0)}" for k in order),
            transform=ax.transAxes, ha="center", va="top", fontsize=5.6)
    ax.set_title("upper-left: JudgeOnly    lower-right: DEFER", fontsize=6, loc="left", pad=4)

    path = fs.save(fig, "paired_variants", outdir, fs.WIDTH_1COL)
    meta = {
        "name": "paired_variants", "file": path.name,
        "takeaway": ("Variant by variant the cascade dominates the judge-only pipeline: it "
                     "rescues many variants JudgeOnly loses and gives up almost none."),
        "data_sources": ["results/eval_attacks/all_trials.csv"],
        "n": {"variants": sum(len(v) for v in vars_by_ap.values()), **dict(counts)},
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F5. Leave-one-out ablation on the shared subset
# --------------------------------------------------------------------- #
# Takeaway: P3, P2 and P4 each stop attacks the others miss; P1 and P5 do not
# show on this subset (P5 is measured in F6).
def fig_ablation(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt

    # arms as (label, group, suffix): the v3.1 leave-one-out runs are groups of
    # their own (q235_local2_disabled_P<i>_v31); the earlier ones are suffixes
    v31 = dict(_ABL)                 # the reported leave-one-out arms (v3.2)
    have_v31 = [i for i, g in v31.items() if any(t["group"] == g for t in trials)]
    if len(have_v31) == 5:
        arms = [("DEFER", BOUNDARY_GROUP, "")] + [(f"minus P{i}", v31[i], "") for i in have_v31]
    else:
        sufs = sorted({t["suffix"] for t in trials if t["group"] == DEV_GROUP and t.get("suffix")})
        arms = [("DEFER (subset)", DEV_GROUP, "")] + [(f"minus {s.split('_')[-1]}", DEV_GROUP, s) for s in sufs]

    def pick(g, suf, benign):
        return [t for t in trials if t["group"] == g and t["domain"] == DEV_DOMAIN
                and t.get("suffix", "") == suf and t["config"] == "agenticcyops"
                and ((t["ap"] == "benign" and t["outcome"] == "benign") if benign
                     else (t["ap"] != "benign" and t.get("outcome") in MEASURABLE))]

    # shared subset: variants present in every arm
    subset = set.intersection(*[{_CLUSTER(t) for t in pick(g, suf, False)} for _l, g, suf in arms])
    asr, ben = [], []
    for _lbl, g, suf in arms:
        asr.append(asr_ci([t for t in pick(g, suf, False) if _CLUSTER(t) in subset]))
        ben.append(rate_ci(pick(g, suf, True), lambda t: float(t.get("collateral_denials") or 0) > 0))

    fig, (ax, axb) = plt.subplots(
        1, 2, figsize=(fs.WIDTH_1COL, 2.4), sharey=True,
        gridspec_kw={"width_ratios": [2.3, 1.0], "wspace": 0.12})
    y = np.arange(len(arms))[::-1]
    base = 100 * asr[0][0]
    for ax_, vals, xlabel in ((ax, asr, "Attack success (%)"),
                              (axb, ben, "Any denial (%)")):
        pts = [100 * v[0] for v in vals]
        lo = [100 * (v[0] - v[1]) for v in vals]
        hi = [100 * (v[2] - v[0]) for v in vals]
        colors = [fs.CONFIG_COLOR["DEFER"]] + [tiers.COLOR["content_independent"]] * (len(arms) - 1)
        ax_.barh(y, pts, height=0.6, color=colors, zorder=2)
        ax_.errorbar(pts, y, xerr=[lo, hi], fmt="none", zorder=3, **fs.ERRORBAR_KW)
        ax_.set_xlabel(xlabel)
        fs.style_axes(ax_, ygrid=False, xgrid=True)
    for yi, v in zip(y, asr):            # label right of the interval
        ax.text(100 * v[2] + 0.8, yi, f"{100 * v[0]:.1f}", va="center", ha="left", fontsize=6)
    ax.axvline(base, color=fs.EMPHASIS, linestyle="--", linewidth=0.8, zorder=4)
    ax.set_yticks(y)
    ax.set_yticklabels([a[0] for a in arms], fontsize=7)
    ax.set_xlim(0, max(100 * v[2] for v in asr) * 1.25 + 1)

    path = fs.save(fig, "ablation", outdir, fs.WIDTH_1COL)
    meta = {
        "name": "ablation", "file": path.name,
        "takeaway": ("Removing any principle lets attacks through that the others do not catch, "
                     "P3 most; removing P2 halves the benign incidents with a denial."
                     if len(have_v31) == 5 else
                     "Removing P3, P2 or P4 each lets attacks through that the others do not "
                     "catch; on this subset P1 and P5 never bind."),
        "data_sources": ["results/eval_attacks/all_trials.csv"],
        "n": {"shared_variants": len(subset),
              "asr_pct": {a[0]: round(100 * v[0], 1) for a, v in zip(arms, asr)},
              "benign_any_denial_pct": {a[0]: round(100 * v[0], 1) for a, v in zip(arms, ben)}},
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F6. P5 evidence on the read-dependent attack paths
# --------------------------------------------------------------------- #
# Takeaway: reads are the one place the judges cannot help and the store policy
# is what closes the leak.
def fig_p5_reads(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt

    # the v3.1 runs when the v3.1 minus-P5 arm exists (a group of its own),
    # the earlier runs (a suffix of DEV_GROUP) otherwise
    p5_v31 = _ABL[5]
    if any(t["group"] == p5_v31 for t in trials):
        g, gp5, sp5 = BOUNDARY_GROUP, p5_v31, ""
    else:
        g, gp5, sp5 = DEV_GROUP, DEV_GROUP, "_disabled_P5"
    pool = [t for t in trials if t["group"] in (g, gp5) and t["domain"] == DEV_DOMAIN
            and t.get("outcome") in MEASURABLE and t["ap"] in ("ap4", "ap14")]
    arms = [("Flat", "flat", "", g), ("ACL", "acl_hardened", "", g), ("JudgeOnly", "llm_judge", "", g),
            ("DEFER\nminus P5", "agenticcyops", sp5, gp5), ("DEFER", "agenticcyops", "", g)]
    # AP-14 only earns a place if it succeeds somewhere; on this split it never does
    aps = [a for a in ("ap4", "ap14") if any(_EXEC(t) for t in pool if t["ap"] == a)]

    fig, ax = plt.subplots(figsize=(fs.WIDTH_1COL, 2.4))
    axr = ax.twinx()
    w = 0.38
    x = np.arange(len(arms))
    meta_n = {}
    for k, ap in enumerate(aps):
        vals, expo = [], []
        for _lbl, cfg, suf, grp in arms:
            ts = [t for t in pool if t["ap"] == ap and t["config"] == cfg
                  and t.get("suffix", "") == suf and t["group"] == grp]
            vals.append(asr_ci(ts))
            known = [t for t in ts if str(t.get("exposed", "")).lower() in ("true", "false")]
            expo.append(sum(1 for t in known if str(t["exposed"]).lower() == "true") / len(known)
                        if known else float("nan"))
        off = (k - (len(aps) - 1) / 2) * w
        pts = [100 * v[0] for v in vals]
        lo = [100 * (v[0] - v[1]) for v in vals]
        hi = [100 * (v[2] - v[0]) for v in vals]
        colr = fs.CONFIG_COLOR["DEFER"] if ap == "ap4" else tiers.COLOR["similarity"]
        ax.bar(x + off, pts, width=w * 0.92, color=colr, zorder=2,
               label=ap.replace("ap", "AP-"))
        ax.errorbar(x + off, pts, yerr=[lo, hi], fmt="none", zorder=3, **fs.ERRORBAR_KW)
        axr.plot(x + off, [100 * e for e in expo], linestyle="none", marker="o",
                 markerfacecolor="none", markeredgecolor=fs.EMPHASIS,
                 markeredgewidth=0.9, markersize=4, zorder=5, clip_on=False)
        meta_n[ap.replace("ap", "AP-")] = {
            "asr_pct": {a[0].replace("\n", " "): round(p, 1) for a, p in zip(arms, pts)},
            "exposure_pct": {a[0].replace("\n", " "): (None if math.isnan(e) else round(100 * e, 1))
                             for a, e in zip(arms, expo)}}

    ax.set_xticks(x)
    ax.set_xticklabels([a[0] for a in arms], fontsize=6.5)
    ax.set_ylabel("Attack success (%)")
    ax.set_ylim(0, 100)
    fs.style_axes(ax)
    axr.set_ylabel("Exposure (%)", color=fs.EMPHASIS)
    axr.set_ylim(0, 105)
    axr.grid(False)
    axr.spines["top"].set_visible(False)
    axr.spines["right"].set_visible(True)
    axr.spines["right"].set_linewidth(0.6)
    ax.legend(loc="upper right", handlelength=1.1, borderpad=0.2)

    path = fs.save(fig, "p5_reads", outdir, fs.WIDTH_1COL)
    meta = {
        "name": "p5_reads", "file": path.name,
        "takeaway": ("On the read-dependent paths the judges do not help: removing the store "
                     "policy (P5) reopens the leak that DEFER closes, at unchanged exposure."),
        "data_sources": ["results/eval_attacks/all_trials.csv"],
        "n": meta_n,
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F7. Panel composition: security versus benign rejection
# --------------------------------------------------------------------- #
# Takeaway: diversity buys security; the last points of size cost benign
# rejection; shared lineage throws the security away.
def fig_panel_composition(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import csv
    import matplotlib.pyplot as plt

    src = BASE_DIR / "results" / ("benign_panel_rejection_local.csv" if LOCAL4 else "benign_panel_rejection.csv")
    agg: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for r in csv.DictReader(open(src, newline="")):
        p = r["panel"]
        agg[p]["sec_k"] = float(r["security_letthrough"] or 0)
        agg[p]["sec_n"] = float(r["security_n"] or 0)
        if r["benign_rejected"]:
            agg[p]["ben_k"] += float(r["benign_rejected"])
            agg[p]["ben_n"] += float(r["benign_n"])

    label = {"single": "Single", "div3": "Div3", "div4": "Div4", "lin3": "Lin3",
             "div3x": "Div3x", "div3l": "Div3L", "local4": "Local4"}
    pts = {}
    for p, d in agg.items():
        sec = 100 * d["sec_k"] / d["sec_n"] if d["sec_n"] else float("nan")
        ben = 100 * d["ben_k"] / d["ben_n"] if d["ben_n"] else float("nan")
        pts[p] = (ben, sec)

    fig, ax = plt.subplots(figsize=(fs.WIDTH_1COL, 2.4))
    if LOCAL4:
        # every panel is re-adjudicated on the same rounds: plot all four,
        # single-lineage panels in the "executed" colour, mixed ones in DEFER's
        style = {"single": (fs.OUTCOME_COLOR["executed"], (6, 3), "Single (Qwen3-32B)"),
                 "lin3": (fs.OUTCOME_COLOR["executed"], (6, 3), "Lin3 (three Qwen-lineage)"),
                 "div3l": (fs.CONFIG_COLOR["DEFER"], (-6, -10), "Div3L"),
                 "local4": (fs.CONFIG_COLOR["DEFER"], (6, -9), "Local4 (reported)")}
        for p, (col, off, name) in style.items():
            if p not in pts:
                continue
            ben, sec = pts[p]
            ax.plot(ben, sec, marker="o", markersize=5, color=col, zorder=3)
            ax.annotate(name, (ben, sec), textcoords="offset points", xytext=off,
                        fontsize=7, ha="right" if off[0] < 0 else "left")
    path_order = [p for p in ("single", "div3", "div4") if p in pts and not LOCAL4]
    ax.plot([pts[p][0] for p in path_order], [pts[p][1] for p in path_order],
            color="#999999", linewidth=0.8, zorder=1)
    for p in path_order:
        ben, sec = pts[p]
        ax.plot(ben, sec, marker="o", markersize=5, color=fs.CONFIG_COLOR["DEFER"], zorder=3)
        ax.annotate(label[p], (ben, sec), textcoords="offset points", xytext=(5, 4), fontsize=7)
    if "lin3" in pts and math.isnan(pts["lin3"][0]) and not LOCAL4:
        # no benign estimate for lin3: park it on the left edge, open marker
        sec = pts["lin3"][1]
        ax.plot(0.6, sec, marker="o", markersize=5, markerfacecolor="none",
                markeredgecolor=fs.OUTCOME_COLOR["executed"], markeredgewidth=1.2, zorder=3)
        ax.annotate("Lin3 - benign n/a\nsame size as Div3, shared lineage",
                    (0.6, sec), textcoords="offset points", xytext=(7, 1),
                    fontsize=6, color=fs.OUTCOME_COLOR["executed"], va="center")
    ax.set_xlabel("Benign proposals rejected (%)")
    ax.set_ylabel("Injected actions let through (%)")
    # div3x has a benign estimate but no security number (its panel never ran),
    # so it is drawn as an open marker on the benign axis at y=0 with a note.
    if "div3x" in pts and math.isnan(pts["div3x"][1]):
        ben = pts["div3x"][0]
        ax.plot(ben, 0, marker="s", markersize=5, markerfacecolor="none",
                markeredgecolor=tiers.COLOR["content_independent"], markeredgewidth=1.2, zorder=3)
        ax.annotate("Div3x - security n/a\nDiv4 without the Qwen validator",
                    (ben, 0), textcoords="offset points", xytext=(6, 8),
                    fontsize=6, color=tiers.COLOR["content_independent"], va="bottom")
    _bx = [v[0] for v in pts.values() if not math.isnan(v[0])]
    _by = [v[1] for v in pts.values() if not math.isnan(v[1])]
    ax.set_xlim(0, (max(_bx) if _bx else 1) * 1.45)
    ax.set_ylim(-0.6, (max(_by) if _by else 1) * 1.25)
    fs.style_axes(ax)

    path = fs.save(fig, "panel_composition", outdir, fs.WIDTH_1COL)
    meta = {
        "name": "panel_composition", "file": path.name,
        "takeaway": (("Lineage, not size, buys security: the mixed-lineage panels let through "
                      "about 1% of replayed attack actions, a same-size single-lineage panel "
                      "(Lin3) about 10%, at similar benign rejection.") if LOCAL4 else
                     ("Diversity buys security: Div4 lets nothing through, and the last points "
                      "of it cost a few points of benign rejection. A same-size panel of one "
                      "model lineage (Lin3) gives the security back.")),
        "data_sources": [src.relative_to(BASE_DIR).as_posix(),
                         "results/asb/e2e_validator_group_q235_div4_*/general/results.csv"],
        "n": {label[p]: {"benign_rejected_pct": None if math.isnan(v[0]) else round(v[0], 1),
                         "letthrough_pct": None if math.isnan(v[1]) else round(v[1], 1),
                         "security_n": int(agg[p]["sec_n"])} for p, v in pts.items()},
    }
    return path, meta


# --------------------------------------------------------------------- #
#  Validator votes (F8)
# --------------------------------------------------------------------- #
def validator_rounds(group: str = DEV_GROUP) -> tuple[list[str], list[dict[str, str]]]:
    if LOCAL4:
        return _local4_rounds()
    return _logged_rounds(group)


def _local4_benign_by_scenario(config: str, group: str = BOUNDARY_GROUP) -> dict:
    """Per benign scenario (denied, proposed) under the Local4 replay."""
    from analysis.replay_panels import load_all_votes, load_rounds, outcomes
    arm = "full" if config == "agenticcyops" else "judgeonly"
    if group == REPORTED_GROUP:           # the reported rounds are kept apart
        arm = f"rep_{arm}"
        rounds = [json.loads(ln) for ln in open(BASE_DIR / "cache" / "replay_rep" / "rounds.jsonl")]
        rounds = [r for r in rounds if r["arm"] == arm]
    else:
        rounds = load_rounds()[arm]
    res = outcomes(arm, group, config, (DEV_DOMAIN,), "", "Local4", load_all_votes(), rounds)
    return dict(res["domains"][DEV_DOMAIN]["benign_by_scenario"])


def _local4_panel_delta(group: str, domain: str) -> int | None:
    """Local4 minus as-run denied benign tool calls under FULL (``None`` when
    the group has no replay rounds)."""
    from analysis.replay_panels import load_all_votes, outcomes
    if group != REPORTED_GROUP:
        return None
    f = BASE_DIR / "cache" / "replay_rep" / "rounds.jsonl"
    if not f.exists():
        return None
    rounds = [r for r in map(json.loads, open(f)) if r["arm"] == "rep_full" and r["domain"] == domain]
    res = outcomes("rep_full", group, "agenticcyops", (domain,), "", "Local4", load_all_votes(), rounds)
    per = res["domains"][domain].get("benign_trials", {})
    return sum(den - as_run for den, as_run in per.values())


def _local4_rounds() -> tuple[list[str], list[dict[str, str]]]:
    """Every judged FULL round (four domains) with the four local votes: the
    reported (v3.1) runs when their rounds are cached, the earlier runs otherwise."""
    from analysis.p3_eligibility import JUDGED_PATHS
    from analysis.replay_panels import PANELS, load_all_votes, load_rounds
    members = list(PANELS["Local4"][0])
    V = load_all_votes()
    rep = BASE_DIR / "cache" / "replay_rep" / "rounds.jsonl"
    if rep.exists():                  # the reported FULL rounds, E2 siblings excluded
        src = [r for r in map(json.loads, open(rep))
               if r["arm"] == "rep_full" and r["path"] in JUDGED_PATHS and _original_tid(r["trial_id"])]
    else:
        src = [r for r in load_rounds()["full"] if r["path"] != "allowed_no_p3"]
    rounds = [{m: V[m].get(r["key"], "error") for m in members} for r in src]
    return members, rounds


def _logged_rounds(group: str = DEV_GROUP) -> tuple[list[str], list[dict[str, str]]]:
    """Per-round validator -> vote maps from every domain of a group.

    Deduped per trial the way ``parse_logs`` dedupes (newest file wins); only
    rounds that reached the full recorded panel are kept.
    """
    rounds_by_tf: dict[tuple[str, str], list[dict]] = defaultdict(list)
    newest: dict[str, str] = {}
    panel: tuple[str, ...] | None = None
    for d in ("cyberops", "finance", "healthcare", "legal"):
        for f in map(str, run_logs(group, d, "agenticcyops")):
            for ln in open(f, errors="ignore"):
                if not ln.strip():
                    continue
                try:
                    e = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                if e.get("action") != "consensus_result":
                    continue
                vs, vals = e.get("votes") or [], e.get("validators") or []
                if not vs or len(vs) != len(vals):
                    continue
                if panel is None:
                    panel = tuple(vals)
                if tuple(vals) != panel:
                    continue
                tid = e.get("trial_id")
                rounds_by_tf[(tid, f)].append(dict(zip(vals, vs)))
                newest[tid] = f
    rounds = []
    for tid, f in newest.items():
        rounds.extend(rounds_by_tf[(tid, f)])
    return list(panel or ()), rounds


# --------------------------------------------------------------------- #
#  F8. Validator behaviour
# --------------------------------------------------------------------- #
# Takeaway: the judges agree only moderately, so the quorum is a design knob
# with a large effect.
def fig_validator_behavior(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt

    panel, rounds = validator_rounds()
    # An API validator that was out of credit returned an error, which the
    # panel counts as a rejection (analysis/outage.py). Treating those errors
    # as votes would make the unavailable validators look strict and agree
    # with each other; so kappa uses the rounds in which both validators of a
    # pair actually voted, and reject rates and the quorum sweep use the
    # rounds in which all four did.
    voted = lambda r, v: r.get(v) in ("approve", "reject")
    clean = [r for r in rounds if all(voted(r, v) for v in panel)]
    approve = {v: np.array([1 if r.get(v) == "approve" else 0 for r in clean]) for v in panel}

    def kappa(vi, vj):
        both = [r for r in rounds if voted(r, vi) and voted(r, vj)]
        a = np.array([r[vi] == "approve" for r in both], dtype=float)
        b = np.array([r[vj] == "approve" for r in both], dtype=float)
        po = float((a == b).mean())
        pa, pb = a.mean(), b.mean()
        pe = pa * pb + (1 - pa) * (1 - pb)
        return (po - pe) / (1 - pe) if pe < 1 else float("nan")

    k = len(panel)
    M = np.full((k, k), np.nan)
    for i, vi in enumerate(panel):
        for j, vj in enumerate(panel):
            M[i, j] = 1 - approve[vi].mean() if i == j else kappa(vi, vj)

    fig, (ax, axq) = plt.subplots(
        1, 2, figsize=(fs.WIDTH_1COL, 2.2),
        gridspec_kw={"width_ratios": [1.15, 1.0], "wspace": 0.55})
    im = ax.imshow(M, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    short = [v.split("_")[0] for v in panel]
    for i in range(k):
        for j in range(k):
            ax.text(j, i, f"{M[i, j]:.2f}", ha="center", va="center", fontsize=5.4,
                    color="white" if M[i, j] > 0.55 else "black")
    ax.set_xticks(range(k)); ax.set_xticklabels(short, fontsize=6)
    ax.set_yticks(range(k)); ax.set_yticklabels(short, fontsize=6)
    ax.tick_params(length=0)
    ax.grid(False)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("kappa (diag: reject rate)", fontsize=6, loc="right", pad=3)

    # quorum sweep
    app = np.vstack([approve[v] for v in panel]).sum(axis=0)
    qs = np.arange(1, k + 1)
    share = [100 * float((app >= q).mean()) for q in qs]
    axq.plot(qs, share, marker="o", color=tiers.COLOR["panel"], zorder=3)
    deployed = 3
    axq.axvline(deployed, color=fs.EMPHASIS, linestyle="--", linewidth=0.8, zorder=2)
    axq.annotate("deployed", (deployed, max(share)), textcoords="offset points",
                 xytext=(-2, -8), fontsize=6, ha="right")
    axq.set_xticks(qs)
    axq.set_xlabel(f"Quorum (of {k})")
    axq.set_ylabel("Proposals approved (%)")
    axq.set_ylim(0, 105)
    fs.style_axes(axq)
    fs.panel_label(ax, "(a)"); fs.panel_label(axq, "(b)")

    path = fs.save(fig, "validator_behavior", outdir, fs.WIDTH_1COL)
    meta = {
        "name": "validator_behavior", "file": path.name,
        "takeaway": ("The four judges agree only moderately with each other, so how many of "
                     "them must approve changes what gets through by tens of points."),
        "data_sources": (["cache/replay_rep/rounds.jsonl", "cache/validators/*.jsonl"]
                         if (BASE_DIR / "cache" / "replay_rep" / "rounds.jsonl").exists()
                         else [f"logs/*_eval_attacks_{DEV_GROUP}/agenticcyops_*.jsonl"]),
        "n": {"rounds": len(rounds), "rounds_all_voted": len(clean), "panel": list(panel),
              "kappa": {f"{a}|{b}": round(float(M[i, j]), 2) for i, a in enumerate(panel)
                        for j, b in enumerate(panel) if i < j},
              "reject_rate_pct": {v: round(100 * (1 - approve[v].mean()), 1) for v in panel},
              "approved_pct_by_quorum": {int(q): round(s, 1) for q, s in zip(qs, share)}},
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F12. Channels
# --------------------------------------------------------------------- #
# Takeaway: every channel is exposed and the cascade reduces all five; the largest
# residual is on the handoff channel.
CHANNEL_CODE = {"alert_text": "C1 task input", "tool_response": "C2 tool response",
                "memory": "C3 memory", "handoff": "C4 handoff",
                "proposal_justification": "C5 rationale"}


def fig_channels(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt

    pool = [t for t in trials if t["group"] == BOUNDARY_GROUP and t["ap"] != "benign"
            and not t.get("suffix") and t.get("outcome") in MEASURABLE and t.get("channel")]
    chans = [c for c in CHANNEL_CODE if any(t["channel"] == c for t in pool)]

    fig, ax = plt.subplots(figsize=(fs.WIDTH_1COL, 2.4))
    axr = ax.twinx()
    x = np.arange(len(chans))
    w = 0.36
    out = {}
    for k, (lbl, cfg) in enumerate((("Flat", "flat"), ("DEFER", "agenticcyops"))):
        vals, expo = [], []
        for c in chans:
            ts = [t for t in pool if t["channel"] == c and t["config"] == cfg]
            vals.append(asr_ci(ts))
            known = [t for t in ts if str(t.get("exposed", "")).lower() in ("true", "false")]
            expo.append(sum(1 for t in known if str(t["exposed"]).lower() == "true") / len(known)
                        if known else float("nan"))
        off = (k - 0.5) * w
        pts = [100 * v[0] for v in vals]
        lo = [100 * (v[0] - v[1]) for v in vals]
        hi = [100 * (v[2] - v[0]) for v in vals]
        ax.bar(x + off, pts, width=w * 0.92, color=fs.CONFIG_COLOR[lbl], label=lbl, zorder=2)
        ax.errorbar(x + off, pts, yerr=[lo, hi], fmt="none", zorder=3, **fs.ERRORBAR_KW)
        axr.plot(x + off, [100 * e for e in expo], linestyle="none", marker="o",
                 markerfacecolor="none", markeredgecolor=fs.EMPHASIS, markeredgewidth=0.9,
                 markersize=3.6, zorder=5, clip_on=False)
        out[lbl] = {CHANNEL_CODE[c]: {"asr_pct": round(p, 1),
                                      "exposure_pct": None if math.isnan(e) else round(100 * e, 1)}
                    for c, p, e in zip(chans, pts, expo)}

    # where does the DEFER residual on the tool-response channel come from?
    resid = defaultdict(int)
    for t in pool:
        if t["channel"] == "tool_response" and t["config"] == "agenticcyops" and _EXEC(t):
            resid[f"{t['domain']} {t['ap']}"] += 1
    if resid:
        top = max(resid, key=resid.get)
        j = chans.index("tool_response")
        ax.annotate(f"residual: {top}", (j, ax.get_ylim()[1] * 0.62), fontsize=5.6,
                    ha="center", color=fs.OUTCOME_COLOR["executed"])

    ax.set_xticks(x)
    ax.set_xticklabels([CHANNEL_CODE[c].split(" ", 1)[0] for c in chans])
    ax.set_xlabel("Injection channel")
    ax.set_ylabel("Attack success (%)")
    fs.style_axes(ax)
    axr.set_ylabel("Exposure (%)")
    axr.set_ylim(0, 105)
    axr.grid(False)
    axr.spines["top"].set_visible(False)
    axr.spines["right"].set_visible(True)
    axr.spines["right"].set_linewidth(0.6)
    # below the axes: the exposure markers fill the top of the plot
    from matplotlib.lines import Line2D
    handles, labels = ax.get_legend_handles_labels()
    handles.append(Line2D([], [], linestyle="none", marker="o", markerfacecolor="none",
                          markeredgecolor="black", markersize=4))
    labels.append("exposure")
    ax.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=3,
              handlelength=1.1, borderpad=0.2, frameon=False)

    path = fs.save(fig, "channels", outdir, fs.WIDTH_1COL)
    meta = {
        "name": "channels", "file": path.name,
        "takeaway": ("Where exposure is measured the injected content does reach the model, "
                     "and the cascade reduces all five channels; the largest residual is on "
                     "the handoff channel."),
        "data_sources": ["results/eval_attacks/all_trials.csv"],
        "n": out | {"channels": {CHANNEL_CODE[c]: sum(1 for t in pool if t["channel"] == c)
                                 for c in chans},
                    "defer_tool_response_residual": dict(resid)},
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F13. Third-party benchmarks (ASB, legacy primaries)
# --------------------------------------------------------------------- #
# Takeaway: ACL does nothing against injected actions on tools the agent
# already holds; the cascade blocks most of what the models emit.
ASB_FAMILY = {"DPI": "Direct PI", "IPI": "Indirect PI", "MP": "Memory poisoning",
              "PoT": "PoT backdoor", "POT": "PoT backdoor"}


def fig_asb_families(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import csv
    import matplotlib.pyplot as plt

    rows = []
    for g in ("A", "C", "D", "E"):
        p = BASE_DIR / "results_legacy_v1" / "asb" / f"e2e_validator_group_{g}" / "general" / "results.csv"
        if p.exists():
            rows += list(csv.DictReader(open(p, newline="")))
    fams = [f for f in ("DPI", "IPI", "MP", "PoT") if any(r["attack_type"] == f for r in rows)]

    def share(rs, col):
        return 100 * sum(1 for r in rs if str(r.get(col, "")).lower() == "true") / len(rs) if rs else float("nan")

    fig, ax = plt.subplots(figsize=(fs.WIDTH_1COL, 2.4))
    x = np.arange(len(fams))
    w = 0.26
    out, ns = {}, {}
    for k, (lbl, cfg) in enumerate((("Flat", "flat"), ("ACL", "acl_hardened"),
                                    ("DEFER", "agenticcyops"))):
        vals = []
        for f in fams:
            rs = [r for r in rows if r["attack_type"] == f and r["config"] == cfg]
            vals.append(share(rs, "attack_succeeded_end_to_end"))
            ns[f] = len(rs)
        ax.bar(x + (k - 1) * w, vals, width=w * 0.9, color=fs.CONFIG_COLOR[lbl],
               label=lbl, zorder=2)
        out[lbl] = {ASB_FAMILY[f]: round(v, 1) for f, v in zip(fams, vals)}
    emitted = [share([r for r in rows if r["attack_type"] == f and r["config"] == "agenticcyops"],
                     "attack_succeeded_llm") for f in fams]
    ax.plot(x, emitted, linestyle="none", marker="o", markerfacecolor="none",
            markeredgecolor=fs.EMPHASIS, markeredgewidth=1.0, markersize=4.5, zorder=5,
            label="emitted by primary")
    out["emitted by primary"] = {ASB_FAMILY[f]: round(v, 1) for f, v in zip(fams, emitted)}

    ax.set_xticks(x)
    ax.set_xticklabels([f"{ASB_FAMILY[f]}\n(n={ns[f]:,})" for f in fams], fontsize=6)
    ax.set_ylabel("Attack success (%)")
    fs.style_axes(ax)
    ax.legend(loc="upper right", handlelength=1.1, borderpad=0.2, fontsize=6)

    blocked = {f: (100 * (1 - out["DEFER"][ASB_FAMILY[f]] / e) if e else float("nan"))
               for f, e in zip(fams, emitted)}
    # pooled over families: of everything the primary emitted, how much never executed
    acy = [r for r in rows if r["config"] == "agenticcyops"]
    n_emit = sum(1 for r in acy if str(r.get("attack_succeeded_llm", "")).lower() == "true")
    n_e2e = sum(1 for r in acy if str(r.get("attack_succeeded_end_to_end", "")).lower() == "true")
    pooled = 100 * (1 - n_e2e / n_emit) if n_emit else float("nan")

    path = fs.save(fig, "asb_families", outdir, fs.WIDTH_1COL)
    meta = {
        "name": "asb_families", "file": path.name,
        "takeaway": (f"On a third-party benchmark, connectivity limits do almost nothing "
                     f"against actions injected on tools the agent already holds, while the "
                     f"cascade stops {pooled:.0f}% of what the models actually emit."),
        "data_sources": ["results_legacy_v1/asb/e2e_validator_group_{A,C,D,E}/general/results.csv"],
        "n": out | {"trials_per_family_per_config": ns,
                    "blocked_share_of_emitted_pct": {ASB_FAMILY[f]: None if math.isnan(v) else round(v, 1)
                                                     for f, v in blocked.items()},
                    "blocked_share_pooled_pct": round(pooled, 1),
                    "emitted_n": n_emit},
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F11. Transfer across domains and primaries
# --------------------------------------------------------------------- #
# Takeaway: security transfers across domains and primaries; cost does not.
def fig_transfer(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt
    from analysis.generate_tables import TAGGED

    def clean(g):
        return not any(t in g for t in TAGGED)

    rows = [(BOUNDARY_GROUP, d) for d in ("cyberops", "finance", "healthcare", "legal")]
    # primaries: the v3.1 runs where they exist, the earlier runs otherwise
    have = {t["group"] for t in trials}
    prim = ["scout_div4", "mistral_div3p"]
    prim += list(_PRIM.values()) if _PRIM["Llama-3.1-8B"] in have else ["llama8b_div4"]
    rows += [(g, "cyberops") for g in prim if g in have]
    rows = [(g, d) for g, d in rows if clean(g)]
    name = {BOUNDARY_GROUP: "Qwen3-235B", "q235_div4": "Qwen3-235B", "scout_div4": "Llama-4-Scout",
            "mistral_div3p": "Mistral-Small", "llama8b_div4": "Llama-3.1-8B",
            **{g: m for m, g in _PRIM.items()}}

    fig, (ax, axb) = plt.subplots(
        1, 2, figsize=(fs.WIDTH_2COL, 3.15), sharey=True,
        gridspec_kw={"width_ratios": [2.1, 1.0], "wspace": 0.08})
    y = np.arange(len(rows))[::-1]
    out = {}
    for yi, (g, d) in zip(y, rows):
        for lbl, cfg in (("Flat", "flat"), ("ACL", "acl_hardened"), ("DEFER", "agenticcyops")):
            ts = [t for t in trials if t["group"] == g and t["domain"] == d
                  and t["ap"] != "benign" and not t.get("suffix")
                  and t.get("outcome") in MEASURABLE and t["config"] == cfg]
            if not ts:
                continue
            p, lo, hi = asr_ci(ts)
            ax.plot(100 * p, yi, marker="o", markersize=4.2, color=fs.CONFIG_COLOR[lbl],
                    zorder=3, label=lbl if yi == y[0] else None)
            if lbl == "DEFER":
                ax.errorbar([100 * p], [yi], xerr=[[100 * (p - lo)], [100 * (hi - p)]],
                            fmt="none", zorder=2, **fs.ERRORBAR_KW)
            out.setdefault(f"{name[g]} / {d}", {})[lbl] = round(100 * p, 1)
        bt = [t for t in trials if t["group"] == g and t["domain"] == d
              and t["ap"] == "benign" and t["outcome"] == "benign"
              and not t.get("suffix") and t["config"] == "agenticcyops"]
        if bt:
            q, qlo, qhi = rate_ci(bt, lambda t: float(t.get("collateral_denials") or 0) > 0)
            axb.plot(100 * q, yi, marker="s", markersize=4.2, color=fs.BENIGN_COLOR, zorder=3)
            axb.errorbar([100 * q], [yi], xerr=[[100 * (q - qlo)], [100 * (qhi - q)]],
                         fmt="none", zorder=2, **fs.ERRORBAR_KW)
            out.setdefault(f"{name[g]} / {d}", {})["benign any-denial"] = round(100 * q, 1)

    ax.set_yticks(y)
    ax.set_yticklabels([f"{name[g]} / {d}" for g, d in rows], fontsize=7)
    ax.set_xlabel("Attack success (%)")
    axb.set_xlabel("Benign any-denial (%), DEFER")
    ax.set_ylim(-0.6, len(rows) - 0.4)
    for a in (ax, axb):
        fs.style_axes(a, ygrid=False, xgrid=True)
    n_dom = sum(1 for g, _d in rows if g == BOUNDARY_GROUP)
    ax.axhline(len(rows) - n_dom - 0.5, color="#cccccc", linewidth=0.6)
    ax.legend(loc="lower right", handlelength=0.8, borderpad=0.2, fontsize=6)

    path = fs.save(fig, "transfer", outdir, fs.WIDTH_2COL)
    meta = {
        "name": "transfer", "file": path.name,
        "takeaway": ("The cascade holds its attack-success reduction across four domains and "
                     "five primary models; what it costs on benign work does not transfer "
                     "and varies widely by domain."),
        "data_sources": ["results/eval_attacks/all_trials.csv"],
        "n": out,
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F10. State carry-over
# --------------------------------------------------------------------- #
# Takeaway: the first benign incident after the attacks is at the isolated
# level; from the second on, benign incidents deny each other through state
# that never expires.
def fig_state_carryover(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt

    # the v3.1 persistent runs when present, the earlier ones otherwise
    v31p = any(t["group"] == _PERSIST[0] for t in trials)
    pers_group = _PERSIST[0] if v31p else f"{DEV_GROUP}_persistent"
    # the isolated reference is the same code and panel as the persistent run:
    # v3.1, as run with the two live judges (the persistent run has no replay)
    iso_group = _PREVIOUS if v31p else DEV_GROUP
    # first timestamp per benign trial, from the persistent logs
    order: dict[tuple[str, str], str] = {}
    for d in ("cyberops", "finance", "healthcare", "legal"):
        for f in map(str, run_logs(pers_group, d)):
            for ln in open(f, errors="ignore"):
                if '"benign"' not in ln:
                    continue
                try:
                    e = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                tid = e.get("trial_id")
                if e.get("ap") == "benign" and tid:
                    ts = e.get("timestamp", "")
                    if tid not in order or ts < order[tid]:
                        order[tid] = ts

    ben = [t for t in trials if t["group"] == pers_group and t["ap"] == "benign"
           and t["outcome"] == "benign" and t["config"] == "agenticcyops"]
    by_dom: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for t in ben:
        by_dom[t["domain"]].append((order.get(trial_id(t), ""), float(t.get("collateral_denials") or 0)))

    # as run, like the persistent sequence (the Local4 table re-counts the
    # isolated runs' benign denials under another panel; 2026-10-02 audit)
    as_run = load_trials(BASE_DIR / "results" / "eval_attacks" / "all_trials.csv")
    iso = [t for t in as_run if t["group"] == iso_group and t["domain"] == DEV_DOMAIN
           and t["ap"] == "benign" and t["outcome"] == "benign"
           and not t.get("suffix") and t["config"] == "agenticcyops"]
    iso_mean = float(np.mean([float(t.get("collateral_denials") or 0) for t in iso])) if iso else float("nan")

    fig, ax = plt.subplots(figsize=(fs.WIDTH_1COL, 2.4))
    series = {}
    for d, vals in by_dom.items():
        seq = [v for _ts, v in sorted(vals, key=lambda kv: kv[0])]
        series[d] = seq
        main = d == DEV_DOMAIN
        ax.plot(range(1, len(seq) + 1), seq, marker="o" if main else None,
                markersize=3, linewidth=1.0 if main else 0.7,
                color=fs.CONFIG_COLOR["DEFER"] if main else "#bbbbbb",
                label=d if main else None, zorder=3 if main else 2)
    top = max((max(s) for s in series.values() if s), default=1)
    ax.axhline(iso_mean, color=fs.EMPHASIS, linestyle="--", linewidth=0.8, zorder=4)
    ax.axhspan(iso_mean, top * 1.12, color=fs.OUTCOME_COLOR["executed"], alpha=0.07, lw=0, zorder=0)
    ax.annotate(f"isolated-state mean ({iso_mean:.1f})", (len(series.get(DEV_DOMAIN, [1])), iso_mean),
                textcoords="offset points", xytext=(-2, 4), ha="right", fontsize=6)
    ax.set_xlabel("Benign incident position in persistent sequence")
    from matplotlib.ticker import MaxNLocator
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_ylabel("Denials per incident")
    ax.set_ylim(0, top * 1.12)
    fs.style_axes(ax)
    ax.legend(loc="upper right", handlelength=1.0, borderpad=0.2, fontsize=6)

    path = fs.save(fig, "state_carryover", outdir, fs.WIDTH_1COL)
    meta = {
        "name": "state_carryover", "file": path.name,
        "takeaway": ("With state carried across incidents the first benign incident after the "
                     "attacks is at the isolated level; from the second on, legitimate incidents "
                     "deny each other through replay and ledger state that never expires."),
        "data_sources": [f"logs/*_eval_attacks_{pers_group}/*.jsonl",
                         "results/eval_attacks/all_trials.csv"],
        "n": {"isolated_mean_denials": round(iso_mean, 2),
              "sequence_len": {d: len(s) for d, s in series.items()},
              "persistent_mean_denials": {d: round(float(np.mean(s)), 2)
                                          for d, s in series.items() if s}},
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F9. Where the cost goes
# --------------------------------------------------------------------- #
# Takeaway: the judges are most of the added time; the denials that cost
# benign work are spread over the deterministic checks and P4.
DOMAIN_SHORT = {"cyberops": "CyberOps", "finance": "Finance",
                "healthcare": "Health", "legal": "Legal"}

DENY_BUCKET = [("P2", "P2 parameter/scope", tiers.COLOR["content_independent"]),
               ("P3_llm", "P3 LLM panel", tiers.COLOR["panel"]),
               ("P3_det", "P3 deterministic", "#5a9bd4"),
               ("P4", "P4 memory", tiers.COLOR["similarity"]),
               ("P5", "P5 store policy", "#7fd4bd")]


def _deny_bucket(mech: str) -> str | None:
    m = str(mech or "")
    if m == "P3_llm_consensus_reject":
        return "P3_llm"
    for p in ("P2", "P4", "P5"):
        if m.startswith(p):
            return p
    if m.startswith("P3"):
        return "P3_det"
    if m.startswith("P1"):
        return "P2"                      # registry checks sit with the structural ones
    return None


def benign_cost_from_logs(group: str, domains, configs) -> dict:
    """Per (domain, config): denial buckets, redactions, and a latency split.

    A denial is counted once, at the point that enforces it. ``consensus_vote``
    events are individual validator opinions, not denials; a ``tool_call`` denied
    with ``P3_verified_execution`` is the gate surfacing a panel rejection that
    ``consensus_result`` already reported, so it is not counted twice.
    """
    out: dict = defaultdict(lambda: {"deny": defaultdict(int), "redact": 0, "proposed": 0,
                                     "lat": defaultdict(list)})
    for d in domains:
        for cfg in configs:
            newest: dict[str, str] = {}
            per_tf: dict[tuple[str, str], dict] = defaultdict(
                lambda: {"deny": defaultdict(int), "redact": 0, "prop": set(),
                         "lat": defaultdict(float)})
            for f in map(str, run_logs(group, d, cfg)):
                for ln in open(f, errors="ignore"):
                    if not ln.strip():
                        continue
                    try:
                        e = json.loads(ln)
                    except json.JSONDecodeError:
                        continue
                    if e.get("ap") != "benign":
                        continue
                    tid = e.get("trial_id")
                    if not tid:
                        continue
                    newest[tid] = f
                    act, mech = e.get("action"), e.get("mechanism")
                    dec = str(e.get("auth_decision") or "").lower()
                    rec = per_tf[(tid, f)]
                    if str(act).endswith("_proposed") and e.get("call_id"):
                        rec["prop"].add(e["call_id"])     # tool call, memory write or read
                    if dec == "redact":
                        rec["redact"] += 1
                    elif (dec == "deny" or (dec == "escalate" and act == "tool_call")) \
                            and act != "consensus_vote":
                        if not (act == "tool_call" and mech == "P3_verified_execution"):
                            b = _deny_bucket(mech)
                            if b:
                                rec["deny"][b] += 1
                    lat = e.get("latency_ms")
                    if lat:
                        if act == "llm_call":
                            rec["lat"]["primary"] += float(lat)
                        elif act == "consensus_result":
                            rec["lat"]["panel"] += float(lat)
                        elif act != "consensus_vote":
                            rec["lat"]["deterministic"] += float(lat)
            agg = out[(d, cfg)]
            for (tid, f), rec in per_tf.items():
                if newest.get(tid) != f:
                    continue
                for b, v in rec["deny"].items():
                    agg["deny"][b] += v
                agg["redact"] += rec["redact"]
                agg["proposed"] += len(rec["prop"])
                for k, v in rec["lat"].items():
                    agg["lat"][k].append(v / 1000.0)
    return out


def fig_cost(trials: list[dict], outdir: Path) -> tuple[Path, dict]:
    import matplotlib.pyplot as plt

    domains = ("cyberops", "finance", "healthcare", "legal")
    cost = benign_cost_from_logs(BOUNDARY_GROUP, domains, ("agenticcyops",))
    if LOCAL4:
        # the panel bucket on the panel the paper reports: the replay changes
        # only panel decisions, so Local4's benign tool denials minus the live
        # ones is the change in panel denials (2026-10-02 audit; before, the
        # bucket counted the live two-judge panel)
        for d in domains:
            delta = _local4_panel_delta(BOUNDARY_GROUP, d)
            if delta is not None:
                bucket = cost[(d, "agenticcyops")]["deny"]
                bucket["P3_llm"] = max(0, bucket["P3_llm"] + delta)
    lat_cfgs = [("Flat", "flat"), ("NoJudge", "symbolic_only"),
                ("DEFER", "agenticcyops"), ("JudgeOnly", "llm_judge")]
    latc = benign_cost_from_logs(BOUNDARY_GROUP, (DEV_DOMAIN,), [c for _l, c in lat_cfgs])
    scan = scan_proposals(BOUNDARY_GROUP, DEV_DOMAIN, [c for _l, c in lat_cfgs], benign=True)

    fig, axes = plt.subplots(1, 3, figsize=(fs.WIDTH_2COL, 3.15),
                             gridspec_kw={"wspace": 0.42})
    axa, axb, axc = axes

    # (a) denials per domain, stacked by the principle that denied them. The
    # buckets hold tool-call and memory-operation denials, so the denominator
    # is every proposed action (tool calls, memory writes, memory reads).
    x = np.arange(len(domains))
    bottom = np.zeros(len(domains))
    props = {d: cost[(d, "agenticcyops")]["proposed"] or 1 for d in domains}
    a_out = {}
    for key, lbl, col in DENY_BUCKET:
        vals = np.array([100 * cost[(d, "agenticcyops")]["deny"].get(key, 0) / props[d]
                         for d in domains])
        if vals.sum() == 0:
            continue
        axa.bar(x, vals, bottom=bottom, width=0.62, color=col, label=lbl, zorder=2)
        bottom += vals
        a_out[lbl] = {d: round(v, 2) for d, v in zip(domains, vals)}
    red = np.array([100 * cost[(d, "agenticcyops")]["redact"] / props[d] for d in domains])
    axa.bar(x, red, bottom=bottom, width=0.62, facecolor="none", edgecolor=fs.BENIGN_COLOR,
            hatch="///", linewidth=0.6, label="redactions", zorder=2)
    a_out["redactions"] = {d: round(v, 2) for d, v in zip(domains, red)}
    axa.set_xticks(x)
    axa.set_xticklabels([DOMAIN_SHORT.get(d, d) for d in domains], fontsize=6.5)
    axa.set_ylabel("Benign actions denied (%)")
    fs.style_axes(axa)
    axa.legend(loc="lower left", bbox_to_anchor=(-0.02, 1.0), ncol=2, fontsize=5.0,
               handlelength=0.9, borderpad=0.2, labelspacing=0.22, columnspacing=0.7)

    # (b) latency split
    xb = np.arange(len(lat_cfgs))
    bottom = np.zeros(len(lat_cfgs))
    b_out = {}
    for key, lbl, col in (("primary", "primary model", "#999999"),
                          ("deterministic", "deterministic checks", tiers.COLOR["content_independent"]),
                          ("panel", "LLM panel", tiers.COLOR["panel"])):
        vals = np.array([float(np.median(latc[(DEV_DOMAIN, c)]["lat"].get(key) or [0]))
                         for _l, c in lat_cfgs])
        axb.bar(xb, vals, bottom=bottom, width=0.62, color=col, label=lbl, zorder=2)
        bottom += vals
        b_out[lbl] = {l: round(v, 2) for (l, _c), v in zip(lat_cfgs, vals)}
    p95 = []
    for _l, c in lat_cfgs:
        tot = np.array(latc[(DEV_DOMAIN, c)]["lat"].get("primary") or [0]) * 0
        for k in ("primary", "deterministic", "panel"):
            arr = np.array(latc[(DEV_DOMAIN, c)]["lat"].get(k) or [0.0])
            if arr.size == tot.size:
                tot = tot + arr
        p95.append(float(np.percentile(tot, 95)) if tot.size else 0.0)
    axb.errorbar(xb, bottom, yerr=[np.zeros(len(xb)), np.maximum(np.array(p95) - bottom, 0)],
                 fmt="none", zorder=3, **fs.ERRORBAR_KW)
    axb.set_xticks(xb)
    axb.set_xticklabels([l for l, _c in lat_cfgs], fontsize=6, rotation=20, ha="right")
    axb.set_ylabel("Median incident latency (s)")
    fs.style_axes(axb)
    axb.legend(loc="lower left", bbox_to_anchor=(-0.02, 1.0), ncol=1, fontsize=5.0,
               handlelength=0.9, borderpad=0.2, labelspacing=0.22)

    # (c) tokens per incident
    c_out = {}
    bottom = np.zeros(len(lat_cfgs))
    for key, lbl, col in (("primary_tokens", "primary", "#999999"),
                          ("validator_tokens", "validator", tiers.COLOR["panel"])):
        vals = []
        for _l, cfg in lat_cfgs:
            bt = [t for t in benign_trials(trials) if t["config"] == cfg]
            vals.append(float(np.mean([float(t.get(key) or 0) for t in bt])) if bt else 0.0)
        vals = np.array(vals)
        axc.bar(xb, vals, bottom=bottom, width=0.62, color=col, label=lbl, zorder=2)
        bottom += vals
        c_out[lbl] = {l: round(v) for (l, _c), v in zip(lat_cfgs, vals)}
    axc.set_xticks(xb)
    axc.set_xticklabels([l for l, _c in lat_cfgs], fontsize=6, rotation=20, ha="right")
    axc.set_ylabel("Tokens per incident")
    fs.style_axes(axc)
    axc.legend(loc="lower left", bbox_to_anchor=(-0.02, 1.0), ncol=2, fontsize=5.0,
               handlelength=0.9, borderpad=0.2, columnspacing=0.7)

    for a, t in zip(axes, ("(a)", "(b)", "(c)")):
        fs.panel_label(a, t)

    path = fs.save(fig, "cost", outdir, fs.WIDTH_2COL)
    meta = {
        "name": "cost", "file": path.name,
        "takeaway": ("The judges account for most of the time the cascade adds, while the "
                     "benign work it blocks is spread across the deterministic checks and "
                     "the memory checks, and is much heavier outside the development domain."),
        "data_sources": [f"logs/*_eval_attacks_{BOUNDARY_GROUP}/*.jsonl",
                         "results/eval_attacks/all_trials.csv"],
        "n": {"denied_pct_of_proposals": a_out, "median_latency_s": b_out,
              "tokens_per_incident": c_out, "benign_proposals": props},
    }
    return path, meta


# --------------------------------------------------------------------- #
#  F15. Adaptive attacker (pending data)
# --------------------------------------------------------------------- #
# Takeaway: (pending) how quickly a budgeted attacker finds a variant that gets
# through when it may retry.
def fig_adaptive(trials: list[dict], outdir: Path) -> tuple[Path, dict] | None:
    import csv
    import matplotlib.pyplot as plt

    files = sorted(glob.glob(str(BASE_DIR / "results" / "adaptive" / "*.csv")))
    if not files:
        return None                                   # data not collected yet
    rows = []
    for f in files:
        rows += list(csv.DictReader(open(f, newline="")))
    if not rows:
        return None

    fig, ax = plt.subplots(figsize=(fs.WIDTH_1COL, 2.3))
    out = {}
    styles = {"black-box": "-", "white-box": "--"}
    colors = {}
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        groups[(r["mode"], r["target_set"])].append(r)
    for (mode, target), grp in sorted(groups.items()):
        pts = sorted((int(r["iteration"]), float(r["asr"])) for r in grp)
        ks = [k for k, _ in pts]
        vs = [100 * v for _, v in pts]
        colors.setdefault(target, fs.CONFIG_COLOR["DEFER"] if len(colors) == 0
                          else fs.OUTCOME_COLOR["executed"])
        ax.plot(ks, vs, linestyle=styles.get(mode, "-"), marker="o", markersize=3,
                color=colors[target], label=f"{mode}, {target}")
        out[f"{mode}/{target}"] = {int(k): round(v, 1) for k, v in zip(ks, vs)}
    ax.set_xlabel("Attempts k")
    ax.set_ylabel("ASR@k (%)")
    fs.style_axes(ax)
    ax.legend(loc="upper left", fontsize=6, handlelength=1.2, borderpad=0.2)

    path = fs.save(fig, "adaptive", outdir, fs.WIDTH_1COL)
    return path, {"name": "adaptive", "file": path.name,
                  "takeaway": ("A budgeted attacker that may retry finds a way through only "
                               "slowly, and the white-box attacker is not much faster."),
                  "data_sources": ["results/adaptive/*.csv"], "n": out}


# --------------------------------------------------------------------- #
#  F14. Cascade pipeline numbers for the TikZ design figure
# --------------------------------------------------------------------- #
def write_cascade_defs(trials: list[dict], outdir: Path) -> dict:
    """Regenerate the ``\\def`` block the TikZ pipeline figure reads.

    The design figure itself is hand-drawn TikZ; only its two annotations are
    data, so they are written here and ``\\input`` by the .tex file.
    """
    cfgs = [CFG_BY_LABEL[c] for c in fs.CONFIG_ORDER]
    judged = judged_fraction(REPORTED_GROUP, DEV_DOMAIN, cfgs)["agenticcyops"]
    # the v3.1 runs also carry the E2 siblings; count the reported 75 variants only
    keep = {(t["ap"], t["variant"]) for t in dev_attacks(trials, group=DEV_GROUP)
            if t["config"] == "agenticcyops"}
    blocked = [t["blocked_by"] for t in dev_attacks(trials, group=REPORTED_GROUP)
               if t["config"] == "agenticcyops" and t["outcome"] == "blocked"
               and (t["ap"], t["variant"]) in keep]
    shares, n = tier_shares(blocked)
    det = 100 * (1 - shares.get("panel", 0))         # every tier but the panel
    defs = (
        "% regenerated by `make figures` -- do not edit by hand\n"
        f"\\def\\judgedpct{{{100 * judged:.0f}}}\n"
        f"\\def\\deterministicpct{{{det:.0f}}}\n"
        f"\\def\\interceptionsn{{{n}}}\n")
    (outdir / "cascade_pipeline_defs.tex").write_text(defs)
    return {"judged_pct": round(100 * judged, 1), "deterministic_pct": round(det, 1),
            "interceptions_n": n}


# --------------------------------------------------------------------- #
FIGURES = {
    "judgment_boundary": fig_judgment_boundary,
    "interception_tiers": fig_interception_tiers,
    "ap_heatmap": fig_ap_heatmap,
    "paired_variants": fig_paired_variants,
    "ablation": fig_ablation,
    "p5_reads": fig_p5_reads,
    "panel_composition": fig_panel_composition,
    "validator_behavior": fig_validator_behavior,
    "cost": fig_cost,
    "state_carryover": fig_state_carryover,
    "transfer": fig_transfer,
    "channels": fig_channels,
    "asb_families": fig_asb_families,
    "adaptive": fig_adaptive,
}


def build_contact_sheet(outdir: Path, names: list[str], ncol: int = 3) -> Path | None:
    """Tile every PNG preview into one sheet for review."""
    import matplotlib.pyplot as plt

    preview = Path(outdir) / "preview"
    imgs = [(n, preview / f"{n}.png") for n in names if (preview / f"{n}.png").exists()]
    if not imgs:
        return None
    nrow = math.ceil(len(imgs) / ncol)
    fig, axes = plt.subplots(nrow, ncol, figsize=(4.2 * ncol, 2.9 * nrow))
    for ax in np.atleast_1d(axes).ravel():
        ax.axis("off")
    for ax, (name, p) in zip(np.atleast_1d(axes).ravel(), imgs):
        ax.imshow(plt.imread(p))
        ax.set_title(name, fontsize=9, fontweight="bold")
    out = preview / "contact_sheet.png"
    fig.savefig(out, dpi=110, bbox_inches="tight", pad_inches=0.06)
    plt.close(fig)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="paper/figs", help="output directory")
    ap.add_argument("--only", action="append", default=None,
                    help="render only these figures (repeatable)")
    args = ap.parse_args()

    outdir = Path(args.out)
    if not outdir.is_absolute():
        outdir = BASE_DIR / outdir
    fs.apply()
    trials = load_trials(ALL_TRIALS)
    # the reported variants: the v3.1 runs also carry the E2 siblings
    ORIGINAL.update((t["domain"], t["ap"], str(t["variant"])) for t in trials
                    if t["group"] == DEV_GROUP and t["ap"] != "benign" and not t.get("suffix")
                    and t["config"] == "agenticcyops")
    # every v3.1 run (boundary, ablation arms, other primaries) carries them
    trials = [t for t in trials if not carries_siblings(t["group"]) or t["ap"] == "benign"
              or (t["domain"], t["ap"], str(t["variant"])) in ORIGINAL]

    wanted = args.only or list(FIGURES)
    manifest = []
    for name in wanted:
        fn = FIGURES.get(name)
        if fn is None:
            raise SystemExit(f"unknown figure: {name} (have: {', '.join(FIGURES)})")
        result = fn(trials, outdir)
        if result is None:                      # data not collected yet (F15)
            print(f"[skip] {name}: input data not present")
            continue
        path, meta = result
        manifest.append(meta)
        print(f"[ok] {path.relative_to(BASE_DIR)}")

    if not args.only:
        defs = write_cascade_defs(trials, outdir)
        print(f"[ok] {(outdir / 'cascade_pipeline_defs.tex').relative_to(BASE_DIR)} {defs}")
        sheet = build_contact_sheet(outdir, [m["name"] for m in manifest])
        if sheet:
            print(f"[ok] {sheet.relative_to(BASE_DIR)}")

    mpath = outdir / "figures.json"
    existing = {}
    if mpath.exists() and args.only:
        existing = {m["name"]: m for m in json.loads(mpath.read_text())}
    for m in manifest:
        existing[m["name"]] = m
    ordered = [existing[k] for k in FIGURES if k in existing]
    mpath.write_text(json.dumps(ordered, indent=2) + "\n")
    print(f"[ok] {mpath.relative_to(BASE_DIR)}")


if __name__ == "__main__":
    main()
