"""The judgment boundary at defense-freeze-v3.1 (the audit fixes), live.

Group ``q235_local2_v31``: Qwen3-235B, all five boundary configurations, four
domains, local2 panel live (Mistral-Small, Gemma-4). Panel-free
configurations (FLAT, ACL, NOJUDGE) are reported as run; JUDGEONLY and FULL as
the direct outcome under Local4, from the logged panel rounds re-judged
offline (votes cached by message hash in ``cache/validators/``), with the live
local2 value alongside. The reported numbers (``results/replay_tables.json``,
v2.2 code, Local4) are shown for comparison. Only the variants of the
reported runs count (the payload files also carry the E2 siblings).

    python -m analysis.replay_v31 build     # -> cache/replay_v31/{rounds,messages}.jsonl
    python -m analysis.replay_run query --replay-dir cache/replay_v31 --validator L1_mistral --url ...
    python -m analysis.replay_v31 tables    # -> results/replay_v31.json, .md, docs/figures/boundary_v31.png
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict

import numpy as np

from analysis.p3_eligibility import _payload, trials
from analysis.replay_panels import asr, load_all_votes, outcomes
from attacks.effects import build_calls, evaluate_effects
from config import BASE_DIR

OUT = BASE_DIR / "cache" / "replay_v31"
GROUP = "q235_local2_v31"
D4 = ("cyberops", "healthcare", "finance", "legal")
PANEL_FREE = {"FLAT": "flat", "ACL": "acl_hardened", "NOJUDGE": "symbolic_only"}
JUDGED = {"JUDGEONLY": ("llm_judge", "v31_judgeonly"), "FULL": ("agenticcyops", "v31_full")}
# (label, group, config, domains, suffix, include_unjudged)
ARMS = [("v31_full", GROUP, "agenticcyops", D4, "", True),
        ("v31_judgeonly", GROUP, "llm_judge", D4, "", False),
        # leave-one-out at v3.1 (CyberOps); -P3 has no panel
        # (the run tag follows the ablation tag, so these parse as their own groups)
        *[(f"v31_full_minus_p{i}", f"q235_local2_disabled_P{i}_v31", "agenticcyops", ("cyberops",), "", False)
          for i in (1, 2, 4, 5)],
        # the other two primaries at v3.1 (CyberOps)
        ("v31_oss120_full", "oss120_local2_v31", "agenticcyops", ("cyberops",), "", True),
        ("v31_oss120_judgeonly", "oss120_local2_v31", "llm_judge", ("cyberops",), "", False),
        ("v31_llama8b_full", "llama8b_local2_v31", "agenticcyops", ("cyberops",), "", True),
        ("v31_llama8b_judgeonly", "llama8b_local2_v31", "llm_judge", ("cyberops",), "", False)]


def build() -> None:
    from analysis.replay import rounds
    OUT.mkdir(parents=True, exist_ok=True)
    messages: dict[str, str] = {}
    with open(OUT / "rounds.jsonl", "w") as fr:
        for label, group, config, domains, suffix, unjudged in ARMS:
            n = 0
            for r in rounds(group, config, domains, suffix, include_unjudged=unjudged):
                messages.setdefault(r.key, r.message)
                row = asdict(r)
                row.pop("message")
                row["arm"] = label
                fr.write(json.dumps(row) + "\n")
                n += 1
            print(f"{label:16s} {n:6d} rounds", flush=True)
    with open(OUT / "messages.jsonl", "w") as fm:
        for k, m in messages.items():
            fm.write(json.dumps({"key": k, "message": m}) + "\n")
    print(f"distinct messages: {len(messages)}")


def _keep(domain: str) -> set[tuple[str, str]]:
    return {tuple(t.split("_")[1:3]) for t in trials("q235_div4", domain, "agenticcyops")
            if "_benign_" not in t}


def _ci(ts: list[dict]) -> str:
    p, lo, hi, n = asr(ts)
    return f"{100 * p:.1f} [{100 * lo:.1f}, {100 * hi:.1f}]" if n else "n/a"


def _as_run(domain: str, config: str, keep) -> tuple[list[dict], Counter]:
    attack, benign = [], Counter()
    for tid, ev in trials(GROUP, domain, config).items():
        calls = [c for c in build_calls(ev) if c.kind == "tool"]
        if "_benign_" in tid:
            benign["proposed"] += len(calls)
            benign["denied"] += sum(c.denied for c in calls)
            continue
        ap, var = tid.split("_")[1:3]
        p = _payload(domain, tid)
        if (ap, var) not in keep or not p:
            continue
        v = evaluate_effects(p[1], ev, config=config)
        if v.outcome in ("executed", "blocked", "not_attempted"):
            attack.append({"domain": domain, "ap": ap, "variant": var, "outcome": v.outcome})
    return attack, benign


def _row(attack, benign) -> dict:
    pct = lambda a, b: round(100 * a / b, 1) if b else None
    return {"asr": _ci(attack), "n": len(attack),
            "benign_denied": pct(benign.get("denied", 0), benign.get("proposed", 0))}


def tables() -> dict:
    V = load_all_votes()
    R: dict[str, list[dict]] = {}
    for ln in open(OUT / "rounds.jsonl"):
        r = json.loads(ln)
        R.setdefault(r["arm"], []).append(r)
    rt = json.loads((BASE_DIR / "results" / "replay_tables.json").read_text())
    reported = rt["domains"]
    # JUDGEONLY and NOJUDGE were reported for the development domain only
    for label, key in (("JUDGEONLY", "judgeonly"), ("NOJUDGE", "nojudge")):
        reported.setdefault("cyberops", {})[key] = rt["development"][label]["asr"]
    res: dict = {}
    for d in D4:
        keep = _keep(d)
        row: dict = {}
        for label, cfg in PANEL_FREE.items():
            row[label] = _row(*_as_run(d, cfg, keep))
        for label, (cfg, arm) in JUDGED.items():
            live = _row(*_as_run(d, cfg, keep))
            o = outcomes(arm, GROUP, cfg, (d,), "", "Local4", V, R.get(arm, []))
            a4 = [t for t in o["domains"][d]["attack"] if (t["ap"], t["variant"]) in keep]
            row[label] = {**_row(a4, Counter(o["domains"][d]["benign"])),
                          "missing_votes": o["missing_votes"], "live_local2": live}
        row["reported_v22_local4"] = reported.get(d, {})
        res[d] = row
    (BASE_DIR / "results" / "replay_v31.json").write_text(json.dumps(res, indent=1))
    lines = ["# The judgment boundary at defense-freeze-v3.1 (audit fixes), Qwen3-235B", "",
             "Generated by `python -m analysis.replay_v31 tables`. FLAT, ACL and NOJUDGE as run; "
             "JUDGEONLY and FULL as the direct outcome under Local4 (live local2 in parentheses). "
             "Reported = the v2.2 runs under Local4. ASR % [95% CI]; benign = legitimate tool "
             "proposals denied or escalated %.", ""]
    for d, row in res.items():
        rep = row["reported_v22_local4"]
        lines += [f"## {d}", "", "| Config | v3.1 ASR | v3.1 benign denied | reported ASR |",
                  "|---|---|---|---|"]
        for label in ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL"):
            r = row[label]
            live = f" ({r['live_local2']['asr']})" if "live_local2" in r else ""
            rep_v = rep.get({"FLAT": "flat", "ACL": "acl", "FULL": "full", "JUDGEONLY": "judgeonly",
                             "NOJUDGE": "nojudge"}[label], "not run")
            lines.append(f"| {label} | {r['asr']}{live} | {r['benign_denied']} | {rep_v} |")
        lines.append("")
    (BASE_DIR / "results" / "replay_v31.md").write_text("\n".join(lines))
    figure(res)
    return res


def figure(res: dict | None = None):
    """Attack success per configuration and domain: v3.1 (Local4 for the
    panel configurations) beside the reported runs, 95% intervals."""
    import re
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from analysis import figstyle as fs
    fs.apply()
    res = res or json.loads((BASE_DIR / "results" / "replay_v31.json").read_text())
    parse = lambda ci: [float(x) for x in re.findall(r"[0-9.]+", ci or "")][:3]
    cfgs = ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL")
    names = {"FLAT": "Flat", "ACL": "ACL", "JUDGEONLY": "JudgeOnly", "NOJUDGE": "NoJudge", "FULL": "DEFER"}
    key = {"FLAT": "flat", "ACL": "acl", "JUDGEONLY": "judgeonly", "NOJUDGE": "nojudge", "FULL": "full"}
    fig, axes = plt.subplots(1, 4, figsize=(fs.WIDTH_2COL, 2.4), sharey=True)
    w = 0.38
    for ax, d in zip(axes, D4):
        row = res[d]
        for i, c in enumerate(cfgs):
            rep = parse(row["reported_v22_local4"].get(key[c]))
            new = parse(row[c]["asr"])
            if len(rep) == 3:
                ax.bar(i - w / 2, rep[0], width=w, color="white", edgecolor="#666666", hatch="////",
                       linewidth=0.6, zorder=2, label="reported (v2.2)" if i == 0 else None)
                if rep[0] == 0:
                    ax.text(i - w / 2, 0.4, "0", ha="center", fontsize=5.5, color="#555555")
                ax.errorbar(i - w / 2, rep[0], yerr=[[rep[0] - rep[1]], [rep[2] - rep[0]]],
                            fmt="none", zorder=3, **fs.ERRORBAR_KW)
            ax.bar(i + w / 2, new[0], width=w, color=fs.CONFIG_COLOR[names[c]], zorder=2,
                   edgecolor="#555555", linewidth=0.4, label="v3.1 (filled)" if i == 0 else None)
            if new[0] == 0:
                ax.text(i + w / 2, 0.4, "0", ha="center", fontsize=5.5, color="#555555")
            ax.errorbar(i + w / 2, new[0], yerr=[[new[0] - new[1]], [new[2] - new[0]]],
                        fmt="none", zorder=3, **fs.ERRORBAR_KW)
        ax.set_xticks(range(len(cfgs)))
        ax.set_xticklabels([names[c] for c in cfgs], rotation=45, ha="right", fontsize=6.5)
        ax.set_title({"cyberops": "CyberOps"}.get(d, d.capitalize()), fontsize=8)
        fs.style_axes(ax)
    axes[0].set_ylabel("Attack success (%)")
    fig.legend(*axes[0].get_legend_handles_labels(), frameon=False, fontsize=7, ncol=2,
               loc="lower center", bbox_to_anchor=(0.5, -0.08))
    fig.tight_layout(w_pad=0.6)
    path = BASE_DIR / "docs" / "figures" / "boundary_v31.png"
    fig.savefig(path, dpi=200, bbox_inches="tight")
    fig.savefig(BASE_DIR / "paper" / "figs" / "boundary_v31.pdf", bbox_inches="tight")
    plt.close(fig)
    figure_domains(res)
    return path


def figure_domains(res: dict | None = None):
    """The boundary at v3.1 only, in every domain: attack success (top, 95%
    intervals) and legitimate tool proposals denied or escalated (bottom)."""
    import re
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from analysis import figstyle as fs
    fs.apply()
    res = res or json.loads((BASE_DIR / "results" / "replay_v31.json").read_text())
    parse = lambda ci: [float(x) for x in re.findall(r"[0-9.]+", ci or "")][:3]
    cfgs = ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL")
    names = {"FLAT": "Flat", "ACL": "ACL", "JUDGEONLY": "JudgeOnly", "NOJUDGE": "NoJudge", "FULL": "DEFER"}
    fig, axes = plt.subplots(2, 4, figsize=(fs.WIDTH_2COL, 3.4), sharey="row", sharex=True,
                             gridspec_kw={"height_ratios": [1.6, 1.0], "hspace": 0.12})
    x = np.arange(len(cfgs))
    for k, d in enumerate(D4):
        ax, axb = axes[0, k], axes[1, k]
        for i, c in enumerate(cfgs):
            a, lo, hi = parse(res[d][c]["asr"])
            col = fs.CONFIG_COLOR[names[c]]
            ax.bar(i, a, width=0.66, color=col, zorder=2, edgecolor="#555555", linewidth=0.4)
            ax.errorbar(i, a, yerr=[[a - lo], [hi - a]], fmt="none", zorder=3, **fs.ERRORBAR_KW)
            ax.text(i, hi + 1.0, f"{a:.1f}", ha="center", va="bottom", fontsize=5.5)
            b = res[d][c]["benign_denied"]
            axb.bar(i, b, width=0.66, color=col, alpha=0.55, zorder=2, edgecolor="#555555", linewidth=0.4)
            axb.text(i, b + 1.5, f"{b:.0f}", ha="center", va="bottom", fontsize=5.5)
        ax.set_title({"cyberops": "CyberOps"}.get(d, d.capitalize()), fontsize=8)
        axb.set_xticks(x)
        axb.set_xticklabels([names[c] for c in cfgs], rotation=45, ha="right", fontsize=6.5)
        ax.set_ylim(0, 52)
        axb.set_ylim(0, 72)
        fs.style_axes(ax)
        fs.style_axes(axb)
    axes[0, 0].set_ylabel("Attack success (%)")
    axes[1, 0].set_ylabel("Legit. denied (%)")
    path = BASE_DIR / "docs" / "figures" / "boundary_domains.png"
    fig.savefig(path, dpi=200, bbox_inches="tight")
    fig.savefig(BASE_DIR / "paper" / "figs" / "boundary_domains.pdf", bbox_inches="tight")
    plt.close(fig)
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["build", "tables"])
    a = ap.parse_args()
    if a.cmd == "build":
        build()
    else:
        tables()
        print((BASE_DIR / "results" / "replay_v31.md").read_text())
