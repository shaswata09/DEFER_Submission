"""The judgment boundary for the two primaries run live at defense-freeze-v2.9.

Groups ``oss120_local2_v29`` (gpt-oss-120b) and ``llama8b_local2_v29``
(Llama-3.1-8B), CyberOps development split, all five boundary
configurations, local2 panel live. Panel-free configurations (FLAT, ACL,
NOJUDGE) are reported as run; JUDGEONLY and FULL as the direct outcome under
Local4 (a model never judges its own proposals, so gpt-oss-120b's panel is
the other three, two of three), with the live local2 value alongside. The
payload files also carry the E2 siblings; only the original 75 variants
count.

    python -m analysis.primaries_tables     # -> results/primaries_v29.json, .md
    python -m analysis.primaries_tables --v31   # the same at v3.1 -> results/primaries_v31.*, primaries_boundary_v31.png
    python -m analysis.primaries_tables --v32   # the reported runs (v3.2) -> results/primaries_v32.*, primaries_boundary_v32.png
"""
from __future__ import annotations

import json
from collections import Counter

from analysis.p3_eligibility import JUDGED_PATHS, _payload, call_path, trials
from analysis.replay_panels import asr, load_all_votes, load_rounds, outcomes
from attacks.effects import build_calls, evaluate_effects
from pathlib import Path

from config import BASE_DIR

DOM = "cyberops"
PRIMARIES = {"gpt-oss-120b": ("oss120_local2_v29", "oss120"), "Llama-3.1-8B": ("llama8b_local2_v29", "llama8b")}
# the same primaries at defense-freeze-v3.1 (``--v31``): rounds in cache/replay_v31
PRIMARIES_V31 = {"gpt-oss-120b": ("oss120_local2_v31", "v31_oss120"),
                 "Llama-3.1-8B": ("llama8b_local2_v31", "v31_llama8b")}
# the reported runs (``--v32``, defense-freeze-v3.2): rounds in cache/replay_rep
PRIMARIES_V32 = {"gpt-oss-120b": ("oss120_local2_v32", "rep_oss120"),
                 "Llama-3.1-8B": ("llama8b_local2_v32", "rep_llama8b")}
_MODES = {"v29": (PRIMARIES, None, "v2.9"), "v31": (PRIMARIES_V31, "replay_v31", "v3.1"),
          "v32": (PRIMARIES_V32, "replay_rep", "v3.2")}
PANEL_FREE = {"FLAT": "flat", "ACL": "acl_hardened", "NOJUDGE": "symbolic_only"}
JUDGED = {"JUDGEONLY": ("llm_judge", "judgeonly"), "FULL": ("agenticcyops", "full")}


def _pct(x: float) -> str:
    return f"{100 * x:.1f}"


def _ci(ts: list[dict]) -> str:
    p, lo, hi, n = asr(ts)
    return f"{_pct(p)} [{_pct(lo)}, {_pct(hi)}]" if n else "n/a"


def original_variants() -> set[tuple[str, str]]:
    return {tuple(t.split("_")[1:3]) for t in trials("q235_div4", DOM, "agenticcyops") if "_benign_" not in t}


def as_run(group: str, cfg: str, keep) -> tuple[list[dict], Counter, Counter]:
    attack, benign, paths = [], Counter(), Counter()
    for tid, ev in trials(group, DOM, cfg).items():
        calls = [c for c in build_calls(ev) if c.kind == "tool"]
        if "_benign_" in tid:
            benign["proposed"] += len(calls)
            benign["denied"] += sum(c.denied for c in calls)
            benign["incidents"] += 1
            benign["any"] += any(c.denied for c in calls)
            continue
        ap, var = tid.split("_")[1:3]
        if (ap, var) not in keep:
            continue
        for c in calls:
            paths[call_path(c, ev)] += 1
        p = _payload(DOM, tid)
        v = evaluate_effects(p[1], ev, config=cfg)
        if v.outcome in ("executed", "blocked", "not_attempted"):
            attack.append({"domain": DOM, "ap": ap, "variant": var, "outcome": v.outcome})
    return attack, benign, paths


def summarize(attack, benign, paths=None) -> dict:
    att = [t for t in attack if t["outcome"] != "not_attempted"]
    out = {"asr": _ci(attack), "n": len(attack),
           "attempt": _pct(len(att) / len(attack)) if attack else "n/a",
           "block_given_attempt": _pct(sum(t["outcome"] == "blocked" for t in att) / len(att)) if att else "n/a"}
    if benign.get("proposed"):
        out["benign_denied"] = _pct(benign["denied"] / benign["proposed"])
    if paths:
        tot = sum(paths.values())
        out["judged"] = _pct(sum(paths[p] for p in JUDGED_PATHS) / tot) if tot else "n/a"
    return out


def build(mode: str = "v29") -> dict:
    prim, replay_set, _label = _MODES[mode]
    V, R = load_all_votes(), load_rounds()
    if replay_set:
        R = {}
        for ln in open(BASE_DIR / "cache" / replay_set / "rounds.jsonl"):
            r = json.loads(ln)
            R.setdefault(r["arm"], []).append(r)
    keep = original_variants()
    res: dict = {}
    for name, (group, arm) in prim.items():
        row: dict = {}
        for label, cfg in PANEL_FREE.items():
            a, b, _p = as_run(group, cfg, keep)
            row[label] = summarize(a, b)
        for label, (cfg, suffix) in JUDGED.items():
            a_live, b_live, paths = as_run(group, cfg, keep)
            key = f"{arm}_{suffix}"
            r4 = outcomes(key, group, cfg, (DOM,), "", "Local4", V, R.get(key, []))
            a4 = [t for t in r4["domains"][DOM]["attack"] if (t["ap"], t["variant"]) in keep]
            row[label] = {**summarize(a4, Counter(r4["domains"][DOM]["benign"]), paths),
                          "missing_votes": r4["missing_votes"],
                          "live_local2": summarize(a_live, b_live)}
        res[name] = row
    return res


def _parse(ci: str) -> tuple[float, float, float]:
    import re
    v = [float(x) for x in re.findall(r"[0-9.]+", ci)]
    return (v[0], v[1], v[2]) if len(v) == 3 else (float("nan"),) * 3


def figure(out: dict, v31="v29") -> Path:
    """Grouped bars: attack success per boundary configuration, one bar per
    primary (Qwen3-235B from results/replay_tables.json), 95% intervals."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from analysis import figstyle as fs
    fs.apply()
    if v31 == "v32":
        q = json.loads((BASE_DIR / "results" / "reported_boundary.json").read_text())["domains"]["cyberops"]
        qwen = {k: {"asr": q[k]["asr"]} for k in ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL")}
    elif v31 in ("v31", True):
        q = json.loads((BASE_DIR / "results" / "replay_v31.json").read_text())["cyberops"]
        qwen = {k: {"asr": q[k]["asr"]} for k in ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL")}
    else:
        qwen = json.loads((BASE_DIR / "results" / "replay_tables.json").read_text())["development"]
    rows = {"Qwen3-235B": {k: qwen[k]["asr"] for k in ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL")},
            **{n: {k: r[k]["asr"] for k in ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL")} for n, r in out.items()}}
    cfgs = ["FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL"]
    labels = {"FLAT": "Flat", "ACL": "ACL", "JUDGEONLY": "JudgeOnly", "NOJUDGE": "NoJudge", "FULL": "DEFER"}
    colors = ["#555555", "#56B4E9", "#CC79A7"]
    fig, ax = plt.subplots(figsize=(fs.WIDTH_2COL * 0.8, 2.6))
    w = 0.26
    for k, (name, r) in enumerate(rows.items()):
        vals = [_parse(r[c]) for c in cfgs]
        xs = [i + (k - 1) * w for i in range(len(cfgs))]
        ax.bar(xs, [v[0] for v in vals], width=w, color=colors[k], label=name, zorder=2)
        ax.errorbar(xs, [v[0] for v in vals], yerr=[[v[0] - v[1] for v in vals], [v[2] - v[0] for v in vals]],
                    fmt="none", zorder=3, **fs.ERRORBAR_KW)
    ax.set_xticks(range(len(cfgs)))
    ax.set_xticklabels([labels[c] for c in cfgs])
    ax.set_ylabel("Attack success (%)")
    ax.legend(frameon=False, fontsize=7, ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.12))
    fs.style_axes(ax)
    name = {"v29": "primaries_boundary", "v31": "primaries_boundary_v31",
            "v32": "primaries_boundary_v32"}[v31]
    path = BASE_DIR / "docs" / "figures" / f"{name}.png"
    fig.savefig(path, dpi=200, bbox_inches="tight")
    fig.savefig(BASE_DIR / "paper" / "figs" / f"{name}.pdf", bbox_inches="tight")  # for the paper
    plt.close(fig)
    return path


def main() -> None:
    import sys
    tag = "v32" if "--v32" in sys.argv[1:] else "v31" if "--v31" in sys.argv[1:] else "v29"
    out = build(tag)
    (BASE_DIR / "results" / f"primaries_{tag}.json").write_text(json.dumps(out, indent=1))
    lines = [f"# Judgment boundary for gpt-oss-120b and Llama-3.1-8B (live at {_MODES[tag][2]}, CyberOps)", "",
             "JUDGEONLY and FULL: direct outcome under Local4 (live local2 value in `live_local2`).", ""]
    for name, row in out.items():
        lines += [f"## {name}", "", "| Config | ASR % [95% CI] | Attempt % | Block|att. % | Judged % | Benign denied % |",
                  "|---|---|---|---|---|---|"]
        for label in ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL"):
            r = row[label]
            lines.append(f"| {label} | {r['asr']} | {r['attempt']} | {r['block_given_attempt']} | "
                         f"{r.get('judged', '0' if label in PANEL_FREE else 'n/a')} | {r.get('benign_denied', 'n/a')} |")
        lines.append("")
    (BASE_DIR / "results" / f"primaries_{tag}.md").write_text("\n".join(lines))
    figure(out, tag)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
