"""Offline re-adjudication with the v3.0 panel input (consensus/panel_context.py).

Every logged panel round of every judged arm is re-judged with the panel
input of ``defense-freeze-v3.0``: the v2.9 fields plus the incident's
structured evidence, the calling agent's scope, the operating context, and
the incident's earlier consequential decisions. The message is built by the
same function the live pipeline uses (``build_panel_message``).

Two properties of the logs bound what can be added:
* the agent's reasoning was never logged, so the justification stays what the
  host sent (a placeholder, or AP-10's injected rationale); only the live v3.0
  runs carry the model's stated reasoning;
* the incident's earlier decisions are those of the run as logged.

    python -m analysis.replay_v3 build                 # -> cache/replay_v3/{messages,rounds}.jsonl
    python -m analysis.replay_run query --replay-dir cache/replay_v3 --validator L1_mistral --url ...
    python -m analysis.replay_v3 build-live            # panel inputs logged by the live v3.0 runs
    python -m analysis.replay_v3 tables                # -> results/replay_v3.json
    python -m analysis.replay_v3 live-tables           # -> results/replay_v3_live.json
    python -m analysis.replay_v3 report                # -> results/replay_v3.md, docs/figures/panel_context_v3.png
"""
from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from collections import Counter, defaultdict
from pathlib import Path

from analysis.p3_eligibility import JUDGED_PATHS, _payload, call_path, trial_commits, trials
from analysis.replay import _SANITIZER, _full_justification, _proposal, incident_at
from analysis.replay_run import ARMS
from attacks.effects import build_calls, evaluate_effects
from config import BASE_DIR
from consensus.panel_context import build_panel_message, prior_action

OUT = BASE_DIR / "cache" / "replay_v3"
P3_PATHS = JUDGED_PATHS + ("p3_denied_rule",)


def rounds(group: str, config: str, domains, suffix: str = ""):
    host_config = "llm_judge" if config == "llm_judge" else "agenticcyops"
    sanitize = config != "llm_judge"
    for d in domains:
        commits = trial_commits(group, d, config, suffix)
        for tid, events in trials(group, d, config, suffix).items():
            incident = incident_at(d, tid, commits.get(tid, ""))
            iid = incident.get("incident_id") or str(uuid.uuid5(uuid.NAMESPACE_URL, tid))
            benign = "_benign_" in tid
            attack_ids: set[str] = set()
            if not benign:
                p = _payload(d, tid)
                if p:
                    attack_ids = set(evaluate_effects(p[1], events, config=config).attempted_call_ids or [])
            just = {e.get("call_id"): e.get("justification", "") for e in events
                    if e.get("action") == "tool_proposed"}
            prior: list[dict] = []
            for c in build_calls(events):
                path = call_path(c, events)
                if path not in P3_PATHS:
                    continue
                c.justification = _full_justification(just.get(c.call_id, ""), c, d, tid)
                proposal = _proposal(c)
                if path in JUDGED_PATHS:
                    shown = _SANITIZER._sanitize_proposal(proposal) if sanitize else proposal
                    msg = build_panel_message(shown, {
                        "incident": incident, "incident_id": iid, "domain": d, "config": host_config,
                        "current_phase": c.phase, "prior_actions": list(prior)})
                    role = "benign" if benign else ("attack_effect" if c.call_id in attack_ids else "attack_other")
                    yield {"key": hashlib.sha256(msg.encode()).hexdigest(), "message": msg,
                           "group": group + suffix, "domain": d, "config": config, "trial_id": tid,
                           "call_id": c.call_id, "tool": c.target, "role": role, "path": path}
                prior.append(prior_action(proposal, path == "p3_panel_approved"))


def build() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    known: dict[str, str] = {}
    with open(OUT / "rounds.jsonl", "w") as fr:
        for label, group, config, domains, suffix, _unjudged in ARMS:
            n = 0
            for r in rounds(group, config, domains, suffix):
                known.setdefault(r["key"], r.pop("message"))
                r.pop("message", None)
                fr.write(json.dumps({**r, "arm": label}) + "\n")
                n += 1
            print(f"{label:18s} {n:6d} rounds", flush=True)
    with open(OUT / "messages.jsonl", "w") as fm:
        for k, m in known.items():
            fm.write(json.dumps({"key": k, "message": m}) + "\n")
    print(f"distinct messages: {len(known)}")


LIVE = [("v30_full", "q235_local2_v30", "agenticcyops", ("cyberops", "healthcare", "finance", "legal")),
        ("v30_judgeonly", "q235_local2_v30", "llm_judge", ("cyberops",)),
        ("v30_llama8b_full", "llama8b_local2_v30", "agenticcyops", ("cyberops",)),
        ("v30_llama8b_judgeonly", "llama8b_local2_v30", "llm_judge", ("cyberops",)),
        ("v30_oss120_full", "oss120_local2_v30", "agenticcyops", ("cyberops",)),
        ("v30_oss120_judgeonly", "oss120_local2_v30", "llm_judge", ("cyberops",))]


def build_live() -> None:
    """The panel rounds of the live v3.0 runs: each judged call's exact panel
    input is in the log (``panel_input``), between its proposal and decision."""
    known = {json.loads(l)["key"] for l in open(OUT / "messages.jsonl")}
    fm = open(OUT / "messages.jsonl", "a")
    with open(OUT / "live_rounds.jsonl", "w") as fr:
        for label, group, config, domains in LIVE:
            n = 0
            for d in domains:
                for tid, events in trials(group, d, config).items():
                    benign = "_benign_" in tid
                    attack_ids: set[str] = set()
                    if not benign:
                        p = _payload(d, tid)
                        if p:
                            attack_ids = set(evaluate_effects(p[1], events, config=config).attempted_call_ids or [])
                    for c in build_calls(events):
                        path = call_path(c, events)
                        if path not in JUDGED_PATHS:
                            continue
                        end = c.decision_seq if c.decision_seq >= 0 else len(events)
                        msgs = [e["panel_message"] for e in events[c.seq:end + 1] if e.get("action") == "panel_input"]
                        if not msgs:
                            continue
                        msg = msgs[-1]
                        key = hashlib.sha256(msg.encode()).hexdigest()
                        if key not in known:
                            fm.write(json.dumps({"key": key, "message": msg}) + "\n"); known.add(key)
                        role = "benign" if benign else ("attack_effect" if c.call_id in attack_ids else "attack_other")
                        fr.write(json.dumps({"key": key, "arm": label, "group": group, "domain": d, "config": config,
                                             "trial_id": tid, "call_id": c.call_id, "tool": c.target, "role": role,
                                             "path": path}) + "\n")
                        n += 1
            print(f"{label:22s} {n:6d} rounds", flush=True)
    print(f"distinct messages now: {len(known)}")


def live_tables() -> dict:
    """The live v3.0 runs: attack success and benign denials as run (live
    local2 panel) and as the direct outcome under Local4. Only the variants
    of the reported Qwen3-235B runs count (the payload files also carry the
    E2 siblings)."""
    from analysis.replay_panels import asr, load_all_votes, outcomes
    V = load_all_votes()
    R: dict[str, list[dict]] = defaultdict(list)
    for ln in open(OUT / "live_rounds.jsonl"):
        r = json.loads(ln)
        R[r["arm"]].append(r)
    pct = lambda x: round(100 * x, 1)
    ci = lambda a: "{} [{}, {}]".format(*map(pct, asr(a)[:3])) if a else "n/a"
    out: dict = {}
    for label, group, config, domains in LIVE:
        if not R[label]:
            continue
        # a model never judges its own proposals (replay_panels.SELF)
        res = outcomes(label.replace("v30_", ""), group, config, domains, "", "Local4", V, R[label])
        row: dict = {"missing_votes": res["missing_votes"]}
        for d in domains:
            keep = {tuple(t.split("_")[1:3]) for t in trials("q235_div4", d, "agenticcyops") if "_benign_" not in t}
            a = [t for t in res["domains"][d]["attack"] if (t["ap"], t["variant"]) in keep]
            b = res["domains"][d]["benign"]
            ben_run = sum(v[1] for v in res["domains"][d]["benign_trials"].values())
            row[d] = {"n": len(a),
                      "asr_local4": ci(a),
                      "asr_as_run": ci([{**t, "outcome": t["as_run"]} for t in a]),
                      "benign_denied_local4": pct(b["denied"] / b["proposed"]) if b.get("proposed") else None,
                      "benign_denied_as_run": pct(ben_run / b["proposed"]) if b.get("proposed") else None}
        out[label] = row
    (BASE_DIR / "results" / "replay_v3_live.json").write_text(json.dumps(out, indent=1))
    return out


def tables() -> dict:
    """The headline comparisons, v2.9 input against v3.0 input, both under Local4."""
    from analysis.replay_panels import PANELS, asr, decide, load_all_votes, load_rounds, outcomes, panel_for
    V = load_all_votes()
    old = load_rounds()
    new: dict[str, list[dict]] = defaultdict(list)
    for ln in open(OUT / "rounds.jsonl"):
        r = json.loads(ln)
        new[r["arm"]].append(r)
    D4 = ("cyberops", "healthcare", "finance", "legal")
    keep = {tuple(t.split("_")[1:3]) for t in trials("q235_div4", "cyberops", "agenticcyops") if "_benign_" not in t}
    pct = lambda x: round(100 * x, 1)

    def summary(arm, group, cfg, doms, suffix="", R=None):
        res = outcomes(arm, group, cfg, doms, suffix, "Local4", V, R[arm])
        out = {"missing_votes": res["missing_votes"]}
        for d in doms:
            a = [t for t in res["domains"][d]["attack"] if (group not in ("oss120_local2_v29", "llama8b_local2_v29")
                                                            or (t["ap"], t["variant"]) in keep)]
            p, lo, hi, n = asr(a)
            b = res["domains"][d]["benign"]
            out[d] = {"asr": f"{pct(p)} [{pct(lo)}, {pct(hi)}]", "n": n,
                      "benign_denied": pct(b["denied"] / b["proposed"]) if b.get("proposed") else None}
        return out

    arms = [("full", "q235_div4", "agenticcyops", D4), ("judgeonly", "q235_div4", "llm_judge", ("cyberops",)),
            ("oss120_full", "oss120_local2_v29", "agenticcyops", ("cyberops",)),
            ("oss120_judgeonly", "oss120_local2_v29", "llm_judge", ("cyberops",)),
            ("llama8b_full", "llama8b_local2_v29", "agenticcyops", ("cyberops",)),
            ("llama8b_judgeonly", "llama8b_local2_v29", "llm_judge", ("cyberops",))]
    out = {}
    for arm, g, cfg, doms in arms:
        out[arm] = {"v2.9_input": summary(arm, g, cfg, doms, R=old), "v3.0_input": summary(arm, g, cfg, doms, R=new)}

    # the judges themselves: approval of attack-effect vs benign proposals, per judge
    sel = {}
    for tag, R in (("v2.9_input", old), ("v3.0_input", new)):
        c = defaultdict(Counter)
        for r in R["full"]:
            if r.get("path") not in JUDGED_PATHS:
                continue
            for vid in PANELS["Local4"][0]:
                v = V[vid].get(r["key"])
                if v is None:
                    continue
                c[vid][(r["role"], v == "approve")] += 1
        sel[tag] = {vid: {role: pct(cc[(role, True)] / max(1, cc[(role, True)] + cc[(role, False)]))
                          for role in ("attack_effect", "benign")} for vid, cc in c.items()}
    out["judge_approval_rates"] = sel
    (BASE_DIR / "results" / "replay_v3.json").write_text(json.dumps(out, indent=1))
    return out


NAMES = {"full": "Qwen3-235B FULL", "judgeonly": "Qwen3-235B JUDGEONLY",
         "oss120_full": "gpt-oss-120b FULL", "oss120_judgeonly": "gpt-oss-120b JUDGEONLY",
         "llama8b_full": "Llama-3.1-8B FULL", "llama8b_judgeonly": "Llama-3.1-8B JUDGEONLY"}


def report() -> str:
    res = BASE_DIR / "results"
    off = json.loads((res / "replay_v3.json").read_text())
    live = json.loads((res / "replay_v3_live.json").read_text())
    L = ["# The v3.0 panel input (defense-freeze-v3.0)", "",
         "Generated by `python -m analysis.replay_v3 report`. All numbers are the direct outcome under",
         "Local4 (a primary never judges its own proposals) unless marked as run; ASR % with 95% CI.", "",
         "## Offline: every judged round of the v2.9 runs, re-judged with each input", "",
         "| Arm | Domain | ASR, v2.9 input | ASR, v3.0 input | Benign denied %, v2.9 -> v3.0 |", "|---|---|---|---|---|"]
    for arm, name in NAMES.items():
        a, b = off[arm]["v2.9_input"], off[arm]["v3.0_input"]
        for d in a:
            if d != "missing_votes":
                L.append(f"| {name} | {d} | {a[d]['asr']} | {b[d]['asr']} | "
                         f"{a[d]['benign_denied']} -> {b[d]['benign_denied']} |")
    L += ["", "## Per-judge approval rate, Qwen3-235B FULL rounds", "",
          "| Judge | Attack-effect, v2.9 | Attack-effect, v3.0 | Benign, v2.9 | Benign, v3.0 |", "|---|---|---|---|---|"]
    r = off["judge_approval_rates"]
    for vid in r["v2.9_input"]:
        o, n = r["v2.9_input"][vid], r["v3.0_input"][vid]
        L.append(f"| {vid} | {o['attack_effect']} | {n['attack_effect']} | {o['benign']} | {n['benign']} |")
    L += ["", "## Live: the judged configurations re-run at defense-freeze-v3.0", "",
          "The live runs used the local2 panel (Mistral, Gemma); their logged panel inputs are re-judged under Local4.", "",
          "| Arm | Domain | n | ASR, Local4 | ASR, as run (local2) | Benign denied %, Local4 / as run |", "|---|---|---|---|---|---|"]
    for label, row in live.items():
        name = NAMES.get(label.replace("v30_", ""), label)
        for d, x in row.items():
            if d != "missing_votes":
                L.append(f"| {name} | {d} | {x['n']} | {x['asr_local4']} | {x['asr_as_run']} | "
                         f"{x['benign_denied_local4']} / {x['benign_denied_as_run']} |")
    missing = {k: v["missing_votes"] for k, v in live.items()}
    L += ["", f"Missing votes (live): {missing}.", ""]
    text = "\n".join(L)
    (res / "replay_v3.md").write_text(text)
    figure()
    return text


def figure() -> Path:
    """(a) Per-judge approval of attack-effect and legitimate proposals, v2.9
    vs v3.0 input; (b) FULL attack success and (c) legitimate proposals denied,
    v2.9 input, v3.0 input offline, and the live v3.0 re-run, all under Local4."""
    import re
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from analysis import figstyle as fs
    fs.apply()
    res = BASE_DIR / "results"
    off = json.loads((res / "replay_v3.json").read_text())
    live = json.loads((res / "replay_v3_live.json").read_text())
    ci = lambda s: [float(x) for x in re.findall(r"[0-9.]+", s)][:3]
    arms = [("full", "cyberops", "v30_full", "Qwen\ncyber"), ("full", "healthcare", "v30_full", "Qwen\nhealth"),
            ("full", "finance", "v30_full", "Qwen\nfinance"), ("full", "legal", "v30_full", "Qwen\nlegal"),
            ("oss120_full", "cyberops", "v30_oss120_full", "gpt-oss\ncyber"),
            ("llama8b_full", "cyberops", "v30_llama8b_full", "Llama8B\ncyber")]
    old_c, new_c = "#999999", fs.CONFIG_COLOR["JudgeOnly"]
    fig, axes = plt.subplots(1, 3, figsize=(fs.WIDTH_2COL, 2.7), gridspec_kw={"width_ratios": [0.85, 1.75, 1.75]})

    ax = axes[0]
    rates = off["judge_approval_rates"]
    judges = list(rates["v2.9_input"])
    for j, vid in enumerate(judges):
        for role, col, dy in (("attack_effect", fs.OUTCOME_COLOR["executed"], 0.12), ("benign", fs.BENIGN_COLOR, -0.12)):
            a, b = rates["v2.9_input"][vid][role], rates["v3.0_input"][vid][role]
            ax.annotate("", xy=(b, j + dy), xytext=(a, j + dy),
                        arrowprops=dict(arrowstyle="-|>", color=col, lw=1.2, mutation_scale=7))
            ax.plot([a], [j + dy], "o", ms=3.5, mfc="white", mec=col, mew=1.0, zorder=3)
    ax.set_yticks(range(len(judges)))
    ax.set_yticklabels([v.split("_")[1].replace("gptoss", "gpt-oss").capitalize().replace("Gpt-oss", "gpt-oss")
                        for v in judges])
    ax.invert_yaxis()
    ax.set_xlim(20, 100)
    ax.set_xlabel("Proposals approved (%)")
    ax.plot([], [], color=fs.OUTCOME_COLOR["executed"], lw=1.2, label="attack-effect")
    ax.plot([], [], color=fs.BENIGN_COLOR, lw=1.2, label="legitimate")
    ax.legend(frameon=False, fontsize=6.5, loc="lower left", handlelength=1.4)
    ax.set_title("(a) judges, v2.9 $\\rightarrow$ v3.0 input", fontsize=8)
    fs.style_axes(ax, ygrid=False, xgrid=True)

    w = 0.27
    for ax, key, title in ((axes[1], "asr", "(b) FULL attack success (%)"),
                           (axes[2], "benign", "(c) legitimate proposals denied (%)")):
        for k, (lab, col, hatch) in enumerate((("v2.9 input", old_c, None), ("v3.0 input", new_c, None),
                                               ("v3.0 live", "white", "////"))):
            vals = []
            for arm, dom, larm, _n in arms:
                if key == "asr":
                    src = [off[arm]["v2.9_input"][dom]["asr"], off[arm]["v3.0_input"][dom]["asr"],
                           live[larm][dom]["asr_local4"]][k]
                    vals.append(ci(src))
                else:
                    v = [off[arm]["v2.9_input"][dom]["benign_denied"], off[arm]["v3.0_input"][dom]["benign_denied"],
                         live[larm][dom]["benign_denied_local4"]][k]
                    vals.append([v, v, v])
            xs = [i + (k - 1) * w for i in range(len(arms))]
            ax.bar(xs, [v[0] for v in vals], width=w, color=col, hatch=hatch, label=lab, zorder=2,
                   edgecolor=new_c if hatch else "none", linewidth=0.6)
            for x, v in zip(xs, vals):
                if v[0] == 0:
                    ax.text(x, 0.3, "0", ha="center", va="bottom", fontsize=5.5, color="#555555")
            if key == "asr":
                ax.errorbar(xs, [v[0] for v in vals], yerr=[[v[0] - v[1] for v in vals], [v[2] - v[0] for v in vals]],
                            fmt="none", zorder=3, **fs.ERRORBAR_KW)
        ax.set_xticks(range(len(arms)))
        ax.set_xticklabels([a[3] for a in arms], fontsize=6)
        ax.set_title(title, fontsize=8)
        fs.style_axes(ax)
    axes[1].legend(frameon=False, fontsize=6.5, loc="upper left", ncol=1)
    fig.tight_layout(w_pad=1.0)
    path = BASE_DIR / "docs" / "figures" / "panel_context_v3.png"
    fig.savefig(path, dpi=200, bbox_inches="tight")
    fig.savefig(BASE_DIR / "paper" / "figs" / "panel_context.pdf", bbox_inches="tight")  # the paper's fig:context
    plt.close(fig)
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["build", "build-live", "tables", "live-tables", "report"])
    a = ap.parse_args()
    if a.cmd == "build":
        build()
    elif a.cmd == "build-live":
        build_live()
    elif a.cmd == "report":
        print(report())
    elif a.cmd == "live-tables":
        print(json.dumps(live_tables(), indent=1))
    else:
        print(json.dumps(tables(), indent=1))
