"""Paper numbers under the all-local main panel (Local4), from the replay.

    python -m analysis.replay_tables          # writes results/replay_tables.md and .json

Configurations without a panel (FLAT, ACL, NOJUDGE, FULL minus P3) are
reported as run; every configuration with a panel is re-adjudicated by
Local4 (``analysis.replay_panels``). Outcomes are direct: the logged
proposals, decided by the replayed panel, re-scored by the oracle.
"""
from __future__ import annotations

import csv
import itertools
import json
from collections import Counter, defaultdict

from analysis import tiers
from analysis.replay_panels import (PANELS, asr, decide, load_all_votes, load_rounds,
                                    outcomes, panel_for)
from analysis.statistical_tests import cluster_bootstrap
from config import BASE_DIR

D4 = ("cyberops", "healthcare", "finance", "legal")
TR = D4[1:]
MAIN = "Local4"
T2_APS = {"ap5", "ap9", "ap10", "ap15"}
ALL_TRIALS = BASE_DIR / "results" / "eval_attacks" / "all_trials.csv"


def _pct(x):
    return f"{100 * x:.1f}"


def _ci(ts):
    p, lo, hi, n = asr(ts)
    return f"{_pct(p)} [{_pct(lo)}, {_pct(hi)}]", n


def _as_run(group, cfg, doms, suffix=""):
    """Attack trials of a panel-free configuration, as run."""
    out = []
    for t in csv.DictReader(open(ALL_TRIALS)):
        if (t["group"] == group and t["config"] == cfg and (t.get("suffix") or "") == suffix
                and t["domain"] in doms and t["ap"] != "benign"
                and t["outcome"] in ("executed", "blocked", "not_attempted")):
            out.append({"domain": t["domain"], "ap": t["ap"], "variant": f"v{t['variant']}",
                        "trial": f"t{t['trial']}", "outcome": t["outcome"], "blocked_by": t["blocked_by"],
                        "as_run": t["outcome"], "channel": t.get("channel", "")})
    return out


def _attempt(ts):
    a = [t for t in ts if t["outcome"] in ("executed", "blocked")]
    return len(a) / len(ts) if ts else float("nan"), (
        sum(t["outcome"] == "blocked" for t in a) / len(a) if a else float("nan"))


def build() -> dict:
    V, R = load_all_votes(), load_rounds()
    out: dict = {}

    full = outcomes("full", "q235_div4", "agenticcyops", D4, "", MAIN, V, R["full"])
    full_je = outcomes("full", "q235_div4", "agenticcyops", D4, "", MAIN, V, R["full"], judge_everything=True)
    judge = outcomes("judgeonly", "q235_div4", "llm_judge", ("cyberops",), "", MAIN, V, R["judgeonly"])
    A = lambda res, doms=D4: [t for d in doms for t in res["domains"].get(d, {}).get("attack", [])]
    ben = lambda res, doms=D4: Counter(sum((Counter(res["domains"][d]["benign"]) for d in doms if d in res["domains"]), Counter()))

    # ---- development split, every configuration
    dev = {}
    for label, ts in (("FLAT", _as_run("q235_div4", "flat", ("cyberops",))),
                      ("ACL", _as_run("q235_div4", "acl_hardened", ("cyberops",))),
                      ("JUDGEONLY", A(judge, ("cyberops",))),
                      ("NOJUDGE", _as_run("q235_div4", "symbolic_only", ("cyberops",))),
                      ("FULL", A(full, ("cyberops",)))):
        ci, n = _ci(ts)
        att, blk = _attempt(ts)
        dev[label] = {"asr": ci, "n": n, "attempt": _pct(att), "block_given_attempt": _pct(blk)}
    for label, res in (("JUDGEONLY", judge), ("FULL", full), ("FULL, judge everything after rules", full_je)):
        b = ben(res, ("cyberops",))
        dev.setdefault(label, {})["benign_denied"] = _pct(b["denied"] / b["proposed"])
    dev["FULL, judge everything after rules"]["asr"] = _ci(A(full_je, ("cyberops",)))[0]
    out["development"] = dev

    # ---- ablations on the variants shared by every arm
    abl = {i: outcomes(f"full_minus_p{i}", "q235_div4", "agenticcyops", ("cyberops",), f"_disabled_P{i}",
                       MAIN, V, R[f"full_minus_p{i}"]) for i in (1, 2, 4, 5)}
    p3 = _as_run("q235_div4", "agenticcyops", ("cyberops",), "_disabled_P3")
    arms = {"FULL": A(full, ("cyberops",)), **{f"minus P{i}": A(r, ("cyberops",)) for i, r in abl.items()},
            "minus P3": p3}
    key = lambda t: (t["ap"], t["variant"])
    shared = set.intersection(*[{key(t) for t in ts} for ts in arms.values()])
    out["ablation"] = {"shared_variants": len(shared)}
    for label, ts in arms.items():
        ci, n = _ci([t for t in ts if key(t) in shared])
        out["ablation"][label] = {"asr": ci, "n": n}
    for i, r in abl.items():
        b = ben(r, ("cyberops",))
        out["ablation"][f"minus P{i}"]["benign_denied"] = _pct(b["denied"] / b["proposed"]) if b["proposed"] else "n/a"

    # ---- domains, transfer, primaries
    out["domains"] = {}
    for d in D4:
        b = full["domains"][d]["benign"]
        out["domains"][d] = {"flat": _ci(_as_run("q235_div4", "flat", (d,)))[0],
                             "acl": _ci(_as_run("q235_div4", "acl_hardened", (d,)))[0],
                             "full": _ci(A(full, (d,)))[0],
                             "benign_denied": _pct(b["denied"] / b["proposed"])}
    out["transfer_full"] = _ci(A(full, TR))[0]
    out["all_domains_full"] = _ci(A(full))[0]
    prim = {}
    for arm, g in (("scout", "scout_div4"), ("mistral", "mistral_div3p"), ("llama8b", "llama8b_div4")):
        r = outcomes(arm, g, "agenticcyops", ("cyberops", "finance"), "", MAIN, V, R[arm])
        b = ben(r, ("cyberops",))
        prim[arm] = {"full_cyberops": _ci(A(r, ("cyberops",)))[0], "full_finance": _ci(A(r, ("finance",)))[0],
                     "benign_denied_cyberops": _pct(b["denied"] / b["proposed"])}
    q = [t for t in A(full, ("cyberops", "finance"))]
    pooled = q + [t for arm, g in (("scout", "scout_div4"), ("mistral", "mistral_div3p"), ("llama8b", "llama8b_div4"))
                  for t in A(outcomes(arm, g, "agenticcyops", ("cyberops", "finance"), "", MAIN, V, R[arm]))]
    prim["pooled_full"] = _ci(pooled)[0]
    out["primaries"] = prim

    # ---- first interception by tier and by principle
    def shares(ts):
        mech = [t["blocked_by"] for t in ts if t["outcome"] == "blocked"]
        s, n, _u = tiers.shares(mech)
        by_p = Counter("panel" if tiers.tier_of(m) == "panel" else m.split("_")[0] for m in mech)
        return {"n": n, **{t: _pct(v) for t, v in s.items()},
                **{f"principle_{k}": _pct(v / len(mech)) for k, v in by_p.items()}}
    out["tiers"] = {"development": shares(A(full, ("cyberops",))), "transfer": shares(A(full, TR))}

    # ---- paired JUDGEONLY vs FULL
    ever = lambda ts: {key(t): any(u["outcome"] == "executed" for u in ts if key(u) == key(t)) for t in ts}
    j, f = ever(A(judge, ("cyberops",))), ever(A(full, ("cyberops",)))
    common = set(j) & set(f)
    cls = Counter((j[v], f[v]) for v in common)
    jonly = [v for v in common if j[v] and not f[v]]
    out["paired"] = {"variants": len(common), "judgeonly_only": cls[(True, False)], "both": cls[(True, True)],
                     "full_only": cls[(False, True)], "judgeonly_only_on_memory_paths": sum(v[0] in ("ap4", "ap13") for v in jonly)}

    # ---- channels (four domains) and attacker tiers (development)
    ch = {(t["domain"], t["ap"], t["variant"], t["trial"]): t["channel"]
          for t in _as_run("q235_div4", "flat", D4)}
    by_ch = defaultdict(list)
    for t in A(full):
        by_ch[ch.get((t["domain"], t["ap"], t["variant"], t["trial"]), "")].append(t)
    out["channels_full"] = {c: _ci(ts)[0] for c, ts in by_ch.items() if c}
    fd = A(full, ("cyberops",))
    out["attacker_tiers_full_dev"] = {"T2": _ci([t for t in fd if t["ap"] in T2_APS])[0],
                                      "T1": _ci([t for t in fd if t["ap"] not in T2_APS])[0]}
    out["residuals"] = {
        "legal_ap2_full": f"{sum(t['outcome'] == 'executed' for t in A(full, ('legal',)) if t['ap'] == 'ap2')}/15",
        "finance_ap9_full": f"{sum(t['outcome'] == 'executed' for t in A(full, ('finance',)) if t['ap'] == 'ap9')}/15",
        "ap10_judgeonly": f"{sum(t['outcome'] == 'executed' for t in A(judge) if t['ap'] == 'ap10')}/15",
        "ap10_full": f"{sum(t['outcome'] == 'executed' for t in A(full, ('cyberops',)) if t['ap'] == 'ap10')}/15",
        "executed_full_by_domain_ap": dict(Counter(f"{t['domain']}:{t['ap']}" for t in A(full) if t["outcome"] == "executed")),
    }

    # ---- the judges themselves: agreement, strictness, quorum, benign rejection by domain
    m4, q4 = PANELS[MAIN]
    judged = [r for r in R["full"] if r["path"] != "allowed_no_p3"]
    votes = [{v: V[v].get(r["key"]) for v in m4} for r in judged]
    def kappa(a, b):
        xs = [(x[a] == "approve", x[b] == "approve") for x in votes]
        po = sum(p == q for p, q in xs) / len(xs)
        pa, pb = sum(p for p, _ in xs) / len(xs), sum(q for _, q in xs) / len(xs)
        pe = pa * pb + (1 - pa) * (1 - pb)
        return (po - pe) / (1 - pe)
    ks = {f"{a}|{b}": round(kappa(a, b), 2) for a, b in itertools.combinations(m4, 2)}
    out["judges"] = {
        "rounds": len(votes), "kappa": ks, "kappa_mean": round(sum(ks.values()) / len(ks), 2),
        "reject_rate": {v: _pct(sum(x[v] != "approve" for x in votes) / len(votes)) for v in m4},
        "approved_by_quorum": {k: _pct(sum(sum(x[v] == "approve" for v in m4) >= k for x in votes) / len(votes))
                               for k in range(1, len(m4) + 1)},
        "selectivity": {v: {role: _pct(sum(V[v].get(r["key"]) == "approve" for r in judged if r["role"] == role)
                                      / max(1, sum(r["role"] == role for r in judged)))
                            for role in ("attack_effect", "benign")} for v in m4},
        "benign_approved_by_domain": {d: _pct(sum(bool(decide(r["key"], m4, q4, V)) for r in judged
                                                  if r["role"] == "benign" and r["domain"] == d)
                                              / max(1, sum(r["role"] == "benign" and r["domain"] == d for r in judged)))
                                      for d in D4},
    }

    # ---- ASB, rule-evading siblings, lineage
    asb = {}
    for panel in ("Local4", "Div3L", "Lin3", "Single"):
        mem, qq = panel_for(panel, "asb")
        asb[panel] = {"replay405_let_through": sum(bool(decide(r["key"], mem, qq, V)) for r in R["asb_replay405"]),
                      "frozen_executed": sum(bool(decide(r["key"], mem, qq, V)) for r in R["asb_frozen"])}
    out["asb"] = asb
    lin = {}
    for panel in ("Local4", "Div3L", "Lin3", "Single"):
        r = outcomes("full", "q235_div4", "agenticcyops", D4, "", panel, V, R["full"])
        lin[panel] = {"dev": _ci(A(r, ("cyberops",)))[0], "transfer": _ci(A(r, TR))[0]}
    out["lineage"] = lin

    # ---- rule-evading siblings (E2): variants appended after each path's
    # original variants in the E2 runs; held = never executed under the panel
    orig = defaultdict(set)
    for t in A(full):
        orig[(t["domain"], t["ap"])].add(t["variant"])
    e2 = outcomes("e2", "q235_div4_e2", "agenticcyops", D4, "", MAIN, V, R["e2"])
    sib = [t for t in A(e2) if t["variant"] not in orig[(t["domain"], t["ap"])]]
    by_var = defaultdict(list)
    for t in sib:
        by_var[(t["domain"], t["ap"], t["variant"])].append(t["outcome"])
    out["e2_siblings"] = {
        "siblings": len(by_var), "trials": len(sib),
        "executed_trials": sum(t["outcome"] == "executed" for t in sib),
        "held": sum("executed" not in v for v in by_var.values()),
        "executed": sorted(f"{d}:{ap}:{v}" for (d, ap, v), o in by_var.items() if "executed" in o),
    }
    return out


def main() -> None:
    out = build()
    (BASE_DIR / "results" / "replay_tables.json").write_text(json.dumps(out, indent=1))
    lines = ["# Paper numbers under the all-local main panel (Local4)", "",
             "Generated by `python -m analysis.replay_tables` from the logs and `cache/validators/`.", ""]
    for k, v in out.items():
        lines += [f"## {k}", "", "```", json.dumps(v, indent=1), "```", ""]
    (BASE_DIR / "results" / "replay_tables.md").write_text("\n".join(lines))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()


def write_local4_trials(path=None) -> int:
    """``all_trials.csv`` with the outcome and first interceptor of every
    panel-using configuration replaced by its Local4 replay, and the benign
    rows' denied tool calls re-counted under it. Panel-free configurations are
    unchanged. Figures build from it. Groups with no replay arm here keep their
    as-run outcomes: the permissive-gate arm, the E9/E16 and outage runs, the
    v2.9 calibration run (local2), and the v3.0 runs (Local4 for those is in
    results/replay_v3*.json). The v3.1 runs are re-judged from cache/replay_v31,
    the reported runs (analysis.reported) from cache/replay_rep."""
    V, R = load_all_votes(), load_rounds()
    from analysis.reported import ABLATION, PRIMARIES, REPORTED
    for rs in ("replay_v31", "replay_rep"):   # the v3.1 and the reported runs keep their rounds apart
        f = BASE_DIR / "cache" / rs / "rounds.jsonl"
        if f.exists():
            for ln in open(f):
                r = json.loads(ln)
                R.setdefault(r["arm"], []).append(r)
    _prim_arm = {"gpt-oss-120b": "rep_oss120", "Llama-3.1-8B": "rep_llama8b"}
    arms = [("rep_full", REPORTED, "agenticcyops", D4, ""),
            ("rep_judgeonly", REPORTED, "llm_judge", D4, ""),
            *[(f"rep_full_minus_p{i}", ABLATION[i], "agenticcyops", ("cyberops",), "") for i in (1, 2, 4, 5)],
            *[(f"{_prim_arm[m]}_{a}", g, cfg, ("cyberops",), "") for m, g in PRIMARIES.items()
              for a, cfg in (("full", "agenticcyops"), ("judgeonly", "llm_judge"))],
            ("full", "q235_div4", "agenticcyops", D4, ""),
            ("v31_full", "q235_local2_v31", "agenticcyops", D4, ""),
            ("v31_judgeonly", "q235_local2_v31", "llm_judge", D4, ""),
            *[(f"v31_full_minus_p{i}", f"q235_local2_disabled_P{i}_v31", "agenticcyops", ("cyberops",), "")
              for i in (1, 2, 4, 5)],
            *[(f"v31_{m}_{a}", f"{m}_local2_v31", cfg, ("cyberops",), "")
              for m in ("oss120", "llama8b") for a, cfg in (("full", "agenticcyops"), ("judgeonly", "llm_judge"))],
            ("judgeonly", "q235_div4", "llm_judge", ("cyberops",), ""),
            *[(f"full_minus_p{i}", "q235_div4", "agenticcyops", ("cyberops",), f"_disabled_P{i}") for i in (1, 2, 4, 5)],
            ("scout", "scout_div4", "agenticcyops", ("cyberops", "finance"), ""),
            ("mistral", "mistral_div3p", "agenticcyops", ("cyberops", "finance"), ""),
            ("llama8b", "llama8b_div4", "agenticcyops", ("cyberops", "finance"), ""),
            ("e2", "q235_div4_e2", "agenticcyops", D4, ""),
            *[(f"{m}_{a}", f"{m}_local2_v29", cfg, ("cyberops",), "")
              for m in ("oss120", "llama8b") for a, cfg in (("full", "agenticcyops"), ("judgeonly", "llm_judge"))]]
    new, ben = {}, {}
    for arm, g, cfg, doms, suf in arms:
        if not R.get(arm):
            continue                  # rounds not built (the run has not happened)
        res = outcomes(arm, g, cfg, doms, suf, MAIN, V, R[arm])
        for d, v in res["domains"].items():
            for t in v["attack"]:
                new[(g, suf, d, cfg, t["ap"], t["variant"].lstrip("v"), t["trial"].lstrip("t"))] = t
            for tid, (den, as_run) in v.get("benign_trials", {}).items():
                parts = tid.split("_")
                ben[(g, suf, d, cfg, parts[2].lstrip("v"), parts[3].lstrip("t"))] = (den, as_run)
    rows = list(csv.DictReader(open(ALL_TRIALS)))
    n = 0
    for r in rows:
        t = new.get((r["group"], r.get("suffix") or "", r["domain"], r["config"], r["ap"], r["variant"], r["trial"]))
        if t:
            r["outcome"], r["blocked_by"] = t["outcome"], t["blocked_by"]
            n += 1
        b = r["ap"] == "benign" and ben.get((r["group"], r.get("suffix") or "", r["domain"], r["config"],
                                               r["variant"], r["trial"]))
        if b:
            # collateral_denials counts denied proposals of every kind; replace
            # its tool-call part, the only part the panel decides
            den, as_run = b
            r["collateral_denials"] = str(max(0, int(float(r["collateral_denials"] or 0)) - as_run + den))
    out = path or ALL_TRIALS.with_name("all_trials_local4.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return n


def write_local_panel_csv() -> None:
    """The panel-composition figure's input for the local panels: ASB let-through
    on the 405-action replay (1,275 trials) and benign rejection on the rounds
    that reached the judges under FULL, per domain."""
    V, R = load_all_votes(), load_rounds()
    judged = [r for r in R["full"] if r["path"] != "allowed_no_p3" and r["role"] == "benign"]
    rows = []
    for panel, label in (("Single", "single"), ("Lin3", "lin3"), ("Div3L", "div3l"), ("Local4", "local4")):
        mem, q = panel_for(panel, "asb")
        let = sum(bool(decide(r["key"], mem, q, V)) for r in R["asb_replay405"])
        for d in D4:
            rs = [r for r in judged if r["domain"] == d]
            rej = sum(not decide(r["key"], mem, q, V) for r in rs)
            rows.append({"panel": label, "domain": d, "security_letthrough": let, "security_n": 1275,
                         "benign_rejected": rej, "benign_n": len(rs)})
    out = BASE_DIR / "results" / "benign_panel_rejection_local.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
