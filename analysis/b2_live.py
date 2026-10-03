"""B2 and the replay calibration: FULL at defense-freeze-v2.9, live, local2 panel.

The live run (group ``q235_local2_v29``; CyberOps development split, three
trials per variant, 20 benign scenarios x 3) uses the two local judges that fit
beside the primary, Mistral-Small and Gemma-4, two of two. From it:

    1. who decides consequential proposals: the auto-gates (P3.9) or the panel;
    2. ASR with a 95% cluster-bootstrap interval on the original 75 variants
       (the payload files also carry the E2 siblings, which are left out);
    3. benign denial: share of legitimate tool proposals denied;
    4. median benign-incident latency (six concurrent streams share the
       primary and the judges, as in the original runs' launch pattern);
    5. the risk scores the v2.9 scorer logs (P3_L1_scores), attack vs benign.

Calibration: the original ``q235_div4`` FULL runs re-adjudicated under the same
two judges. The live run differs in the defense version (v2.9: scorer wiring,
ledger log key) and in everything the agents did after a decision; the gap
between the two is what the direct outcome cannot see.

    python -m analysis.b2_live            # writes results/b2_live.json
"""
from __future__ import annotations

import json
import statistics
from collections import Counter

from analysis.p3_eligibility import _payload, trials
from analysis.replay_panels import load_all_votes, load_rounds, outcomes
from analysis.statistical_tests import cluster_bootstrap
from attacks.effects import build_calls, evaluate_effects, trial_costs
from config import BASE_DIR

LIVE = "q235_local2_v29"
MAIN = "q235_div4"
DOM = "cyberops"
SCORES = ("scope", "reversibility", "alignment", "precedent", "proportionality")


def _pct(x: float) -> float:
    return round(100 * x, 1)


def _ci(ts: list[dict]) -> dict:
    if not ts:
        return {"asr": None, "n": 0}
    p, lo, hi = cluster_bootstrap(ts, lambda t: t["outcome"] == "executed",
                                  lambda t: f"{t['ap']}:{t['variant']}")
    return {"asr": _pct(p), "ci": [_pct(lo), _pct(hi)], "n": len(ts)}


def original_variants() -> set[tuple[str, str]]:
    return {tuple(tid.split("_")[1:3]) for tid in trials(MAIN, DOM, "agenticcyops")
            if "_benign_" not in tid}


def live() -> dict:
    keep = original_variants()
    attack, benign_lat = [], []
    prop = den = inc = anyd = 0
    decided = Counter()
    scores = {"attack": [], "benign": []}
    for tid, ev in trials(LIVE, DOM, "agenticcyops").items():
        benign = "_benign_" in tid
        if not benign and tuple(tid.split("_")[1:3]) not in keep:
            continue                                  # E2 siblings in the payload files
        for e in ev:
            if e.get("action") == "P3_L2_scores":
                decided["gate:" + (e.get("mechanism") or "")] += 1
            elif e.get("action") == "consensus_result" and e.get("layer") == "L6":
                decided["panel:" + e.get("auth_decision", "")] += 1
            elif e.get("action") == "P3_L1_scores":
                scores["benign" if benign else "attack"].append({k: e.get(k) for k in SCORES})
        if benign:
            cs = [c for c in build_calls(ev) if c.kind == "tool"]
            n = sum(c.denied for c in cs)
            prop += len(cs)
            den += n
            inc += 1
            anyd += n > 0
            span = trial_costs(ev).get("span_s")
            if span:
                benign_lat.append(span)
            continue
        ap, var = tid.split("_")[1:3]
        p = _payload(DOM, tid)
        if not p:
            continue
        v = evaluate_effects(p[1], ev, config="agenticcyops")
        if v.outcome in ("executed", "blocked", "not_attempted"):
            attack.append({"ap": ap, "variant": var, "outcome": v.outcome})
    att = [t for t in attack if t["outcome"] != "not_attempted"]
    summ = lambda xs, k: round(statistics.mean(x[k] for x in xs if x[k] is not None), 3) if xs else None
    return {
        "variants": len({(t["ap"], t["variant"]) for t in attack}),
        "attack": _ci(attack),
        "attempt": _pct(len(att) / len(attack)) if attack else None,
        "benign_incidents": inc,
        "benign_denied": _pct(den / prop) if prop else None,
        "benign_any_denial": _pct(anyd / inc) if inc else None,
        "benign_median_latency_s": round(statistics.median(benign_lat), 1) if benign_lat else None,
        "p3_decisions": dict(decided),
        "scores_mean": {k: {s: summ(v, s) for s in SCORES} for k, v in scores.items()},
        "scores_n": {k: len(v) for k, v in scores.items()},
    }


def replay() -> dict:
    V, R = load_all_votes(), load_rounds()
    res = outcomes("full", MAIN, "agenticcyops", (DOM,), "", "Local2", V, R["full"])
    d = res["domains"][DOM]
    b = d["benign"]
    return {"missing_votes": res["missing_votes"], "attack": _ci(d["attack"]),
            "benign_denied": _pct(b["denied"] / b["proposed"]) if b.get("proposed") else None}


def main() -> None:
    out = {"live_v29_local2": live(), "replay_v22_local2": replay()}
    path = BASE_DIR / "results" / "b2_live.json"
    path.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
