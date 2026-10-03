"""The mechanism analyses of the paper, on the reported runs.

Each was first run on the earlier runs; this module repeats it on the reported
composition (analysis.reported: CyberOps at defense-freeze-v3.2, the other
domains at v3.1 with AP-9 and JUDGEONLY re-run at v3.1.4) with the code the
2026-10-02 audit corrected:

    gate      the permissive approve gate (P3.9) on every proposal that reached
              the panel, from the risk scores the run logged; what it approves
              by role, and what substituting it for the panel executes; per
              domain, and the v2.9 calibration run beside it
    siblings  the rule-evading siblings (E2) against their parents
    evidence  P2.2 with structured evidence only, with the shipped embedding
              model, the reported variants and the siblings apart
    expiry    expiry and identity policies for the stateful checks, replayed
              faithfully (per process, real incident ids, live proposals) on the
              persistent runs (v3.1), with lower and upper bounds
    judges    agreement, per-judge discrimination and per-domain approval of
              legitimate proposals over the reported FULL rounds (Local4),
              siblings excluded
    fidelity  cached votes against the votes logged live

Logs and cached votes only; no model is queried (P2.2 embeds on the CPU).

    python -m analysis.v31_mechanisms     # -> results/v31_mechanisms.{json,md}
"""
from __future__ import annotations

import itertools
import json
import re
from collections import Counter, defaultdict

from analysis.p3_eligibility import JUDGED_PATHS, _payload, call_path, trials
from analysis.replay_panels import PANELS, decide, load_all_votes, panel_for
from analysis.reported import DOMAINS as D4, PERSIST, REPORTED as GROUP
from config import BASE_DIR

CALIBRATION = "q235_local2_v29"
REPLAY_SETS = (BASE_DIR / "cache" / "replay_rep", BASE_DIR / "cache" / "replay_v31")
ROUNDS = BASE_DIR / "cache" / "replay_rep" / "rounds.jsonl"
TRIALS = BASE_DIR / "results" / "eval_attacks" / "all_trials_local4.csv"


def pct(a, b) -> float:
    return round(100 * a / b, 1) if b else 0.0


def siblings_of() -> dict[tuple[str, str, str], tuple[str, str, str]]:
    """(domain, ap, variant) of each E2 sibling -> its parent (variant_id apN_vKe2)."""
    out = {}
    for f in sorted((BASE_DIR / "domains").glob("*/payloads/ap*_variants.json")):
        dom, ap = f.parts[-3], f.name.split("_")[0]
        for i, v in enumerate(json.loads(f.read_text())):
            m = re.match(r"ap\d+_v(\d+)e2$", v.get("variant_id", ""))
            if m:
                out[(dom, ap, str(i + 1))] = (dom, ap, m.group(1))
    return out


def _key(tid: str):
    m = re.match(r"(\w+?)_(ap\d+)_v(\d+)_t\d+", tid)
    return (m.group(1), m.group(2), m.group(3)) if m else None


def gate(sib) -> dict:
    """The permissive gate, per domain, on the rounds that reached the panel."""
    import analysis.gate_offline as go
    from attacks.effects import build_calls, evaluate_effects
    from consensus.auto_gates import AutoGates

    orig = go.trials
    go.trials = lambda g, d, c, suffix="": {t: e for t, e in orig(g, d, c, suffix).items()
                                           if _key(t) not in sib}
    out = {}
    try:
        for g, domains in ((GROUP, D4), (CALIBRATION, ("cyberops",))):
            gate_ = AutoGates(mode="permissive")
            sub = go.simulate("permissive", False, g, domains=domains)
            for d in domains:
                c = Counter()
                for tid, events in go.trials(g, d, "agenticcyops").items():
                    benign = "_benign_" in tid
                    ids = set()
                    if not benign and (p := _payload(d, tid)):
                        ids = set(evaluate_effects(p[1], events, config="agenticcyops").attempted_call_ids or [])
                    for call in build_calls(events):
                        if call_path(call, events) not in JUDGED_PATHS:
                            continue
                        role = "benign" if benign else ("attack" if call.call_id in ids else "other")
                        sc = go.logged_scores(call, events)
                        if sc is None:
                            continue
                        dec, _r, det = gate_.evaluate(sc)
                        c[(role, "n")] += 1
                        c[(role, "gate_approves")] += bool(dec and det.get("approved"))
                s = sub.get(d, {})
                out[f"{g}/{d}"] = {f"{r}|{k}": v for (r, k), v in sorted(c.items())} | {
                    "attack_incident_approved_pct": pct(c[("attack", "gate_approves")] + c[("other", "gate_approves")],
                                                        c[("attack", "n")] + c[("other", "n")]),
                    "attack_approved_pct": pct(c[("attack", "gate_approves")], c[("attack", "n")]),
                    "benign_approved_pct": pct(c[("benign", "gate_approves")], c[("benign", "n")]),
                    "trials": s.get("n", 0), "executed_as_run": s.get("executed_as_run", 0),
                    "executed_with_gate": s.get("executed_with_gate", 0)}
    finally:
        go.trials = orig
    # the shipped default gate, live: a decision is logged as P3_auto_*
    live = Counter()
    from analysis.runlogs import run_logs
    for d in D4:
        for f in run_logs(GROUP, d, "agenticcyops"):
            for ln in open(f, errors="ignore"):
                if '"P3_L2_scores"' in ln or '"P3_auto_' in ln:
                    e = json.loads(ln)
                    live[str(e.get("mechanism"))] += 1
    out["live_gate_events"] = dict(live)
    return out


def siblings(sib) -> dict:
    import csv
    rows = [r for r in csv.DictReader(open(TRIALS)) if r["group"] == GROUP]
    parents = set(sib.values())
    out = {}
    for cfg in ("flat", "acl_hardened", "llm_judge", "symbolic_only", "agenticcyops"):
        for lbl, keys in (("siblings", set(sib)), ("parents", parents)):
            rs = [r for r in rows if r["config"] == cfg and (r["domain"], r["ap"], r["variant"]) in keys]
            out[f"{cfg}|{lbl}"] = f"{sum(r['outcome'] == 'executed' for r in rs)}/{len(rs)}"
    by = defaultdict(list)
    for r in rows:
        if r["config"] == "agenticcyops" and (r["domain"], r["ap"], r["variant"]) in sib:
            by[(r["domain"], r["ap"], r["variant"])].append((r["outcome"], r["blocked_by"]))
    held = [k for k, v in by.items() if all(o != "executed" for o, _ in v)]
    out["siblings_n"] = len(by)
    out["held"] = len(held)
    out["held_with_a_panel_interception"] = sum(
        any(b in ("P3_llm_consensus_reject", "P3_consensus_reject") for _, b in by[k]) for k in held)
    out["executed"] = sorted(":".join(k) for k, v in by.items() if any(o == "executed" for o, _ in v))
    out["executed_trials"] = sum(o == "executed" for v in by.values() for o, _ in v)
    out["full_blocked_by"] = dict(Counter(b for v in by.values() for o, b in v if o == "blocked"))
    return out


def evidence(sib) -> dict:
    from analysis.trusted_evidence import evaluate, shipped_embedding_model
    model = shipped_embedding_model()
    res = {}
    for name, skip in (("reported", lambda t: _key(t) in sib), ("siblings", lambda t: _key(t) not in sib
                                                                  and "_benign_" not in t)):
        tot = Counter()
        for v in evaluate(GROUP, embedding_model=model, skip=skip).values():
            tot.update(v)
        res[name] = dict(sorted(tot.items()))
    return res


def expiry() -> dict:
    from analysis.ledger_expiry import sequence, simulate
    out = {}
    policies = (("shipped", None, False), ("skeleton_5", 5, False), ("skeleton_2", 2, False),
                ("skeleton_1", 1, False), ("identity", None, True), ("identity_1", 1, True))
    for g in PERSIST:
        seq = sequence(g, "cyberops")
        base = simulate(seq, None, False)
        rec = {"reproduces_logged": f"{base.get('benign_agree', 0) + base.get('attack_agree', 0)}/"
                                    f"{base.get('benign_consequential', 0) + base.get('attack_consequential', 0)}"}
        for name, w, ident in policies:
            lo, hi = simulate(seq, w, ident), simulate(seq, w, ident, upper=True)
            n = lo.get("benign_consequential", 0)
            den = lambda r: r.get("benign_denied_L4", 0) + r.get("benign_denied_L5", 0)
            rec[name] = {"denied_low": den(lo), "denied_high": den(hi), "of": n,
                         "pct_low": pct(den(lo), n), "pct_high": pct(den(hi), n)}
        first = next((items for t, _f, _i, items in seq if "_benign_" in t), [])
        rec["first_benign_stateful_denials"] = sum(it["logged"] != "pass" for it in first)
        out[g] = rec
    # what the stateful checks intercept in the isolated attack runs: within one
    # incident a structural replay cannot occur, so expiry cannot touch these
    kinds = Counter()
    from analysis.runlogs import run_logs
    for f in run_logs(GROUP, "cyberops", "agenticcyops"):
        for ln in open(f, errors="ignore"):
            if '"P3_L4_check"' in ln or '"P3_L5_check"' in ln:
                e = json.loads(ln)
                if e.get("auth_decision") in ("deny", "escalate") and "_benign_" not in str(e.get("trial_id")):
                    kinds[str(e.get("mechanism"))] += 1
    out["isolated_stateful_denials_by_kind"] = dict(kinds)
    return out


def judges(sib) -> dict:
    V = load_all_votes()
    members = PANELS["Local4"][0]
    rounds = [json.loads(ln) for ln in open(ROUNDS)]
    full = [r for r in rounds if r["arm"] == "rep_full" and r["path"] in JUDGED_PATHS
            and _key(r["trial_id"]) not in sib
            and all(V[m].get(r["key"]) in ("approve", "reject") for m in members)]
    vec = {m: [V[m][r["key"]] == "approve" for r in full] for m in members}

    def kappa(a, b):
        n = len(a)
        po = sum(x == y for x, y in zip(a, b)) / n
        pa, pb = sum(a) / n, sum(b) / n
        pe = pa * pb + (1 - pa) * (1 - pb)
        return (po - pe) / (1 - pe)
    ks = {f"{a}|{b}": round(kappa(vec[a], vec[b]), 2) for a, b in itertools.combinations(members, 2)}
    cnt = [sum(vec[m][i] for m in members) for i in range(len(full))]
    disc = {role: {m: pct(sum(V[m][r["key"]] == "approve" for r in full if r["role"] == role),
                          sum(r["role"] == role for r in full)) for m in members}
            for role in ("attack_effect", "benign")}
    mem, q = panel_for("Local4", "rep_full")
    legit = {}
    for d in D4:
        dec = [decide(r["key"], mem, q, V) for r in full if r["role"] == "benign" and r["domain"] == d]
        dec = [x for x in dec if x is not None]
        legit[d] = {"approved_pct": pct(sum(dec), len(dec)), "n": len(dec)}
    return {"rounds": len(full), "kappa": ks, "kappa_min": min(ks.values()), "kappa_max": max(ks.values()),
            "kappa_mean": round(sum(ks.values()) / len(ks), 2),
            "approved_pct_by_quorum": {k: pct(sum(c >= k for c in cnt), len(cnt)) for k in (1, 2, 3, 4)},
            "approve_pct_by_role": disc, "panel_approves_legitimate": legit}


def fidelity() -> dict:
    V = load_all_votes()
    out = {}
    for rs in REPLAY_SETS:
        f = rs / "rounds.jsonl"
        if not f.exists():
            continue
        c = Counter()
        for ln in open(f):
            r = json.loads(ln)
            for m, lv in (r.get("logged_votes") or {}).items():
                nv, lv = V.get(m, {}).get(r["key"]), str(lv).lower()
                if nv in ("approve", "reject") and lv in ("approve", "reject"):
                    c[(m, nv == lv)] += 1
        per = {m: {"reproduced": c[(m, True)], "of": c[(m, True)] + c[(m, False)],
                   "pct": pct(c[(m, True)], c[(m, True)] + c[(m, False)])} for m in sorted({m for m, _ in c})}
        tot = sum(v["of"] for v in per.values())
        per["all"] = {"reproduced": sum(v["reproduced"] for v in per.values()), "of": tot,
                      "pct": pct(sum(v["reproduced"] for v in per.values()), tot)}
        out[rs.name] = per
    return out


def main() -> None:
    sib = siblings_of()
    res = {"gate": gate(sib), "siblings": siblings(sib), "evidence": evidence(sib),
           "expiry": expiry(), "judges": judges(sib), "fidelity": fidelity()}
    (BASE_DIR / "results" / "v31_mechanisms.json").write_text(json.dumps(res, indent=1))
    L = ["# Mechanism analyses on the reported runs", "",
         "Generated by `python -m analysis.v31_mechanisms` (logs and cached votes only). "
         "The 75 reported variants per domain; the E2 siblings only where named.", ""]
    for k, v in res.items():
        L += [f"## {k}", "", "```", json.dumps(v, indent=1), "```", ""]
    (BASE_DIR / "results" / "v31_mechanisms.md").write_text("\n".join(L))
    print("\n".join(L))


if __name__ == "__main__":
    main()
