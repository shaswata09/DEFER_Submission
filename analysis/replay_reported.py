"""The reported boundary after the 2026-10-02 audit, under Local4.

The reported runs are a composition (analysis.reported): CyberOps at
defense-freeze-v3.2, the other three domains at v3.1 with AP-9 and JUDGEONLY
re-run at v3.1.4. Panel-free configurations (FLAT, ACL, NOJUDGE) are reported
as run; JUDGEONLY and FULL as the direct outcome under Local4, from the logged
panel rounds re-judged offline (votes cached by message hash), with the live
local2 value alongside. Also: FULL with every rule-surviving call judged
(JUDGEREST), the judged fraction per configuration, and the leave-one-out arms
(CyberOps, v3.2). Only the 75 reported variants per domain count (the runs also
carry the E2 siblings).

    python -m analysis.replay_reported build    # -> cache/replay_rep/{rounds,messages}.jsonl
    python -m analysis.replay_run query --replay-dir cache/replay_rep --validator L1_mistral --url ...
    python -m analysis.replay_reported tables   # -> results/reported_boundary.{json,md}, figures
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import asdict

from analysis.p3_eligibility import JUDGED_PATHS, _payload, paths, trials
from analysis.replay_panels import asr, load_all_votes, outcomes
from analysis.reported import ABLATION, DOMAINS, FREEZE, PREVIOUS, PRIMARIES, REPORTED
from attacks.effects import build_calls, evaluate_effects
from config import BASE_DIR

OUT = BASE_DIR / "cache" / "replay_rep"
D4 = DOMAINS
PANEL_FREE = {"FLAT": "flat", "ACL": "acl_hardened", "NOJUDGE": "symbolic_only"}
JUDGED = {"JUDGEONLY": ("llm_judge", "rep_judgeonly"), "FULL": ("agenticcyops", "rep_full")}
_PRIM_ARM = {"gpt-oss-120b": "rep_oss120", "Llama-3.1-8B": "rep_llama8b"}
# (label, group, config, domains, suffix, include_unjudged)
ARMS = [("rep_full", REPORTED, "agenticcyops", D4, "", True),
        ("rep_judgeonly", REPORTED, "llm_judge", D4, "", False),
        # leave-one-out (CyberOps, v3.2); -P3 has no panel
        *[(f"rep_full_minus_p{i}", ABLATION[i], "agenticcyops", ("cyberops",), "", False)
          for i in (1, 2, 4, 5)],
        *[(f"{_PRIM_ARM[m]}_{a}", g, cfg, ("cyberops",), "", a == "full")
          for m, g in PRIMARIES.items() for a, cfg in (("full", "agenticcyops"), ("judgeonly", "llm_judge"))]]


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
            print(f"{label:24s} {n:6d} rounds", flush=True)
    with open(OUT / "messages.jsonl", "w") as fm:
        for k, m in messages.items():
            fm.write(json.dumps({"key": k, "message": m}) + "\n")
    print(f"distinct messages: {len(messages)}")


def load_rounds() -> dict[str, list[dict]]:
    R: dict[str, list[dict]] = {}
    for ln in open(OUT / "rounds.jsonl"):
        r = json.loads(ln)
        R.setdefault(r["arm"], []).append(r)
    return R


def keep(domain: str) -> set[tuple[str, str]]:
    """The 75 reported variants of a domain, as (ap, 'v<n>')."""
    return {tuple(t.split("_")[1:3]) for t in trials("q235_div4", domain, "agenticcyops")
            if "_benign_" not in t}


def _variant(tid: str) -> tuple[str, str]:
    return tuple(tid.split("_")[1:3])


def _ci(ts: list[dict]) -> str:
    p, lo, hi, n = asr(ts)
    return f"{100 * p:.1f} [{100 * lo:.1f}, {100 * hi:.1f}]" if n else "n/a"


def pct(a, b):
    return round(100 * a / b, 1) if b else None


def as_run(group: str, domain: str, config: str, kv) -> tuple[list[dict], Counter]:
    attack, benign = [], Counter()
    for tid, ev in trials(group, domain, config).items():
        calls = [c for c in build_calls(ev) if c.kind == "tool"]
        if "_benign_" in tid:
            benign["proposed"] += len(calls)
            benign["denied"] += sum(c.denied for c in calls)
            benign["incidents"] += 1
            benign["incidents_with_denial"] += any(c.denied for c in calls)
            continue
        ap, var = _variant(tid)
        p = _payload(domain, tid)
        if (ap, var) not in kv or not p:
            continue
        v = evaluate_effects(p[1], ev, config=config)
        if v.outcome in ("executed", "blocked", "not_attempted"):
            attack.append({"domain": domain, "ap": ap, "variant": var, "outcome": v.outcome})
    return attack, benign


def row(attack: list[dict], benign: Counter) -> dict:
    att = [t for t in attack if t["outcome"] != "not_attempted"]
    return {"asr": _ci(attack), "n": len(attack),
            "attempt": pct(len(att), len(attack)),
            "block_given_attempt": pct(sum(t["outcome"] == "blocked" for t in att), len(att)),
            "benign_denied": pct(benign.get("denied", 0), benign.get("proposed", 0))}


def judged_fraction(group: str, config: str, domains, kv_by_domain) -> dict:
    """Share of tool proposals that reached the panel (attack and benign
    incidents), and the share allowed without entering P3."""
    out = {}
    for kind in ("attack", "benign"):
        c = Counter()
        for d in domains:
            for tid, ev in trials(group, d, config).items():
                benign = "_benign_" in tid
                if (kind == "benign") != benign:
                    continue
                if not benign and _variant(tid) not in kv_by_domain[d]:
                    continue
                from analysis.p3_eligibility import call_path
                for cl in build_calls(ev):
                    if cl.kind != "tool":
                        continue
                    pth = call_path(cl, ev)
                    c["n"] += 1
                    c["judged"] += pth in JUDGED_PATHS
                    c["no_p3"] += pth == "allowed_no_p3"
                    c["rule_denied"] += pth in ("denied_before_p3", "p3_denied_rule")
        out[kind] = {"judged_pct": pct(c["judged"], c["n"]), "allowed_no_p3_pct": pct(c["no_p3"], c["n"]),
                     "rule_denied_pct": pct(c["rule_denied"], c["n"]), "proposals": c["n"]}
    return out


def tables() -> dict:
    V = load_all_votes()
    R = load_rounds()
    kv = {d: keep(d) for d in D4}
    prev_path = BASE_DIR / "results" / "replay_v31.json"
    prev = json.loads(prev_path.read_text()) if prev_path.exists() else {}
    res: dict = {"freeze": FREEZE, "domains": {}}
    for d in D4:
        r: dict = {}
        for label, cfg in PANEL_FREE.items():
            r[label] = row(*as_run(REPORTED, d, cfg, kv[d]))
        for label, (cfg, arm) in JUDGED.items():
            live = row(*as_run(REPORTED, d, cfg, kv[d]))
            o = outcomes(arm, REPORTED, cfg, (d,), "", "Local4", V, R.get(arm, []))
            a4 = [t for t in o["domains"][d]["attack"] if (t["ap"], t["variant"]) in kv[d]]
            r[label] = {**row(a4, Counter(o["domains"][d]["benign"])),
                        "missing_votes": o["missing_votes"], "live_local2": live}
        je = outcomes("rep_full", REPORTED, "agenticcyops", (d,), "", "Local4", V, R.get("rep_full", []),
                      judge_everything=True)
        a4 = [t for t in je["domains"][d]["attack"] if (t["ap"], t["variant"]) in kv[d]]
        r["JUDGEREST"] = row(a4, Counter(je["domains"][d]["benign"]))
        for label, cfg in (("FULL", "agenticcyops"), ("JUDGEONLY", "llm_judge")):
            r[label]["judged"] = judged_fraction(REPORTED, cfg, (d,), kv)
        r["previous_v31"] = {k: (prev.get(d, {}).get(k) or {}).get("asr")
                             for k in ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL")}
        res["domains"][d] = r
    # pooled over the four domains and over the three non-CyberOps domains
    for name, doms in (("all_four", D4), ("other_three", D4[1:])):
        pooled = {}
        for label, cfg in PANEL_FREE.items():
            att = [t for d in doms for t in as_run(REPORTED, d, cfg, kv[d])[0]]
            pooled[label] = _ci(att)
        for label, (cfg, arm) in JUDGED.items():
            o = outcomes(arm, REPORTED, cfg, doms, "", "Local4", V, R.get(arm, []))
            pooled[label] = _ci([t for d in doms for t in o["domains"][d]["attack"]
                                 if (t["ap"], t["variant"]) in kv[d]])
        res[name] = pooled
    res["ablation"] = ablation(V, R, kv["cyberops"])
    (BASE_DIR / "results" / "reported_boundary.json").write_text(json.dumps(res, indent=1))
    write_md(res)
    return res


def ablation(V, R, kv) -> dict:
    """Leave-one-out, CyberOps, v3.2: each arm beside FULL on the same variants."""
    out = {}
    o = outcomes("rep_full", REPORTED, "agenticcyops", ("cyberops",), "", "Local4", V, R.get("rep_full", []))
    full_att = [t for t in o["domains"]["cyberops"]["attack"] if (t["ap"], t["variant"]) in kv]
    out["FULL"] = {**row(full_att, Counter(o["domains"]["cyberops"]["benign"])),
                   **_any_denial(REPORTED, o), "judged": judged_fraction(REPORTED, "agenticcyops", ("cyberops",), {"cyberops": kv})["attack"]["judged_pct"]}
    for i, g in ABLATION.items():
        arm = f"rep_full_minus_p{i}"
        if i == 3:                                    # no panel without P3
            att, ben = as_run(g, "cyberops", "agenticcyops", kv)
            rec = {**row(att, ben), "any_denial": pct(ben["incidents_with_denial"], ben["incidents"])}
        else:
            oi = outcomes(arm, g, "agenticcyops", ("cyberops",), "", "Local4", V, R.get(arm, []))
            att = [t for t in oi["domains"]["cyberops"]["attack"] if (t["ap"], t["variant"]) in kv]
            rec = {**row(att, Counter(oi["domains"]["cyberops"]["benign"])), **_any_denial(g, oi)}
        rec["judged"] = judged_fraction(g, "agenticcyops", ("cyberops",), {"cyberops": kv})["attack"]["judged_pct"]
        out[f"minus_P{i}"] = rec
    return out


def _any_denial(group: str, o: dict) -> dict:
    """Benign incidents with at least one denied tool proposal, under the
    replayed decisions (``benign_by_scenario`` holds per-trial counts)."""
    per = o["domains"]["cyberops"].get("benign_trials") or {}
    if per:
        n = len(per)
        return {"any_denial": pct(sum(1 for v in per.values() if v[0] > 0), n)}
    return {}


def write_md(res: dict) -> None:
    L = ["# The reported boundary (post-audit), Qwen3-235B, Local4", "",
         "Generated by `python -m analysis.replay_reported tables`. CyberOps at defense-freeze-v3.2; "
         "healthcare, finance, legal at v3.1 with AP-9 and JUDGEONLY re-run at v3.1.4. FLAT, ACL, NOJUDGE "
         "as run; JUDGEONLY and FULL as the direct outcome under Local4 (live local2 in parentheses); "
         "JUDGEREST = FULL with every rule-surviving call judged. ASR % [95% CI]; benign denied = "
         "legitimate tool proposals denied or escalated %. Previous = the v3.1 boundary before the audit.", ""]
    for d, r in res["domains"].items():
        L += [f"## {d} ({res['freeze'][d]})", "",
              "| Config | ASR | Attempt % | Block given attempt % | Benign denied % | Previous (v3.1) |",
              "|---|---|---|---|---|---|"]
        for label in ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL", "JUDGEREST"):
            x = r[label]
            live = f" ({x['live_local2']['asr']})" if "live_local2" in x else ""
            L.append(f"| {label} | {x['asr']}{live} | {x['attempt']} | {x['block_given_attempt']} | "
                     f"{x['benign_denied']} | {r['previous_v31'].get(label, '') or ''} |")
        for label in ("FULL", "JUDGEONLY"):
            j = r[label]["judged"]
            L.append(f"\n{label} judged fraction: attack {j['attack']['judged_pct']}%, benign "
                     f"{j['benign']['judged_pct']}%; rule-denied attack {j['attack']['rule_denied_pct']}%; "
                     f"allowed without P3: attack {j['attack']['allowed_no_p3_pct']}%, benign "
                     f"{j['benign']['allowed_no_p3_pct']}%.")
        L.append("")
    for name in ("all_four", "other_three"):
        L.append(f"Pooled, {name.replace('_', ' ')}: " + ", ".join(f"{k} {v}" for k, v in res[name].items()))
    L += ["", "## Leave-one-out (CyberOps, v3.2)", "",
          "| Arm | ASR | Attempt % | Block given attempt % | Judged % | Benign denied % | Any denial % |",
          "|---|---|---|---|---|---|---|"]
    for k, x in res["ablation"].items():
        L.append(f"| {k} | {x['asr']} | {x['attempt']} | {x['block_given_attempt']} | {x.get('judged')} | "
                 f"{x['benign_denied']} | {x.get('any_denial', '')} |")
    (BASE_DIR / "results" / "reported_boundary.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["build", "tables"])
    a = ap.parse_args()
    build() if a.cmd == "build" else print(json.dumps(tables(), indent=1)[:4000])
