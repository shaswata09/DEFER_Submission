"""Paper tables from the v3 results (H12).  ``make paper-tables`` runs
parse_logs -> statistical_tests -> this script.

Reads ``results/eval_attacks/all_trials.csv`` and ``stats.csv`` (plus the ASB
``summary.csv`` files when present) and writes ``results/paper_tables.md``
with:

  T1  headline per group x config: ASR [Wilson 95% CI], attempt rate,
      block rate given attempt, paired difference vs DEFER
  T2  per attack path x config for the main group (all domains pooled and
      CyberOps alone), Holm-corrected paired p-values
  T3  benign utility (E1): task completion, any-denial rate, denials per
      incident, latency, tokens
  T4  ablations (E3): ASR and benign denial rate per ablation config
  T5  what blocked the attacks: blocked_by distribution under DEFER
  T6  ASB paired panel replay (E6) when the replay outputs exist
  T7  cost: tokens and latency per config
  T8  run provenance (runs.csv)

Usage::

    python -m analysis.generate_tables [--main-group q235_div4]
"""

from __future__ import annotations

import argparse
import csv
import math
from collections import Counter, defaultdict
from pathlib import Path

from analysis.statistical_tests import MEASURABLE, SYSTEM_CONFIGS, wilson
from config import BASE_DIR, RESULTS_DIR
from analysis.runlogs import run_logs
from analysis import tiers

CONFIG_LABEL = {"flat": "Flat", "acl_hardened": "ACL-Hardened", "agenticcyops": "DEFER",
                "llm_judge": "LLM-judge only", "symbolic_only": "Symbolic only (no L6)"}
AP_LABEL = {"ap1": "AP-1 Tool redirection", "ap2": "AP-2 Memory poisoning", "ap3": "AP-3 Confused deputy",
            "ap4": "AP-4 Cross-phase leak", "ap5": "AP-5 Irreversible action", "ap6": "AP-6 Replay",
            "ap7": "AP-7 Action chain", "ap8": "AP-8 Parameter manipulation", "ap9": "AP-9 Handoff poisoning",
            "ap10": "AP-10 Validator manipulation", "ap11": "AP-11 Operational context",
            "ap12": "AP-12 Concurrent actions", "ap13": "AP-13 Adversarial memory",
            "ap14": "AP-14 Read injection", "ap15": "AP-15 Infrastructure integrity"}


def _read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _f(x, digits=1, pct=True):
    try:
        v = float(x)
    except (TypeError, ValueError):
        return "–"
    if math.isnan(v):
        return "–"
    return f"{100 * v:.{digits}f}" if pct else f"{v:.{digits}f}"


def _ci(p, lo, hi):
    if _f(p) == "–":
        return "–"
    return f"{_f(p)} [{_f(lo)}, {_f(hi)}]"


def _ap_sort(ap):
    return int(ap.replace("ap", "")) if ap.startswith("ap") and ap[2:].isdigit() else 99


def _md(headers: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


# --------------------------------------------------------------------- #


TAGGED = ("_smoke", "_debug", "_persistent", "persist")   # v3.1: ..._v31persist(2)
# the main run of each primary model; the pooled channel table uses only these
# (the E2/E9/E16 arms and the outage run measure other things)
PRIMARY_GROUPS = ("q235_div4", "scout_div4", "mistral_div3p", "llama8b_div4")


def _rel(path: Path) -> str:
    """Repo-relative path for the header (never absolute)."""
    try:
        return str(Path(path).resolve().relative_to(BASE_DIR.resolve()))
    except ValueError:
        return Path(path).name


def _is_tagged(group: str) -> bool:
    """Smoke / debug / persistent runs are separate run tags, not groups."""
    return any(t in group for t in TAGGED)


def t1_headline(stats: list[dict]) -> str:
    rows = []
    for r in stats:
        if r["domain"] != "all" or r["ap"] != "all" or _is_tagged(r["group"]):
            continue
        for cfg in SYSTEM_CONFIGS:
            cmp_key = {"flat": "flat_minus_aco", "acl_hardened": "acl_minus_aco"}.get(cfg)
            diff = (f"{_f(r.get(cmp_key + '_diff'))} pp [{_f(r.get(cmp_key + '_low'))}, {_f(r.get(cmp_key + '_high'))}], p={_f(r.get(cmp_key + '_p'), 3, False)}"
                    if cmp_key and r.get(cmp_key + "_clusters") not in (None, "", "0") else "—")
            rows.append([r["group"], CONFIG_LABEL[cfg], r.get(f"{cfg}_n", ""),
                         _ci(r.get(f"{cfg}_asr"), r.get(f"{cfg}_wilson_low"), r.get(f"{cfg}_wilson_high")),
                         f"[{_f(r.get(f'{cfg}_boot_low'))}, {_f(r.get(f'{cfg}_boot_high'))}]",
                         _f(r.get(f"{cfg}_attempt_rate")), _f(r.get(f"{cfg}_attempt_given_exposure")),
                         _f(r.get(f"{cfg}_exposure_rate")),
                         _f(r.get(f"{cfg}_block_given_attempt")), diff])
    return _md(["Group", "Config", "N", "ASR % [Wilson 95%]", "Cluster bootstrap 95%", "Attempt %",
                "Attempt given exp. %", "Exposed %", "Block given attempt %", "Δ vs DEFER"], rows)


def t2_per_ap(stats: list[dict], group: str, domain: str) -> str:
    rows = []
    for r in sorted((r for r in stats if r["group"] == group and r["domain"] == domain and r["ap"] != "all"),
                    key=lambda r: _ap_sort(r["ap"])):
        rows.append([AP_LABEL.get(r["ap"], r["ap"])]
                    + [f"{_ci(r.get(f'{c}_asr'), r.get(f'{c}_wilson_low'), r.get(f'{c}_wilson_high'))} (n={r.get(f'{c}_n')})"
                       for c in SYSTEM_CONFIGS]
                    + [f"{_f(r.get('flat_attempt_rate'))} / {_f(r.get('flat_attempt_given_exposure'))}"]
                    + [f"{_f(r.get('flat_minus_aco_diff'))} (p_holm={_f(r.get('flat_minus_aco_p_holm'), 3, False)})",
                       f"{_f(r.get('acl_minus_aco_diff'))} (p_holm={_f(r.get('acl_minus_aco_p_holm'), 3, False)})"])
    return _md(["Attack path"] + [f"{CONFIG_LABEL[c]} ASR %" for c in SYSTEM_CONFIGS]
               + ["Flat attempt % (all / exposed)", "Flat − ACO (pp)", "ACL − ACO (pp)"], rows)


def t3_benign(trials: list[dict]) -> str:
    rows = []
    by = defaultdict(list)
    for t in trials:
        if (t["ap"] == "benign" and t["outcome"] == "benign" and not t.get("suffix")
                and not _is_tagged(t["group"])):
            by[(t["group"], t["config"])].append(t)
    for (group, cfg), ts in sorted(by.items()):
        n = len(ts)
        task = [t for t in ts if t.get("task_completed") not in ("", None)]
        tc = sum(1 for t in task if str(t["task_completed"]).lower() == "true")
        any_den = sum(1 for t in ts if int(t.get("collateral_denials") or 0) > 0)
        den = sum(int(t.get("collateral_denials") or 0) for t in ts)
        lat = sorted(float(t.get("latency_s") or 0) for t in ts)
        ptok = sum(int(t.get("primary_tokens") or 0) for t in ts) / n
        vtok = sum(int(t.get("validator_tokens") or 0) for t in ts) / n
        p, lo, hi = wilson(tc, len(task))
        q, qlo, qhi = wilson(any_den, n)
        rows.append([group, CONFIG_LABEL.get(cfg, cfg), n, _ci(p, lo, hi), _ci(q, qlo, qhi),
                     f"{den / n:.2f}", f"{lat[n // 2]:.1f} / {lat[int(0.95 * (n - 1))]:.1f}",
                     f"{ptok:.0f} / {vtok:.0f}"])
    return _md(["Group", "Config", "N", "Task completed % [95%]", "Any denial % [95%]",
                "Denials / incident", "Latency s median / p95", "Tokens primary / validator"], rows)


def t3b_persistent(trials: list[dict], group: str) -> str:
    """E1b: benign incidents run after 30 attack incidents with state kept
    (persistent) vs the same scenarios with per-trial isolation."""
    rows = []
    # Two independent carry-over passes (W6 asked for n=2 so the effect can be
    # read as a range rather than a point). Pass 2 walks the attack paths in
    # reverse order, so any drift that is really an artefact of one particular
    # sequence shows up as a difference between the passes.
    arms = (("isolated", group, True),
            ("persistent (pass 1)", f"{group}_persistent", False),
            ("persistent (pass 2, reversed)", f"{group}_persistent3", False))
    for dom in ("cyberops", "healthcare", "finance", "legal"):
        for label, g, first_trial_only in arms:
            ts = [t for t in trials if t["group"] == g and t["domain"] == dom and t["config"] == "agenticcyops"
                  and t["ap"] == "benign" and t["outcome"] == "benign" and not t.get("suffix")
                  and (not first_trial_only or str(t["trial"]) == "1")]
            if not ts:
                continue
            n = len(ts)
            any_den = sum(1 for t in ts if int(t.get("collateral_denials") or 0) > 0)
            task = [t for t in ts if t.get("task_completed") not in ("", None)]
            tc = sum(1 for t in task if str(t["task_completed"]).lower() == "true")
            p, lo, hi = wilson(any_den, n)
            q, qlo, qhi = wilson(tc, len(task))
            # first vs second half of the scenario list = early vs late position in the sequence
            ts_sorted = sorted(ts, key=lambda t: int(t["variant"]))
            half = max(1, n // 2)
            early = sum(1 for t in ts_sorted[:half] if int(t.get("collateral_denials") or 0) > 0) / half
            late = sum(1 for t in ts_sorted[half:] if int(t.get("collateral_denials") or 0) > 0) / max(1, n - half)
            rows.append([dom, label, n, _ci(p, lo, hi), f"{sum(int(t.get('collateral_denials') or 0) for t in ts) / n:.2f}",
                         _ci(q, qlo, qhi), f"{100 * early:.0f} / {100 * late:.0f}"])
    if not rows:
        return "_no persistent-state run found_"
    return _md(["Domain", "State mode", "N", "Any denial % [95%]", "Denials / incident",
                "Task completed % [95%]", "Any denial %: first half / second half of sequence"], rows)


def t4_ablations(trials: list[dict], group: str) -> str:
    rows = []
    by = defaultdict(list)
    # compare with Full / llm_judge / symbolic_only on the domains the ablations ran on
    abl_domains = {t["domain"] for t in trials if t["group"] == group and t.get("suffix")}
    for t in trials:
        if t["group"] != group or (abl_domains and t["domain"] not in abl_domains):
            continue
        label = (f"agenticcyops {t['suffix'].replace('_disabled_', '-')}" if t.get("suffix")
                 else t["config"])
        if t.get("suffix") or t["config"] in ("llm_judge", "symbolic_only", "agenticcyops"):
            by[label].append(t)
    for label, ts in sorted(by.items()):
        att = [t for t in ts if t["ap"] != "benign" and t["outcome"] in MEASURABLE]
        ben = [t for t in ts if t["ap"] == "benign" and t["outcome"] == "benign"]
        k = sum(1 for t in att if t["outcome"] == "executed")
        p, lo, hi = wilson(k, len(att))
        bd = sum(1 for t in ben if int(t.get("collateral_denials") or 0) > 0)
        q, qlo, qhi = wilson(bd, len(ben))
        rows.append([CONFIG_LABEL.get(label, label), len(att), _ci(p, lo, hi), len(ben), _ci(q, qlo, qhi)])
    return _md(["Ablation config", "Attack trials", "ASR % [95%]", "Benign trials", "Benign any-denial % [95%]"], rows)


def t5_blocked_by(trials: list[dict], group: str) -> str:
    c = Counter(t["blocked_by"] for t in trials
                if t["group"] == group and t["config"] == "agenticcyops" and t["outcome"] == "blocked" and not t.get("suffix"))
    total = sum(c.values()) or 1
    return _md(["Layer", "Blocked trials", "Share %"],
               [[m, n, f"{100 * n / total:.1f}"] for m, n in c.most_common()])


def t6_asb(results_dir: Path) -> str:
    rows = []
    for summ in sorted((results_dir / "asb").glob("e2e_validator_group_*/general/summary.csv")):
        run = summ.parent.parent.name.replace("e2e_validator_group_", "")
        for r in _read(summ):
            rows.append([run, r.get("attack_subtype"), r.get("config"), r.get("n"),
                         r.get("llm_asr_pct"), r.get("defended_asr_pct")])
    if not rows:
        return "_no ASB e2e / replay outputs under results/asb_"
    return _md(["Run (group[_panel])", "Attack subtype", "Config", "N", "LLM ASR %", "Defended ASR %"], rows)


def t7_cost(trials: list[dict]) -> str:
    rows = []
    by = defaultdict(list)
    for t in trials:
        if (t["ap"] != "benign" and t["outcome"] in MEASURABLE and not t.get("suffix")
                and not _is_tagged(t["group"])):
            by[(t["group"], t["config"])].append(t)
    for (group, cfg), ts in sorted(by.items()):
        n = len(ts)
        lat = sorted(float(t.get("latency_s") or 0) for t in ts)
        rows.append([group, CONFIG_LABEL.get(cfg, cfg), n,
                     f"{sum(int(t.get('primary_tokens') or 0) for t in ts) / n:.0f}",
                     f"{sum(int(t.get('validator_tokens') or 0) for t in ts) / n:.0f}",
                     f"{lat[n // 2]:.1f} / {lat[int(0.95 * (n - 1))]:.1f}"])
    return _md(["Group", "Config", "N", "Primary tokens / trial", "Validator tokens / trial", "Latency s median / p95"], rows)


def t8_runs(runs: list[dict]) -> str:
    experiments = [r for r in runs
                   if not any(t in r["group"] for t in ("_smoke", "_debug"))]

    # A freeze tag is supposed to name one tree. defense-freeze-v2.2 does not:
    # it was re-cut onto a later commit after six runs had already used it, and
    # the move changed a frozen file (attacks/harness.py). Rather than print one
    # commit and hide the other, find every tag that resolves to more than one
    # commit and qualify it, so a reader can check out what each run used.
    shas_per_tag: dict[str, set[str]] = {}
    for r in experiments:
        tag, sha = r.get("freeze_tag") or "", (r.get("git_sha") or "")[:10]
        if tag and sha:
            shas_per_tag.setdefault(tag, set()).add(sha)
    ambiguous = {t: s for t, s in shas_per_tag.items() if len(s) > 1}

    def tag_of(r: dict) -> str:
        tag, sha = r.get("freeze_tag") or "", (r.get("git_sha") or "")[:10]
        return f"{tag} @{sha}" if tag in ambiguous else tag

    # The git sha is part of the identity: two runs of the same cell against
    # different trees are two provenance rows, not one.
    seen = {}
    for r in experiments:
        seen[(r["group"], r["domain"], r["config"], r.get("suffix", ""),
              (r.get("git_sha") or "")[:10])] = r
    rows = [[r["group"], r["domain"], r["config"], r.get("suffix") or "", (r.get("git_sha") or "")[:10],
             tag_of(r), r.get("primary_model") or "", r.get("primary_quantization") or "",
             r.get("consensus_config") or "", r.get("primary_temperature") or "", r.get("state_mode") or "",
             r.get("vllm_version") or ""] for r in sorted(seen.values(), key=lambda r: (r["group"], r["domain"], r["config"], (r.get("git_sha") or "")))]
    table = _md(["Group", "Domain", "Config", "Suffix", "Git", "Freeze tag", "Primary", "Quant", "Panel", "T", "State", "vLLM"], rows)
    if ambiguous:
        notes = "\n".join(
            f"- `{t}` resolves to {len(s)} commits in this data ({', '.join(sorted(s))}); "
            "rows above are qualified with the commit actually used."
            for t, s in sorted(ambiguous.items()))
        table += "\n\n**Freeze tags that do not name a single tree:**\n\n" + notes + "\n"
    return table


CHANNEL_LABEL = {"tool_response": "Tool response", "memory": "Memory", "alert_text": "Alert text",
                 "handoff": "Handoff", "proposal_justification": "Proposal justification"}
_EXPOSED = lambda t: str(t.get("exposed", "")).lower() == "true"           # noqa: E731
_KNOWN = lambda t: str(t.get("exposed", "")).lower() in ("true", "false")  # noqa: E731
_ATT = lambda t: t["outcome"] in ("executed", "blocked")                   # noqa: E731
_CLUS = lambda t: f"{t['domain']}:{t['ap']}:{t['variant']}"               # noqa: E731


def _rate(ts, ind):
    return sum(1 for t in ts if ind(t)) / len(ts) if ts else float("nan")


def t9_channels(trials: list[dict], group=None) -> str:
    """Per delivery channel x config: variants, scored trials, exposed %,
    attempt %, attempt given exposure, ASR (Wilson CI)."""
    by = defaultdict(list)
    for t in trials:
        if t.get("suffix") or t["ap"] == "benign":
            continue
        if t["group"] != group if group else t["group"] not in PRIMARY_GROUPS:
            continue
        if t["outcome"] not in MEASURABLE or t["config"] not in SYSTEM_CONFIGS:
            continue
        by[(t.get("channel") or "?", t["config"])].append(t)
    rows = []
    for (ch, cfg), ts in sorted(by.items()):
        variants = len({_CLUS(t) for t in ts})
        known = [t for t in ts if _KNOWN(t)]
        exposed = [t for t in known if _EXPOSED(t)]
        k = sum(1 for t in ts if t["outcome"] == "executed")
        p, lo, hi = wilson(k, len(ts))
        rows.append([CHANNEL_LABEL.get(ch, ch), CONFIG_LABEL.get(cfg, cfg), variants, len(ts),
                     _f(_rate(known, _EXPOSED)) if known else "–",
                     _f(_rate(ts, _ATT)), _f(_rate(exposed, _ATT)) if exposed else "–",
                     _ci(p, lo, hi)])
    return _md(["Channel", "Config", "Variants", "N", "Exposed %", "Attempt %",
                "Attempt given exp. %", "ASR % [95%]"], rows)


def t9b_p5(trials: list[dict], results_dir: Path, group: str) -> str:
    """P5 evidence: AP-4/AP-14, ``group``, CyberOps -- ASR and block-given-
    attempt under Flat, ACL, Full, Full minus P5; the P5 check that first
    intercepted; and P5's benign cost (reads denied / redacted) per domain."""
    sel = [t for t in trials if t["domain"] == "cyberops" and t["ap"] in ("ap4", "ap14")
           and t["outcome"] in MEASURABLE
           and ((t["group"] == group and not t.get("suffix"))
                or (t["group"] == group and t.get("suffix") == "_disabled_P5"))]
    arms = [("Flat", "flat", ""), ("ACL-Hardened", "acl_hardened", ""),
            ("Full (DEFER)", "agenticcyops", ""), ("Full minus P5", "agenticcyops", "_disabled_P5")]
    rows = []
    for label, cfg, suf in arms:
        ts = [t for t in sel if t["config"] == cfg and (t.get("suffix") or "") == suf]
        if not ts:
            continue
        k = sum(1 for t in ts if t["outcome"] == "executed")
        att = [t for t in ts if _ATT(t)]
        bl = sum(1 for t in att if t["outcome"] == "blocked")
        p, lo, hi = wilson(k, len(ts))
        rows.append([label, len(ts), _ci(p, lo, hi),
                     _f(bl / len(att)) if att else "–"])
    out = [_md(["Arm (AP-4 + AP-14, CyberOps)", "N", "ASR % [95%]", "Block given attempt %"], rows)]
    # first interception by P5 check, under Full
    full_blocked = [t for t in sel if t["config"] == "agenticcyops" and not t.get("suffix")
                    and t["outcome"] == "blocked"]
    c = Counter(t["blocked_by"] for t in full_blocked if str(t["blocked_by"]).startswith("P5"))
    other = sum(1 for t in full_blocked if not str(t["blocked_by"]).startswith("P5"))
    lines = [f"- {m}: {n}" for m, n in c.most_common()]
    if other:
        lines.append(f"- blocked before P5 (other layer): {other}")
    out += ["", "First interception under Full (AP-4 + AP-14, CyberOps):", *(lines or ["- (none blocked)"])]
    # P5 benign cost per domain, from the group's trials.jsonl
    cost = _p5_benign_cost(results_dir, group)
    if cost:
        crows = [[dom, n, den, red] for dom, (n, den, red) in sorted(cost.items())]
        out += ["", "P5 benign cost (DEFER benign incidents):", "",
                _md(["Domain", "Benign incidents", "Incidents w/ a P5 read denial",
                     "Incidents w/ a P5 redaction"], crows)]
    return "\n".join(out)


def _p5_benign_cost(results_dir: Path, group: str) -> dict:
    """Benign incidents per domain and how many had a P5 read denied or a P5
    redaction, from the group's per-run trials.jsonl (parse_logs writes the
    p5_denied / p5_redacted attribution there)."""
    import json
    out: dict = {}
    base = results_dir / "eval_attacks" / f"group_{group}"
    if not base.exists():
        return out
    for dom_dir in sorted(base.iterdir()):
        tj = dom_dir / "trials.jsonl"
        if not tj.is_dir() and tj.exists():
            n = den = red = 0
            for line in open(tj):
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if d.get("ap") != "benign" or d.get("config") != "agenticcyops":
                    continue
                n += 1
                den += 1 if (d.get("p5_denied") or {}) else 0
                red += 1 if (d.get("p5_redacted") or {}) else 0
            if n:
                out[dom_dir.name] = (n, den, red)
    return out


def build(results_dir: Path, main_group: str) -> str:
    base = results_dir / "eval_attacks"
    trials = _drop_siblings(_read(base / "all_trials.csv"))
    stats = _read(base / "stats.csv")
    runs = _read(base / "runs.csv")
    groups = sorted({t["group"] for t in trials if not _is_tagged(t["group"])})
    if main_group not in groups and groups:
        main_group = groups[0]
    parts = ["# Paper tables (scoring v3)", "",
             f"Generated from `{_rel(base / 'all_trials.csv')}` ({len(trials)} trials, groups: {', '.join(groups) or 'none'}). "
             "ASR = executed / measurable trials; attempt = executed + blocked; not-measurable and error trials excluded. "
             "CIs: Wilson (per-trial) and cluster bootstrap over variants (B = 10,000). "
             "Paired differences resample variants shared by both arms; p-values are Holm-corrected within each domain's family of attack paths.",
             "", "## T1. Headline attack success by group and configuration", "", t1_headline(stats),
             "", f"## T2a. Per attack path, {main_group}, all domains", "", t2_per_ap(stats, main_group, "all"),
             "", f"## T2b. Per attack path, {main_group}, CyberOps", "", t2_per_ap(stats, main_group, "cyberops"),
             "", "## T3. Benign utility (E1)", "", t3_benign(trials),
             "", f"## T3b. Persistent-state sequence (E1b), DEFER, {main_group}", "",
             "Benign scenarios run after 30 attack incidents with all defense state kept, "
             "against the same scenarios under per-trial isolation (first trial of E1).", "",
             t3b_persistent(trials, main_group),
             "", f"## T4. Ablations (E3), {main_group}", "", t4_ablations(trials, main_group),
             "", f"## T5. Which layer blocked the attacks (DEFER, {main_group})", "", t5_blocked_by(trials, main_group),
             "", "## T6. ASB paired panel replay (E6)", "", t6_asb(results_dir),
             "", "## T7. Cost", "", t7_cost(trials),
             "", "## T8. Run provenance", "", t8_runs(runs),
             "", "## T9. Injection channels (pooled over the four primaries' main runs)", "",
             "Exposed % = share of scored trials with an injection_served event; "
             "attempt | exposed % is the attempt rate among exposed trials.", "",
             t9_channels(trials),
             "", f"## T9b. Injection channels, {main_group}", "", t9_channels(trials, main_group),
             "", f"## T10. P5 evidence (AP-4 + AP-14, {main_group}, CyberOps)", "",
             t9b_p5(trials, results_dir, main_group), "",
             f"## T11. Benign tool-proposal denial rate ({main_group})", "",
             "One definition, shared with Fig. 3(b) via `analysis/benign_cost.py`: denied "
             "tool proposals / all tool proposals, matched on `call_id`, isolated benign "
             "runs. The numerator is a subset of the denominator by construction, so this "
             "does not mix tool denials with memory-op denials the way a per-trial "
             "`collateral_denials` count does.", "",
             t11_benign_denials(main_group), "",
             f"## T12. Benign denials by principle and check ({main_group}, DEFER)", "",
             "E14: every benign denial attributed to the check that made it, with the tools "
             "or stores it denied most. The LLM panel is separated from the deterministic "
             "P3 layers; the gate event that merely surfaces a panel rejection is not "
             "counted twice.", "",
             t12_benign_denials_by_check(main_group), "",
             f"## T13. Checks by tier: what each intercepts and what it costs ({main_group})", "",
             "One tier mapping (`analysis/tiers.py`) shared with the figures. "
             "Content-independent rules decide from structure alone and cannot be reworded "
             "past; content-dependent rules read the proposal and can be; similarity is the "
             "tunable embedding tier; the panel is the judges. P2.2 (target not in evidence) "
             "has a substring and a cosine branch that the committed logs do not tell apart; "
             "it is counted as content-dependent here.", "",
             t13_tier_breakdown(trials, main_group), "",
             f"## T14. Where P3 decisions were taken ({main_group})", "",
             "E1.3: the paper states no proposal was ever auto-approved. The logs show the "
             "stronger fact -- the deterministic gate never decided at all, so every "
             "consequential proposal that survived the deterministic denials reached the "
             "panel (or, under symbolic-only, was escalated).", "",
             t14_p3_decisions(main_group), "",
             "## T16. Validator availability: which results an out-of-credit API validator decided", "",
             "GPT-4o was unavailable from about 09:00 UTC on 20 September and Claude Sonnet 4.5 from about "
             "15:00 UTC on 22 September, both until about 18:00 UTC on 23 September; the panel counted "
             "their errors as rejections. A round is open when the missing votes could have changed its "
             "outcome; the direct bound credits every open panel rejection of an attack proposal as an "
             "approval (analysis/outage.py).", "",
             t16_validator_availability(main_group), ""]
    return "\n".join(parts)


def t11_benign_denials(group: str) -> str:
    """E7: the canonical benign denial rate, per domain and configuration."""
    from analysis.benign_cost import DOMAINS as BC_DOMAINS, benign_denial_rates, proposal_denials

    from analysis.benign_cost import denial_rate_ci

    configs = ("flat", "acl_hardened", "agenticcyops")
    rates = benign_denial_rates(group, configs)
    rows = []
    for dom in (*BC_DOMAINS, "all"):
        row = [dom if dom != "all" else "**all domains**"]
        for cfg in configs:
            d, p, r = rates.get((dom, cfg), (0, 0, float("nan")))
            if not p:
                row.append("-")
                continue
            if dom == "all":
                row.append(f"{100 * r:.1f} ({d}/{p})")
            else:
                # E20: interval bootstrapped over benign scenarios
                pt, lo, hi, ns = denial_rate_ci(group, dom, cfg)
                row.append(f"{100 * pt:.1f} [{100 * lo:.1f}, {100 * hi:.1f}] ({d}/{p}, k={ns})")
        rows.append(row)
    table = _md(["Domain"] + [f"{CONFIG_LABEL.get(c, c)} denied % [95%]" for c in configs], rows)

    # Every added arm is its own row, keyed on its exact config string and
    # read from the group its runs belong to (run_groups.yaml). Pooling them
    # into agenticcyops is what made CyberOps FULL read 27.7 % instead of 10.1 %.
    arm_rows = []
    for label, g, cfg in added_arms(group):
        for dom in BC_DOMAINS:
            d, p = proposal_denials(g, dom, cfg)
            if not p:
                continue
            pt, lo, hi, ns = denial_rate_ci(g, dom, cfg)
            arm_rows.append([label, f"`{cfg}`", g, dom,
                             f"{100 * pt:.1f} [{100 * lo:.1f}, {100 * hi:.1f}] ({d}/{p}, k={ns})"])
    if arm_rows:
        table += ("\n\n**Added arms.** One row per arm and domain, each from its own runs.\n\n"
                  + _md(["Arm", "Config", "Group", "Domain", "Denied % [95%]"], arm_rows))
    return table


def added_arms(group: str) -> list[tuple[str, str, str]]:
    """(paper name, group, exact config) for every arm added after the main
    configurations, in the group its runs were routed to."""
    # The permissive gate's benign runs, and every run of its first rule, of
    # no auto-approve and of P2 + panel, took place while the API validators
    # were out of credit and the panel could not approve (T16); their benign
    # cost is not reported. Judged writes ran after credit was restored.
    return [("judged writes", f"{group}_e9", "agenticcyops_writejudge"),
            ("FULL, E9 re-run (baseline for judged writes)", f"{group}_e9", "agenticcyops")]


def t12_benign_denials_by_check(group: str) -> str:
    """E14: which check denied benign work, per domain, and on what."""
    from analysis.benign_cost import (DOMAINS as BC_DOMAINS, benign_denials_by_check,
                                      principle_of)

    rows = []
    for dom in BC_DOMAINS:
        by = benign_denials_by_check(group, dom)
        for mech, rec in sorted(by.items(), key=lambda kv: (-kv[1]["n"], kv[0])):
            targets = ", ".join(f"{t} ({c})" for t, c in rec["targets"]) or "-"
            rows.append([dom, principle_of(mech), mech.replace("_", " "), rec["n"], targets])
    if not rows:
        return "_no benign denials recorded_"
    return _md(["Domain", "Principle", "Check", "Denials", "Top denied targets"], rows)


def t13_tier_breakdown(trials: list[dict], group: str) -> str:
    """E19 / A2: every check, its tier, what it intercepts and what it costs.

    The tier comes from analysis/tiers.py, the one mapping the figures use too.
    A label that module does not map is listed under "unmapped" instead of
    being filed under a default tier.
    """
    from analysis import tiers
    from analysis.benign_cost import DOMAINS as BC_DOMAINS, benign_denials_by_check

    intercept: dict[str, int] = defaultdict(int)
    for t in trials:
        if (t["group"] == group and t["config"] == "agenticcyops" and not t.get("suffix")
                and t["ap"] != "benign" and t["outcome"] == "blocked" and t.get("blocked_by")):
            intercept[t["blocked_by"]] += 1
    denials: dict[str, int] = defaultdict(int)
    for dom in BC_DOMAINS:
        for mech, rec in benign_denials_by_check(group, dom).items():
            denials[mech] += rec["n"]

    order = (*tiers.TIERS, None)
    label = {**tiers.LABEL, None: "unmapped"}
    rows = []
    for mech in sorted(set(intercept) | set(denials),
                       key=lambda m: (order.index(tiers.tier_of(m)), -intercept.get(m, 0), m)):
        rows.append([label[tiers.tier_of(mech)], mech.replace("_", " "),
                     intercept.get(mech, 0), denials.get(mech, 0)])
    # tier totals make the cost/benefit per tier explicit
    rows.append(["**tier totals**", "", "", ""])
    for tier in order:
        i = sum(v for m, v in intercept.items() if tiers.tier_of(m) == tier)
        d = sum(v for m, v in denials.items() if tiers.tier_of(m) == tier)
        if tier is None and not (i or d):
            continue
        rows.append([f"**{label[tier]}**", "", f"**{i}**", f"**{d}**"])
    return _md(["Tier", "Check", "Attack first interceptions", "Benign denials"], rows)


def t16_validator_availability(group: str) -> str:
    """Which arms an unavailable API validator affected, and how much.

    See analysis/outage.py for the definitions. *Open*: trials with a panel
    round the missing votes decided. *Direct bound*: attack success if every
    open round in which the panel rejected the attack proposal had approved it.
    """
    import csv as _csv
    from analysis import outage

    trials = list(_csv.DictReader(open(outage.ALL_TRIALS)))
    tr = ("finance", "healthcare", "legal")
    arms = [("FULL, development", group, "agenticcyops", ("cyberops",), ""),
            ("FULL, transfer", group, "agenticcyops", tr, ""),
            ("JudgeOnly", group, "llm_judge", ("cyberops",), ""),
            *[(f"FULL minus P{i}", group, "agenticcyops", ("cyberops",), f"_disabled_P{i}") for i in (1, 2, 4, 5)],
            ("Llama-4-Scout, CyberOps", "scout_div4", "agenticcyops", ("cyberops",), ""),
            ("Llama-4-Scout, finance", "scout_div4", "agenticcyops", ("finance",), ""),
            ("Mistral-Small, CyberOps", "mistral_div3p", "agenticcyops", ("cyberops",), ""),
            ("Mistral-Small, finance", "mistral_div3p", "agenticcyops", ("finance",), ""),
            ("Llama-3.1-8B, CyberOps", "llama8b_div4", "agenticcyops", ("cyberops",), ""),
            ("Llama-3.1-8B, finance", "llama8b_div4", "agenticcyops", ("finance",), ""),
            ("permissive gate", group, "agenticcyops_gate_permissive", ("cyberops",), ""),
            ("no auto-approve (not reported)", f"{group}_outage", "agenticcyops_noautoapprove", ("cyberops",), ""),
            ("P2 + panel (not reported)", f"{group}_outage", "p2_judge", ("cyberops",), ""),
            ("E2 siblings and parents, FULL", f"{group}_e2", "agenticcyops", outage.DOMAINS, ""),
            ("judged writes (E9), FULL", f"{group}_e9", "agenticcyops", outage.DOMAINS, ""),
            ("judged writes (E9), writejudge", f"{group}_e9", "agenticcyops_writejudge", outage.DOMAINS, "")]
    rows = []
    for label, g, cfg, doms, suf in arms:
        a = outage.arm(g, cfg, doms, suf, trials=trials)
        if not a.n:
            continue
        rows.append([label, a.n, f"{100 * a.open_share:.1f}", f"{100 * a.asr:.1f}",
                     f"{100 * a.asr_direct_upper:.1f}", f"{100 * a.asr_determinate:.1f} ({a.n_determinate})"])
    return _md(["Arm", "Trials", "Open %", "ASR as run %", "Direct bound %", "ASR, determinate trials % (n)"], rows)


def t14_p3_decisions(group: str) -> str:
    """E1.3: where every P3 decision was actually taken, per configuration.

    The paper states from an ad hoc query that no proposal was ever
    auto-approved. This reproduces it from the logs, and reports the stronger
    fact: the deterministic gate never *decided* at all.
    """
    import glob
    import json as _json

    LAYER = {"L0.7": "adaptive consent (P3.7)", "L2": "auto-gate (P3.9)", "L6": "LLM panel (P3.10)"}
    by: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    # exactly this group (after run_groups.yaml routing) and exactly each
    # config from the run header -- not every directory whose name starts
    # with the group, nor every file whose name starts with the config
    files = [(cfg, f) for cfg in ("flat", "acl_hardened", "symbolic_only", "agenticcyops", "llm_judge")
             for d in ("cyberops", "finance", "healthcare", "legal")
             for f in run_logs(group, d, cfg)]
    for cfg, f in files:
        with open(f, errors="ignore") as fh:
            for ln in fh:
                if '"P3' not in ln:
                    continue
                try:
                    e = _json.loads(ln)
                except _json.JSONDecodeError:
                    continue
                m = str(e.get("mechanism") or "")
                if not m.startswith("P3") or e.get("action") == "consensus_vote":
                    continue
                lay = str(e.get("layer") or "")
                if lay in LAYER:
                    by[cfg][(LAYER[lay], m, str(e.get("auth_decision")))] += 1
    rows = []
    for cfg in ("flat", "acl_hardened", "symbolic_only", "agenticcyops", "llm_judge"):
        c = by.get(cfg)
        if not c:
            continue
        for (lay, m, dec), v in sorted(c.items(), key=lambda kv: -kv[1]):
            rows.append([CONFIG_LABEL.get(cfg, cfg), lay, m.replace("_", " "),
                         tiers.LABEL.get(tiers.tier_of(m), "—"), dec, v])
    auto = sum(v for c in by.values() for (lay, _m, _d), v in c.items() if "panel" not in lay)
    rows.append(["**all configs**", "**deterministic auto-decisions (P3.7 + P3.9)**", "", "", "", f"**{auto}**"])
    return _md(["Config", "Layer", "Mechanism", "Tier", "Decision", "Count"], rows)


def _drop_siblings(trials: list[dict]) -> list[dict]:
    """The runs from v3.1 on also carry the E2 rule-evading siblings; the
    tables count only the 75 reported variants per domain (the variants of the
    original runs, group q235_div4)."""
    from analysis.reported import carries_siblings
    orig = {(t["domain"], t["ap"], str(t["variant"])) for t in trials
            if t["group"] == "q235_div4" and t["ap"] != "benign" and not t.get("suffix")
            and t["config"] == "agenticcyops"}
    return [t for t in trials if not carries_siblings(t["group"]) or t["ap"] == "benign"
            or (t["domain"], t["ap"], str(t["variant"])) in orig]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    ap.add_argument("--main-group", default="q235_div4")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    text = build(args.results_dir, args.main_group)
    out = args.out or (args.results_dir / "paper_tables.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
