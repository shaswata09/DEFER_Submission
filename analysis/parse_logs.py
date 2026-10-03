"""Rebuild results.csv (scoring v3) and run metadata from the JSONL logs (H12).

Every attack / benign run writes ``logs/<domain>_eval_attacks_<group>[_disabled_X]/
<config>_<ts>.jsonl``.  This script turns those logs into:

    results/eval_attacks/group_<group>[_disabled_X]/<domain>/results.csv   (v3 columns)
    results/eval_attacks/group_<group>[_disabled_X]/<domain>/trials.jsonl  (rows + oracle details)
    results/eval_attacks/all_trials.csv     every trial of every run, with group/domain/suffix
    results/eval_attacks/runs.csv           one row per log file: header fields (git SHA,
                                            freeze tag, model, panel, temperature, seed, state mode)

By default the ``trial_complete`` rows written at run time are used
(the oracle ran on the same events).  ``--rescore`` re-runs the effects
oracle on the events with the payloads now on disk.

Usage::

    python -m analysis.parse_logs                 # every run under LOGS_DIR
    python -m analysis.parse_logs --group q235_div4 --domain cyberops
    python -m analysis.parse_logs --rescore
"""

from __future__ import annotations

import argparse
import csv
import json
import functools
import re
from collections import defaultdict
from pathlib import Path

from attacks.harness import RESULT_COLUMNS
from config import LOGS_DIR, RESULTS_DIR
from logging_utils.run_metadata import HEADER_FIELDS
from analysis.runlogs import load_run_groups

DOMAINS = ("cyberops", "healthcare", "finance", "legal")
_DIR_RE = re.compile(r"^(cyberops|healthcare|finance|legal)_eval_attacks_(.+?)(_disabled_[A-Z0-9]+)?$")
# the run directory names the run (group carries the run tag, e.g. _persistent);
# the header's own group/config/domain are the same except for the tag
RUN_COLUMNS = ["log_file", "domain", "group", "suffix", "config"] + [
    k for k in HEADER_FIELDS if k not in ("domain", "group", "config")]


def units_of(runs: list[tuple[str, str, str, Path]],
             overrides: dict[str, str]) -> list[tuple[str, str, str, list[Path]]]:
    """Split each log directory into (domain, group, suffix, files) units,
    sending every file listed in ``overrides`` to its own group."""
    units: dict[tuple[str, str, str], list[Path]] = {}
    for domain, group, suffix, d in runs:
        for path in sorted(d.glob("*.jsonl")):
            g = overrides.get(f"{d.name}/{path.name}", group)
            units.setdefault((domain, g, suffix), []).append(path)
    return [(dom, g, suf, files) for (dom, g, suf), files in units.items()]


def discover_runs(logs_dir: Path = LOGS_DIR) -> list[tuple[str, str, str, Path]]:
    """(domain, group, suffix, dir) for every attack/benign log directory."""
    out = []
    if not logs_dir.exists():
        return out
    for d in sorted(logs_dir.iterdir()):
        m = _DIR_RE.match(d.name)
        if d.is_dir() and m and any(d.glob("*.jsonl")):
            out.append((m.group(1), m.group(2), m.group(3) or "", d))
    return out


def read_events(path: Path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


@functools.lru_cache(maxsize=None)
def _payload_channel(domain: str, ap: str, variant: int) -> str:
    """``meta.channel`` of a payload variant ("" when unknown / benign)."""
    if not str(ap).startswith("ap"):
        return ""
    from attacks.payload_schema import load_variants, meta_of
    vs = load_variants(domain, ap)
    if 0 < variant <= len(vs):
        return str(meta_of(vs[variant - 1]).get("channel") or "")
    return ""


def _p5_attribution(events: list[dict]) -> dict:
    """P5 activity of one trial (T9 P5 table): memory reads a P5 check denied,
    and reads returned with P5 field redaction / sanitization, by mechanism."""
    denied: dict[str, int] = {}
    redacted: dict[str, int] = {}
    for e in events:
        if e.get("action") != "memory_read":
            continue
        mech = str(e.get("mechanism") or "")
        if not mech.startswith("P5_"):
            continue
        if e.get("auth_decision") in ("deny", "escalate"):
            denied[mech] = denied.get(mech, 0) + 1
        elif mech in ("P5_field_filtering", "P5_injection_sanitization"):
            redacted[mech] = redacted.get(mech, 0) + 1
    return {"p5_denied": denied, "p5_redacted": redacted}


def parse_run_dir(domain: str, group: str, suffix: str, log_dir: Path | None,
                  rescore: bool = False, paths: list[Path] | None = None,
                  ) -> tuple[list[dict], list[dict], list[dict]]:
    """Returns (result rows, trial detail rows, run header rows).

    ``exposed`` and ``channel`` (T2) come from the ``trial_complete`` event;
    logs written before T2 carry neither, so ``channel`` falls back to the
    payload's ``meta.channel`` and ``exposed`` stays empty.
    """
    rows: dict[tuple, dict] = {}
    details: dict[tuple, dict] = {}
    runs: list[dict] = []
    events_by_trial: dict[str, list[dict]] = defaultdict(list)
    for path in (sorted(paths) if paths is not None else sorted(log_dir.glob("*.jsonl"))):
        for e in read_events(path):
            if e.get("action") == "run_header":
                runs.append({**{k: e.get(k) for k in HEADER_FIELDS}, "log_file": path.name,
                             "domain": domain, "group": group, "suffix": suffix})
                continue
            tid = e.get("trial_id")
            if tid:
                events_by_trial[tid].append(e)
            if e.get("action") == "trial_complete" and not rescore:
                key = (e.get("ap"), str(e.get("variant")), str(e.get("trial")), e.get("config"))
                row = {c: e.get(c, "") for c in RESULT_COLUMNS}
                row.update({"domain": domain, "group": group})
                if row.get("channel") in ("", None):
                    row["channel"] = _payload_channel(domain, str(e.get("ap")), int(e.get("variant") or 0))
                if row.get("exposed") is None:
                    row["exposed"] = ""
                rows[key] = row                      # last write wins (resumed runs)
                details[key] = {**row, "suffix": suffix, "details": e.get("details"),
                                "error": e.get("error"), "trial_id": tid,
                                **_p5_attribution(events_by_trial.get(tid, []))}
    if rescore:
        from analysis.reevaluate_logs import OfflineHarness, _load_payloads, _parse_trial_id
        from attacks.effects import evaluate_benign, trial_costs
        from attacks.harness import load_payloads
        payloads = _load_payloads(domain)
        benign = load_payloads(domain, "benign_alerts.json") or load_payloads(domain, "benign_workflows.json")
        harnesses: dict[str, OfflineHarness] = {}
        for tid, events in events_by_trial.items():
            parsed = _parse_trial_id(tid)
            if parsed is None:
                if "_benign_" not in tid:
                    continue
                # <domain>_benign_v<scenario>_t<trial>_<config>
                parts = tid.split("_")
                ap, vid, config = "benign", parts[2], "_".join(parts[4:])
                trial_num = int(parts[3].lstrip("t"))
                variant_num = int(vid.lstrip("v"))
                payload = benign[variant_num - 1] if 0 < variant_num <= len(benign) else {}
            else:
                ap, vid, trial_num, config = parsed
                variant_num = int(vid.split("_v")[-1])
                payload = payloads.get((ap, vid)) or {}
            h = harnesses.setdefault(config, OfflineHarness(config=config, group=group, domain=domain))
            h.set_trial_events(events)
            if ap == "benign":
                v = evaluate_benign(payload, events)
                lo = {**v.as_dict(), **trial_costs(events)}
            else:
                h.evaluate_success(ap, payload, {})
                lo = h.last_outcome
            header = next((e for e in events if e.get("action") == "run_header"), {})
            key = (ap, str(variant_num), str(trial_num), config)
            row = {"domain": domain, "ap": ap, "variant": variant_num, "trial": trial_num,
                   "config": config, "group": group, "outcome": lo.get("outcome", ""),
                   "blocked_by": lo.get("blocked_by", ""),
                   "collateral_denials": int(lo.get("collateral_denials") or 0),
                   "task_completed": "" if lo.get("task_completed") is None else lo.get("task_completed"),
                   "latency_s": round(lo.get("span_s") or 0.0, 3),
                   "primary_tokens": int(lo.get("primary_tokens") or 0),
                   "validator_tokens": int(lo.get("validator_tokens") or 0),
                   "seed": header.get("seed", ""),
                   "exposed": "" if lo.get("exposed") is None else lo.get("exposed"),
                   "channel": _payload_channel(domain, ap, variant_num)}
            rows[key] = row
            details[key] = {**row, "suffix": suffix, "details": lo.get("details"), "trial_id": tid}
    ordered = sorted(rows.values(), key=lambda r: (str(r["config"]), str(r["ap"]), int(r["variant"] or 0), int(r["trial"] or 0)))
    return ordered, list(details.values()), runs


def write_run(domain: str, group: str, suffix: str, rows: list[dict], details: list[dict],
              results_dir: Path = RESULTS_DIR) -> Path:
    out_dir = results_dir / "eval_attacks" / f"group_{group}{suffix}" / domain
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=RESULT_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    with open(out_dir / "trials.jsonl", "w") as f:
        for d in details:
            f.write(json.dumps(d, default=str) + "\n")
    return out_dir / "results.csv"


def reported_rows(rows: list[dict]) -> list[dict]:
    """Rows of the virtual reported group (analysis.reported): each reported
    (domain, path, config) cell taken from the member group that ran it."""
    from analysis.reported import COMPOSITION, REPORTED, member_for
    out = []
    for r in rows:
        d = r.get("domain")
        if r.get("suffix") or r.get("group") not in COMPOSITION.get(d, ()):
            continue
        if member_for(d, str(r.get("ap")), str(r.get("config"))) == r["group"]:
            out.append({**r, "group": REPORTED})
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--group", default=None)
    ap.add_argument("--domain", default=None)
    # v3.1.4: re-scoring is the default; a run's own trial_complete verdict was
    # computed by the oracle of its day (the v3.1 JUDGEONLY runs predate the
    # step-6 fix, every run predates the v3.1.4 effect-spec repairs)
    ap.add_argument("--rescore", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--logs-dir", type=Path, default=LOGS_DIR)
    ap.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    args = ap.parse_args()

    all_rows: list[dict] = []
    all_runs: list[dict] = []
    units = units_of(discover_runs(args.logs_dir), load_run_groups())
    # same order as the log directories, so all_trials.csv keeps its row order
    for domain, group, suffix, files in sorted(
            units, key=lambda u: f"{u[0]}_eval_attacks_{u[1]}{u[2]}"):
        if args.group and group != args.group:
            continue
        if args.domain and domain != args.domain:
            continue
        rows, details, runs = parse_run_dir(domain, group, suffix, None,
                                            rescore=args.rescore, paths=files)
        if not rows:
            continue
        path = write_run(domain, group, suffix, rows, details, args.results_dir)
        print(f"[{group}{suffix}/{domain}] {len(rows)} trials -> {path}")
        all_rows.extend({**r, "suffix": suffix} for r in rows)
        all_runs.extend(runs)

    if all_rows and not (args.group or args.domain):
        all_rows.extend(reported_rows(all_rows))

    if all_rows and (args.group or args.domain):
        # A filtered parse rebuilds only the selected per-run results; the
        # aggregate files span every group and are rewritten by a full parse.
        print(f"filtered parse ({len(all_rows)} rows): all_trials.csv / runs.csv left unchanged")
    elif all_rows:
        out = args.results_dir / "eval_attacks"
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "all_trials.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=RESULT_COLUMNS + ["suffix"], extrasaction="ignore")
            w.writeheader()
            w.writerows(all_rows)
        with open(out / "runs.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=RUN_COLUMNS, extrasaction="ignore")
            w.writeheader()
            for r in all_runs:
                w.writerow({k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in r.items()})
        print(f"wrote {out / 'all_trials.csv'} ({len(all_rows)} rows) and runs.csv ({len(all_runs)} log files)")
    else:
        print("no runs found")


if __name__ == "__main__":
    main()
