"""Static InjecAgent benchmark sweep.

Runs every (attack_family × variant × domain × config × case) combination
through the deterministic P1-P5 trial driver and produces the ASR
summary table.

Default sweep size
==================

  attack_families: dh, ds                   (2)
  variants:        base, enhanced           (2)
  domains:         cyberops / healthcare / finance / legal  (4)
  configs:         flat / acl_hardened / agenticcyops       (3)
  cases:           2,108                    (510 + 544 + 510 + 544)

Total attack-tool evaluations: ~2,108 × (avg 1.5 attacker tools) × 4 × 3
≈ 38,000 trials.  Completes in under a minute on CPU (no LLM calls).

Outputs
=======

* ``results/injecagent/injecagent_static_results.csv``  -- one row per
  (case × attacker_tool × domain × config) with allowed/mechanism/stage
* ``results/injecagent/injecagent_static_summary.csv``  -- ASR pivoted
  by (family, variant, domain, config)
* ``results/injecagent/injecagent_static_summary.md``    -- same as
  markdown
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from config import BASE_DIR

from benchmarks.injecagent.harness.trial_driver import (
    DefensePipeline, load_cases, run_case,
)

RESULTS_DIR = BASE_DIR / "results" / "injecagent" / "static"
DEFAULT_DOMAINS = ["cyberops", "healthcare", "finance", "legal"]
DEFAULT_CONFIGS = ["flat", "acl_hardened", "agenticcyops"]
DEFAULT_FAMILIES = ["dh", "ds"]
DEFAULT_VARIANTS = ["base", "enhanced"]


def run_sweep(
    domains: list[str],
    configs: list[str],
    families: list[str],
    variants: list[str],
    case_limit: int | None = None,
    embedding_model=None,
) -> list[dict]:
    """Run the full sweep and return per-trial records."""
    rows: list[dict] = []
    # Create one pipeline per (domain, config) combo (state is per-trial stateless
    # beyond in-memory registry extension).
    pipelines: dict[tuple[str, str], DefensePipeline] = {}
    for dom in domains:
        for cfg in configs:
            print(f"  building pipeline  domain={dom:10s}  config={cfg}")
            pipelines[(dom, cfg)] = DefensePipeline(
                domain=dom, config=cfg, embedding_model=embedding_model)

    for family in families:
        for variant in variants:
            cases = load_cases(family, variant)
            if case_limit:
                cases = cases[:case_limit]
            print(f"\n>> {family}-{variant}  {len(cases)} cases")
            for i, case in enumerate(cases):
                for (dom, cfg), pipe in pipelines.items():
                    for r in run_case(case, pipe):
                        r["family"] = family
                        r["variant"] = variant
                        r["case_idx"] = i
                        rows.append(r)
                if (i + 1) % 100 == 0:
                    print(f"   {family}-{variant}: {i+1}/{len(cases)} cases")
    return rows


# --------------------------------------------------------------------- #
#  Aggregation
# --------------------------------------------------------------------- #


def summarize(rows: list[dict]) -> list[dict]:
    """Produce an ASR-pivoted summary table.

    Key: (family, variant, domain, config) -> {n, asr_pct, n_blocked_by_principle}
    """
    from collections import defaultdict
    bucket = defaultdict(lambda: {"n": 0, "succ": 0, "mech_counts": defaultdict(int)})
    for r in rows:
        k = (r["family"], r["variant"], r["domain"], r["config"])
        b = bucket[k]
        b["n"] += 1
        if r["allowed"]:
            b["succ"] += 1
        mech = r["mechanism"]
        # Normalise to primary principle
        principle = _mechanism_to_principle(mech)
        b["mech_counts"][principle] += 1

    summary = []
    for (fam, var, dom, cfg), b in sorted(bucket.items()):
        asr = 100 * b["succ"] / b["n"] if b["n"] else 0.0
        summary.append({
            "family":  fam,
            "variant": var,
            "domain":  dom,
            "config":  cfg,
            "n":       b["n"],
            "succeeded": b["succ"],
            "blocked": b["n"] - b["succ"],
            "asr_pct": round(asr, 2),
            "mech_primary": max(b["mech_counts"], key=b["mech_counts"].get)
                             if b["mech_counts"] else "none",
            "mech_counts": dict(b["mech_counts"]),
        })
    return summary


def _mechanism_to_principle(mech: str) -> str:
    if mech in ("flat_no_defense",):   return "(flat no defense)"
    if mech in ("acl_no_deny",):       return "(acl no deny)"
    if mech in ("no_defense_fired",):  return "P1-P5 passed"
    if mech.startswith("P1") or "authenticated" in mech.lower(): return "P1"
    if mech.startswith("P2"): return "P2"
    if mech.startswith("P3"): return "P3"
    if mech.startswith("P4"): return "P4"
    if mech.startswith("P5"): return "P5"
    return "other"


# --------------------------------------------------------------------- #
#  Output writers
# --------------------------------------------------------------------- #


def write_detail_csv(rows: list[dict], out_dir: Path) -> Path:
    path = out_dir / "injecagent_static_results.csv"
    fields = ["family", "variant", "case_idx", "case_user_tool",
              "case_attack_type", "domain", "config",
              "attacker_tool_ia", "attacker_tool_orig",
              "allowed", "mechanism", "stage", "reason"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return path


def write_summary_csv(summary: list[dict], out_dir: Path) -> Path:
    path = out_dir / "injecagent_static_summary.csv"
    fields = ["family", "variant", "domain", "config", "n",
              "succeeded", "blocked", "asr_pct", "mech_primary"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in summary:
            w.writerow(r)
    return path


def write_summary_md(summary: list[dict], out_dir: Path) -> Path:
    path = out_dir / "injecagent_static_summary.md"
    lines = ["# InjecAgent Static Benchmark — ASR Summary\n"]
    lines.append("| Family | Variant | Domain | Config | n | ASR% | Primary mechanism |")
    lines.append("|---|---|---|---|---:|---:|---|")
    for r in summary:
        lines.append(
            f"| {r['family']} | {r['variant']} | {r['domain']} | "
            f"{r['config']} | {r['n']} | {r['asr_pct']:.1f} | {r['mech_primary']} |"
        )
    lines.append("")
    # Aggregate across variant/family per (domain, config)
    from collections import defaultdict
    agg = defaultdict(lambda: {"n": 0, "s": 0})
    for r in summary:
        k = (r["domain"], r["config"])
        agg[k]["n"] += r["n"]
        agg[k]["s"] += r["succeeded"]
    lines.append("\n## Aggregate across all 2,108 cases\n")
    lines.append("| Domain | Config | n | ASR% |")
    lines.append("|---|---|---:|---:|")
    for (dom, cfg), v in sorted(agg.items()):
        asr = 100 * v["s"] / v["n"] if v["n"] else 0.0
        lines.append(f"| {dom} | {cfg} | {v['n']} | {asr:.1f} |")
    path.write_text("\n".join(lines))
    return path


# --------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------- #


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", default=",".join(DEFAULT_DOMAINS))
    ap.add_argument("--configs", default=",".join(DEFAULT_CONFIGS))
    ap.add_argument("--families", default=",".join(DEFAULT_FAMILIES))
    ap.add_argument("--variants", default=",".join(DEFAULT_VARIANTS))
    ap.add_argument("--case-limit", type=int, default=None,
                    help="Cap cases per (family,variant) for a quick run.")
    ap.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    ap.add_argument("--embedding-model", type=str, default=None,
                    help="Optional path to a SentenceTransformer model. If set, "
                         "enables P2-L2/P4/P5 semantic checks.")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    model = None
    if args.embedding_model:
        from sentence_transformers import SentenceTransformer
        print(f"Loading embedding model: {args.embedding_model}")
        model = SentenceTransformer(args.embedding_model)

    rows = run_sweep(
        domains=args.domains.split(","),
        configs=args.configs.split(","),
        families=args.families.split(","),
        variants=args.variants.split(","),
        case_limit=args.case_limit,
        embedding_model=model,
    )
    summary = summarize(rows)

    detail = write_detail_csv(rows, args.out_dir)
    summ_csv = write_summary_csv(summary, args.out_dir)
    summ_md = write_summary_md(summary, args.out_dir)

    print(f"\nwrote  {detail}  ({len(rows)} rows)")
    print(f"wrote  {summ_csv}  ({len(summary)} aggregate rows)")
    print(f"wrote  {summ_md}")

    # Headline printout
    print("\n=== Aggregate ASR  (flat / acl_hardened / agenticcyops) ===")
    from collections import defaultdict
    agg = defaultdict(lambda: {"n": 0, "s": 0})
    for r in summary:
        k = (r["domain"], r["config"])
        agg[k]["n"] += r["n"]
        agg[k]["s"] += r["succeeded"]
    for (dom, cfg), v in sorted(agg.items()):
        asr = 100 * v["s"] / v["n"] if v["n"] else 0.0
        print(f"  {dom:10s}  {cfg:14s}  ASR={asr:6.2f}%  ({v['s']}/{v['n']})")


if __name__ == "__main__":
    main()
