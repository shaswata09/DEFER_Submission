"""Post-hoc principle-disable ablation derived from existing attack-path
results, no re-run required.

What this gives you (free, ~30s) versus what requires a re-run:

  ✓ "How many trials did each P-layer uniquely catch?"
        Read straight off the Mechanism column of results.csv.
  ✓ "Upper-bound ASR if Pn were disabled"
        upper_bound_minus_Pn = (current_succ + Pn_caught) / total
        i.e. assume every Pn-catch becomes a success.  This is the
        worst-case counterfactual; some catches might still be caught
        by P_{n+1}/P_{n+2}/... downstream, which we did not observe
        because the chain stopped at Pn.
  ✗ "Exact ASR if Pn were disabled" -- requires re-run via
        attacks.harness --disable-principles Pn (the Python pipeline
        actually reaches the next layers when Pn is skipped).
  ✗ "Pn-only ASR" (single-principle isolation) -- requires re-run.

The upper-bound is sufficient for many paper claims:

  > "Removing P3 from DEFER would increase ASR by AT MOST X pp."

This is publishable without an additional sweep.

Inputs:
    results/eval_attacks/group_<G>/<domain>/results.csv   (one per (group, domain))

Outputs:
    results/eval_attacks/group_<G>/<domain>/ablation_from_logs.{csv,md}

CLI::

    python -m analysis.ablation_from_logs --groups A --domain cyberops
    python -m analysis.ablation_from_logs --groups A --domain all
    python -m analysis.ablation_from_logs --groups A,C,E --domain cyberops
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from config import BASE_DIR

ALL_DOMAINS = ("cyberops", "healthcare", "finance", "legal")
PRINCIPLES  = ("P1", "P2", "P3", "P4", "P5")


def _principle_of(mechanism: str) -> str:
    """Return 'P1'..'P5' if the mechanism string starts with that token,
    'agent_refused' / 'none' / 'other' otherwise."""
    if not isinstance(mechanism, str):
        return "other"
    m = mechanism.strip()
    for p in PRINCIPLES:
        if m.startswith(p + "_") or m == p:
            return p
    if m == "agent_refused":
        return "agent_refused"
    if m.startswith("not_measurable"):
        return "not_measurable"
    if m == "none" or m == "":
        return "none"
    return "other"


def _summary_for_csv(df: pd.DataFrame, group: str, domain: str) -> pd.DataFrame:
    """Per-group, per-domain ablation summary frame."""
    acy = df[df.Config == "agenticcyops"].copy()
    if acy.empty:
        return pd.DataFrame()
    # Scoring v2: trials whose criterion cannot be decided from the logs are
    # excluded from every rate (they are neither successes nor catches).
    if "Outcome" in acy.columns:
        acy = acy[~acy.Outcome.isin(["not_measurable", "error"])]
    else:
        acy = acy[~acy.Mechanism.astype(str).str.startswith("not_measurable")]
    if acy.empty:
        return pd.DataFrame()

    total = len(acy)
    current_succ = int(acy.Succeeded.sum())
    current_asr = round(100 * current_succ / total, 2)
    acy["principle"] = acy.Mechanism.map(_principle_of)
    counts = acy.principle.value_counts()

    rows: list[dict] = []
    rows.append({
        "group": group, "domain": domain,
        "kind": "baseline",
        "principle": "agenticcyops_full",
        "trials": total,
        "successes": current_succ,
        "asr_pct": current_asr,
        "delta_pct": 0.0,
        "note": "current full-stack DEFER ASR",
    })
    for p in PRINCIPLES:
        caught = int(counts.get(p, 0))
        upper_succ = current_succ + caught
        upper_asr = round(100 * upper_succ / total, 2)
        rows.append({
            "group": group, "domain": domain,
            "kind": "leave_one_out_upper_bound",
            "principle": f"-{p}",
            "trials": total,
            "successes": upper_succ,
            "asr_pct": upper_asr,
            "delta_pct": round(upper_asr - current_asr, 2),
            "note": (f"{p} caught {caught} trials; if P{p[-1]} were disabled "
                      f"and downstream layers caught NONE of them (worst case), "
                      f"ASR would rise from {current_asr}% to {upper_asr}% "
                      f"(+{round(upper_asr - current_asr, 2)}pp)"),
        })
    # Also surface non-Pn buckets so they're not lost
    for k in ("agent_refused", "none", "other"):
        if k in counts.index:
            rows.append({
                "group": group, "domain": domain,
                "kind": "context",
                "principle": k,
                "trials": total,
                "successes": int(counts[k]),
                "asr_pct": round(100 * int(counts[k]) / total, 2),
                "delta_pct": 0.0,
                "note": f"{k} fired on {int(counts[k])} trials",
            })
    return pd.DataFrame(rows)


def _md_section(df: pd.DataFrame, group: str, domain: str) -> str:
    if df.empty:
        return f"### Group {group} / {domain}\n\nNo agenticcyops trials in results.csv.\n"
    base = df[df.kind == "baseline"].iloc[0]
    out = [f"### Group {group} / {domain}", "",
            f"- Trials evaluated: **{int(base.trials):,}**",
            f"- Current DEFER ASR: **{base.asr_pct:.2f}%** ({int(base.successes)}/{int(base.trials)})",
            "",
            "**Upper-bound −Pn ASR (worst case if Pn disabled):**",
            "",
            "| ablation | Pn caught | upper-bound ASR | Δ vs full |",
            "|---|---:|---:|---:|"]
    for _, r in df[df.kind == "leave_one_out_upper_bound"].iterrows():
        caught = r.successes - base.successes
        out.append(f"| {r.principle} | {caught} | {r.asr_pct:.2f}% | +{r.delta_pct:.2f}pp |")
    if (df.kind == "context").any():
        out += ["", "**Context (non-P-layer outcomes):**", ""]
        for _, r in df[df.kind == "context"].iterrows():
            out.append(f"- `{r.principle}`: {int(r.successes)} trials ({r.asr_pct:.2f}%)")
    out.append("")
    return "\n".join(out)


def generate(groups: list[str], domains: list[str]) -> None:
    eval_root = BASE_DIR / "results" / "eval_attacks"
    md_parts = ["# Post-hoc principle-disable ablation",
                 "",
                 "Upper-bound counterfactual derived from existing "
                 "`results.csv` (no re-run).  Each row assumes a Pn-catch "
                 "becomes a success when Pn is disabled -- a worst-case "
                 "bound; the true ablation requires a re-run with "
                 "`attacks.harness --disable-principles Pn`.",
                 ""]
    all_dfs: list[pd.DataFrame] = []

    for g in groups:
        for d in domains:
            csv_path = eval_root / f"group_{g}" / d / "results.csv"
            if not csv_path.exists():
                print(f"[skip] no results.csv at {csv_path}")
                continue
            df = pd.read_csv(csv_path)
            summary = _summary_for_csv(df, group=g, domain=d)
            if summary.empty:
                print(f"[skip] {g}/{d}: no agenticcyops trials")
                continue
            out_dir = csv_path.parent
            summary.to_csv(out_dir / "ablation_from_logs.csv", index=False)
            md_parts.append(_md_section(summary, g, d))
            all_dfs.append(summary)
            print(f"[wrote] {out_dir / 'ablation_from_logs.csv'}")

    if all_dfs:
        # Consolidated MD per group (or root if multi-group)
        if len(groups) == 1:
            md_root = eval_root / f"group_{groups[0]}"
        else:
            md_root = eval_root
        md_path = md_root / "ablation_from_logs.md"
        md_path.write_text("\n".join(md_parts) + "\n")
        print(f"[wrote] {md_path}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--groups", default="A",
                    help="Comma-separated subset of {A,B,C,D,E,F}")
    ap.add_argument("--domain", default="cyberops",
                    help="One of {cyberops,healthcare,finance,legal} or 'all'")
    args = ap.parse_args()

    groups = [g.strip().upper() for g in args.groups.split(",") if g.strip()]
    if args.domain == "all":
        domains = list(ALL_DOMAINS)
    else:
        if args.domain not in ALL_DOMAINS:
            raise SystemExit(f"[fail] unknown domain: {args.domain}")
        domains = [args.domain]

    generate(groups=groups, domains=domains)


if __name__ == "__main__":
    main()
