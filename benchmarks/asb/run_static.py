"""Static (deterministic, no live LLM) ASB benchmark runner.

Mirror of ``benchmarks/injecagent/run_static.py`` but for ASB cases.
Drives every (case, attacker tool) through the DEFER P1-P5
defense pipeline under the **general** neutral domain (see
``domains/general/configs/``).  Records per-trial allow/deny + the
mechanism that fired, then writes:

  results/asb/asb_static_results.csv     -- one row per (case, attacker tool, config)
  results/asb/asb_static_summary.csv     -- pivoted ASR per (attack_type, config)
  results/asb/asb_static_summary.md      -- human-readable summary

Attack-type axes (from ASB):

  - DPI:  Direct Prompt Injection
  - IPI:  Indirect Prompt Injection (overlaps InjecAgent)
  - MP:   Memory Poisoning  (exercises P4)
  - PoT:  Plan-of-Thought Backdoor

Note on threat model
====================
We do not defend against training-time agent compromise (PoT
backdoors implant trojans in the agent's weights).  We measure
whether the *runtime malicious actions* a backdoored agent emits
get caught at the action layer -- the same evaluation we apply to
DPI/IPI.

Domain projection
=================
ASB scenarios are run **only** under ``domains/general/`` -- a single
neutral domain config (no industry-specific sensitive patterns or
operational context).  We do NOT cross-project to cyberops/healthcare/
finance/legal because ASB scenarios (e-commerce, autonomous driving,
academic advising, ...) don't naturally map to enterprise security
domains.  Paper claim: lower-bound on full-stack performance, since
domain-tuned layers (P3-L0.5, P5 sensitive patterns) are not exercised.

CLI
===
::

    python -m benchmarks.asb.run_static            # all attacks, all configs
    python -m benchmarks.asb.run_static --attacks DPI,IPI
    python -m benchmarks.asb.run_static --case-limit 50  # smoke-test subset

Prerequisites: a populated ``benchmarks/asb/data/cases/*.json`` and
``tools.json`` -- produce them via::

    ./benchmarks/asb/scripts/ingest_upstream.sh
    python -m benchmarks.asb.scripts.convert_cases
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

from config import BASE_DIR, MODELS_DIR

# We re-use the InjecAgent DefensePipeline since the per-case logic
# (build proposal, drive through P1-P5, return verdict) is identical
# at the symbolic layer.  ASB-specific glue is the tool overlay.
from benchmarks.injecagent.harness.trial_driver import DefensePipeline
from benchmarks.asb.harness.tool_loader import (
    load_asb_tools, resolve_case_tools, NAMESPACE_PREFIX,
)

DATA_DIR = Path(__file__).resolve().parent / "data"
CASES_DIR = DATA_DIR / "cases"
RESULTS_DIR = BASE_DIR / "results" / "asb"

ATTACK_FILES = {
    "DPI": "dpi.json",
    "IPI": "ipi.json",
    "MP":  "mp.json",
    "POT": "pot.json",        # canonical key (uppercase, matches run_e2e.py)
}
DEFAULT_ATTACKS = list(ATTACK_FILES)
DEFAULT_CONFIGS = ["flat", "acl_hardened", "agenticcyops"]


def load_cases(attack_type: str) -> list[dict]:
    path = CASES_DIR / ATTACK_FILES[attack_type]
    if not path.exists():
        raise SystemExit(
            f"[fail] No converted cases for {attack_type} at {path}.\n"
            "Run the ingest + convert pipeline first:\n"
            "  ./benchmarks/asb/scripts/ingest_upstream.sh\n"
            "  python -m benchmarks.asb.scripts.convert_cases\n")
    with open(path) as f:
        return json.load(f)


def _register_asb_tools_in_pipeline(pipe: DefensePipeline) -> None:
    """Inject ASB_* tools into the pipeline's auth registry overlay
    (in-memory only, never persisted), mirroring the IA_* mechanism.
    Must be called once per pipeline instance before evaluate()."""
    if pipe.auth is None:
        return
    reg = load_asb_tools()
    tools_section = pipe.auth._registry.setdefault("tools", {})
    dom_tools = tools_section.setdefault(pipe.domain, {})
    for asb_name, schema in reg["asb_name_to_schema"].items():
        dom_tools[asb_name] = {
            "description":            schema["description"],
            "category":               f"asb_{schema['scenario']}",
            "asb_benchmark":          True,
            "expected_response_keys": [],
        }


def run_case(case: dict, pipeline: DefensePipeline) -> list[dict]:
    """Drive every attacker-tool of the case through the pipeline."""
    resolved = resolve_case_tools(case)
    rows = []
    for asb_tool in resolved["attacker_tools"]:
        decision = pipeline.evaluate(case, asb_tool)
        rows.append({
            "asb_case_id":   case.get("asb_case_id", ""),
            "scenario":      case.get("scenario", ""),
            "attack_type":   case.get("attack_type", ""),
            "case_user_tool": case.get("User Tool"),
            "attacker_tool_asb": asb_tool,
            "config":        pipeline.config,
            "domain":        pipeline.domain,
            "allowed":       decision["allowed"],
            "mechanism":     decision["mechanism"],
            "stage":         decision["stage"],
            "reason":        decision["reason"],
        })
    return rows


def run_sweep(attacks: list[str],
              configs: list[str],
              case_limit: int | None,
              embedding_model=None) -> list[dict]:
    rows: list[dict] = []
    pipelines: dict[str, DefensePipeline] = {}
    for cfg in configs:
        pipelines[cfg] = DefensePipeline(
            domain="general", config=cfg, embedding_model=embedding_model)
        _register_asb_tools_in_pipeline(pipelines[cfg])

    for attack in attacks:
        cases = load_cases(attack)
        if case_limit:
            cases = cases[:case_limit]
        print(f"\n>> {attack}  {len(cases)} cases")
        for i, case in enumerate(cases):
            for cfg, pipe in pipelines.items():
                for r in run_case(case, pipe):
                    r["case_idx"] = i
                    rows.append(r)
            if (i + 1) % 100 == 0:
                print(f"   {attack}: {i+1}/{len(cases)} cases")
    return rows


def write_results(rows: list[dict], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    fields = ["attack_type", "scenario", "asb_case_id", "case_idx",
              "case_user_tool", "attacker_tool_asb",
              "domain", "config", "allowed", "mechanism", "stage", "reason"]
    det_path = out_dir / "asb_static_results.csv"
    with open(det_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)

    # Pivot: ASR per (attack_type, config) -- "allowed" means the attack got through
    pivot: dict[tuple, dict] = defaultdict(lambda: {"n": 0, "allowed": 0})
    for r in rows:
        k = (r["attack_type"], r["config"])
        pivot[k]["n"] += 1
        if r["allowed"]:
            pivot[k]["allowed"] += 1

    summ_fields = ["attack_type", "config", "n", "asr_pct"]
    summ_rows = []
    for (atk, cfg), v in sorted(pivot.items()):
        n = v["n"] or 1
        summ_rows.append({"attack_type": atk, "config": cfg,
                          "n": v["n"],
                          "asr_pct": round(100 * v["allowed"] / n, 2)})
    with open(out_dir / "asb_static_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=summ_fields)
        w.writeheader(); w.writerows(summ_rows)

    md_lines = ["# ASB static benchmark — summary", "",
                "| attack_type | config | n | ASR% |",
                "|---|---|---:|---:|"]
    for r in summ_rows:
        md_lines.append(f"| {r['attack_type']} | {r['config']} | {r['n']:,} | {r['asr_pct']:.2f}% |")
    (out_dir / "asb_static_summary.md").write_text("\n".join(md_lines) + "\n")

    print(f"\nwrote {det_path}")
    print(f"wrote {out_dir / 'asb_static_summary.csv'}")
    print(f"wrote {out_dir / 'asb_static_summary.md'}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--attacks", default=",".join(DEFAULT_ATTACKS),
                    help="Comma-separated subset of {DPI,IPI,MP,PoT}")
    ap.add_argument("--configs", default=",".join(DEFAULT_CONFIGS))
    ap.add_argument("--case-limit", type=int, default=None,
                    help="Cap #cases per attack (smoke-test mode).")
    ap.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    ap.add_argument("--embedding-model", type=str,
                    default=str(MODELS_DIR / "Qwen" / "Qwen3-Embedding-0.6B"),
                    help="Local SentenceTransformer for P2-L2 (set empty to disable)")
    args = ap.parse_args()

    attacks = [a.strip().upper() for a in args.attacks.split(",") if a.strip()]
    bad = [a for a in attacks if a not in ATTACK_FILES]
    if bad:
        sys.exit(f"[fail] unknown attack types: {bad}.  Valid: {list(ATTACK_FILES)}")
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]

    emb = None
    if args.embedding_model:
        from sentence_transformers import SentenceTransformer
        emb = SentenceTransformer(args.embedding_model)

    print(f"ASB static sweep:  attacks={attacks}  configs={configs}  domain=general")

    rows = run_sweep(attacks=attacks, configs=configs,
                     case_limit=args.case_limit, embedding_model=emb)
    write_results(rows, args.out_dir)

    # Headline print
    print("\n=== ASB static ASR (general domain) ===")
    print(f"{'attack':<10}{'config':<16}{'n':>6}{'ASR%':>10}")
    pivot: dict[tuple, dict] = defaultdict(lambda: {"n": 0, "allowed": 0})
    for r in rows:
        k = (r["attack_type"], r["config"])
        pivot[k]["n"] += 1
        if r["allowed"]:
            pivot[k]["allowed"] += 1
    for (atk, cfg), v in sorted(pivot.items()):
        n = v["n"] or 1
        print(f"{atk:<10}{cfg:<16}{v['n']:>6}{100*v['allowed']/n:>9.2f}")


if __name__ == "__main__":
    main()
