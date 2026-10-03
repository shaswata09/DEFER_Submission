"""End-to-end InjecAgent runner (static).

For a chosen model group, drive the 50-case representative subset
through:

  1.  The live primary LLM (group-specific) against a ReAct prompt
      that includes the poisoned tool response.
  2.  The parsed tool-call proposal through the P1-P5 defense stack.

Per (group, domain, config, case, trial) we record:

  * whether the LLM emitted an attacker tool call         (llm-level ASR)
  * whether P1-P5 would have blocked that call               (defense)
  * the overall end-to-end outcome (llm + defense combined)

Scope (defaults):

  50 cases (representative subset)  x  6 trials  x  3 configs
    x  4 domains  =  3,600 trials per group.

Outputs land under ``results/injecagent/e2e_validator_group_<G>/<domain>/``.

Usage::

  python -m benchmarks.injecagent.run_e2e --group A
  python -m benchmarks.injecagent.run_e2e --group D --trials 6 \\
        --domains cyberops,healthcare
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

from config import BASE_DIR, MODELS_DIR

from benchmarks.injecagent.harness.live_llm_driver import (
    GROUP_CONFIGS, run_live_trial,
)
from benchmarks.injecagent.harness.tool_loader import (
    load_injecagent_tools, resolve_case_tools,
)
from benchmarks.injecagent.harness.trial_driver import DefensePipeline
from logging_utils import ExperimentLogger
from logging_utils.run_metadata import build_run_header

HERE = Path(__file__).resolve().parent
CASES_PATH = HERE / "representative_cases.json"
RESULTS_DIR = BASE_DIR / "results" / "injecagent"

DEFAULT_DOMAINS = ["cyberops", "healthcare", "finance", "legal"]
DEFAULT_CONFIGS = ["flat", "acl_hardened", "agenticcyops"]


def load_cases(path: Path = CASES_PATH) -> list[dict]:
    if not path.exists():
        raise SystemExit(
            f"Representative subset not found: {path}\n"
            "Generate it first with:\n"
            "  python -m benchmarks.injecagent.representative_subset")
    with open(path) as f:
        return json.load(f)


# --------------------------------------------------------------------- #
#  Defense overlay on live-LLM output
# --------------------------------------------------------------------- #


async def apply_defense(case: dict, llm_action: Optional[str],
                         pipeline: DefensePipeline,
                         attacker_phase: str = "admin") -> dict:
    """Run the LLM-proposed action through the defense pipeline.

    Uses ``evaluate_with_consensus`` so the agenticcyops pipeline can
    escalate to P3-L6 LLM consensus when all symbolic layers pass.
    """
    if llm_action is None:
        return {"defense_evaluated": False, "defense_blocked": None,
                "defense_mechanism": None, "defense_stage": None}

    reg = load_injecagent_tools()
    orig_to_ia = reg["original_name_to_ia_name"]
    attacker_originals = case.get("Attacker Tools", []) or []

    target_original = None
    for t in attacker_originals:
        if t == llm_action or llm_action.startswith(t):
            target_original = t; break
    if target_original is None:
        return {"defense_evaluated": False, "defense_blocked": None,
                "defense_mechanism": None, "defense_stage": None}
    ia_tool = orig_to_ia.get(target_original)
    if ia_tool is None:
        return {"defense_evaluated": False, "defense_blocked": None,
                "defense_mechanism": None, "defense_stage": None}

    decision = await pipeline.evaluate_with_consensus(
        case, ia_tool, attacker_phase=attacker_phase)
    return {
        "defense_evaluated": True,
        "defense_blocked":   not decision["allowed"],
        "defense_mechanism": decision["mechanism"],
        "defense_stage":     decision["stage"],
    }


# --------------------------------------------------------------------- #
#  Orchestration
# --------------------------------------------------------------------- #


async def run_sweep(group_id: str,
                    cases: list[dict],
                    domains: list[str],
                    configs: list[str],
                    trials: int,
                    temperature: float,
                    concurrency: int,
                    embedding_model=None) -> list[dict]:

    print(f"Building pipelines for group {group_id}")
    consensus_profile = GROUP_CONFIGS[group_id].get("consensus")
    print(f"  P3-L6 consensus profile: {consensus_profile}")
    pipelines: dict[tuple[str, str], DefensePipeline] = {}
    for dom in domains:
        for cfg in configs:
            pipelines[(dom, cfg)] = DefensePipeline(
                domain=dom, config=cfg, embedding_model=embedding_model,
                consensus_config_name=consensus_profile)

    # One JSONL logger per (domain, config) -- matches the attack-path
    # convention (logs/<domain>_<eval>_<group>/<config>_<ts>.jsonl).
    primary_model = GROUP_CONFIGS[group_id]["primary_model"]
    loggers: dict[tuple[str, str], ExperimentLogger] = {}
    for dom in domains:
        for cfg in configs:
            loggers[(dom, cfg)] = ExperimentLogger(
                eval_name=f"{dom}_injecagent_e2e_{group_id}", domain=dom,
                config=cfg, model=primary_model,
                header=build_run_header(
                    group=group_id, config=cfg, domain=dom,
                    primary_url=GROUP_CONFIGS[group_id].get("primary_url"),
                    primary_provider=GROUP_CONFIGS[group_id].get("primary_type", "openai"),
                    primary_model=primary_model,
                    api_key_env=GROUP_CONFIGS[group_id].get("api_key_env"),
                    consensus_config=GROUP_CONFIGS[group_id].get("consensus")))

    sem = asyncio.Semaphore(concurrency)
    all_rows: list[dict] = []
    t_start = time.time()

    async def one_cell(case: dict, cfg: str, trial_id: int):
        async with sem:
            # Single live-LLM call; shared across domains
            t_llm = time.perf_counter()
            trial = await run_live_trial(
                group_id=group_id, case=case, temperature=temperature,
                config_name=cfg)
            llm_latency_ms = (time.perf_counter() - t_llm) * 1000
            trial["trial_id"] = trial_id
            # Project the LLM-emitted action through every domain's defense
            llm_action = trial["emitted_action"]
            cid = case.get("ia_case_id", "unknown")
            for dom in domains:
                t_def = time.perf_counter()
                defense = await apply_defense(case, llm_action,
                                               pipelines[(dom, cfg)])
                def_latency_ms = (time.perf_counter() - t_def) * 1000
                row = {**trial, "domain": dom, **defense}
                row["attack_succeeded_end_to_end"] = (
                    row["attack_succeeded_llm"] and
                    not (row["defense_blocked"] or False))
                all_rows.append(row)

                # --- Structured JSONL logging (matches attack-path pattern) ---
                L = loggers[(dom, cfg)]
                L.set_trial_id(f"{cid}_t{trial_id}")
                L.log(
                    source="primary_llm",
                    destination=trial.get("model", primary_model),
                    action="llm_generation",
                    latency_ms=llm_latency_ms,
                    tokens_prompt=trial.get("prompt_tokens"),
                    tokens_completion=trial.get("completion_tokens"),
                    extra={
                        "ia_case_id": cid,
                        "user_tool": trial.get("user_tool"),
                        "attack_type": trial.get("attack_type"),
                        "family": trial.get("family"),
                        "emitted_action": trial.get("emitted_action"),
                        "emitted_args": trial.get("emitted_args"),
                        "refused_with_final_answer":
                            trial.get("refused_with_final_answer"),
                        "attack_succeeded_llm":
                            trial.get("attack_succeeded_llm"),
                        "raw_generation_excerpt":
                            (trial.get("raw_generation") or "")[:300],
                        "error": trial.get("error"),
                    },
                )
                L.log(
                    source="defense_pipeline",
                    destination=(llm_action or "no_action"),
                    action="defense_evaluation",
                    auth_decision=(
                        "deny" if defense.get("defense_blocked") else
                        ("allow" if defense.get("defense_evaluated") else None)),
                    mechanism=defense.get("defense_mechanism"),
                    latency_ms=def_latency_ms,
                    extra={
                        "defense_stage": defense.get("defense_stage"),
                        "defense_evaluated": defense.get("defense_evaluated"),
                        "attack_succeeded_end_to_end":
                            row["attack_succeeded_end_to_end"],
                    },
                )
            return

    total_cells = len(cases) * len(configs) * trials
    done = 0

    async def schedule():
        nonlocal done
        coros = []
        for case in cases:
            for cfg in configs:
                for t_i in range(trials):
                    coros.append(one_cell(case, cfg, t_i))
        # Run in chunks so we can report progress
        chunk = max(concurrency, 20)
        for i in range(0, len(coros), chunk):
            await asyncio.gather(*coros[i:i + chunk])
            done = min(i + chunk, len(coros))
            elapsed = time.time() - t_start
            rate = done / elapsed if elapsed else 0
            eta = (len(coros) - done) / rate if rate else 0
            print(f"   group {group_id}: {done}/{len(coros)} cells  "
                  f"elapsed {elapsed:.0f}s  ETA {eta:.0f}s")

    await schedule()
    for L in loggers.values():
        L.close()
    return all_rows


# --------------------------------------------------------------------- #
#  CSV output
# --------------------------------------------------------------------- #


def write_results(rows: list[dict], group_id: str, out_root: Path) -> None:
    """Write results.csv per (group,domain) + a master summary."""
    by_domain: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_domain[r["domain"]].append(r)

    base = out_root / f"e2e_validator_group_{group_id}"
    base.mkdir(parents=True, exist_ok=True)

    fields = [
        "group", "domain", "config", "trial_id", "ia_case_id", "user_tool",
        "attack_type", "family", "temperature", "model",
        "emitted_action", "emitted_args", "refused_with_final_answer",
        "attack_succeeded_llm",
        "defense_evaluated", "defense_blocked", "defense_mechanism",
        "defense_stage",
        "attack_succeeded_end_to_end",
        "prompt_tokens", "completion_tokens", "error",
    ]

    for dom, dom_rows in by_domain.items():
        dom_dir = base / dom
        dom_dir.mkdir(parents=True, exist_ok=True)
        with open(dom_dir / "results.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(dom_rows)

        # Summary
        cfg_stats = defaultdict(lambda: {"n": 0, "llm_succ": 0,
                                           "e2e_succ": 0, "refused": 0,
                                           "defense_blocked_llm_succ": 0})
        for r in dom_rows:
            k = r["config"]
            cfg_stats[k]["n"] += 1
            if r["attack_succeeded_llm"]: cfg_stats[k]["llm_succ"] += 1
            if r["attack_succeeded_end_to_end"]: cfg_stats[k]["e2e_succ"] += 1
            if r["refused_with_final_answer"]: cfg_stats[k]["refused"] += 1
            if r["defense_evaluated"] and r["defense_blocked"]:
                cfg_stats[k]["defense_blocked_llm_succ"] += 1

        summ_fields = ["group", "domain", "config", "n",
                       "llm_asr_pct", "defended_asr_pct",
                       "refused_pct", "defense_save_rate_pct"]
        rows_summ = []
        for cfg, v in cfg_stats.items():
            n = v["n"] or 1
            llm_succ = v["llm_succ"]
            e2e_succ = v["e2e_succ"]
            save_rate = (100 * v["defense_blocked_llm_succ"] / llm_succ
                          if llm_succ else 0)
            rows_summ.append({
                "group": group_id, "domain": dom, "config": cfg,
                "n": n,
                "llm_asr_pct":       round(100 * llm_succ / n, 2),
                "defended_asr_pct":  round(100 * e2e_succ / n, 2),
                "refused_pct":       round(100 * v["refused"] / n, 2),
                "defense_save_rate_pct": round(save_rate, 2),
            })
        with open(dom_dir / "summary.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=summ_fields)
            w.writeheader(); w.writerows(rows_summ)

    # Write aggregated group summary across all domains
    all_summ = []
    for dom, dom_rows in by_domain.items():
        cfg_stats = defaultdict(lambda: {"n": 0, "llm_succ": 0, "e2e_succ": 0})
        for r in dom_rows:
            k = r["config"]
            cfg_stats[k]["n"] += 1
            if r["attack_succeeded_llm"]: cfg_stats[k]["llm_succ"] += 1
            if r["attack_succeeded_end_to_end"]: cfg_stats[k]["e2e_succ"] += 1
        for cfg, v in cfg_stats.items():
            n = v["n"] or 1
            all_summ.append({
                "group": group_id, "domain": dom, "config": cfg,
                "n": v["n"],
                "llm_asr_pct":      round(100 * v["llm_succ"] / n, 2),
                "defended_asr_pct": round(100 * v["e2e_succ"] / n, 2),
            })
    with open(base / "group_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["group", "domain", "config", "n",
                                           "llm_asr_pct", "defended_asr_pct"])
        w.writeheader(); w.writerows(all_summ)


# --------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------- #


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--group", required=True, choices=sorted(GROUP_CONFIGS))
    ap.add_argument("--domains", default=",".join(DEFAULT_DOMAINS))
    ap.add_argument("--configs", default=",".join(DEFAULT_CONFIGS))
    ap.add_argument("--trials", type=int, default=6)
    ap.add_argument("--case-limit", type=int, default=None,
                    help="Cap # cases (from the representative subset).")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--concurrency", type=int, default=8,
                    help="Max concurrent LLM calls")
    ap.add_argument("--out-root", type=Path, default=RESULTS_DIR)
    ap.add_argument("--embedding-model", type=str,
                    default=str(MODELS_DIR / "Qwen" / "Qwen3-Embedding-0.6B"))
    args = ap.parse_args()

    cases = load_cases()
    if args.case_limit:
        cases = cases[:args.case_limit]
    domains = args.domains.split(",")
    configs = args.configs.split(",")

    total_cells = len(cases) * len(configs) * args.trials
    total_rows = total_cells * len(domains)
    print(f"Group: {args.group}  "
          f"primary={GROUP_CONFIGS[args.group]['primary_model']}  "
          f"consensus={GROUP_CONFIGS[args.group]['consensus']}")
    print(f"Cases: {len(cases)}  configs: {configs}  trials: {args.trials}  "
          f"domains: {domains}")
    print(f"Live LLM calls: {total_cells:,}    output rows: {total_rows:,}\n")

    emb = None
    if args.embedding_model:
        from sentence_transformers import SentenceTransformer
        # CPU on purpose: the GPUs are owned by vLLM (>90% full), and the attack
        # harness / MMA embed on CPU too, so every evaluation uses the same path.
        emb = SentenceTransformer(args.embedding_model, device="cpu")

    rows = asyncio.run(run_sweep(
        group_id=args.group, cases=cases, domains=domains, configs=configs,
        trials=args.trials, temperature=args.temperature,
        concurrency=args.concurrency, embedding_model=emb,
    ))
    write_results(rows, args.group, args.out_root)

    # Print headline
    print(f"\n=== End-to-end ASR (group {args.group}) ===")
    print(f"{'domain':<12}{'config':<16}{'n':>5} {'LLM ASR%':>10} {'Defended ASR%':>14}")
    agg: dict[tuple, dict] = defaultdict(lambda: {"n": 0, "llm": 0, "e2e": 0})
    for r in rows:
        k = (r["domain"], r["config"])
        agg[k]["n"] += 1
        if r["attack_succeeded_llm"]: agg[k]["llm"] += 1
        if r["attack_succeeded_end_to_end"]: agg[k]["e2e"] += 1
    for (d, c), v in sorted(agg.items()):
        n = v["n"] or 1
        print(f"{d:<12}{c:<16}{v['n']:>5} "
              f"{100*v['llm']/n:>9.2f} {100*v['e2e']/n:>13.2f}")


if __name__ == "__main__":
    main()
