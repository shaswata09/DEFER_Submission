"""ASB live-LLM end-to-end runner (Stage 2: DPI / IPI / MP / PoT).

Mirror of ``benchmarks/injecagent/run_e2e.py`` but for ASB cases.
``--attacks`` selects any subset of the four families; the harness
dispatches the right prompt shape per case via
:func:`benchmarks.asb.harness.live_llm_driver.build_conversation`.

For each (case, config, trial) cell:

  1. Call the chosen group's primary LLM with a ReAct prompt that
     includes the agent's full toolset (normal + attack).
  2. Parse the generation for ``Action: <tool>``.
  3. If the parsed action matches an attacker tool, project it through
     the P1-P5 defense pipeline (under the **general** neutral domain)
     and optionally P3-L6 LLM consensus.
  4. Record the outcome to CSV + JSONL.

CLI::

    python -m benchmarks.asb.run_e2e --group A --attacks DPI --case-limit 30
    python -m benchmarks.asb.run_e2e --group A --attacks DPI \\
        --configs agenticcyops --trials 1
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

from config import BASE_DIR, MODELS_DIR, model_display_name

from benchmarks.asb.harness.live_llm_driver import (
    GROUP_CONFIGS, run_live_trial, case_attacker_ids,
)
from benchmarks.asb.harness.tool_loader import (
    load_asb_tools, NAMESPACE_PREFIX,
)
from benchmarks.injecagent.harness.trial_driver import DefensePipeline
from logging_utils import ExperimentLogger
from logging_utils.run_metadata import build_run_header

HERE = Path(__file__).resolve().parent
DATA_DIR = HERE / "data"
CASES_DIR = DATA_DIR / "cases"
RESULTS_DIR = BASE_DIR / "results" / "asb"

ATTACK_FILES = {
    "DPI":  "dpi.json",
    "IPI":  "ipi.json",
    "MP":   "mp.json",
    "POT":  "pot.json",
}
DEFAULT_ATTACKS = list(ATTACK_FILES)
DEFAULT_CONFIGS = ["flat", "acl_hardened", "agenticcyops"]
DOMAIN = "general"                         # ASB scenarios -> neutral domain


# --------------------------------------------------------------------- #
#  Loading
# --------------------------------------------------------------------- #

def load_cases(attacks: list[str]) -> list[dict]:
    out: list[dict] = []
    for atk in attacks:
        path = CASES_DIR / ATTACK_FILES[atk]
        if not path.exists():
            raise SystemExit(
                f"[fail] {atk} cases not found at {path}.\n"
                "Run the ingest + convert pipeline first:\n"
                "  ./benchmarks/asb/scripts/ingest_upstream.sh\n"
                f"  python -m benchmarks.asb.scripts.convert_cases --families {atk}\n")
        with open(path) as f:
            out.extend(json.load(f))
    return out


# --------------------------------------------------------------------- #
#  Defense overlay
# --------------------------------------------------------------------- #

def _register_asb_tools_in_pipeline(pipe: DefensePipeline) -> None:
    """Inject ASB_* tools into the pipeline's auth registry overlay.
    Mirrors :func:`benchmarks.injecagent.harness.trial_driver.DefensePipeline._register_ia_tools_in_auth`."""
    if pipe.auth is None:
        return
    reg = load_asb_tools()
    tools_section = pipe.auth._registry.setdefault("tools", {})
    dom_tools = tools_section.setdefault(pipe.domain, {})
    for asb_name, schema in reg["asb_name_to_schema"].items():
        dom_tools[asb_name] = {
            "description":            schema.get("description", ""),
            "category":               f"asb_{schema.get('scenario','unknown')}",
            "asb_benchmark":          True,
            "expected_response_keys": [],
        }


def _resolve_attacker_target(case: dict, llm_action: str) -> Optional[str]:
    """Return the canonical ASB_<scenario>_<tool> identifier the LLM's
    action corresponds to, or None if the LLM emitted something else."""
    if not llm_action:
        return None
    candidates = case_attacker_ids(case)
    al = llm_action.strip()
    if al in candidates:
        return al
    al_lower = al.lower()
    for c in candidates:
        cl = c.lower()
        if al_lower == cl or al_lower.startswith(cl) or cl.startswith(al_lower) and len(al_lower) >= 8:
            return c
    return None


def apply_defense(case: dict, llm_action: Optional[str],
                  pipeline: DefensePipeline,
                  attacker_phase: str = "admin") -> dict:
    """Sync defense path (no consensus).  Used for ablation runs."""
    target = _resolve_attacker_target(case, llm_action)
    if target is None:
        return {"defense_evaluated": False, "defense_blocked": None,
                "defense_mechanism": None, "defense_stage": None}

    # ASB cases don't have InjecAgent-style "Tool Response" content --
    # synthesise one from the User Instruction (which contains the
    # injection for DPI) so P2-L3 / P5-L5 have evidence to classify.
    syn_case = dict(case)
    syn_case.setdefault("Tool Response", case.get("Tool Response", "") or
                                          case.get("User Instruction", "")[:500])
    decision = pipeline.evaluate(syn_case, target, attacker_phase=attacker_phase)
    return {
        "defense_evaluated": True,
        "defense_blocked":   not decision["allowed"],
        "defense_mechanism": decision["mechanism"],
        "defense_stage":     decision["stage"],
    }


async def apply_defense_async(case: dict, llm_action: Optional[str],
                              pipeline: DefensePipeline,
                              attacker_phase: str = "admin") -> dict:
    """Async variant: P1-P5 plus P3-L6 LLM consensus when configured."""
    target = _resolve_attacker_target(case, llm_action)
    if target is None:
        return {"defense_evaluated": False, "defense_blocked": None,
                "defense_mechanism": None, "defense_stage": None}

    syn_case = dict(case)
    syn_case.setdefault("Tool Response", case.get("Tool Response", "") or
                                          case.get("User Instruction", "")[:500])
    decision = await pipeline.evaluate_with_consensus(
        syn_case, target, attacker_phase=attacker_phase)
    return {
        "defense_evaluated": True,
        "defense_blocked":   not decision["allowed"],
        "defense_mechanism": decision["mechanism"],
        "defense_stage":     decision["stage"],
    }


# --------------------------------------------------------------------- #
#  Orchestration
# --------------------------------------------------------------------- #

def load_replay(path: Path) -> dict[tuple, dict]:
    """Primary outputs of a finished run, keyed by (case id, config, trial).

    Used by ``--replay-from`` (E6): the defense step is re-run on the
    recorded ``emitted_action`` / ``emitted_args`` so that panels can be
    compared on identical primary outputs without any primary GPU time.
    """
    out: dict[tuple, dict] = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            key = (r.get("asb_case_id"), r.get("config"), str(r.get("trial_id")))
            try:
                args = json.loads(r.get("emitted_args") or "{}")
            except json.JSONDecodeError:
                args = {}
            out[key] = {
                "emitted_action": r.get("emitted_action") or None,
                "emitted_args": args,
                "user_tool": r.get("user_tool"),
                "refused_with_final_answer": str(r.get("refused_with_final_answer")).lower() == "true",
                "attack_succeeded_llm": str(r.get("attack_succeeded_llm")).lower() == "true",
                "prompt_tokens": int(r.get("prompt_tokens") or 0),
                "completion_tokens": int(r.get("completion_tokens") or 0),
                "model": model_display_name(r.get("model")),
                "temperature": r.get("temperature"),
                "raw_generation": "",
                "error": r.get("error") or None,
                "replayed_from": str(path),
            }
    return out


async def run_sweep(group_id: str,
                    cases: list[dict],
                    configs: list[str],
                    trials: int,
                    temperature: float,
                    concurrency: int,
                    embedding_model=None,
                    consensus_override: Optional[str] = None,
                    replay: Optional[dict] = None) -> list[dict]:
    print(f"Building pipelines for group {group_id}  domain={DOMAIN}")
    consensus_profile = consensus_override or GROUP_CONFIGS[group_id].get("consensus")
    print(f"  P3-L6 consensus profile: {consensus_profile}"
          + ("  (override)" if consensus_override else "")
          + (f"  replaying {len(replay)} recorded primary outputs" if replay else ""))
    pipelines: dict[str, DefensePipeline] = {}
    for cfg in configs:
        pipelines[cfg] = DefensePipeline(
            domain=DOMAIN, config=cfg, embedding_model=embedding_model,
            consensus_config_name=consensus_profile)
        _register_asb_tools_in_pipeline(pipelines[cfg])

    primary_model = GROUP_CONFIGS[group_id]["primary_model"]
    loggers: dict[str, ExperimentLogger] = {}
    for cfg in configs:
        loggers[cfg] = ExperimentLogger(
            eval_name=f"asb_dpi_e2e_{group_id}",
            domain=DOMAIN, config=cfg, model=primary_model,
            header=build_run_header(
                group=group_id, config=cfg, domain=DOMAIN,
                primary_url=GROUP_CONFIGS[group_id].get("primary_url"),
                primary_provider=GROUP_CONFIGS[group_id].get("primary_type", "openai"),
                primary_model=primary_model,
                api_key_env=GROUP_CONFIGS[group_id].get("api_key_env"),
                consensus_config=consensus_profile,
                replay_from=(next(iter(replay.values()))["replayed_from"] if replay else None),
                probe=not replay))

    sem = asyncio.Semaphore(concurrency)
    missing_replay = 0
    all_rows: list[dict] = []
    t_start = time.time()

    async def one_cell(case: dict, cfg: str, trial_id: int):
        nonlocal missing_replay
        async with sem:
            t_llm = time.perf_counter()
            if replay is not None:
                key = (case.get("asb_case_id"), cfg, str(trial_id))
                if key not in replay:
                    missing_replay += 1
                    return
                # same row shape as run_live_trial(): case / config identity
                # comes from this run, the primary's output from the recording
                rec = replay[key]
                trial = {
                    "group": group_id,
                    "asb_case_id": case.get("asb_case_id", ""),
                    "scenario": case.get("scenario", ""),
                    "agent_name": case.get("agent_name", ""),
                    "attack_type": case.get("attack_type", ""),
                    "attack_subtype": case.get("attack_subtype", ""),
                    "config": cfg,
                    **rec,
                    "user_tool": rec.get("user_tool") or case.get("User Tool", ""),
                    "emitted_args": json.dumps(rec.get("emitted_args") or {}, default=str)[:400],
                }
            else:
                trial = await run_live_trial(
                    group_id=group_id, case=case, temperature=temperature,
                    config_name=cfg)
            llm_latency_ms = (time.perf_counter() - t_llm) * 1000
            trial["trial_id"] = trial_id
            llm_action = trial["emitted_action"]

            t_def = time.perf_counter()
            defense = await apply_defense_async(case, llm_action, pipelines[cfg])
            def_latency_ms = (time.perf_counter() - t_def) * 1000
            row = {**trial, **defense}
            row["attack_succeeded_end_to_end"] = (
                row["attack_succeeded_llm"] and
                not (row["defense_blocked"] or False))
            all_rows.append(row)

            # Structured JSONL audit -- matches the attack-path schema
            cid = case.get("asb_case_id", "unknown")
            L = loggers[cfg]
            L.set_trial_id(f"{cid}_t{trial_id}")
            L.log(
                source="primary_llm",
                destination=trial.get("model", primary_model),
                action="llm_generation",
                latency_ms=llm_latency_ms,
                tokens_prompt=trial.get("prompt_tokens"),
                tokens_completion=trial.get("completion_tokens"),
                extra={
                    "asb_case_id":     cid,
                    "scenario":        case.get("scenario"),
                    "agent_name":      case.get("agent_name"),
                    "attack_type":     case.get("attack_type"),
                    "attack_subtype":  case.get("attack_subtype"),
                    "user_tool":       trial.get("user_tool"),
                    "emitted_action":  llm_action,
                    "emitted_args":    trial.get("emitted_args"),
                    "refused":         trial.get("refused_with_final_answer"),
                    "attack_succeeded_llm": trial.get("attack_succeeded_llm"),
                    "raw_generation_excerpt":
                        (trial.get("raw_generation") or "")[:300],
                    "error":           trial.get("error"),
                },
            )
            L.log(
                source="defense_pipeline",
                destination=(llm_action or "no_action"),
                action="defense_evaluation",
                auth_decision=("deny" if defense.get("defense_blocked") else
                                ("allow" if defense.get("defense_evaluated") else None)),
                mechanism=defense.get("defense_mechanism"),
                latency_ms=def_latency_ms,
                extra={
                    "defense_stage":     defense.get("defense_stage"),
                    "defense_evaluated": defense.get("defense_evaluated"),
                    "attack_succeeded_end_to_end":
                        row["attack_succeeded_end_to_end"],
                },
            )

    async def schedule():
        coros = [one_cell(c, cfg, t)
                  for c in cases for cfg in configs for t in range(trials)]
        chunk = max(concurrency, 20)
        for i in range(0, len(coros), chunk):
            await asyncio.gather(*coros[i:i + chunk])
            elapsed = time.time() - t_start
            done = min(i + chunk, len(coros))
            rate = done / elapsed if elapsed else 0
            eta = (len(coros) - done) / rate if rate else 0
            print(f"   group {group_id}: {done}/{len(coros)} cells  "
                  f"elapsed {elapsed:.0f}s  ETA {eta:.0f}s")

    await schedule()
    for L in loggers.values():
        L.close()
    if missing_replay:
        print(f"   {missing_replay} (case, config, trial) cells had no recorded primary output; skipped")
    return all_rows


# --------------------------------------------------------------------- #
#  CSV output
# --------------------------------------------------------------------- #

def write_results(rows: list[dict], group_id: str, out_root: Path, tag: str = "") -> None:
    # Write into a 'general/' subdir to mirror InjecAgent's
    # <group>/<domain>/results.csv layout, so the shared analytics tool
    # picks it up via its directory walk.
    base = out_root / f"e2e_validator_group_{group_id}{('_' + tag) if tag else ''}"
    dom_dir = base / "general"
    dom_dir.mkdir(parents=True, exist_ok=True)
    # Stamp every row with domain="general" so analytics pivots align
    # with InjecAgent's per-domain output schema.
    for r in rows:
        r.setdefault("domain", "general")

    fields = [
        "group", "asb_case_id", "scenario", "agent_name", "attack_type",
        "attack_subtype", "config", "trial_id", "user_tool", "domain",
        "temperature", "model", "emitted_action", "emitted_args",
        "refused_with_final_answer", "attack_succeeded_llm",
        "defense_evaluated", "defense_blocked", "defense_mechanism",
        "defense_stage", "attack_succeeded_end_to_end",
        "prompt_tokens", "completion_tokens", "error",
    ]
    det = dom_dir / "results.csv"
    with open(det, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)

    # Summary: per (attack_subtype, config)
    pivot: dict[tuple, dict] = defaultdict(lambda: {"n": 0, "llm": 0, "e2e": 0})
    for r in rows:
        k = (r.get("attack_subtype", ""), r["config"])
        pivot[k]["n"] += 1
        if r["attack_succeeded_llm"]:           pivot[k]["llm"] += 1
        if r["attack_succeeded_end_to_end"]:    pivot[k]["e2e"] += 1
    summ_fields = ["attack_subtype", "config", "n",
                   "llm_asr_pct", "defended_asr_pct"]
    summ_rows = []
    for (sub, cfg), v in sorted(pivot.items()):
        n = v["n"] or 1
        summ_rows.append({"attack_subtype": sub, "config": cfg, "n": v["n"],
                          "llm_asr_pct":      round(100 * v["llm"] / n, 2),
                          "defended_asr_pct": round(100 * v["e2e"] / n, 2)})
    summ = dom_dir / "summary.csv"
    with open(summ, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=summ_fields)
        w.writeheader(); w.writerows(summ_rows)

    print(f"\n  wrote {det}  ({len(rows)} rows)")
    print(f"  wrote {summ}  ({len(summ_rows)} per-(subtype,config) cells)")


# --------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------- #

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--group", required=True, choices=sorted(GROUP_CONFIGS))
    ap.add_argument("--attacks", default=",".join(DEFAULT_ATTACKS),
                    help="Comma-separated subset of {DPI}.  Stage 1 only DPI.")
    ap.add_argument("--configs", default=",".join(DEFAULT_CONFIGS))
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--case-limit", type=int, default=None)
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--out-root", type=Path, default=RESULTS_DIR)
    ap.add_argument("--embedding-model", type=str,
                    default=str(MODELS_DIR / "Qwen" / "Qwen3-Embedding-0.6B"))
    ap.add_argument("--replay-from", type=Path, default=None,
                    help="results.csv of a finished run: reuse its emitted_action / "
                         "emitted_args per (case, config, trial) and re-run only the "
                         "defense step (E6 paired replay; no primary calls).")
    ap.add_argument("--consensus-config", default=None,
                    help="Validator panel to use instead of the group's (div4, div3, lin3, single).")
    ap.add_argument("--cases-file", type=Path, default=None,
                    help="JSON list of asb_case_id to restrict the run to "
                         "(e.g. benchmarks/asb/representative_cases.json).")
    ap.add_argument("--tag", default="",
                    help="Suffix for the output directory (e2e_validator_group_<G>_<tag>).")
    args = ap.parse_args()

    attacks = [a.strip().upper() for a in args.attacks.split(",") if a.strip()]
    bad = [a for a in attacks if a not in ATTACK_FILES]
    if bad:
        raise SystemExit(f"[fail] unknown attacks: {bad}.  Valid: {list(ATTACK_FILES)}")
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]

    cases = load_cases(attacks)
    if args.cases_file:
        with open(args.cases_file) as f:
            wanted = json.load(f)
        wanted = {c["asb_case_id"] if isinstance(c, dict) else c for c in wanted}
        cases = [c for c in cases if c.get("asb_case_id") in wanted]
        print(f"Restricted to {len(cases)} cases from {args.cases_file}")
    if args.case_limit:
        cases = cases[:args.case_limit]
    replay = load_replay(args.replay_from) if args.replay_from else None

    print(f"Group: {args.group}  primary={GROUP_CONFIGS[args.group]['primary_model']}")
    print(f"Attacks: {attacks}  Configs: {configs}  Trials: {args.trials}")
    print(f"Cases: {len(cases)}  -> live LLM calls: {len(cases)*len(configs)*args.trials}\n")

    emb = None
    if args.embedding_model:
        from sentence_transformers import SentenceTransformer
        # CPU on purpose: the GPUs are owned by vLLM (>90% full), and the attack
        # harness / MMA embed on CPU too, so every evaluation uses the same path.
        emb = SentenceTransformer(args.embedding_model, device="cpu")

    rows = asyncio.run(run_sweep(
        group_id=args.group, cases=cases, configs=configs,
        trials=args.trials, temperature=args.temperature,
        concurrency=args.concurrency, embedding_model=emb,
        consensus_override=args.consensus_config, replay=replay,
    ))
    tag = args.tag or (args.consensus_config if args.consensus_config else "")
    if replay and not tag:
        tag = "replay"
    write_results(rows, args.group, args.out_root, tag=tag)

    print(f"\n=== ASB DPI ASR (group {args.group}) ===")
    print(f"{'subtype':<22}{'config':<16}{'n':>5}{'LLM ASR%':>10}{'Defended ASR%':>14}")
    pivot: dict[tuple, dict] = defaultdict(lambda: {"n": 0, "llm": 0, "e2e": 0})
    for r in rows:
        k = (r.get("attack_subtype", ""), r["config"])
        pivot[k]["n"] += 1
        if r["attack_succeeded_llm"]:        pivot[k]["llm"] += 1
        if r["attack_succeeded_end_to_end"]: pivot[k]["e2e"] += 1
    for (sub, cfg), v in sorted(pivot.items()):
        n = v["n"] or 1
        print(f"{sub:<22}{cfg:<16}{v['n']:>5}{100*v['llm']/n:>9.2f}{100*v['e2e']/n:>13.2f}")


if __name__ == "__main__":
    main()
