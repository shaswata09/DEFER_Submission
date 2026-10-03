"""
TAMAS baseline runner -- runs every (scenario x attack x trial) with NO defenses.

Writes ``results/tamas/baseline_results.json``.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from benchmarks._unused_tamas.eval_runner import run_grid, save_results

HERE = Path(__file__).resolve().parent
SCENARIOS_DIR = HERE / "scenarios"
DEFAULT_OUT = HERE.parents[1] / "results" / "tamas" / "baseline_results.json"


def _scenario_paths() -> list[Path]:
    return sorted(SCENARIOS_DIR.glob("*_config.json"))


async def _amain(args: argparse.Namespace) -> None:
    paths = _scenario_paths()
    print(f"[baseline] scenarios found: {len(paths)}")
    for p in paths:
        print(f"  - {p.name}")

    results = await run_grid(
        scenario_paths=paths,
        middleware_factory=lambda _scenario: None,   # no defenses
        trials_per_cell=args.trials,
        include_benign=not args.no_benign,
        only_scenario=args.scenario,
        only_attack=args.attack,
    )
    print(f"[baseline] total trials: {len(results)}")
    save_results(results, args.out)
    print(f"[baseline] wrote {args.out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5,
                    help="trials per (scenario x attack) cell")
    ap.add_argument("--scenario", type=str, default=None,
                    help="limit to one scenario")
    ap.add_argument("--attack", type=str, default=None,
                    help="limit to one attack type")
    ap.add_argument("--no-benign", action="store_true",
                    help="skip benign-baseline trials")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    asyncio.run(_amain(args))


if __name__ == "__main__":
    main()
