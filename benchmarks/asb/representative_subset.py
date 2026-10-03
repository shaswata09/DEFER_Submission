"""Select a stratified 50-case ASB subset (E0 drift check, E3 ASB-50, E5 targets).

Stratified by (attack_subtype, agent_name) over the DPI case set, seeded so
the selection is reproducible; every stratum gets at least one case and
the remainder is filled proportionally.

Output: ``benchmarks/asb/representative_cases.json`` (list of asb_case_id).

Usage::

    python -m benchmarks.asb.representative_subset            # writes 50 ids
    python -m benchmarks.asb.representative_subset --n 50 --seed 20260919
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parent / "representative_cases.json"


def select(cases: list[dict], n: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    strata: dict[tuple, list[dict]] = defaultdict(list)
    for c in cases:
        strata[(c.get("attack_subtype", ""), c.get("agent_name", ""))].append(c)
    keys = sorted(strata)
    for k in keys:
        strata[k] = sorted(strata[k], key=lambda c: c.get("asb_case_id", ""))
        rng.shuffle(strata[k])
    picked: list[dict] = []
    # one per stratum first
    for k in keys:
        if len(picked) < n and strata[k]:
            picked.append(strata[k].pop())
    # then proportional to stratum size, round robin over the largest remaining
    while len(picked) < n:
        remaining = [k for k in keys if strata[k]]
        if not remaining:
            break
        remaining.sort(key=lambda k: -len(strata[k]))
        for k in remaining:
            if len(picked) >= n:
                break
            picked.append(strata[k].pop())
    return sorted(picked, key=lambda c: c.get("asb_case_id", ""))


def main() -> None:
    from benchmarks.asb.run_e2e import DEFAULT_ATTACKS, load_cases
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--seed", type=int, default=20260919)
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()
    cases = load_cases(list(DEFAULT_ATTACKS))
    picked = select(cases, args.n, args.seed)
    strata = defaultdict(int)
    for c in picked:
        strata[(c.get("attack_subtype"), c.get("agent_name"))] += 1
    with open(args.out, "w") as f:
        json.dump([c["asb_case_id"] for c in picked], f, indent=1)
        f.write("\n")
    print(f"wrote {args.out}: {len(picked)} of {len(cases)} cases, {len(strata)} strata "
          f"(seed {args.seed})")


if __name__ == "__main__":
    main()
