"""Select a stratified subset of InjecAgent cases for live e2e evaluation.

Running every (group x domain x config x trial) over all 2,108 upstream
cases is too expensive at live-LLM rates.  We pick a representative
**50-case subset** by stratified sampling across the 17 upstream attack
categories, covering both direct-harm and data-stealing families with
base (non-jailbreak) variants only.

Output: ``benchmarks/injecagent/representative_cases.json``
(list of cases with an added ``ia_case_id`` for referencing).
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUT_PATH = Path(__file__).resolve().parent / "representative_cases.json"


def _load_base() -> list[dict]:
    """Load dh-base and ds-base cases, tag with family, mint an id."""
    cases = []
    for family, fn in [("dh", "test_cases_dh_base.json"),
                       ("ds", "test_cases_ds_base.json")]:
        with open(DATA_DIR / fn) as f:
            arr = json.load(f)
        for i, c in enumerate(arr):
            c = dict(c)
            c["_family"] = family
            c["ia_case_id"] = f"{family}_base_{i:04d}"
            cases.append(c)
    return cases


def stratified_subset(n: int = 50, seed: int = 42) -> list[dict]:
    """Pick ``n`` cases spread as evenly as possible across attack types.

    Always includes at least 1 case per distinct (family, attack_type)
    bucket.  Remaining slots are distributed round-robin across the
    largest buckets.
    """
    cases = _load_base()
    rng = random.Random(seed)

    # Bucket by (family, attack_type)
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for c in cases:
        k = (c["_family"], c.get("Attack Type", "unknown"))
        buckets[k].append(c)

    # Shuffle within each bucket deterministically
    for b in buckets.values():
        rng.shuffle(b)

    chosen: list[dict] = []
    # Round-robin pass: pick 1 from each bucket until we hit n
    order = sorted(buckets.keys())
    idx = {k: 0 for k in order}
    while len(chosen) < n:
        progressed = False
        for k in order:
            if len(chosen) >= n:
                break
            i = idx[k]
            if i < len(buckets[k]):
                chosen.append(buckets[k][i])
                idx[k] += 1
                progressed = True
        if not progressed:
            break  # buckets exhausted (unlikely with 1054 cases)

    return chosen


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args()

    subset = stratified_subset(n=args.n, seed=args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(subset, f, indent=2)

    from collections import Counter
    ctr = Counter((c["_family"], c.get("Attack Type")) for c in subset)
    print(f"Wrote {len(subset)} cases -> {args.out}")
    print("Distribution by (family, attack_type):")
    for (fam, atype), n in sorted(ctr.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {fam:3s}  {str(atype):30s}  {n}")


if __name__ == "__main__":
    main()
