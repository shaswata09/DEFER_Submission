"""Archive the v2.1 log files of the reworked attack paths (T8).

AP-2, AP-3, AP-4 and AP-14 are rerun on the v2.2 payloads; their v2.1 rows
must not mix with the new ones. Each harness invocation logs one attack
path, so a log file is archived when every ``trial_complete`` event in it
belongs to one of the reworked paths. Files are MOVED (never deleted) to
``results/eval_attacks/_superseded_v2.1/logs/<log dir>/``; ``parse_logs``
reads only ``logs/``, so the archived trials leave ``all_trials.csv`` on the
next full parse.

Main groups and their ablation dirs are archived; smoke / debug /
persistent runs are left alone (they never enter the headline tables).

    python -m scripts.archive_superseded            # dry run: report only
    python -m scripts.archive_superseded --apply    # move the files
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from collections import Counter
from pathlib import Path

from config import BASE_DIR, LOGS_DIR, RESULTS_DIR

REWORKED = {"ap2", "ap3", "ap4", "ap14"}
MAIN_GROUPS = ("q235_div4", "scout_div4", "mistral_div3p", "llama8b_div4")
SKIP_TAGS = ("_smoke", "_debug", "_persistent", "t6smoke")
ARCHIVE = RESULTS_DIR / "eval_attacks" / "_superseded_v2.1" / "logs"
_DIR = re.compile(r"^(cyberops|healthcare|finance|legal)_eval_attacks_(.+)$")


def _aps_in(path: Path) -> Counter:
    c: Counter = Counter()
    with open(path) as f:
        for line in f:
            if '"trial_complete"' not in line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("action") == "trial_complete":
                c[str(e.get("ap"))] += 1
    return c


def plan() -> tuple[list[tuple[Path, Counter]], list[tuple[Path, Counter]]]:
    move, mixed = [], []
    for d in sorted(LOGS_DIR.iterdir()):
        m = _DIR.match(d.name)
        if not d.is_dir() or not m:
            continue
        tail = m.group(2)
        if any(t in tail for t in SKIP_TAGS):
            continue
        if not any(tail == g or tail.startswith(g + "_disabled_") for g in MAIN_GROUPS):
            continue
        for f in sorted(d.glob("*.jsonl")):
            aps = _aps_in(f)
            if not aps:
                continue
            hit = {a for a in aps if a in REWORKED}
            if not hit:
                continue
            (move if set(aps) <= REWORKED else mixed).append((f, aps))
    return move, mixed


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true", help="move the files (default: report)")
    args = ap.parse_args()
    move, mixed = plan()
    trials = sum(sum(c.values()) for _, c in move)
    by_dir = Counter(f.parent.name for f, _ in move)
    print(f"{len(move)} log files / {trials} trials of {sorted(REWORKED)} to archive:")
    for d, n in sorted(by_dir.items()):
        print(f"  {d}: {n} files")
    if mixed:
        print(f"\n{len(mixed)} files mix reworked and kept paths and are NOT moved:")
        for f, c in mixed:
            print(f"  {f.relative_to(BASE_DIR)}: {dict(c)}")
    if not args.apply:
        print("\n(dry run; pass --apply to move)")
        return
    for f, _ in move:
        dest = ARCHIVE / f.parent.name / f.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(f), str(dest))
    print(f"\nmoved {len(move)} files to {ARCHIVE.relative_to(BASE_DIR)}/")


if __name__ == "__main__":
    main()
