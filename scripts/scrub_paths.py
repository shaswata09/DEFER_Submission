#!/usr/bin/env python3
"""Replace the absolute repo path with a placeholder in tracked text files.

The repo is published as an artifact, so run logs should not carry the
absolute path of the machine that produced them. The path only ever appears
in provenance metadata (``command``, ``changed_files``, notebook output),
never as an analysis key, so substituting it changes no number -- the check
is that ``parse_logs`` produces the same row count afterwards.

Usage:
    python scripts/scrub_paths.py --check    # report, change nothing
    python scripts/scrub_paths.py            # rewrite in place
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PLACEHOLDER = "<REPO_ROOT>"
# Extensions worth rewriting; anything else is left alone so we never touch
# a binary or a checked-in model artefact.
TEXT_SUFFIXES = {".jsonl", ".json", ".csv", ".ipynb", ".md", ".out", ".log",
                 ".txt", ".py", ".sh", ".yaml", ".yml", ".tex"}


def repo_root() -> str:
    """The absolute path of this checkout -- the string to remove. Derived at
    run time so the path never has to be written into the repository."""
    return subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                          text=True, check=True).stdout.strip()


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True,
                         text=True, check=True).stdout
    return [Path(p) for p in out.split("\0") if p]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="report files that still contain the path; exit 1 if any")
    args = ap.parse_args()

    ABS = repo_root()
    hits: list[tuple[Path, int]] = []
    for f in tracked_files():
        if f.suffix not in TEXT_SUFFIXES or not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        n = text.count(ABS)
        if not n:
            continue
        hits.append((f, n))
        if not args.check:
            f.write_text(text.replace(ABS, PLACEHOLDER), encoding="utf-8")

    total = sum(n for _, n in hits)
    verb = "still contain" if args.check else "scrubbed"
    print(f"{len(hits)} files {verb} the absolute path ({total} occurrences)")
    for f, n in sorted(hits, key=lambda x: -x[1])[:10]:
        print(f"  {n:7d}  {f}")
    if len(hits) > 10:
        print(f"  ... and {len(hits) - 10} more")
    return 1 if (args.check and hits) else 0


if __name__ == "__main__":
    sys.exit(main())
