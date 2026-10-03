#!/bin/bash
# Progress of the revision runs, read from the JSONL logs (the stage logs are
# block-buffered and lag behind).   scripts/progress.sh [group-substring]
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python3 - "${1:-}" <<'PY'
import glob, json, os, sys, collections, time
flt = sys.argv[1]
rows = collections.defaultdict(lambda: collections.Counter())
last = {}
for d in sorted(glob.glob("logs/*_eval_attacks_*")):
    name = os.path.basename(d)
    if "_aborted" in d or (flt and flt not in name): continue
    for f in glob.glob(d + "/*.jsonl"):
        cfg = os.path.basename(f).rsplit("_", 2)[0]
        with open(f) as fh:
            for line in fh:
                if '"trial_complete"' not in line: continue
                e = json.loads(line)
                k = (name, cfg, "benign" if e.get("ap") == "benign" else "attack")
                rows[k][e.get("outcome")] += 1
        last[(name, cfg)] = max(last.get((name, cfg), 0), os.path.getmtime(f))
now = time.time(); total = 0
print(f"{'run':<44}{'config':<15}{'kind':<8}{'done':>5}  outcomes{'':<38}idle")
for (name, cfg, kind), c in sorted(rows.items()):
    n = sum(c.values()); total += n
    idle = int(now - last.get((name, cfg), now))
    print(f"{name.replace('_eval_attacks', ''):<44}{cfg:<15}{kind:<8}{n:>5}  {str(dict(c))[:44]:<46}{idle:>4}s")
print(f"total trials: {total}")
PY
