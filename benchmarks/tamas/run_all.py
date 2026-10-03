"""Run the TAMAS instances in parallel through ``run_crew.py`` (resumable).

Attack instances: DPI, impersonation, byzantine, colluding, contradicting,
5 scenarios x 10 each (250). The 50 IPI instances are run as benign tasks:
upstream releases their user queries but not the injected tool content, and
no IPI scoring script, so as released they are ordinary tasks in the same
five domains and serve as the benign companion set.

    python -m benchmarks.tamas.run_all --out-dir logs/tamas_q235_local2_v29 \
        --model hosted_vllm/Qwen/Qwen3-235B-A22B-Instruct-2507 --base-url http://127.0.0.1:8000/v1 \
        --configs flat,full --trials 3 --workers 12
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ATTACKS = ("DPI", "impersonation", "byzantine", "colluding", "contradicting", "IPI")
SCENARIOS = ("education", "finance", "healthcare", "legal", "news")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--gate", default="http://127.0.0.1:8300")
    ap.add_argument("--configs", default="flat,full")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--python", default=str(Path.home() / ".conda/envs/tamas/bin/python"))
    ap.add_argument("--timeout", type=int, default=1200)
    a = ap.parse_args()
    out = Path(a.out_dir); out.mkdir(parents=True, exist_ok=True)
    done = set()
    if (out / "runs.jsonl").exists():
        done = {json.loads(l)["trial_id"] for l in open(out / "runs.jsonl") if l.strip()}
    jobs = []
    for trial in range(1, a.trials + 1):              # trial-major: every instance gets trial 1 first
        for cfg in a.configs.split(","):
            for attack in ATTACKS:
                for sc in SCENARIOS:
                    for i in range(10):
                        tid = f"tamas_{attack}_{sc}_v{i + 1}_t{trial}_{cfg}"
                        if tid not in done:
                            jobs.append((attack, sc, i, cfg, trial, tid))
    print(f"{len(jobs)} runs to do ({len(done)} done)", flush=True)
    t0, n = time.time(), 0

    def one(job):
        nonlocal n
        attack, sc, i, cfg, trial, tid = job
        cmd = [a.python, str(HERE / "run_crew.py"), "--attack", attack, "--scenario", sc, "--index", str(i),
               "--config", cfg, "--trial", str(trial), "--model", a.model, "--base-url", a.base_url,
               "--gate", a.gate, "--out-dir", str(out)]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=open(out / "stderr.log", "a"),
                           timeout=a.timeout, cwd=HERE)
        except subprocess.TimeoutExpired:
            with open(out / "runs.jsonl", "a") as f:
                f.write(json.dumps({"trial_id": tid, "attack": attack, "scenario": sc, "index": i,
                                    "trial": trial, "config": cfg, "status": "timeout"}) + "\n")
        n += 1
        if n % 25 == 0:
            print(f"{n}/{len(jobs)} in {(time.time() - t0) / 60:.1f} min", flush=True)

    with ThreadPoolExecutor(a.workers) as ex:
        list(ex.map(one, jobs))
    print("complete", flush=True)


if __name__ == "__main__":
    main()
