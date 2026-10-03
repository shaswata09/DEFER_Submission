"""Uncertainty and significance for the attack-path results (H12).

* ``wilson(k, n)``: Wilson score interval for a proportion.
* ``cluster_bootstrap``: percentile CI of a rate where trials are resampled
  by *variant* (the cluster: the same payload replayed 3x is not 3
  independent observations), B = 10,000 draws.
* ``paired_diff``: bootstrap CI and two-sided p-value for the difference
  of two configurations' rates over the same variants (paired by
  cluster).
* ``holm``: Holm step-down correction of a family of p-values.

CLI: reads ``results/eval_attacks/all_trials.csv`` and writes
``results/eval_attacks/stats.csv`` with, per (group, domain, ap) and for
the whole group, the ASR of each config with Wilson and bootstrap CIs and
the paired differences flat - agenticcyops and acl_hardened - agenticcyops
with Holm-corrected p-values (family = the APs of one group x domain).

Usage::

    python -m analysis.statistical_tests               # B=10000
    python -m analysis.statistical_tests --B 2000
"""

from __future__ import annotations

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

import numpy as np

from config import RESULTS_DIR

MEASURABLE = ("executed", "blocked", "not_attempted")
SYSTEM_CONFIGS = ("flat", "acl_hardened", "agenticcyops")


# --------------------------------------------------------------------- #
#  Estimators
# --------------------------------------------------------------------- #


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float, float]:
    """(point, low, high) Wilson score interval; (nan, nan, nan) when n = 0."""
    if n <= 0:
        return float("nan"), float("nan"), float("nan")
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


def _clusters(trials: list[dict], key: Callable[[dict], str]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    for t in trials:
        out[key(t)].append(t)
    return out


def rate(trials: list[dict], indicator: Callable[[dict], bool]) -> float:
    if not trials:
        return float("nan")
    return sum(1 for t in trials if indicator(t)) / len(trials)


def cluster_bootstrap(trials: list[dict], indicator: Callable[[dict], bool],
                      cluster_key: Callable[[dict], str], B: int = 10000,
                      seed: int = 0, alpha: float = 0.05) -> tuple[float, float, float]:
    """(point, low, high): percentile bootstrap over clusters (variants)."""
    if not trials:
        return float("nan"), float("nan"), float("nan")
    # clusters in key order: the same trials give the same interval whatever
    # order they arrive in (2026-10-02 audit; dict insertion order differed
    # between the replay tables and the figures)
    cl = _clusters(trials, cluster_key)
    groups = [cl[k] for k in sorted(cl)]
    num = np.array([sum(1 for t in g if indicator(t)) for g in groups], dtype=float)
    den = np.array([len(g) for g in groups], dtype=float)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(groups), size=(B, len(groups)))
    stats = num[idx].sum(axis=1) / den[idx].sum(axis=1)
    return float(num.sum() / den.sum()), float(np.quantile(stats, alpha / 2)), float(np.quantile(stats, 1 - alpha / 2))


def paired_diff(a: list[dict], b: list[dict], indicator: Callable[[dict], bool],
                cluster_key: Callable[[dict], str], B: int = 10000, seed: int = 0,
                alpha: float = 0.05) -> dict:
    """Difference rate(a) - rate(b) with the clusters paired.

    Only clusters present in both arms enter; the bootstrap resamples
    cluster ids and recomputes both rates from the same draw.  The p-value
    is the two-sided bootstrap p for a zero difference.
    """
    ca, cb = _clusters(a, cluster_key), _clusters(b, cluster_key)
    keys = sorted(set(ca) & set(cb))
    if not keys:
        return {"diff": float("nan"), "low": float("nan"), "high": float("nan"),
                "p": float("nan"), "clusters": 0}
    na = np.array([sum(1 for t in ca[k] if indicator(t)) for k in keys], dtype=float)
    da = np.array([len(ca[k]) for k in keys], dtype=float)
    nb = np.array([sum(1 for t in cb[k] if indicator(t)) for k in keys], dtype=float)
    db = np.array([len(cb[k]) for k in keys], dtype=float)
    point = float(na.sum() / da.sum() - nb.sum() / db.sum())
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(keys), size=(B, len(keys)))
    diffs = na[idx].sum(axis=1) / da[idx].sum(axis=1) - nb[idx].sum(axis=1) / db[idx].sum(axis=1)
    low, high = float(np.quantile(diffs, alpha / 2)), float(np.quantile(diffs, 1 - alpha / 2))
    # two-sided bootstrap p: how often the resampled difference crosses zero
    if point == 0:
        p = 1.0
    else:
        p = float(min(1.0, 2 * min((diffs <= 0).mean(), (diffs >= 0).mean())))
    return {"diff": point, "low": low, "high": high, "p": p, "clusters": len(keys)}


def holm(pvalues: list[float]) -> list[float]:
    """Holm step-down adjusted p-values (nan entries are passed through)."""
    idx = [i for i, p in enumerate(pvalues) if not (p is None or math.isnan(p))]
    m = len(idx)
    order = sorted(idx, key=lambda i: pvalues[i])
    adjusted = [float("nan")] * len(pvalues)
    running = 0.0
    for rank, i in enumerate(order):
        val = min(1.0, (m - rank) * pvalues[i])
        running = max(running, val)
        adjusted[i] = running
    return adjusted


# --------------------------------------------------------------------- #
#  CLI over all_trials.csv
# --------------------------------------------------------------------- #

_EXEC = lambda t: t["outcome"] == "executed"
_ATT = lambda t: t["outcome"] in ("executed", "blocked")
_CLUSTER = lambda t: f"{t['domain']}:{t['ap']}:{t['variant']}"
# exposed (T2): the model was shown the injected content; "" on pre-T2 rows
_EXPOSED = lambda t: str(t.get("exposed", "")).lower() == "true"
_HAS_EXPOSURE = lambda t: str(t.get("exposed", "")).lower() in ("true", "false")


def load_trials(path: Path) -> list[dict]:
    with open(path, newline="") as f:
        return [r for r in csv.DictReader(f)]


def compute_stats(trials: list[dict], B: int = 10000, seed: int = 0) -> list[dict]:
    rows: list[dict] = []
    trials = [t for t in trials if t.get("outcome") in MEASURABLE and not t.get("suffix")]
    by_group: dict[str, list[dict]] = _clusters(trials, lambda t: t["group"])
    for group, gt in sorted(by_group.items()):
        def _ap_order(kv):
            return int(kv[0].replace("ap", "") or 0) if kv[0].startswith("ap") else 99

        scopes: list[tuple[str, str, list[dict]]] = [("all", "all", gt)]
        # per attack path pooled over domains (T2a), Holm family ("all", cmp)
        for ap, at in sorted(_clusters(gt, lambda t: t["ap"]).items(), key=_ap_order):
            scopes.append(("all", ap, at))
        for dom, dt in sorted(_clusters(gt, lambda t: t["domain"]).items()):
            scopes.append((dom, "all", dt))
            for ap, at in sorted(_clusters(dt, lambda t: t["ap"]).items(), key=_ap_order):
                scopes.append((dom, ap, at))
        family: dict[tuple, list[tuple[int, str]]] = defaultdict(list)   # (domain, comparison) -> row indices
        for dom, ap, st in scopes:
            by_cfg = _clusters(st, lambda t: t["config"])
            row: dict = {"group": group, "domain": dom, "ap": ap}
            for cfg in SYSTEM_CONFIGS:
                ct = by_cfg.get(cfg, [])
                k, n = sum(1 for t in ct if _EXEC(t)), len(ct)
                p, wl, wh = wilson(k, n)
                _, bl, bh = cluster_bootstrap(ct, _EXEC, _CLUSTER, B=B, seed=seed)
                known = [t for t in ct if _HAS_EXPOSURE(t)]        # rows that carry the T2 flag
                exposed = [t for t in known if _EXPOSED(t)]
                row.update({f"{cfg}_n": n, f"{cfg}_asr": p, f"{cfg}_wilson_low": wl, f"{cfg}_wilson_high": wh,
                            f"{cfg}_boot_low": bl, f"{cfg}_boot_high": bh,
                            f"{cfg}_attempt_rate": rate(ct, _ATT),
                            f"{cfg}_block_given_attempt": rate([t for t in ct if _ATT(t)], lambda t: t["outcome"] == "blocked"),
                            # exposure (T9.3): share shown the content, and attempt among those
                            f"{cfg}_exposure_n": len(known),
                            f"{cfg}_exposure_rate": rate(known, _EXPOSED),
                            f"{cfg}_attempt_given_exposure": rate(exposed, _ATT)})
            for cmp_name, (x, y) in {"flat_minus_aco": ("flat", "agenticcyops"),
                                     "acl_minus_aco": ("acl_hardened", "agenticcyops")}.items():
                d = paired_diff(by_cfg.get(x, []), by_cfg.get(y, []), _EXEC, _CLUSTER, B=B, seed=seed)
                row.update({f"{cmp_name}_diff": d["diff"], f"{cmp_name}_low": d["low"],
                            f"{cmp_name}_high": d["high"], f"{cmp_name}_p": d["p"],
                            f"{cmp_name}_clusters": d["clusters"]})
                if ap != "all":
                    family[(dom, cmp_name)].append((len(rows), cmp_name))
            rows.append(row)
        # Holm within each (domain, comparison) family of APs
        for (dom, cmp_name), members in family.items():
            ps = [rows[i][f"{cmp_name}_p"] for i, _ in members]
            for (i, _), adj in zip(members, holm(ps)):
                rows[i][f"{cmp_name}_p_holm"] = adj
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--trials", type=Path, default=RESULTS_DIR / "eval_attacks" / "all_trials.csv")
    ap.add_argument("--out", type=Path, default=RESULTS_DIR / "eval_attacks" / "stats.csv")
    ap.add_argument("--B", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=0)   # the paper's stated seed (Appendix: seed 0)
    args = ap.parse_args()
    from analysis.generate_tables import _drop_siblings   # the 75 reported variants per domain
    trials = _drop_siblings(load_trials(args.trials))
    rows = compute_stats(trials, B=args.B, seed=args.seed)
    if not rows:
        print("no measurable trials")
        return
    fields = sorted({k for r in rows for k in r}, key=lambda k: (k not in ("group", "domain", "ap"), k))
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()})
    print(f"wrote {args.out} ({len(rows)} rows, B={args.B})")


if __name__ == "__main__":
    main()
