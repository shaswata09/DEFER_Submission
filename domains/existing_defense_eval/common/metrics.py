"""
Statistical metrics for existing-defense bypass evaluation.

Key metric:
    bypass_rate = fraction of (variant x trial) cases where the defense
                  did NOT flag the attack (i.e., attack would proceed).

Mirrors Yi et al. (NAACL 2025) reporting; complements ASR by isolating
the defense's contribution from the LLM's compliance behaviour.
"""

from collections import defaultdict
import numpy as np


def measurable(results: list[dict]) -> list[dict]:
    """Drop trials whose verdict is ``None`` (not measurable)."""
    return [r for r in results if r.get("blocked") is not None]


def compute_bypass_rate(results: list[dict]) -> float:
    """Top-level bypass rate across measurable results."""
    results = measurable(results)
    if not results:
        return 0.0
    return sum(1 for r in results if not r["blocked"]) / len(results)


def compute_per_ap_bypass(results: list[dict]) -> dict[str, dict]:
    """
    Per-AP bypass breakdown.
    Returns {ap: {bypass_rate, total, bypassed, blocked, ci_low, ci_high}}.
    """
    by_ap = defaultdict(list)
    not_measurable = defaultdict(int)
    for r in results:
        if r.get("blocked") is None:
            not_measurable[r["ap"]] += 1
            by_ap.setdefault(r["ap"], [])
            continue
        by_ap[r["ap"]].append(0 if r["blocked"] else 1)

    out = {}
    for ap, vals in by_ap.items():
        n = len(vals)
        bypassed = sum(vals)
        mean, lo, hi = bootstrap_ci(vals) if n else (0.0, 0.0, 0.0)
        out[ap] = {
            "bypass_rate": bypassed / n if n else None,
            "total": n,
            "bypassed": bypassed,
            "blocked": n - bypassed,
            "not_measurable": not_measurable.get(ap, 0),
            "ci_low": lo,
            "ci_high": hi,
        }
    return out


def compute_per_variant_bypass(results: list[dict]) -> dict[tuple, float]:
    """Returns {(ap, variant_id): bypass_rate}."""
    by_var = defaultdict(list)
    for r in measurable(results):
        key = (r["ap"], r.get("variant", "v?"))
        by_var[key].append(0 if r["blocked"] else 1)
    return {k: np.mean(v) for k, v in by_var.items()}


def mcnemar_paired(baseline_outcomes: list[int], defense_outcomes: list[int]) -> dict:
    """
    Paired McNemar test on two binary outcome lists (1=attack succeeded).
    Both lists must be aligned trial-by-trial.

    Returns dict with discordant counts and exact mid-p value.
    """
    assert len(baseline_outcomes) == len(defense_outcomes), "must be paired"
    b = sum(1 for a, d in zip(baseline_outcomes, defense_outcomes)
            if a == 1 and d == 0)  # baseline succeeded, defense blocked
    c = sum(1 for a, d in zip(baseline_outcomes, defense_outcomes)
            if a == 0 and d == 1)  # baseline blocked, defense allowed
    n = b + c
    if n == 0:
        return {"b": 0, "c": 0, "p_value": 1.0, "effect": "no_difference"}
    try:
        from scipy.stats import binomtest
        p = binomtest(min(b, c), n, 0.5, alternative="two-sided").pvalue
    except Exception:
        # Fallback: normal approximation
        chi2 = (b - c) ** 2 / (b + c)
        from math import erfc, sqrt
        p = erfc(sqrt(chi2 / 2))
    effect = "defense_helps" if b > c else "defense_hurts" if c > b else "no_difference"
    return {"b": b, "c": c, "p_value": p, "effect": effect}


def bootstrap_ci(outcomes: list[int], n_resamples: int = 2000, ci: float = 0.95):
    """Bootstrap (mean, ci_low, ci_high)."""
    a = np.array(outcomes, dtype=float)
    if len(a) == 0:
        return (0.0, 0.0, 0.0)
    rng = np.random.default_rng(seed=42)
    samples = rng.choice(a, size=(n_resamples, len(a)), replace=True).mean(axis=1)
    alpha = (1 - ci) / 2
    return (float(a.mean()), float(np.quantile(samples, alpha)),
            float(np.quantile(samples, 1 - alpha)))


def summarize_results(results: list[dict]) -> dict:
    """High-level summary across IPI vs Structural categories."""
    ipi = [r for r in results if r["category"] == "IPI"]
    struct = [r for r in results if r["category"] == "Structural"]
    return {
        "total_trials": len(results),
        "measurable_trials": len(measurable(results)),
        "not_measurable_trials": len(results) - len(measurable(results)),
        "overall_bypass_rate": compute_bypass_rate(results),
        "ipi_trials": len(ipi),
        "ipi_bypass_rate": compute_bypass_rate(ipi),
        "structural_trials": len(struct),
        "structural_bypass_rate": compute_bypass_rate(struct),
        "per_ap": compute_per_ap_bypass(results),
    }
