"""
Standardized plots for existing-defense bypass evaluation.

Every defense notebook produces the same 4 charts so cross-defense
comparison is one-glance:
  1. Bypass rate per AP (with 95% CI), coloured IPI vs Structural
  2. Mean bypass by attack category (IPI vs Structural)
  3. Per-variant heatmap (AP rows x variant columns)
  4. Optional comparison vs a baseline / vs DEFER
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from .attack_categories import AP_NAMES, ap_color, category


def _ap_sort_key(a: str):
    """Sort 'ap1'..'ap15' numerically; fall back to alphabetical for benign
    variant ids like 'benign_01' that don't match the attack-AP pattern."""
    try:
        return (0, int(a[2:]))
    except (ValueError, TypeError):
        return (1, a)


def _sorted_aps(asr_dict: dict) -> list[str]:
    return sorted(asr_dict.keys(), key=_ap_sort_key)


def plot_bypass_per_ap(per_ap: dict, defense_name: str, domain: str,
                       figsize=(15, 6), ylim=(0, 105)):
    """Bar chart of bypass rate per AP with bootstrap 95% CI error bars."""
    aps = [a for a in _sorted_aps(per_ap) if per_ap[a].get("bypass_rate") is not None]
    rates = [per_ap[a]["bypass_rate"] * 100 for a in aps]
    errs_lo = [(per_ap[a]["bypass_rate"] - per_ap[a]["ci_low"]) * 100 for a in aps]
    errs_hi = [(per_ap[a]["ci_high"] - per_ap[a]["bypass_rate"]) * 100 for a in aps]
    colors = [ap_color(a) for a in aps]
    labels = [f"{a.upper()}\n{AP_NAMES.get(a, '')[:18]}" for a in aps]

    fig, ax = plt.subplots(figsize=figsize)
    bars = ax.bar(range(len(aps)), rates, color=colors,
                  yerr=[errs_lo, errs_hi], capsize=4, edgecolor="black", linewidth=0.5)
    for bar, rate in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 2, f"{rate:.0f}%",
                ha="center", va="bottom", fontsize=8)
    ax.set_xticks(range(len(aps)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("Attack Bypass Rate (%)", fontsize=11)
    ax.set_ylim(*ylim)
    ax.set_title(f"{defense_name} — Bypass Rate per Attack Path\n"
                 f"Domain: {domain}   (red = IPI, blue = Structural)", fontsize=12)
    ax.grid(axis="y", alpha=0.3)
    ipi_patch = mpatches.Patch(color="#d62728", label="IPI attack paths")
    struct_patch = mpatches.Patch(color="#1f77b4", label="Structural attack paths")
    ax.legend(handles=[ipi_patch, struct_patch], loc="upper right")
    plt.tight_layout()
    return fig


def plot_bypass_by_category(per_ap: dict, defense_name: str, domain: str,
                            figsize=(7, 5)):
    """Two-bar summary: mean IPI vs mean Structural bypass."""
    ipi_rates = [per_ap[a]["bypass_rate"] for a in per_ap
                 if category(a) == "IPI" and per_ap[a].get("bypass_rate") is not None]
    struct_rates = [per_ap[a]["bypass_rate"] for a in per_ap
                    if category(a) == "Structural" and per_ap[a].get("bypass_rate") is not None]
    fig, ax = plt.subplots(figsize=figsize)
    cats = [f"IPI APs\n(n={len(ipi_rates)})", f"Structural APs\n(n={len(struct_rates)})"]
    means = [np.mean(ipi_rates) * 100 if ipi_rates else 0,
             np.mean(struct_rates) * 100 if struct_rates else 0]
    bars = ax.bar(cats, means, color=["#d62728", "#1f77b4"], edgecolor="black")
    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{m:.1f}%", ha="center", va="bottom", fontsize=11, fontweight="bold")
    ax.set_ylabel("Mean Bypass Rate (%)", fontsize=11)
    ax.set_ylim(0, 110)
    ax.set_title(f"{defense_name} — Bypass by Attack Category\nDomain: {domain}",
                 fontsize=12)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    return fig


def plot_per_variant_heatmap(per_variant: dict, defense_name: str, domain: str,
                             figsize=(10, 8)):
    """Heatmap: rows = AP, columns = variant_id."""
    aps = sorted({k[0] for k in per_variant.keys()}, key=_ap_sort_key)
    variants = sorted({k[1] for k in per_variant.keys()})
    matrix = np.full((len(aps), len(variants)), np.nan)
    for (ap, var), rate in per_variant.items():
        i = aps.index(ap)
        j = variants.index(var)
        matrix[i, j] = rate * 100

    fig, ax = plt.subplots(figsize=figsize)
    im = ax.imshow(matrix, cmap="RdYlGn_r", vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(len(variants)))
    ax.set_xticklabels(variants, rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(aps)))
    ax.set_yticklabels([f"{a.upper()} — {AP_NAMES.get(a, '')[:22]}" for a in aps],
                       fontsize=8)
    for i in range(len(aps)):
        for j in range(len(variants)):
            v = matrix[i, j]
            if not np.isnan(v):
                ax.text(j, i, f"{v:.0f}", ha="center", va="center",
                        fontsize=7, color="white" if v > 50 else "black")
    plt.colorbar(im, ax=ax, label="Bypass Rate (%)")
    ax.set_title(f"{defense_name} — Per-Variant Bypass Heatmap\nDomain: {domain}",
                 fontsize=12)
    plt.tight_layout()
    return fig


def plot_defense_comparison(per_ap_dict_by_defense: dict, domain: str,
                            figsize=(15, 6)):
    """
    Grouped bar chart comparing multiple defenses side-by-side per AP.
    per_ap_dict_by_defense: {defense_name: {ap: {bypass_rate, ...}}}
    """
    defenses = list(per_ap_dict_by_defense.keys())
    all_aps = sorted({a for d in per_ap_dict_by_defense.values() for a in d},
                     key=_ap_sort_key)
    width = 0.8 / len(defenses)
    x = np.arange(len(all_aps))
    fig, ax = plt.subplots(figsize=figsize)
    cmap = plt.get_cmap("tab10")
    for idx, dname in enumerate(defenses):
        per_ap = per_ap_dict_by_defense[dname]
        rates = [(per_ap.get(a, {}).get("bypass_rate") or 0) * 100 for a in all_aps]
        offset = (idx - (len(defenses) - 1) / 2) * width
        ax.bar(x + offset, rates, width, label=dname, color=cmap(idx))
    ax.set_xticks(x)
    ax.set_xticklabels([a.upper() for a in all_aps], rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("Bypass Rate (%)")
    ax.set_ylim(0, 105)
    ax.set_title(f"Defense Comparison — Bypass Rate per AP\nDomain: {domain}",
                 fontsize=12)
    ax.legend(loc="upper right", fontsize=8)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    return fig
