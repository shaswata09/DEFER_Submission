"""Common utilities for existing-defense bypass evaluation across all 4 domains."""

from .attack_loader import load_attack_payloads, extract_untrusted_spans, list_aps
from .attack_categories import (
    IPI_APS,
    STRUCTURAL_APS,
    AP_NAMES,
    category,
    ap_color,
)
from .metrics import (
    compute_bypass_rate,
    compute_per_ap_bypass,
    compute_per_variant_bypass,
    mcnemar_paired,
    bootstrap_ci,
    summarize_results,
)
from .plotting import (
    plot_bypass_per_ap,
    plot_bypass_by_category,
    plot_per_variant_heatmap,
    plot_defense_comparison,
)
from .log_writer import DefenseEvalLogger
from .evaluator import evaluate_filter_defense, evaluate_prompt_defense
from .benign_loader import load_benign_payloads, list_benign_variants
from .benign_evaluator import evaluate_prompt_defense_benign, detect_overrefusal
from .measurability import (
    prompt_defense_targets,
    prompt_defense_measurable,
    default_malicious_response,
    is_prompt_mod_defense,
)

__all__ = [
    "load_attack_payloads", "extract_untrusted_spans", "list_aps",
    "IPI_APS", "STRUCTURAL_APS", "AP_NAMES", "category", "ap_color",
    "compute_bypass_rate", "compute_per_ap_bypass", "compute_per_variant_bypass",
    "mcnemar_paired", "bootstrap_ci", "summarize_results",
    "plot_bypass_per_ap", "plot_bypass_by_category", "plot_per_variant_heatmap",
    "plot_defense_comparison",
    "DefenseEvalLogger",
    "evaluate_filter_defense", "evaluate_prompt_defense",
    "load_benign_payloads", "list_benign_variants",
    "evaluate_prompt_defense_benign", "detect_overrefusal",
    "prompt_defense_targets", "prompt_defense_measurable",
    "default_malicious_response", "is_prompt_mod_defense",
]
