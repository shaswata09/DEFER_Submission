"""
Enhanced Baseline Analytics — Paper-Ready Metrics and Charts.

Produces:
  1. Enhanced CSV with 35+ columns (per-principle metrics, FP rates, consensus details)
  2. Paper-ready charts (attack surface, principle activity, similarity distribution, etc.)
  3. Cross-domain comparison data

Usage:
    python -m analysis.baseline_analytics --domain cyberops --group F --output results/baseline/group_F/cyberops/
    python -m analysis.baseline_analytics --domain all --group F --output results/baseline/group_F/
"""

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.patches as mpatches
import numpy as np
import seaborn as sns

from config import BASE_DIR
from analysis.runlogs import config_files

# ---------------------------------------------------------------------------
# Style constants — consistent with generate_report.py / baseline_dashboard.py
# ---------------------------------------------------------------------------

sns.set_theme(style="whitegrid", font_scale=1.0, palette="muted")
plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "savefig.bbox": "tight",
    "font.family": "sans-serif",
    "axes.titleweight": "bold",
    "axes.titlesize": 13,
})

CONFIGS = ["flat", "acl_hardened", "agenticcyops"]
CONFIG_LABELS = {"flat": "Flat MAS", "acl_hardened": "ACL-Hardened", "agenticcyops": "DEFER"}
CONFIG_COLORS = {"flat": "#e74c3c", "acl_hardened": "#f39c12", "agenticcyops": "#2ecc71"}
PHASES = ["monitor", "analyze", "admin", "report"]
DOMAINS = ["cyberops", "healthcare", "finance", "legal"]

HEADER_COLOR = "#2c3e50"
ACCENT = "#2980b9"

# ---------------------------------------------------------------------------
# Tool-count manifests per domain (from component_registry.json structure)
# In agenticcyops mode each agent sees only its phase tools; in flat/acl all
# tools are visible.  These are loaded dynamically from the registry.
# ---------------------------------------------------------------------------

def _load_tool_registry() -> dict:
    """Load component_registry.json and return {domain: {phase: [tool_names]}}."""
    registry_path = BASE_DIR / "configs" / "component_registry.json"
    if not registry_path.exists():
        return {}
    with open(registry_path) as fh:
        data = json.load(fh)
    result = {}
    for domain, tools in data.get("tools", {}).items():
        phase_map: dict[str, list[str]] = defaultdict(list)
        for tool_name, meta in tools.items():
            phase_map[meta.get("type", "unknown")].append(tool_name)
        result[domain] = dict(phase_map)
    return result


TOOL_REGISTRY = _load_tool_registry()


def _total_tools(domain: str) -> int:
    """Total tools available in a domain."""
    phases = TOOL_REGISTRY.get(domain, {})
    return sum(len(v) for v in phases.values())


def _manifest_tools_per_phase(domain: str) -> dict[str, int]:
    """Tools visible per phase (agenticcyops manifest)."""
    return {phase: len(tools) for phase, tools in TOOL_REGISTRY.get(domain, {}).items()}


# ---------------------------------------------------------------------------
# Log loading — same pattern as verify_baseline.py
# ---------------------------------------------------------------------------

def load_logs(domain: str, config: str, group: str = "F") -> list[dict]:
    """Load JSONL logs for a domain+config baseline run.

    Checks ``{domain}_baseline_{group}`` first, falls back to ``{domain}_baseline``.
    """
    candidates = [
        BASE_DIR / "logs" / f"{domain}_baseline_{group}",
        BASE_DIR / "logs" / f"{domain}_baseline",
    ]
    events: list[dict] = []
    for log_dir in candidates:
        if not log_dir.is_dir():
            continue
        for f in sorted(config_files(log_dir, config)):
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        if events:
            break
    return events


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def _count_mechanism(events: list[dict], *keywords: str) -> int:
    """Count events whose mechanism field contains any of *keywords*."""
    count = 0
    for e in events:
        m = e.get("mechanism", "")
        if m and any(kw in m for kw in keywords):
            count += 1
    return count


def _count_action(events: list[dict], action: str) -> int:
    return sum(1 for e in events if e.get("action") == action)


def _count_action_decision(events: list[dict], action: str, decision: str) -> int:
    return sum(1 for e in events if e.get("action") == action and e.get("auth_decision") == decision)


def _mechanism_and_decision(events: list[dict], keyword: str, decision: str) -> int:
    """Count events matching both mechanism keyword and auth_decision."""
    return sum(
        1 for e in events
        if keyword in e.get("mechanism", "") and e.get("auth_decision") == decision
    )


def _extract_similarities(events: list[dict]) -> list[float]:
    """Extract cosine_similarity values from events (P4 writes)."""
    vals = []
    for e in events:
        cs = e.get("cosine_similarity")
        if cs is not None:
            try:
                vals.append(float(cs))
            except (ValueError, TypeError):
                pass
    return vals


def _phases_completed(events: list[dict]) -> int:
    """Count how many phases had activity."""
    active = set()
    for e in events:
        s = e.get("source", "")
        for p in PHASES:
            if p in s:
                active.add(p)
    return len(active)


# ---------------------------------------------------------------------------
# Per-principle FP rate computation
# ---------------------------------------------------------------------------

def _principle_fp_rates(events: list[dict]) -> dict[str, float]:
    """Compute per-principle false positive rates.

    FP rate = denials attributed to Px / total tool calls.
    For baseline (benign) runs every denial is a false positive.
    """
    tool_calls = [e for e in events if e.get("action") == "tool_call"]
    total = len(tool_calls) if tool_calls else 1  # avoid div-by-zero
    denied = [e for e in tool_calls if e.get("auth_decision") == "deny"]
    rates = {}
    total_denied = 0
    for pnum in range(1, 6):
        prefix = f"P{pnum}"
        count = sum(1 for e in denied if prefix in e.get("mechanism", ""))
        rates[f"p{pnum}_fp_rate"] = round(count / total, 4)
        total_denied += count
    rates["total_fp_rate"] = round(total_denied / total, 4)
    return rates


# ---------------------------------------------------------------------------
# Enhanced CSV row computation
# ---------------------------------------------------------------------------

def compute_enhanced_row(domain: str, config: str, group: str) -> dict[str, Any]:
    """Compute a single row of the enhanced CSV for one domain+config."""
    events = load_logs(domain, config, group)
    if not events:
        return {}

    tool_calls = [e for e in events if e.get("action") == "tool_call"]
    tc_allowed = [e for e in tool_calls if e.get("auth_decision") == "allow"]
    tc_denied = [e for e in tool_calls if e.get("auth_decision") == "deny"]
    consensus_votes = [e for e in events if e.get("action") == "consensus_vote"]
    consensus_results = [e for e in events if e.get("action") == "consensus_result"]

    latencies = [e["latency_ms"] for e in events if e.get("latency_ms")]
    tool_latencies = [e["latency_ms"] for e in tool_calls if e.get("latency_ms")]
    consensus_latencies = [e["latency_ms"] for e in consensus_votes if e.get("latency_ms")]

    tokens_p = sum(e.get("tokens_prompt", 0) or 0 for e in events)
    tokens_c = sum(e.get("tokens_completion", 0) or 0 for e in events)
    tokens_total = sum(e.get("tokens_used", 0) or 0 for e in events)
    # Fallback: if tokens_used not set but prompt+completion are
    if tokens_total == 0 and (tokens_p or tokens_c):
        tokens_total = tokens_p + tokens_c

    mem_reads = _count_action(events, "memory_read")
    mem_writes = _count_action(events, "memory_write")

    similarities = _extract_similarities(events)

    # Tools visible per agent — from llm_call events or manifest
    tools_visible_vals = [e.get("tools_visible") for e in events if e.get("tools_visible") is not None]
    if tools_visible_vals:
        # Average across LLM calls (may differ per phase in agenticcyops)
        tools_visible_avg = round(sum(tools_visible_vals) / len(tools_visible_vals), 1)
    else:
        tools_visible_avg = _total_tools(domain) if config != "agenticcyops" else 0

    # ----- P1 metrics -----
    p1_identity_checks = _count_mechanism(events, "P1_identity", "P1_authenticated")
    p1_identity_allow = sum(
        1 for e in events
        if any(kw in e.get("mechanism", "") for kw in ("P1_identity", "P1_authenticated"))
        and e.get("auth_decision") == "allow"
    )
    p1_identity_deny = sum(
        1 for e in events
        if any(kw in e.get("mechanism", "") for kw in ("P1_identity", "P1_authenticated"))
        and e.get("auth_decision") == "deny"
    )
    p1_response_checks = _count_mechanism(events, "P1_response", "P1_schema")
    p1_response_allow = sum(
        1 for e in events
        if any(kw in e.get("mechanism", "") for kw in ("P1_response", "P1_schema"))
        and e.get("auth_decision") == "allow"
    )
    p1_response_deny = sum(
        1 for e in events
        if any(kw in e.get("mechanism", "") for kw in ("P1_response", "P1_schema"))
        and e.get("auth_decision") == "deny"
    )
    p1_config_checks = _count_mechanism(events, "P1_config")

    # ----- P2 metrics -----
    p2_manifest_checks = _count_mechanism(events, "P2_capability_scoping")
    p2_manifest_allow = _mechanism_and_decision(events, "P2_capability_scoping", "allow")
    p2_manifest_deny = _mechanism_and_decision(events, "P2_capability_scoping", "deny")
    p2_parameter_checks = _count_mechanism(events, "P2_wildcard", "P2_critical", "P2_parameter")
    p2_parameter_allow = sum(
        1 for e in events
        if any(kw in e.get("mechanism", "") for kw in ("P2_wildcard", "P2_critical", "P2_parameter"))
        and e.get("auth_decision") == "allow"
    )
    p2_parameter_deny = sum(
        1 for e in events
        if any(kw in e.get("mechanism", "") for kw in ("P2_wildcard", "P2_critical", "P2_parameter"))
        and e.get("auth_decision") == "deny"
    )
    p2_output_checks = _count_mechanism(events, "P2_sensitive", "P2_output")
    p2_output_allow = sum(
        1 for e in events
        if any(kw in e.get("mechanism", "") for kw in ("P2_sensitive", "P2_output"))
        and e.get("auth_decision") == "allow"
    )
    p2_output_deny = sum(
        1 for e in events
        if any(kw in e.get("mechanism", "") for kw in ("P2_sensitive", "P2_output"))
        and e.get("auth_decision") == "deny"
    )
    p2_output_redact = sum(
        1 for e in events
        if any(kw in e.get("mechanism", "") for kw in ("P2_sensitive", "P2_output"))
        and e.get("auth_decision") == "redact"
    )

    # ----- P3 metrics -----
    p3_approved = sum(1 for e in consensus_results if e.get("auth_decision") == "approved")
    p3_rejected = sum(1 for e in consensus_results if e.get("auth_decision") == "rejected")
    p3_total_validations = len(consensus_results)
    p3_consensus_votes = len(consensus_votes)
    confidences = [e.get("confidence", 0) for e in consensus_votes if e.get("confidence") is not None]
    p3_avg_confidence = round(sum(confidences) / len(confidences), 4) if confidences else 0.0

    p3_chain_events = _count_mechanism(events, "P3_chain", "P3_posture", "P3_dangerous", "P3_velocity")
    p3_operational_events = _count_mechanism(events, "P3_operational", "P3_change", "P3_maintenance", "P3_time")
    p3_replay_events = _count_mechanism(events, "P3_replay", "P3_exact", "P3_no_replay")

    # ----- P4 metrics -----
    p4_write_events = [e for e in events if e.get("action") == "memory_write"]
    p4_write_allow = sum(1 for e in p4_write_events if e.get("auth_decision") == "allow")
    p4_write_deny = sum(1 for e in p4_write_events if e.get("auth_decision") == "deny")
    p4_write_validations = len(p4_write_events)
    p4_avg_sim = round(sum(similarities) / len(similarities), 4) if similarities else 0.0
    p4_min_sim = round(min(similarities), 4) if similarities else 0.0
    p4_max_sim = round(max(similarities), 4) if similarities else 0.0
    p4_schema_checks = _count_mechanism(events, "P4_schema")
    p4_metadata_checks = _count_mechanism(events, "P4_metadata", "P4_invalid")

    # ----- P5 metrics -----
    p5_read_events = [e for e in events if e.get("action") == "memory_read"]
    p5_read_allow = sum(1 for e in p5_read_events if e.get("auth_decision") == "allow")
    p5_read_deny = sum(1 for e in p5_read_events if e.get("auth_decision") == "deny")
    p5_read_validations = len(p5_read_events)
    p5_field_filter = _count_mechanism(events, "P5_field")
    p5_query_scope = _count_mechanism(events, "P5_broad", "P5_irrelevant", "P5_query")
    p5_sanitization = _count_mechanism(events, "P5_injection", "_sanitized")

    # FP rates
    fp = _principle_fp_rates(events)

    # E2E latency (first to last timestamp)
    timestamps = []
    for e in events:
        ts = e.get("timestamp")
        if ts:
            try:
                timestamps.append(datetime.fromisoformat(ts))
            except (ValueError, TypeError):
                pass
    if len(timestamps) >= 2:
        e2e_latency_s = round((max(timestamps) - min(timestamps)).total_seconds(), 2)
    else:
        e2e_latency_s = round(sum(latencies) / 1000, 2) if latencies else 0.0

    row = {
        # Basic
        "config": config,
        "domain": domain,
        "group": group,
        "total_events": len(events),
        "phases_completed": _phases_completed(events),
        # Tool calls
        "tool_calls_total": len(tool_calls),
        "tool_calls_allowed": len(tc_allowed),
        "tool_calls_denied": len(tc_denied),
        "tools_visible_per_agent": tools_visible_avg,
        # P1
        "p1_identity_checks": p1_identity_checks,
        "p1_identity_allow": p1_identity_allow,
        "p1_identity_deny": p1_identity_deny,
        "p1_response_checks": p1_response_checks,
        "p1_response_allow": p1_response_allow,
        "p1_response_deny": p1_response_deny,
        "p1_config_checks": p1_config_checks,
        # P2
        "p2_manifest_checks": p2_manifest_checks,
        "p2_manifest_allow": p2_manifest_allow,
        "p2_manifest_deny": p2_manifest_deny,
        "p2_parameter_checks": p2_parameter_checks,
        "p2_parameter_allow": p2_parameter_allow,
        "p2_parameter_deny": p2_parameter_deny,
        "p2_output_checks": p2_output_checks,
        "p2_output_allow": p2_output_allow,
        "p2_output_deny": p2_output_deny,
        "p2_output_redact": p2_output_redact,
        # P3
        "p3_total_validations": p3_total_validations,
        "p3_approved": p3_approved,
        "p3_rejected": p3_rejected,
        "p3_consensus_votes": p3_consensus_votes,
        "p3_avg_confidence": p3_avg_confidence,
        "p3_chain_events": p3_chain_events,
        "p3_operational_events": p3_operational_events,
        "p3_replay_events": p3_replay_events,
        # P4
        "p4_write_validations": p4_write_validations,
        "p4_write_allow": p4_write_allow,
        "p4_write_deny": p4_write_deny,
        "p4_avg_similarity": p4_avg_sim,
        "p4_min_similarity": p4_min_sim,
        "p4_max_similarity": p4_max_sim,
        "p4_schema_checks": p4_schema_checks,
        "p4_metadata_checks": p4_metadata_checks,
        # P5
        "p5_read_validations": p5_read_validations,
        "p5_read_allow": p5_read_allow,
        "p5_read_deny": p5_read_deny,
        "p5_field_filter_events": p5_field_filter,
        "p5_query_scope_events": p5_query_scope,
        "p5_sanitization_events": p5_sanitization,
        # FP rates
        "p1_fp_rate": fp.get("p1_fp_rate", 0.0),
        "p2_fp_rate": fp.get("p2_fp_rate", 0.0),
        "p3_fp_rate": fp.get("p3_fp_rate", 0.0),
        "p4_fp_rate": fp.get("p4_fp_rate", 0.0),
        "p5_fp_rate": fp.get("p5_fp_rate", 0.0),
        "total_fp_rate": fp.get("total_fp_rate", 0.0),
        # Performance
        "e2e_latency_s": e2e_latency_s,
        "avg_tool_latency_ms": round(sum(tool_latencies) / len(tool_latencies), 2) if tool_latencies else 0.0,
        "consensus_avg_latency_ms": round(sum(consensus_latencies) / len(consensus_latencies), 2) if consensus_latencies else 0.0,
        "total_tokens": tokens_total,
        "tokens_prompt": tokens_p,
        "tokens_completion": tokens_c,
        # Memory
        "memory_reads": mem_reads,
        "memory_writes": mem_writes,
    }
    return row


# ---------------------------------------------------------------------------
# CSV generation
# ---------------------------------------------------------------------------

def write_enhanced_csv(rows: list[dict], output_path: Path):
    """Write the enhanced baseline CSV."""
    if not rows:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with open(output_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  CSV written: {output_path} ({len(rows)} rows, {len(fieldnames)} cols)")


# ---------------------------------------------------------------------------
# Chart 1: Attack Surface Reduction
# ---------------------------------------------------------------------------

def chart_attack_surface(domain: str, output_dir: Path):
    """Grouped bar chart showing tools visible per phase per config."""
    manifest = _manifest_tools_per_phase(domain)
    total = _total_tools(domain)

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(PHASES))
    width = 0.25

    for i, config in enumerate(CONFIGS):
        vals = []
        for phase in PHASES:
            if config == "agenticcyops":
                vals.append(manifest.get(phase, 0))
            else:
                vals.append(total)
        bars = ax.bar(x + i * width, vals, width, label=CONFIG_LABELS[config],
                      color=CONFIG_COLORS[config], edgecolor="white", linewidth=0.5)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                    str(v), ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_xlabel("Pipeline Phase", fontsize=12)
    ax.set_ylabel("Tools Visible to Agent", fontsize=12)
    ax.set_title(f"Attack Surface Reduction — {domain.title()}", fontsize=14, fontweight="bold")
    ax.set_xticks(x + width)
    ax.set_xticklabels([p.title() for p in PHASES])
    ax.legend(frameon=True, framealpha=0.9)
    ax.set_ylim(0, total + 3)

    # Annotation
    if manifest:
        avg_manifest = sum(manifest.get(p, 0) for p in PHASES) / len(PHASES)
        reduction = round((1 - avg_manifest / total) * 100) if total else 0
        ax.text(0.98, 0.95, f"{reduction}% avg reduction",
                transform=ax.transAxes, ha="right", va="top",
                fontsize=11, color=CONFIG_COLORS["agenticcyops"], fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#eafaf1", edgecolor=CONFIG_COLORS["agenticcyops"]))

    plt.tight_layout()
    path = output_dir / "attack_surface.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  Chart saved: {path}")
    return path


# ---------------------------------------------------------------------------
# Chart 2: Principle Activity Heatmap
# ---------------------------------------------------------------------------

_HEATMAP_ROWS = [
    ("P1-L1 identity", "P1_identity", "P1_authenticated"),
    ("P1-L2 response", "P1_response", "P1_schema"),
    ("P1-L3 config", "P1_config",),
    ("P2-L1 manifest", "P2_capability_scoping",),
    ("P2-L2 params", "P2_wildcard", "P2_critical", "P2_parameter"),
    ("P2-L3 output", "P2_sensitive", "P2_output"),
    ("P3 consensus", "P3_verified_execution",),
    ("P3 chain", "P3_chain", "P3_posture", "P3_dangerous", "P3_velocity"),
    ("P3 context", "P3_operational", "P3_change", "P3_maintenance", "P3_time"),
    ("P4 similarity", "P4_embedding", "P4_similarity"),
    ("P4 schema", "P4_schema",),
    ("P5 access", "P5_access_control",),
    ("P5 sanitize", "P5_injection",),
]


def chart_principle_heatmap(domain: str, group: str, output_dir: Path):
    """Heatmap: principle layers x configs, values = event count."""
    data = np.zeros((len(_HEATMAP_ROWS), len(CONFIGS)))
    for j, config in enumerate(CONFIGS):
        events = load_logs(domain, config, group)
        for i, (label, *keywords) in enumerate(_HEATMAP_ROWS):
            data[i, j] = _count_mechanism(events, *keywords)

    fig, ax = plt.subplots(figsize=(8, 8))
    im = ax.imshow(data, aspect="auto", cmap="YlGnBu")

    ax.set_xticks(range(len(CONFIGS)))
    ax.set_xticklabels([CONFIG_LABELS[c] for c in CONFIGS], fontsize=10)
    ax.set_yticks(range(len(_HEATMAP_ROWS)))
    ax.set_yticklabels([r[0] for r in _HEATMAP_ROWS], fontsize=9)

    # Annotate cells
    for i in range(len(_HEATMAP_ROWS)):
        for j in range(len(CONFIGS)):
            val = int(data[i, j])
            color = "white" if val > data.max() * 0.6 else "black"
            ax.text(j, i, str(val), ha="center", va="center", fontsize=9,
                    fontweight="bold", color=color)

    ax.set_title(f"Defensive Principle Activity — {domain.title()}", fontsize=14, fontweight="bold")
    cbar = fig.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label("Event Count", fontsize=10)

    plt.tight_layout()
    path = output_dir / "principle_heatmap.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  Chart saved: {path}")
    return path


# ---------------------------------------------------------------------------
# Chart 3: FP Rate Comparison
# ---------------------------------------------------------------------------

def chart_fp_rates(row: dict, output_dir: Path):
    """Bar chart showing per-principle FP rates for agenticcyops."""
    domain = row.get("domain", "unknown")
    principles = ["P1", "P2", "P3", "P4", "P5"]
    rates = [row.get(f"p{i}_fp_rate", 0) * 100 for i in range(1, 6)]

    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ["#e74c3c" if r > 10 else "#2ecc71" for r in rates]
    bars = ax.bar(principles, rates, color=colors, edgecolor="white", linewidth=0.8, width=0.5)

    # 10% threshold line
    ax.axhline(y=10, color="#e74c3c", linestyle="--", linewidth=1.5, alpha=0.7, label="10% threshold")

    for bar, r in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                f"{r:.1f}%", ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_xlabel("Defensive Principle", fontsize=12)
    ax.set_ylabel("False Positive Rate (%)", fontsize=12)
    ax.set_title(f"Benign FP Rates — DEFER / {domain.title()}", fontsize=14, fontweight="bold")
    ax.legend(loc="upper right")
    ax.set_ylim(0, max(max(rates) * 1.3, 15))

    plt.tight_layout()
    path = output_dir / "fp_rate_comparison.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  Chart saved: {path}")
    return path


# ---------------------------------------------------------------------------
# Chart 4: Config Comparison Radar
# ---------------------------------------------------------------------------

def chart_config_radar(rows: list[dict], output_dir: Path):
    """Spider/radar chart with 6 axes across three configs."""
    domain = rows[0].get("domain", "unknown") if rows else "unknown"
    axes_labels = [
        "Completion\nRate",
        "Tool Calls\nAllowed",
        "Memory\nOps",
        "Principles\nActive",
        "Latency\nEfficiency",
        "Token\nEfficiency",
    ]
    n_axes = len(axes_labels)

    # Compute raw values per config
    raw: dict[str, list[float]] = {}
    for r in rows:
        cfg = r["config"]
        completion = r.get("phases_completed", 0) / 4 * 100  # percentage
        tool_allowed = r.get("tool_calls_allowed", 0)
        mem_ops = r.get("memory_reads", 0) + r.get("memory_writes", 0)
        # Count principles active: any P1-P5 events
        p_active = 0
        for pnum in range(1, 6):
            checks_key = f"p{pnum}_fp_rate"
            # A principle is "active" if there are mechanism events for it
            # Use a heuristic: sum of per-principle checks > 0
            activity_keys = {
                1: ["p1_identity_checks", "p1_response_checks", "p1_config_checks"],
                2: ["p2_manifest_checks", "p2_parameter_checks", "p2_output_checks"],
                3: ["p3_total_validations", "p3_chain_events", "p3_operational_events"],
                4: ["p4_write_validations", "p4_schema_checks", "p4_metadata_checks"],
                5: ["p5_read_validations", "p5_field_filter_events", "p5_query_scope_events"],
            }
            if any(r.get(k, 0) > 0 for k in activity_keys.get(pnum, [])):
                p_active += 1

        latency_eff = 100 / (1 + r.get("e2e_latency_s", 0))  # inverse
        token_eff = 100000 / (1 + r.get("total_tokens", 0))  # inverse

        raw[cfg] = [completion, tool_allowed, mem_ops, p_active * 20, latency_eff, token_eff]

    if not raw:
        return None

    # Normalize to 0-100
    max_vals = [max(raw[c][i] for c in raw) for i in range(n_axes)]
    max_vals = [v if v > 0 else 1 for v in max_vals]
    normalized: dict[str, list[float]] = {}
    for cfg, vals in raw.items():
        normalized[cfg] = [v / m * 100 for v, m in zip(vals, max_vals)]

    # Plot
    angles = np.linspace(0, 2 * np.pi, n_axes, endpoint=False).tolist()
    angles += angles[:1]  # close the polygon

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

    for cfg in CONFIGS:
        if cfg not in normalized:
            continue
        vals = normalized[cfg] + normalized[cfg][:1]
        ax.plot(angles, vals, "o-", linewidth=2, label=CONFIG_LABELS[cfg],
                color=CONFIG_COLORS[cfg], markersize=5)
        ax.fill(angles, vals, alpha=0.1, color=CONFIG_COLORS[cfg])

    ax.set_thetagrids(np.degrees(angles[:-1]), axes_labels, fontsize=9)
    ax.set_ylim(0, 110)
    ax.set_title(f"Configuration Comparison — {domain.title()}", fontsize=14,
                 fontweight="bold", pad=25)
    ax.legend(loc="upper right", bbox_to_anchor=(1.25, 1.1), frameon=True)

    plt.tight_layout()
    path = output_dir / "config_radar.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  Chart saved: {path}")
    return path


# ---------------------------------------------------------------------------
# Chart 5: Consensus Decision Breakdown
# ---------------------------------------------------------------------------

def chart_consensus_breakdown(domain: str, group: str, output_dir: Path):
    """Stacked bar for consensus decisions in agenticcyops."""
    events = load_logs(domain, "agenticcyops", group)
    if not events:
        return None

    consensus_results = [e for e in events if e.get("action") == "consensus_result"
                         and e.get("source") == "consensus_module"]

    if not consensus_results:
        # No consensus data — skip chart
        print("  Chart skipped: consensus_breakdown.png (no consensus_result events)")
        return None

    approved = sum(1 for e in consensus_results if e.get("auth_decision") == "approved")
    rejected = sum(1 for e in consensus_results if e.get("auth_decision") == "rejected")

    fig, ax = plt.subplots(figsize=(8, 5))

    bar_labels = ["Consensus\nDecisions"]
    ax.barh(bar_labels, [approved], color="#2ecc71", edgecolor="white", label="Approved", height=0.4)
    ax.barh(bar_labels, [rejected], left=[approved], color="#e74c3c", edgecolor="white",
            label="Rejected", height=0.4)

    ax.set_xlabel("Number of Tool Call Reviews", fontsize=12)
    ax.set_title(f"P3 Consensus Breakdown — {domain.title()}", fontsize=14, fontweight="bold")
    ax.legend(loc="lower right", frameon=True)

    total = approved + rejected
    if total:
        ax.text(total / 2, 0, f"{approved}/{total} approved",
                ha="center", va="center", fontsize=11, fontweight="bold", color="white")

    # Per-validator detail
    votes = [e for e in events if e.get("action") == "consensus_vote"]
    validator_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"approve": 0, "reject": 0})
    for v in votes:
        src = v.get("source", "unknown")
        dec = v.get("auth_decision", "unknown")
        if dec in ("approve", "reject"):
            validator_stats[src][dec] += 1

    if validator_stats:
        validators = sorted(validator_stats.keys())
        y_pos = np.arange(len(validators)) + 1.5
        approves = [validator_stats[v]["approve"] for v in validators]
        rejects = [validator_stats[v]["reject"] for v in validators]

        ax.barh(validators, approves, color="#2ecc71", edgecolor="white", height=0.35, alpha=0.8)
        ax.barh(validators, rejects, left=approves, color="#e74c3c", edgecolor="white",
                height=0.35, alpha=0.8)

        for v, a, r in zip(validators, approves, rejects):
            if a + r > 0:
                ax.text(a + r + 0.1, v, f"{a}/{a+r}", va="center", fontsize=9)

    plt.tight_layout()
    path = output_dir / "consensus_breakdown.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  Chart saved: {path}")
    return path


# ---------------------------------------------------------------------------
# Summary PDF
# ---------------------------------------------------------------------------

def generate_summary_pdf(charts: list[Optional[Path]], rows: list[dict], domain: str, output_dir: Path):
    """Combine all charts into a summary PDF."""
    pdf_path = output_dir / "baseline_analytics.pdf"
    with PdfPages(str(pdf_path)) as pdf:
        # Title page
        fig, ax = plt.subplots(figsize=(11, 8.5))
        ax.axis("off")
        ax.text(0.5, 0.7, "Enhanced Baseline Analytics", transform=ax.transAxes,
                ha="center", fontsize=30, fontweight="bold", color=HEADER_COLOR)
        ax.text(0.5, 0.58, f"Domain: {domain.title()}", transform=ax.transAxes,
                ha="center", fontsize=18, color=ACCENT)
        ax.text(0.5, 0.48, datetime.now().strftime("%B %d, %Y  %H:%M"), transform=ax.transAxes,
                ha="center", fontsize=12, color="#95a5a6")
        ax.plot([0.25, 0.75], [0.53, 0.53], transform=ax.transAxes, color=ACCENT, linewidth=2)

        # Key stats
        aco = next((r for r in rows if r.get("config") == "agenticcyops"), None)
        if aco:
            stats = [
                f"Total Events: {aco.get('total_events', 0)}",
                f"Phases: {aco.get('phases_completed', 0)}/4",
                f"Consensus Votes: {aco.get('p3_consensus_votes', 0)}",
                f"Total FP Rate: {aco.get('total_fp_rate', 0)*100:.1f}%",
                f"E2E Latency: {aco.get('e2e_latency_s', 0):.1f}s",
            ]
            y = 0.36
            for s in stats:
                ax.text(0.5, y, s, transform=ax.transAxes, ha="center",
                        fontsize=12, color=HEADER_COLOR)
                y -= 0.05

        pdf.savefig(fig, bbox_inches="tight")
        plt.close(fig)

        # Chart pages
        for chart_path in charts:
            if chart_path is None or not chart_path.exists():
                continue
            fig, ax = plt.subplots(figsize=(11, 8.5))
            ax.axis("off")
            img = plt.imread(str(chart_path))
            ax.imshow(img)
            pdf.savefig(fig, bbox_inches="tight")
            plt.close(fig)

    print(f"  PDF saved: {pdf_path}")


# ---------------------------------------------------------------------------
# Cross-domain comparison (--domain all)
# ---------------------------------------------------------------------------

def cross_domain_analysis(group: str, output_dir: Path):
    """Produce cross-domain CSV and comparison chart for agenticcyops."""
    rows = []
    for domain in DOMAINS:
        row = compute_enhanced_row(domain, "agenticcyops", group)
        if row:
            rows.append(row)

    if not rows:
        print("  No cross-domain data available.")
        return

    # Write cross-domain CSV
    csv_path = output_dir / "cross_domain_summary.csv"
    write_enhanced_csv(rows, csv_path)

    # Comparison chart
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Cross-Domain DEFER Comparison", fontsize=16, fontweight="bold",
                 color=HEADER_COLOR, y=0.98)

    domain_names = [r["domain"].title() for r in rows]
    domain_colors = sns.color_palette("Set2", len(rows))

    # (1) Total events + tool calls
    ax = axes[0, 0]
    x = np.arange(len(rows))
    w = 0.35
    ax.bar(x - w/2, [r["total_events"] for r in rows], w, label="Total Events", color="#3498db")
    ax.bar(x + w/2, [r["tool_calls_total"] for r in rows], w, label="Tool Calls", color="#e67e22")
    ax.set_xticks(x)
    ax.set_xticklabels(domain_names)
    ax.set_title("Event Volume")
    ax.legend(fontsize=8)

    # (2) FP rates
    ax = axes[0, 1]
    for i, r in enumerate(rows):
        fp_vals = [r.get(f"p{p}_fp_rate", 0) * 100 for p in range(1, 6)]
        ax.plot(["P1", "P2", "P3", "P4", "P5"], fp_vals, "o-", label=r["domain"].title(),
                color=domain_colors[i], linewidth=2)
    ax.axhline(y=10, color="#e74c3c", linestyle="--", alpha=0.5, label="10% threshold")
    ax.set_title("FP Rates by Principle")
    ax.set_ylabel("FP Rate (%)")
    ax.legend(fontsize=8)

    # (3) Consensus stats
    ax = axes[1, 0]
    approved = [r.get("p3_approved", 0) for r in rows]
    rejected = [r.get("p3_rejected", 0) for r in rows]
    ax.bar(x, approved, 0.5, label="Approved", color="#2ecc71")
    ax.bar(x, rejected, 0.5, bottom=approved, label="Rejected", color="#e74c3c")
    ax.set_xticks(x)
    ax.set_xticklabels(domain_names)
    ax.set_title("P3 Consensus Decisions")
    ax.legend(fontsize=8)

    # (4) Latency + tokens
    ax = axes[1, 1]
    ax2 = ax.twinx()
    bars = ax.bar(x - 0.2, [r["e2e_latency_s"] for r in rows], 0.35, label="Latency (s)",
                  color="#9b59b6", alpha=0.8)
    ax2.bar(x + 0.2, [r["total_tokens"] for r in rows], 0.35, label="Tokens",
            color="#1abc9c", alpha=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(domain_names)
    ax.set_ylabel("Latency (s)", color="#9b59b6")
    ax2.set_ylabel("Tokens", color="#1abc9c")
    ax.set_title("Performance")
    # Combined legend
    lines1, labels1 = ax.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax.legend(lines1 + lines2, labels1 + labels2, fontsize=8, loc="upper left")

    plt.tight_layout()
    chart_path = output_dir / "cross_domain_comparison.png"
    fig.savefig(chart_path)
    plt.close(fig)
    print(f"  Chart saved: {chart_path}")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_analytics(domain: str, group: str, output_dir: Path):
    """Run the full analytics pipeline for one domain."""
    print(f"\n{'='*60}")
    print(f"  Enhanced Baseline Analytics: {domain.title()} (Group {group})")
    print(f"{'='*60}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Compute enhanced CSV
    rows = []
    for config in CONFIGS:
        row = compute_enhanced_row(domain, config, group)
        if row:
            rows.append(row)

    if not rows:
        print(f"  No logs found for {domain} (group {group})")
        return

    csv_path = output_dir / "enhanced_baseline.csv"
    write_enhanced_csv(rows, csv_path)

    # 2. Generate charts
    charts: list[Optional[Path]] = []

    charts.append(chart_attack_surface(domain, output_dir))
    charts.append(chart_principle_heatmap(domain, group, output_dir))

    aco_row = next((r for r in rows if r["config"] == "agenticcyops"), None)
    if aco_row:
        charts.append(chart_fp_rates(aco_row, output_dir))
    else:
        charts.append(None)

    charts.append(chart_config_radar(rows, output_dir))
    charts.append(chart_consensus_breakdown(domain, group, output_dir))

    # 3. Summary PDF
    generate_summary_pdf(charts, rows, domain, output_dir)

    # Summary
    print(f"\n  --- Summary ---")
    for r in rows:
        label = CONFIG_LABELS.get(r["config"], r["config"])
        fp = r.get("total_fp_rate", 0) * 100
        print(f"  {label:>15}: {r['total_events']:>4} events, "
              f"{r['tool_calls_allowed']:>2} allowed, {r['tool_calls_denied']:>2} denied, "
              f"FP={fp:.1f}%, latency={r['e2e_latency_s']:.1f}s")


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Baseline Analytics — Paper-Ready Metrics and Charts"
    )
    parser.add_argument("--domain", default="cyberops",
                        help="Domain to analyze (cyberops, healthcare, finance, legal, or 'all')")
    parser.add_argument("--group", default="F",
                        help="Model group (A-F)")
    parser.add_argument("--output", default=None,
                        help="Output directory (default: results/baseline/group_{group}/{domain}/)")
    args = parser.parse_args()

    domains = DOMAINS if args.domain == "all" else [args.domain]

    for domain in domains:
        if args.output:
            if args.domain == "all":
                out = Path(args.output) / domain
            else:
                out = Path(args.output)
        else:
            out = BASE_DIR / "results" / "baseline" / f"group_{args.group}" / domain
        run_analytics(domain, args.group, out)

    # Cross-domain analysis
    if args.domain == "all":
        cross_out = Path(args.output) if args.output else BASE_DIR / "results" / "baseline" / f"group_{args.group}"
        cross_domain_analysis(args.group, cross_out)
        print(f"\n  Cross-domain analysis complete.")


if __name__ == "__main__":
    main()
