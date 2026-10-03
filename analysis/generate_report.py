"""
Generate a professional PDF report from baseline run results.

Usage:
    python -m analysis.generate_report --domain cyberops --output results/baseline/cyberops/

Produces:
    baseline_report.pdf — multi-page report with:
      Page 1: Title + experiment configuration
      Page 2: Model & GPU assignment table
      Page 3: Baseline metrics summary table
      Page 4: Configuration comparison chart
      Page 5: Tool call heatmap
      Page 6: Per-phase latency chart
      Page 7: Defensive principle activity
      Page 8: Token distribution
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.patches as mpatches
import numpy as np
import seaborn as sns

from config import BASE_DIR
from analysis.runlogs import config_files

sns.set_theme(style="whitegrid", font_scale=1.0, palette="muted")
plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "font.family": "sans-serif",
    "axes.titleweight": "bold",
    "axes.titlesize": 13,
})

CONFIGS = ["flat", "acl_hardened", "agenticcyops"]
CONFIG_LABELS = {"flat": "Flat MAS", "acl_hardened": "ACL-Hardened", "agenticcyops": "DEFER"}
CONFIG_COLORS = {"flat": "#e74c3c", "acl_hardened": "#f39c12", "agenticcyops": "#2ecc71"}
PHASES = ["monitor", "analyze", "admin", "report"]

HEADER_COLOR = "#2c3e50"
ACCENT = "#2980b9"


def load_logs(domain: str, config: str) -> list[dict]:
    log_dir = BASE_DIR / "logs" / f"{domain}_baseline"
    events = []
    for f in sorted(config_files(log_dir, config)):
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    return events


def compute_metrics(domain: str) -> list[dict]:
    rows = []
    for config in CONFIGS:
        events = load_logs(domain, config)
        if not events:
            continue
        tool_calls = [e for e in events if e.get("action") == "tool_call"]
        allowed = [e for e in tool_calls if e.get("auth_decision") == "allow"]
        denied = [e for e in tool_calls if e.get("auth_decision") == "deny"]
        consensus = [e for e in events if e.get("action") == "consensus_vote"]
        latencies = [e.get("latency_ms", 0) for e in events if e.get("latency_ms")]
        tokens_p = sum(e.get("tokens_prompt", 0) or 0 for e in events)
        tokens_c = sum(e.get("tokens_completion", 0) or 0 for e in events)
        sources = set()
        for e in events:
            for p in PHASES:
                if p in e.get("source", ""):
                    sources.add(p)
        rows.append({
            "config": config,
            "label": CONFIG_LABELS.get(config, config),
            "events": len(events),
            "tool_calls": len(tool_calls),
            "allowed": len(allowed),
            "denied": len(denied),
            "consensus": len(consensus),
            "latency_s": round(sum(latencies) / 1000, 1),
            "tokens": tokens_p + tokens_c,
            "phases": len(sources),
        })
    return rows


# ================================================================== #
#  PDF Pages
# ================================================================== #

def page_title(pdf, domain: str):
    """Page 1: Title page."""
    fig, ax = plt.subplots(figsize=(11, 8.5))
    ax.axis("off")

    ax.text(0.5, 0.72, "DEFER", transform=ax.transAxes,
            ha="center", fontsize=36, fontweight="bold", color=HEADER_COLOR)
    ax.text(0.5, 0.62, "Baseline Verification Report", transform=ax.transAxes,
            ha="center", fontsize=22, color="#7f8c8d")
    ax.text(0.5, 0.52, f"Domain: {domain.title()}", transform=ax.transAxes,
            ha="center", fontsize=18, color=ACCENT)

    ax.text(0.5, 0.38, datetime.now().strftime("%B %d, %Y  %H:%M"), transform=ax.transAxes,
            ha="center", fontsize=12, color="#95a5a6")

    # Separator
    ax.plot([0.2, 0.8], [0.45, 0.45], transform=ax.transAxes,
            color=ACCENT, linewidth=2)

    # Config summary
    configs_text = "Configurations tested: Flat MAS  |  ACL-Hardened  |  DEFER"
    ax.text(0.5, 0.28, configs_text, transform=ax.transAxes,
            ha="center", fontsize=11, color="#7f8c8d")

    ax.text(0.5, 0.15, "Securing Multi-Agentic AI Integration in Enterprise Cyber Operations",
            transform=ax.transAxes, ha="center", fontsize=10, style="italic", color="#bdc3c7")

    pdf.savefig(fig, bbox_inches="tight")
    plt.close()


def page_experiment_config(pdf, domain: str):
    """Page 2: Experiment configuration — models, GPUs, validators."""
    fig, ax = plt.subplots(figsize=(11, 8.5))
    ax.axis("off")
    ax.set_title("Experiment Configuration", fontsize=18, fontweight="bold",
                 color=HEADER_COLOR, pad=30)

    # Model table
    model_data = [
        ["Qwen3-235B-A22B-Instruct-2507", "Primary Agents + Host", "Qwen", "GPU 0,1,4,5 (TP=4)", "8000"],
        ["Qwen3-32B", "Validator V1", "Qwen", "GPU 2", "8002"],
        ["DeepSeek-R1-Distill-Qwen-32B", "Validator V2", "DeepSeek", "GPU 3", "8005"],
        ["Claude Sonnet", "Validator V4 (API)", "Anthropic", "API", "--"],
        ["GPT-4o", "Validator V6 (API)", "OpenAI", "API", "--"],
        ["Qwen3-Embedding-0.6B", "Embedding (CPU)", "Qwen", "CPU", "--"],
    ]
    model_headers = ["Model", "Role", "Family", "GPU Assignment", "Port"]

    table1 = ax.table(
        cellText=model_data, colLabels=model_headers,
        cellLoc="center", loc="upper center",
        bbox=[0.02, 0.45, 0.96, 0.45],
    )
    table1.auto_set_font_size(False)
    table1.set_fontsize(9)
    for j in range(len(model_headers)):
        table1[0, j].set_facecolor(HEADER_COLOR)
        table1[0, j].set_text_props(color="white", fontweight="bold")
    for i in range(1, len(model_data) + 1):
        for j in range(len(model_headers)):
            table1[i, j].set_facecolor("#ecf0f1" if i % 2 == 0 else "white")

    # Config comparison
    config_data = [
        ["Tool visibility", "All 16 tools", "All 16 tools", "Manifest only (4-5)"],
        ["Tool enforcement", "None", "ACL (HTTP 403)", "P2 Manifest Enforcer"],
        ["Consensus (P3)", "Disabled", "Disabled", "V1+V2+V4+V6 (3/4)"],
        ["Memory access", "Direct", "Direct + ACL", "MMA Gateway (P4+P5)"],
        ["Write filtering (P4)", "None", "None", "Cosine sim > 0.5"],
        ["Escalation", "Never", "Never", "On bulk/rejection"],
    ]
    config_headers = ["Behavior", "Flat MAS", "ACL-Hardened", "DEFER"]

    table2 = ax.table(
        cellText=config_data, colLabels=config_headers,
        cellLoc="center", loc="lower center",
        bbox=[0.02, 0.02, 0.96, 0.35],
    )
    table2.auto_set_font_size(False)
    table2.set_fontsize(9)
    for j in range(len(config_headers)):
        table2[0, j].set_facecolor(HEADER_COLOR)
        table2[0, j].set_text_props(color="white", fontweight="bold")
    # Color DEFER column
    for i in range(1, len(config_data) + 1):
        table2[i, 3].set_facecolor("#eafaf1")
        table2[i, 1].set_facecolor("#fdedec")
        table2[i, 2].set_facecolor("#fef9e7")

    ax.text(0.5, 0.42, "Model & GPU Assignment", transform=ax.transAxes,
            ha="center", fontsize=12, fontweight="bold", color="#7f8c8d")
    ax.text(0.5, 0.37, "Three-Configuration Comparison", transform=ax.transAxes,
            ha="center", fontsize=12, fontweight="bold", color="#7f8c8d")

    pdf.savefig(fig, bbox_inches="tight")
    plt.close()


def page_metrics_table(pdf, rows: list[dict], domain: str):
    """Page 3: Baseline metrics table."""
    fig, ax = plt.subplots(figsize=(11, 8.5))
    ax.axis("off")
    ax.set_title(f"Baseline Metrics — {domain.title()}", fontsize=18,
                 fontweight="bold", color=HEADER_COLOR, pad=30)

    headers = ["Metric", "Flat MAS", "ACL-Hardened", "DEFER"]
    metric_rows = [
        ("Total Events", "events"),
        ("Tool Calls Attempted", "tool_calls"),
        ("Tool Calls Allowed", "allowed"),
        ("Tool Calls Denied", "denied"),
        ("Consensus Votes", "consensus"),
        ("E2E Latency (s)", "latency_s"),
        ("Total Tokens", "tokens"),
        ("Phases Completed", "phases"),
    ]

    cell_data = []
    for label, key in metric_rows:
        row_vals = [label]
        for config in CONFIGS:
            match = [r for r in rows if r["config"] == config]
            val = match[0].get(key, "--") if match else "--"
            if key == "tokens" and isinstance(val, int):
                val = f"{val:,}"
            row_vals.append(str(val))
        cell_data.append(row_vals)

    table = ax.table(
        cellText=cell_data, colLabels=headers,
        cellLoc="center", loc="center",
        bbox=[0.1, 0.15, 0.8, 0.7],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1, 2.0)

    for j in range(len(headers)):
        table[0, j].set_facecolor(HEADER_COLOR)
        table[0, j].set_text_props(color="white", fontweight="bold", fontsize=11)
    for i in range(1, len(cell_data) + 1):
        table[i, 0].set_text_props(fontweight="bold")
        table[i, 0].set_facecolor("#f8f9f9")
        table[i, 1].set_facecolor("#fdedec")
        table[i, 2].set_facecolor("#fef9e7")
        table[i, 3].set_facecolor("#eafaf1")

    # Key insight box
    if rows:
        flat_tokens = next((r["tokens"] for r in rows if r["config"] == "flat"), 0)
        aco_tokens = next((r["tokens"] for r in rows if r["config"] == "agenticcyops"), 0)
        if flat_tokens > 0:
            reduction = round((1 - aco_tokens / flat_tokens) * 100)
            ax.text(0.5, 0.08, f"DEFER uses {reduction}% fewer tokens than Flat MAS",
                    transform=ax.transAxes, ha="center", fontsize=12,
                    color="#27ae60", fontweight="bold",
                    bbox=dict(boxstyle="round,pad=0.4", facecolor="#eafaf1", edgecolor="#27ae60"))

    pdf.savefig(fig, bbox_inches="tight")
    plt.close()


def page_chart(pdf, chart_path: Path, title: str):
    """Generic page: embed a chart image."""
    if not chart_path.exists():
        return
    fig, ax = plt.subplots(figsize=(11, 8.5))
    ax.axis("off")
    img = plt.imread(str(chart_path))
    ax.imshow(img)
    ax.set_title(title, fontsize=16, fontweight="bold", color=HEADER_COLOR, pad=15)
    pdf.savefig(fig, bbox_inches="tight")
    plt.close()


def page_summary(pdf, rows: list[dict], domain: str):
    """Final page: key findings summary."""
    fig, ax = plt.subplots(figsize=(11, 8.5))
    ax.axis("off")
    ax.set_title("Key Findings", fontsize=18, fontweight="bold",
                 color=HEADER_COLOR, pad=30)

    findings = []
    if rows:
        flat = next((r for r in rows if r["config"] == "flat"), None)
        acl = next((r for r in rows if r["config"] == "acl_hardened"), None)
        aco = next((r for r in rows if r["config"] == "agenticcyops"), None)

        if flat and aco:
            token_red = round((1 - aco["tokens"] / flat["tokens"]) * 100) if flat["tokens"] else 0
            findings.append(f"Token reduction: DEFER uses {token_red}% fewer tokens than Flat MAS")

        if aco:
            findings.append(f"Consensus active: {aco['consensus']} validator votes recorded")
            findings.append(f"False blocks: {aco['denied']} benign calls denied by P3 consensus")
            findings.append(f"Pipeline complete: all {aco['phases']} phases executed successfully")

        if acl:
            findings.append(f"ACL enforcement: {acl['denied']} out-of-scope calls blocked (HTTP 403)")

        if flat:
            findings.append(f"Flat baseline: {flat['allowed']} tool calls with zero enforcement")

    y = 0.80
    for i, finding in enumerate(findings):
        color = "#27ae60" if "reduction" in finding or "complete" in finding else "#2c3e50"
        marker = "+" if "reduction" in finding or "complete" in finding or "active" in finding else "-"
        ax.text(0.08, y, f"  {marker}  {finding}", transform=ax.transAxes,
                fontsize=13, color=color, verticalalignment="top")
        y -= 0.08

    # Bottom note
    ax.text(0.5, 0.1, f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            transform=ax.transAxes, ha="center", fontsize=10, color="#bdc3c7")
    ax.text(0.5, 0.05, f"Domain: {domain.title()} | Configs: 3 | Models: 5 families",
            transform=ax.transAxes, ha="center", fontsize=10, color="#bdc3c7")

    pdf.savefig(fig, bbox_inches="tight")
    plt.close()


# ================================================================== #
#  Main
# ================================================================== #

def generate_report(domain: str, output_dir: str):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    rows = compute_metrics(domain)
    if not rows:
        print(f"No baseline logs for {domain}")
        return

    pdf_path = output_path / "baseline_report.pdf"

    # First generate the individual charts (reuse from dashboard)
    from analysis.baseline_dashboard import (
        generate_config_comparison, generate_tool_heatmap,
        generate_latency_chart, generate_principle_chart, generate_token_pie,
    )
    # Map keys for dashboard compatibility
    dashboard_rows = []
    for r in rows:
        dr = dict(r)
        dr["total_tokens"] = dr.get("tokens", 0)
        dr["config_label"] = dr.get("label", dr["config"])
        dr["tool_calls_allowed"] = dr.get("allowed", 0)
        dr["tool_calls_denied"] = dr.get("denied", 0)
        dr["consensus_votes"] = dr.get("consensus", 0)
        dr["e2e_latency_s"] = dr.get("latency_s", 0)
        dashboard_rows.append(dr)

    generate_config_comparison(dashboard_rows, domain, output_path)
    generate_tool_heatmap(domain, output_path)
    generate_latency_chart(domain, output_path)
    generate_principle_chart(domain, output_path)
    generate_token_pie(dashboard_rows, domain, output_path)

    # Build PDF
    with PdfPages(str(pdf_path)) as pdf:
        page_title(pdf, domain)
        page_experiment_config(pdf, domain)
        page_metrics_table(pdf, rows, domain)
        page_chart(pdf, output_path / "config_comparison.png", "Configuration Comparison")
        page_chart(pdf, output_path / "tool_call_heatmap.png", "Tool Call Distribution")
        page_chart(pdf, output_path / "latency_comparison.png", "Per-Phase Latency")
        page_chart(pdf, output_path / "principle_activity.png", "Defensive Principle Activity")
        page_chart(pdf, output_path / "token_distribution.png", "Token Distribution")
        page_summary(pdf, rows, domain)

    print(f"\nReport saved: {pdf_path} ({len(rows)} configs, 9 pages)")


def main():
    parser = argparse.ArgumentParser(description="Generate baseline PDF report")
    parser.add_argument("--domain", default="cyberops")
    parser.add_argument("--output", default="results/baseline/")
    args = parser.parse_args()
    generate_report(args.domain, args.output)


if __name__ == "__main__":
    main()
