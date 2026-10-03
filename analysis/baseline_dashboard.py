"""
Generate baseline dashboard from benign run logs.

Usage:
    python -m analysis.baseline_dashboard --domain cyberops --output results/baseline/

Produces:
    baseline_summary.csv + baseline_summary.pdf — per-config metrics table
    tool_call_heatmap.png — which tools each phase called per config
    latency_comparison.png — E2E latency across configs
    principle_activity.png — P1-P5 activation (DEFER only)
    config_comparison.png — side-by-side metrics comparison
"""

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.ticker as mticker
import numpy as np
import seaborn as sns

from config import BASE_DIR
from analysis.runlogs import config_files

# ---- Seaborn style ----
sns.set_theme(style="whitegrid", font_scale=1.1, palette="muted")
plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "savefig.bbox": "tight",
    "font.family": "sans-serif",
    "axes.titleweight": "bold",
    "axes.titlesize": 14,
})

CONFIGS = ["flat", "acl_hardened", "agenticcyops"]
CONFIG_LABELS = {"flat": "Flat MAS", "acl_hardened": "ACL-Hardened", "agenticcyops": "DEFER"}
CONFIG_COLORS = {"flat": "#e74c3c", "acl_hardened": "#f39c12", "agenticcyops": "#2ecc71"}
PHASES = ["monitor", "analyze", "admin", "report"]


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
        memory_ops = [e for e in events if e.get("action") in ("memory_read", "memory_write")]
        handoffs = [e for e in events if e.get("action") == "agent_handoff"]
        consensus = [e for e in events if e.get("action") == "consensus_vote"]
        llm_calls = [e for e in events if e.get("action") == "llm_call"]

        allowed = [e for e in tool_calls if e.get("auth_decision") == "allow"]
        denied = [e for e in tool_calls if e.get("auth_decision") == "deny"]

        latencies = [e.get("latency_ms", 0) for e in events if e.get("latency_ms")]
        tokens_p = sum(e.get("tokens_prompt", 0) or 0 for e in events)
        tokens_c = sum(e.get("tokens_completion", 0) or 0 for e in events)

        sources = [e.get("source", "") for e in events]
        active = set()
        for s in sources:
            for p in PHASES:
                if p in s:
                    active.add(p)

        rows.append({
            "config": config,
            "config_label": CONFIG_LABELS.get(config, config),
            "total_events": len(events),
            "tool_calls": len(tool_calls),
            "tool_calls_allowed": len(allowed),
            "tool_calls_denied": len(denied),
            "memory_reads": len([e for e in memory_ops if e.get("action") == "memory_read"]),
            "memory_writes": len([e for e in memory_ops if e.get("action") == "memory_write"]),
            "handoffs": len(handoffs),
            "consensus_votes": len(consensus),
            "llm_calls": len(llm_calls),
            "e2e_latency_s": round(sum(latencies) / 1000, 1),
            "total_tokens": tokens_p + tokens_c,
            "phases_completed": len(active),
            "false_blocks": len(denied),
        })
    return rows


# ================================================================== #
#  Table PDF
# ================================================================== #

def save_table_pdf(rows: list[dict], domain: str, output_dir: Path):
    """Save metrics as a formatted PDF table."""
    if not rows:
        return

    # Select display columns
    display_cols = [
        ("Config", "config_label"),
        ("Events", "total_events"),
        ("Tool Calls", "tool_calls"),
        ("Allowed", "tool_calls_allowed"),
        ("Denied", "tool_calls_denied"),
        ("Consensus", "consensus_votes"),
        ("Latency (s)", "e2e_latency_s"),
        ("Tokens", "total_tokens"),
        ("Phases", "phases_completed"),
    ]

    col_labels = [c[0] for c in display_cols]
    cell_data = []
    for row in rows:
        cell_data.append([str(row.get(c[1], "")) for c in display_cols])

    fig, ax = plt.subplots(figsize=(12, 2 + len(rows) * 0.6))
    ax.axis("off")
    ax.set_title(f"Baseline Summary — {domain.title()}", fontsize=16, fontweight="bold", pad=20)

    table = ax.table(
        cellText=cell_data,
        colLabels=col_labels,
        cellLoc="center",
        loc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 1.8)

    # Style header
    for j in range(len(col_labels)):
        table[0, j].set_facecolor("#2c3e50")
        table[0, j].set_text_props(color="white", fontweight="bold")

    # Style rows by config
    for i, row in enumerate(rows):
        color = CONFIG_COLORS.get(row["config"], "#ecf0f1")
        for j in range(len(col_labels)):
            table[i + 1, j].set_facecolor(sns.light_palette(color, n_colors=3)[0])

    pdf_path = output_dir / "baseline_summary.pdf"
    with PdfPages(str(pdf_path)) as pdf:
        pdf.savefig(fig, bbox_inches="tight")
    plt.close()
    print(f"Saved: {pdf_path}")


def save_summary_csv(rows: list[dict], output_dir: Path):
    if not rows:
        return
    csv_path = output_dir / "baseline_summary.csv"
    header = [k for k in rows[0].keys() if k != "config_label"]
    with open(csv_path, "w") as f:
        f.write(",".join(header) + "\n")
        for row in rows:
            f.write(",".join(str(row.get(k, "")) for k in header) + "\n")
    print(f"Saved: {csv_path}")


# ================================================================== #
#  Charts
# ================================================================== #

def generate_config_comparison(rows: list[dict], domain: str, output_dir: Path):
    """Side-by-side bar chart comparing key metrics across configs."""
    if not rows:
        return

    metrics = [
        ("Tool Calls\nAllowed", "tool_calls_allowed"),
        ("Tool Calls\nDenied", "tool_calls_denied"),
        ("Consensus\nVotes", "consensus_votes"),
        ("Latency\n(seconds)", "e2e_latency_s"),
        ("Tokens\n(÷1000)", None),  # special handling
    ]

    fig, axes = plt.subplots(1, len(metrics), figsize=(16, 5), sharey=False)
    fig.suptitle(f"Configuration Comparison — {domain.title()} Baseline", fontsize=16, fontweight="bold")

    for ax, (label, key) in zip(axes, metrics):
        vals = []
        colors = []
        labels = []
        for row in rows:
            labels.append(CONFIG_LABELS.get(row["config"], row["config"]))
            colors.append(CONFIG_COLORS.get(row["config"], "#95a5a6"))
            if key is None:  # tokens ÷ 1000
                vals.append(row.get("total_tokens", 0) / 1000)
            else:
                vals.append(row.get(key, 0))

        bars = ax.bar(labels, vals, color=colors, edgecolor="white", linewidth=1.5, width=0.6)
        ax.set_title(label, fontsize=10)
        ax.set_ylim(bottom=0)

        # Value labels on bars
        for bar, val in zip(bars, vals):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                        f"{val:.0f}" if val == int(val) else f"{val:.1f}",
                        ha="center", va="bottom", fontsize=9, fontweight="bold")

        ax.tick_params(axis="x", rotation=30)
        sns.despine(ax=ax, left=True)

    plt.tight_layout()
    path = output_dir / "config_comparison.png"
    plt.savefig(path)
    plt.close()
    print(f"Saved: {path}")


def generate_tool_heatmap(domain: str, output_dir: Path):
    """Seaborn heatmap: tools x (phase x config)."""
    all_tools = set()
    data = {}

    for config in CONFIGS:
        events = load_logs(domain, config)
        tool_calls = [e for e in events if e.get("action") == "tool_call"]
        for phase in PHASES:
            phase_calls = [e for e in tool_calls if phase in e.get("source", "")]
            col = f"{phase[:3].upper()}\n{CONFIG_LABELS.get(config, config)[:8]}"
            counts = {}
            for e in phase_calls:
                dest = e.get("destination", "?")
                all_tools.add(dest)
                counts[dest] = counts.get(dest, 0) + 1
            data[col] = counts

    if not all_tools:
        return

    tools_sorted = sorted(all_tools)
    cols = list(data.keys())
    matrix = np.zeros((len(tools_sorted), len(cols)))
    for j, col in enumerate(cols):
        for i, tool in enumerate(tools_sorted):
            matrix[i, j] = data[col].get(tool, 0)

    fig, ax = plt.subplots(figsize=(max(10, len(cols) * 1.2), max(6, len(tools_sorted) * 0.45)))
    sns.heatmap(
        matrix, annot=True, fmt=".0f", cmap="YlOrRd",
        xticklabels=cols, yticklabels=tools_sorted,
        linewidths=0.5, linecolor="white",
        cbar_kws={"label": "Call Count", "shrink": 0.8},
        ax=ax,
    )
    ax.set_title(f"Tool Call Heatmap — {domain.title()} Baseline", fontsize=14, fontweight="bold")
    ax.set_ylabel("")
    ax.tick_params(axis="y", labelsize=9)
    ax.tick_params(axis="x", labelsize=8)

    plt.tight_layout()
    path = output_dir / "tool_call_heatmap.png"
    plt.savefig(path)
    plt.close()
    print(f"Saved: {path}")


def generate_latency_chart(domain: str, output_dir: Path):
    """Grouped bar chart: per-phase latency per config."""
    data = []
    for config in CONFIGS:
        events = load_logs(domain, config)
        for phase in PHASES:
            phase_events = [e for e in events if phase in e.get("source", "")]
            total = sum(e.get("latency_ms", 0) or 0 for e in phase_events) / 1000
            data.append({
                "Phase": phase.title(),
                "Config": CONFIG_LABELS.get(config, config),
                "Latency (s)": total,
                "config_key": config,
            })

    if not data:
        return

    fig, ax = plt.subplots(figsize=(10, 6))

    phases_list = [p.title() for p in PHASES]
    x = np.arange(len(phases_list))
    width = 0.25

    for i, config in enumerate(CONFIGS):
        vals = []
        for phase in phases_list:
            match = [d for d in data if d["Phase"] == phase and d["config_key"] == config]
            vals.append(match[0]["Latency (s)"] if match else 0)
        bars = ax.bar(x + i * width, vals, width,
                      label=CONFIG_LABELS.get(config, config),
                      color=CONFIG_COLORS.get(config, "#95a5a6"),
                      edgecolor="white", linewidth=1)
        for bar, val in zip(bars, vals):
            if val > 0.5:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                        f"{val:.1f}s", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x + width)
    ax.set_xticklabels(phases_list)
    ax.set_ylabel("Latency (seconds)")
    ax.set_title(f"Per-Phase Latency — {domain.title()} Baseline", fontsize=14, fontweight="bold")
    ax.legend(title="Configuration", frameon=True, fancybox=True)
    sns.despine(ax=ax)

    plt.tight_layout()
    path = output_dir / "latency_comparison.png"
    plt.savefig(path)
    plt.close()
    print(f"Saved: {path}")


def generate_principle_chart(domain: str, output_dir: Path):
    """P1-P5 activation chart for DEFER config."""
    events = load_logs(domain, "agenticcyops")
    if not events:
        return

    principles = {
        "P2\nCapability\nScoping": "P2",
        "P3\nVerified\nExecution": "P3",
        "P4\nMemory\nIntegrity": "P4",
        "P5\nAccess\nControl": "P5",
    }

    allows = []
    denies = []
    labels = list(principles.keys())

    for label, key in principles.items():
        p_events = [e for e in events if key in (e.get("mechanism") or "")]
        allows.append(len([e for e in p_events if e.get("auth_decision") == "allow"]))
        denies.append(len([e for e in p_events if e.get("auth_decision") == "deny"]))

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(labels))
    w = 0.35

    bars_allow = ax.bar(x - w / 2, allows, w, label="Allow", color="#2ecc71", edgecolor="white")
    bars_deny = ax.bar(x + w / 2, denies, w, label="Deny (false block)", color="#e74c3c", edgecolor="white")

    for bar, val in zip(bars_allow, allows):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
                    str(val), ha="center", va="bottom", fontsize=10, fontweight="bold")
    for bar, val in zip(bars_deny, denies):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
                    str(val), ha="center", va="bottom", fontsize=10, fontweight="bold", color="#e74c3c")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel("Event Count")
    ax.set_title(f"Defensive Principle Activity — {domain.title()} Benign Baseline",
                 fontsize=14, fontweight="bold")
    ax.legend(frameon=True, fancybox=True)
    sns.despine(ax=ax)

    if sum(denies) == 0:
        ax.text(0.98, 0.95, "Zero false blocks", transform=ax.transAxes,
                ha="right", fontsize=13, color="#27ae60", fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#eafaf1", edgecolor="#27ae60"))
    else:
        ax.text(0.98, 0.95, f"{sum(denies)} false block(s)", transform=ax.transAxes,
                ha="right", fontsize=13, color="#e74c3c", fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#fdedec", edgecolor="#e74c3c"))

    plt.tight_layout()
    path = output_dir / "principle_activity.png"
    plt.savefig(path)
    plt.close()
    print(f"Saved: {path}")


def generate_token_pie(rows: list[dict], domain: str, output_dir: Path):
    """Pie chart showing token savings across configs."""
    if not rows:
        return

    fig, ax = plt.subplots(figsize=(7, 7))
    labels = [CONFIG_LABELS.get(r["config"], r["config"]) for r in rows]
    sizes = [r["total_tokens"] for r in rows]
    colors = [CONFIG_COLORS.get(r["config"], "#95a5a6") for r in rows]

    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct="%1.0f%%",
        startangle=90, textprops={"fontsize": 11},
        wedgeprops={"edgecolor": "white", "linewidth": 2},
    )
    for t in autotexts:
        t.set_fontweight("bold")

    ax.set_title(f"Token Distribution — {domain.title()} Baseline",
                 fontsize=14, fontweight="bold")

    # Add total in center
    total = sum(sizes)
    ax.text(0, 0, f"{total:,}\ntokens", ha="center", va="center",
            fontsize=14, fontweight="bold", color="#2c3e50")

    plt.tight_layout()
    path = output_dir / "token_distribution.png"
    plt.savefig(path)
    plt.close()
    print(f"Saved: {path}")


# ================================================================== #
#  Main
# ================================================================== #

def main():
    parser = argparse.ArgumentParser(description="Baseline dashboard")
    parser.add_argument("--domain", default="cyberops")
    parser.add_argument("--output", default="results/baseline/")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = compute_metrics(args.domain)

    if not rows:
        print(f"No logs found for {args.domain}")
        return

    # Print summary to CLI
    print(f"\nBASELINE SUMMARY — {args.domain.upper()}")
    print("=" * 80)
    header = ["Config", "Events", "Allowed", "Denied", "Consensus", "Latency(s)", "Tokens", "Phases"]
    keys = ["config_label", "total_events", "tool_calls_allowed", "tool_calls_denied",
            "consensus_votes", "e2e_latency_s", "total_tokens", "phases_completed"]
    print("".join(f"{h:<14}" for h in header))
    print("-" * 80)
    for row in rows:
        print("".join(f"{str(row.get(k, '')):14s}" for k in keys))
    print()

    # Generate outputs
    save_summary_csv(rows, output_dir)
    save_table_pdf(rows, args.domain, output_dir)
    generate_config_comparison(rows, args.domain, output_dir)
    generate_tool_heatmap(args.domain, output_dir)
    generate_latency_chart(args.domain, output_dir)
    generate_principle_chart(args.domain, output_dir)
    generate_token_pie(rows, args.domain, output_dir)


if __name__ == "__main__":
    main()
