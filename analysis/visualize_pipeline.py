"""
Generate a pipeline flow diagram from a single trial's logs.

Usage:
    python -m analysis.visualize_pipeline \
        --log logs/cyberops_baseline/agenticcyops_20260408.jsonl \
        --output results/figures/pipeline_flow_agenticcyops.png
"""

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches


PHASES = ["monitor", "analyze", "admin", "report"]
PHASE_COLORS = {
    "monitor": "#4CAF50",
    "analyze": "#2196F3",
    "admin": "#FF9800",
    "report": "#9C27B0",
}


def load_events(log_file: str) -> list[dict]:
    events = []
    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def get_phase(source: str) -> str:
    for p in PHASES:
        if p in source:
            return p
    return "unknown"


def generate_flow_diagram(log_file: str, output_file: str):
    events = load_events(log_file)

    fig, ax = plt.subplots(1, 1, figsize=(16, 8))

    col_width = 3.5
    row_height = 0.6

    # Phase headers
    for idx, phase in enumerate(PHASES):
        x = idx * col_width + 1
        ax.add_patch(mpatches.FancyBboxPatch(
            (x - 1.2, -1), 2.4, 0.8,
            boxstyle="round,pad=0.1",
            facecolor=PHASE_COLORS[phase],
            edgecolor="black", alpha=0.8,
        ))
        ax.text(x, -0.6, phase.upper(), ha="center", va="center",
                fontsize=11, fontweight="bold", color="white")

    # Handoff arrows
    for i in range(len(PHASES) - 1):
        x_start = i * col_width + 2.3
        x_end = (i + 1) * col_width - 0.1
        ax.annotate("", xy=(x_end, -0.6), xytext=(x_start, -0.6),
                     arrowprops=dict(arrowstyle="->", color="black", lw=2))

    # Events per phase
    y_min = 0
    for idx, phase in enumerate(PHASES):
        x = idx * col_width + 1
        phase_events = [e for e in events if get_phase(e.get("source", "")) == phase]

        for i, event in enumerate(phase_events[:12]):  # cap at 12 per phase
            y = -(i + 2) * row_height
            action = event.get("action", "")
            dest = event.get("destination", "")
            decision = event.get("auth_decision", "")

            if action == "tool_call":
                color = "#e8f5e9" if decision == "allow" else "#ffebee"
                icon = "+" if decision == "allow" else "x"
                label = f"{icon} {dest}"
            elif action == "memory_read":
                color = "#e3f2fd"
                label = f"R {dest}"
            elif action == "memory_write":
                color = "#fff3e0"
                label = f"W {dest}"
            elif action == "consensus_vote":
                color = "#f3e5f5"
                vote = event.get("auth_decision", "?")
                label = f"Vote: {vote}"
            elif action == "agent_handoff":
                color = "#fce4ec"
                label = f"-> {dest}"
            else:
                color = "#f5f5f5"
                label = action[:20]

            ax.add_patch(mpatches.FancyBboxPatch(
                (x - 1.1, y - 0.25), 2.2, 0.45,
                boxstyle="round,pad=0.05",
                facecolor=color, edgecolor="#999",
            ))
            ax.text(x, y, label, ha="center", va="center", fontsize=8)
            y_min = min(y_min, y)

    ax.set_xlim(-0.5, len(PHASES) * col_width + 0.5)
    ax.set_ylim(y_min - 1, 0.5)
    ax.axis("off")

    config = events[0].get("config", "unknown") if events else "unknown"
    domain = events[0].get("domain", "unknown") if events else "unknown"
    ax.set_title(f"Pipeline Flow — {domain.title()} / {config}", fontsize=14, fontweight="bold")

    plt.tight_layout()
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    print(f"Saved: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Pipeline flow visualization")
    parser.add_argument("--log", required=True, help="Path to JSONL log file")
    parser.add_argument("--output", default="results/figures/pipeline_flow.png")
    args = parser.parse_args()
    generate_flow_diagram(args.log, args.output)


if __name__ == "__main__":
    main()
