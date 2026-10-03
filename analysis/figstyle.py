"""Shared matplotlib style for the DEFER paper figures.

Every figure in :mod:`analysis.make_figures` imports this module so that a
configuration, a tier or an outcome has the same colour everywhere. Call
:func:`apply` once at start-up, build the figure with the width constants, and
write it with :func:`save` (which emits both the PDF the paper includes and a
200 dpi PNG preview).

Palette is Okabe--Ito (colourblind safe). The TL;DR figure in the paper keeps
its own pastel palette and does not use this module.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt                                    # noqa: E402
from matplotlib import font_manager                                # noqa: E402

# --------------------------------------------------------------------- #
#  Sizes -- IEEE two-column
# --------------------------------------------------------------------- #
WIDTH_1COL = 3.45          # inches, single column
WIDTH_2COL = 7.16          # inches, double column
HEIGHT_1COL = (2.0, 2.6)   # allowed height range, single column
HEIGHT_2COL = (2.6, 3.2)   # allowed height range, double column

# --------------------------------------------------------------------- #
#  Colours (Okabe--Ito)
# --------------------------------------------------------------------- #
# Tier colours, labels and the mechanism -> tier mapping are defined once, in
# analysis/tiers.py, and every table and figure uses that module.
from analysis import tiers  # noqa: E402,F401

# Paper configuration labels -> colour. JudgeOnly shares the panel-tier orange
# and NoJudge the rule-tier blue on purpose: the arm *is* that tier alone.
CONFIG_COLOR = {
    "Flat": "#999999",
    "ACL": "#BBBBBB",
    "JudgeOnly": "#E69F00",
    "NoJudge": "#0072B2",
    "DEFER": "#009E73",
}

OUTCOME_COLOR = {
    "executed": "#D55E00",       # attack executed (vermilion)
    "blocked": "#009E73",        # blocked (green)
    "not_attempted": "#CCCCCC",  # never attempted (grey)
}

BENIGN_COLOR = "#CC79A7"   # benign / cost (purple)
EMPHASIS = "#000000"       # annotations
GRID_COLOR = "#e6e6e6"

# --------------------------------------------------------------------- #
#  Naming -- CSV value -> paper label
# --------------------------------------------------------------------- #
CONFIG_LABEL = {
    "flat": "Flat",
    "acl_hardened": "ACL",
    "symbolic_only": "NoJudge",
    "agenticcyops": "DEFER",
    "llm_judge": "JudgeOnly",
}
# left to right: "no judgment" -> "all judgment", DEFER in between
CONFIG_ORDER = ("Flat", "ACL", "NoJudge", "DEFER", "JudgeOnly")

# Error bars: thin, black, 2 pt caps.
ERRORBAR_KW = dict(ecolor=EMPHASIS, elinewidth=0.8, capsize=2, capthick=0.8)


# Helvetica / Arial first; then their metric-compatible clones (Nimbus Sans is
# the Helvetica metric clone, Liberation Sans / Arimo the Arial one); DejaVu
# Sans is the last resort so a figure always renders.
_FONT_PREFS = ("Helvetica", "Arial", "Nimbus Sans", "Liberation Sans", "Arimo")


def font_family() -> list[str]:
    """The sans stack: Helvetica/Arial when installed, else a metric-compatible
    clone, else DejaVu Sans."""
    installed = {f.name for f in font_manager.fontManager.ttflist}
    return [c for c in _FONT_PREFS if c in installed] + ["DejaVu Sans"]


def apply() -> None:
    """Set the rcParams shared by every figure."""
    plt.rcParams.update({
        "figure.dpi": 200,
        "savefig.dpi": 200,
        "pdf.fonttype": 42,          # embed as TrueType, not Type 3
        "ps.fonttype": 42,
        "font.family": "sans-serif",
        "font.sans-serif": font_family(),
        "font.size": 8,              # body
        "axes.labelsize": 8,
        "axes.labelweight": "bold",  # bold axis titles
        "axes.titlesize": 8,
        "axes.titleweight": "bold",
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
        "legend.frameon": False,
        "lines.linewidth": 1.0,
        "lines.markersize": 4,
        "axes.linewidth": 0.6,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.axisbelow": True,      # grid behind the data
        "grid.color": GRID_COLOR,
        "grid.linewidth": 0.5,
        "figure.autolayout": False,
    })


def style_axes(ax, ygrid: bool = True, xgrid: bool = False) -> None:
    """Spines and grid: light grey y-grid behind the data, no x-grid."""
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_linewidth(0.6)
    ax.set_axisbelow(True)
    # passing line properties with a false first argument turns the grid *on*
    for axis, on in (("y", ygrid), ("x", xgrid)):
        if on:
            ax.grid(True, axis=axis, color=GRID_COLOR, linewidth=0.5)
        else:
            ax.grid(False, axis=axis)


def panel_label(ax, text: str, dx: float = -0.06, dy: float = 1.04) -> None:
    """``(a)`` / ``(b)`` inside a multi-panel figure: bold, left-aligned."""
    ax.text(dx, dy, text, transform=ax.transAxes, fontsize=8,
            fontweight="bold", ha="left", va="bottom")


PAD_INCHES = 0.02


def fit_width(fig, width: float, tol: float = 0.012, iters: int = 8) -> None:
    """Shrink/grow the canvas so the *saved* (tight-bbox) width equals ``width``.

    ``bbox_inches="tight"`` expands the page around tick labels, legends and
    annotations that sit outside the axes, so a figure requested at 3.45 in can
    land at 4.1 in. Axis text has a fixed size in points, so the overhang is
    roughly constant in inches: subtracting the error converges in a few passes.
    Only the width is adjusted; the height stays as the figure asked for it.
    """
    for _ in range(iters):
        fig.canvas.draw()
        bb = fig.get_tightbbox(fig.canvas.get_renderer())
        delta = (bb.width + 2 * PAD_INCHES) - width
        if abs(delta) <= tol:
            return
        w, h = fig.get_size_inches()
        fig.set_size_inches(max(1.0, w - delta), h)


def save(fig, name: str, outdir: Path, width: float | None = None) -> Path:
    """Write ``<outdir>/<name>.pdf`` and ``<outdir>/preview/<name>.png``.

    ``width`` (WIDTH_1COL / WIDTH_2COL) pins the final page width.
    """
    outdir = Path(outdir)
    preview = outdir / "preview"
    outdir.mkdir(parents=True, exist_ok=True)
    preview.mkdir(parents=True, exist_ok=True)
    if width:
        fit_width(fig, width)
    pdf = outdir / f"{name}.pdf"
    fig.savefig(pdf, bbox_inches="tight", pad_inches=PAD_INCHES)
    fig.savefig(preview / f"{name}.png", dpi=200, bbox_inches="tight", pad_inches=PAD_INCHES)
    plt.close(fig)
    return pdf
