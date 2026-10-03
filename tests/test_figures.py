"""The paper figures regenerate from the committed data with no manual step."""
import json
import math
import re

import pytest

from analysis import figstyle as fs
from analysis import make_figures as mf


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """Render every figure once into a scratch directory."""
    out = tmp_path_factory.mktemp("figs")
    fs.apply()
    trials = mf.load_trials(mf.ALL_TRIALS)
    manifest = []
    for name, fn in mf.FIGURES.items():
        res = fn(trials, out)
        if res is None:                      # figure whose input data is absent (F15)
            continue
        _path, meta = res
        manifest.append(meta)
    mf.write_cascade_defs(trials, out)
    (out / "figures.json").write_text(json.dumps(manifest, indent=2))
    return out, manifest


def test_every_rendered_figure_has_a_pdf_and_preview(built):
    out, manifest = built
    assert manifest, "no figures were produced"
    for m in manifest:
        pdf = out / m["file"]
        assert pdf.exists(), f"{m['name']}: missing {m['file']}"
        assert pdf.stat().st_size < 2 * 1024 * 1024, f"{m['name']}: PDF over 2 MB"
        assert (out / "preview" / f"{m['name']}.png").exists(), f"{m['name']}: missing preview"


def test_manifest_has_takeaway_sources_and_no_nan(built):
    _out, manifest = built
    for m in manifest:
        assert m.get("takeaway", "").strip(), f"{m['name']}: empty takeaway"
        assert m.get("data_sources"), f"{m['name']}: no data sources"
        blob = json.dumps(m)
        assert "NaN" not in blob, f"{m['name']}: manifest contains NaN"
        assert "Infinity" not in blob, f"{m['name']}: manifest contains Infinity"

        def _walk(v):
            if isinstance(v, float):
                assert not math.isnan(v) and not math.isinf(v), f"{m['name']}: non-finite value"
            elif isinstance(v, dict):
                for x in v.values():
                    _walk(x)
            elif isinstance(v, list):
                for x in v:
                    _walk(x)
        _walk(m["n"])


def test_pages_match_the_ieee_column_widths(built):
    """figstyle.fit_width pins every page to one or two columns."""
    out, manifest = built
    for m in manifest:
        data = (out / m["file"]).read_bytes()
        box = re.search(rb"/MediaBox\s*\[\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*\]", data)
        assert box, f"{m['name']}: no MediaBox"
        x0, _y0, x1, _y1 = (float(v) for v in box.groups())
        width = (x1 - x0) / 72
        assert (abs(width - fs.WIDTH_1COL) < 0.08 or abs(width - fs.WIDTH_2COL) < 0.08), \
            f"{m['name']}: page is {width:.2f} in, neither one nor two columns"


def test_fonts_are_embedded_and_not_type3(built):
    out, manifest = built
    for m in manifest:
        data = (out / m["file"]).read_bytes()
        assert b"/Type3" not in data, f"{m['name']}: Type 3 font (must embed TrueType/CFF)"
        assert re.search(rb"/BaseFont\s*/", data), f"{m['name']}: no embedded font"


def test_cascade_defs_are_regenerated_from_data(built):
    """F14's TikZ annotations come from a generated \\def block, never typed in."""
    out, _manifest = built
    tex = (out / "cascade_pipeline_defs.tex").read_text()
    for macro in (r"\def\judgedpct", r"\def\deterministicpct", r"\def\interceptionsn"):
        assert macro in tex, f"missing {macro}"
    vals = [int(v) for v in re.findall(r"\{(\d+)\}", tex)]
    assert all(v >= 0 for v in vals) and vals, "no numbers written"


