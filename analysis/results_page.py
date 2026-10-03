"""A self-contained results page for the artifact (a web view
of the results next to the code and data).

    python -m analysis.results_page     # -> docs/results/index.html

Static HTML with inline CSS and a few lines of JavaScript, no external
resources, so it opens from a checkout offline. It is
built only from committed result files and the figure previews.
"""
from __future__ import annotations

import html
import json

from config import BASE_DIR

RES = BASE_DIR / "results"
OUT = BASE_DIR / "docs" / "results" / "index.html"
D4 = ("cyberops", "healthcare", "finance", "legal")
NAMES = {"cyberops": "CyberOps", "healthcare": "Healthcare", "finance": "Finance", "legal": "Legal"}
CFG = ("FLAT", "ACL", "JUDGEONLY", "NOJUDGE", "FULL")
LABEL = {"FLAT": "Flat (no checks)", "ACL": "ACL (connectivity only)",
         "JUDGEONLY": "JudgeOnly (judge every proposal)", "NOJUDGE": "NoJudge (never judge)",
         "FULL": "DEFER (rules first, judge last)"}
REP = {"FLAT": "flat", "ACL": "acl", "JUDGEONLY": "judgeonly", "NOJUDGE": "nojudge", "FULL": "full"}


def _load(name: str) -> dict:
    p = RES / name
    return json.loads(p.read_text()) if p.exists() else {}


def _table(head: list[str], rows: list[list], cls: str = "") -> str:
    e = html.escape
    th = "".join(f"<th>{e(str(h))}</th>" for h in head)
    tr = "".join("<tr>" + "".join(f"<td>{e('' if c is None else str(c))}</td>" for c in r) + "</tr>"
                 for r in rows)
    return f'<table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table>'


def build() -> str:
    v31, ex, rt = _load("replay_v31.json"), _load("v31_extras.json"), _load("replay_tables.json")
    prim = _load("primaries_v31.json") or _load("primaries_v29.json")
    prim_tag = "v3.1" if (RES / "primaries_v31.json").exists() else "v2.9"
    tam = _load("tamas.json")
    mech = _load("v31_mechanisms.json")
    figs_n = {}
    fj = BASE_DIR / "paper" / "figs" / "figures.json"
    if fj.exists():
        figs_n = {x["name"]: x.get("n", {}) for x in json.loads(fj.read_text())}

    # the boundary per domain (a selector switches domains)
    panes = []
    for d in D4:
        row = v31.get(d, {})
        rep = row.get("reported_v22_local4", {})
        rows = [[LABEL[c], row.get(c, {}).get("asr"), row.get(c, {}).get("benign_denied"),
                 rep.get(REP[c], "not run")] for c in CFG]
        panes.append(f'<div class="pane" data-domain="{d}"{" hidden" if d != "cyberops" else ""}>'
                     + _table(["Configuration", "Attack success % [95% CI]", "Legitimate denied %",
                               "Earlier run (v2.2)"], rows) + "</div>")
    buttons = "".join(f'<button data-domain="{d}"{" class=on" if d == "cyberops" else ""}>{NAMES[d]}</button>'
                      for d in D4)

    iw = ex.get("impact_weighting", {})
    iw_rows = [[c, r.get("calls"), r.get("blocked_unweighted"),
                f'{r.get("blocked_weighted_S5")} / {r.get("blocked_weighted_S7")} / {r.get("blocked_weighted_S9")}']
               for c, r in iw.items()]
    pairs = []
    for dom, cmp_ in ex.get("paired", {}).items():
        for k, r in cmp_.items():
            pairs.append([NAMES.get(dom, dom), k.replace("->", " → "), r["a"], r["b"],
                          f'{r["diff"]} [{r["ci"][0]}, {r["ci"][1]}]'])
    between = [[k, r["a"], r["b"], f'{r["diff"]} [{r["ci"][0]}, {r["ci"][1]}]']
               for k, r in ex.get("between_runs", {}).items()]
    jt = [[m] + [r.get(d) for d in D4] for m, r in ex.get("judge_approval_of_legitimate_proposals", {}).items()]

    # the ablation as the figure plots it (v3.1 arms when present)
    an = figs_n.get("ablation", {})
    abl_rows = [[k, v, an.get("benign_any_denial_pct", {}).get(k, "")]
                for k, v in an.get("asr_pct", {}).items()]
    abl_head = f"Leave-one-out (CyberOps, {an.get('shared_variants', '?')} variants)"
    prim_rows = [[name, *(row.get(c, {}).get("asr") for c in CFG)] for name, row in prim.items()]
    tam_rows = [[a, tam.get("flat", {}).get(a, {}).get("asr_as_run"), tam.get("full", {}).get(a, {}).get("asr_as_run"),
                 tam.get("full", {}).get(a, {}).get("asr_local4", "as run")]
                for a in ("DPI", "impersonation", "colluding", "byzantine", "contradicting")]

    g, sb, ev, xp = (mech.get("gate", {}).get("q235_local2_v31", {}), mech.get("siblings", {}),
                     mech.get("evidence", {}), mech.get("expiry", {}).get("q235_local2_v31persist", {}))
    mech_rows = [
        ["Approve gate, offline (CyberOps)", f'approves {g.get("attack_approved_pct")}% of attack proposals, '
         f'{g.get("benign_approved_pct")}% of legitimate ones; substituted for the panel: '
         f'{g.get("executed_as_run")} -> {g.get("executed_with_gate")} executed trials'],
        ["Rule-evading siblings (24)", f'held {sb.get("held")}, the panel intercepting in '
         f'{sb.get("held_with_a_panel_interception")}; executed: {", ".join(sb.get("executed", []))}'],
        ["P2.2 on structured evidence", f'{ev.get("attack|denied_trusted")} attack proposals denied instead of '
         f'{ev.get("attack|denied_full")}; benign {ev.get("benign|denied_trusted")} of {ev.get("benign|calls")}'],
        ["State expiry (first persistent pass)", f'as shipped {xp.get("shipped", {}).get("pct")}% denied; '
         f'identity key, one-incident window {xp.get("identity_1", {}).get("pct")}%'],
        ["Replay fidelity", f'{mech.get("fidelity", {}).get("all", {}).get("pct")}% of '
         f'{mech.get("fidelity", {}).get("all", {}).get("of")} live votes reproduced'],
    ] if mech else []

    figs = [("boundary_domains", "The boundary at v3.1 in four domains, with its cost"),
            ("boundary_v31", "The boundary at v3.1 beside the earlier runs"),
            ("judgment_boundary", "The boundary in CyberOps: attack success and legitimate work denied (v3.1)"),
            ("interception_tiers", "First interception by decision tier (v3.1; ASB live run)"),
            ("ap_heatmap", "Attack success per attack path (v3.1, CyberOps)"),
            ("paired_variants", "Paired outcome per variant, JudgeOnly vs DEFER (v3.1)"),
            ("transfer", "Across domains and primaries (v3.1; Scout and Mistral earlier runs)"),
            ("channels", "By injection channel (v3.1)"), ("cost", "Where the cost goes (v3.1)"),
            ("ablation", "Leave-one-out ablation (v3.1)"),
            ("validator_behavior", "Judge agreement and quorum (v3.1)"),
            ("panel_composition", "Panel composition and lineage (earlier runs)"),
            ("state_carryover", "Persistent state (v3.1)"),
            ("primaries_boundary_v31", "Three primaries (v3.1)"), ("tamas", "TAMAS"),
            ("panel_context_v3", "Judges with more context (v3.0)")]
    gallery = "".join(f'<figure><img loading="lazy" src="../figures/{f}.png" alt="{html.escape(c)}">'
                      f'<figcaption>{html.escape(c)}</figcaption></figure>'
                      for f, c in figs if (BASE_DIR / "docs" / "figures" / f"{f}.png").exists())

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>DEFER results</title>
<style>
:root{{--bg:#fbfbfa;--fg:#1d1d1f;--muted:#5f6368;--line:#e2e2df;--accent:#0b7a5c;--card:#ffffff}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16181a;--fg:#e8e8e6;--muted:#a0a4a8;--line:#2e3134;--accent:#39c79a;--card:#1d2023}}
 figure img{{background:#fff}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1080px;margin:0 auto;padding:24px 16px 64px}}h1{{font-size:26px;margin:0 0 4px}}h2{{font-size:19px;margin:36px 0 8px}}
p.lead,p.note{{color:var(--muted);margin:4px 0 12px}}nav a{{color:var(--accent);margin-right:14px;text-decoration:none}}
.wrap{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;background:var(--card);font-variant-numeric:tabular-nums}}
th,td{{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}}th{{font-weight:600;color:var(--muted)}}
.tabs button{{font:inherit;padding:6px 12px;margin:0 6px 10px 0;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:6px;cursor:pointer}}
.tabs button.on{{border-color:var(--accent);color:var(--accent);font-weight:600}}
.gallery{{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}}
figure{{margin:0;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px}}figure img{{width:100%;height:auto;display:block}}
figcaption{{color:var(--muted);font-size:13px;margin-top:6px}}
</style></head><body><main>
<h1>DEFER: results</h1>
<p class="lead">Deterministic-first enforcement with residual judgment. Reported configuration: <code>defense-freeze-v3.1</code>, Qwen3-235B primary, four open-weight judges (Local4), three trials per variant; intervals are 95% cluster-bootstrap intervals over variants. Built from the committed result files by <code>python -m analysis.results_page</code>.</p>
<nav><a href="#boundary">Boundary</a><a href="#robust">Robustness</a><a href="#earlier">Ablation and primaries</a><a href="#figures">Figures</a></nav>

<h2 id="boundary">The judgment boundary (v3.1)</h2>
<div class="tabs">{buttons}</div>
<div class="wrap">{''.join(panes)}</div>
<p class="note">JudgeOnly and DEFER: every judged round re-judged by the four local judges. "Not run": the earlier runs measured JudgeOnly and NoJudge in CyberOps only.</p>

<h2 id="robust">Robustness of the v3.1 results</h2>
<p class="note">Attack-incident tool calls blocked, unweighted and weighted by a FAIR-style loss class (weight of the most severe class 5 / 7 / 9).</p>
<div class="wrap">{_table(["Configuration", "Calls", "Blocked %", "Blocked %, loss-weighted"], iw_rows)}</div>
<p class="note">Paired differences at v3.1 (percentage points, 95% interval).</p>
<div class="wrap">{_table(["Domain", "Comparison", "From %", "To %", "Difference"], pairs)}</div>
<p class="note">Two independent runs of Flat and ACL, attack paths untouched by the audit fixes.</p>
<div class="wrap">{_table(["Arm", "Earlier run %", "v3.1 %", "Difference"], between)}</div>
<p class="note">Each judge's approval of legitimate proposals it judged (%).</p>
<div class="wrap">{_table(["Judge", *[NAMES[d] for d in D4]], jt)}</div>
<p class="note">Mechanism analyses repeated on the v3.1 runs (results/v31_mechanisms.md).</p>
<div class="wrap">{_table(["Analysis", "Result"], mech_rows)}</div>

<h2 id="earlier">Ablation, other primaries, TAMAS</h2>
<div class="wrap">{_table([abl_head, "Attack success %", "Benign incidents with a denial %"], abl_rows)}</div>
<p class="note">Other primaries (CyberOps, {prim_tag}), attack success %.</p>
<div class="wrap">{_table(["Primary", *CFG], prim_rows)}</div>
<p class="note">TAMAS (Qwen3-235B, CrewAI; earlier runs, not re-run at v3.1), attack success %.</p>
<div class="wrap">{_table(["Attack type", "Flat", "DEFER as run", "DEFER, Local4"], tam_rows)}</div>

<h2 id="figures">Figures</h2>
<div class="gallery">{gallery}</div>
</main>
<script>
document.querySelectorAll('.tabs button').forEach(b=>b.addEventListener('click',()=>{{
  document.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('on',x===b));
  document.querySelectorAll('.pane').forEach(p=>p.hidden=p.dataset.domain!==b.dataset.domain);
}}));
</script></body></html>
"""


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(build())
    print(f"wrote {OUT.relative_to(BASE_DIR)}")


if __name__ == "__main__":
    main()
