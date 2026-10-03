# DEFER -- analysis targets. None of these calls a language model.
PY ?= python

# Paper figures use the re-adjudicated local panel (Local4); set DEFER_PANEL=
# (empty) to plot the as-run Div4 values instead.
DEFER_PANEL ?= local4
export DEFER_PANEL

.PHONY: paper-tables paper-reports parse stats tables reports asb-reports figures readme-figures replay-tables replay-v3 replay-v31 v31-mechanisms b2 primaries-tables primaries-v31 primaries-v32 reported tamas-tables test freeze-check check-payloads

paper-tables: parse stats tables

# PDF reports from the generated tables (per run, consolidated, ASB panels)
paper-reports: reports asb-reports

parse:
	$(PY) -m analysis.parse_logs --rescore

stats:
	$(PY) -m analysis.statistical_tests

tables:
	$(PY) -m analysis.generate_tables

reports:
	$(PY) -m analysis.generate_reports

ASB_PANELS ?= q235_div4_div4,q235_div4_div3,q235_div4_single,q235_div4_lin3
asb-reports:
	for g in $$(echo $(ASB_PANELS) | tr ',' ' '); do $(PY) -m analysis.asb_analytics --groups $$g; done
	$(PY) -m analysis.asb_analytics --groups $(ASB_PANELS) --out-dir results/asb/asb_analytics_panels

# Paper figures: every PDF regenerated from results/ and logs/, no manual step.
# Depends on `parse` so figures and tables are built from the same all_trials.csv
# and cannot drift apart.
figures: parse
	$(PY) -c "from analysis.replay_tables import write_local4_trials; write_local4_trials()"
	$(PY) -m analysis.make_figures --out paper/figs
	$(MAKE) readme-figures

# The result figures shown in README.md (PNG previews written by make_figures).
README_FIGS = judgment_boundary interception_tiers ap_heatmap paired_variants ablation \
              validator_behavior panel_composition transfer channels cost state_carryover
readme-figures:
	mkdir -p docs/figures
	for f in $(README_FIGS); do cp paper/figs/preview/$$f.png docs/figures/$$f.png; done

# Every panel-dependent number in the paper, re-adjudicated from the cached
# local votes in cache/validators/ (CPU only, no model is queried).
replay-tables:
	$(PY) -m analysis.replay_tables > /dev/null
	$(PY) -c "from analysis.replay_tables import write_local4_trials, write_local_panel_csv; write_local4_trials(); write_local_panel_csv()"
	$(PY) -m analysis.statistical_tests --trials results/eval_attacks/all_trials_local4.csv \
	    --out results/eval_attacks/stats_local4.csv > /dev/null

# The v3.0 panel input: offline re-judging of every judged v2.9 round and the
# live v3.0 re-run, both under Local4 (results/replay_v3.md; cached votes only).
replay-v3:
	$(PY) -m analysis.replay_v3 tables > /dev/null
	$(PY) -m analysis.replay_v3 live-tables > /dev/null
	$(PY) -m analysis.replay_v3 report > /dev/null

# The boundary at defense-freeze-v3.1 (the audit fixes), live, Local4 offline
# (results/replay_v31.md, docs/figures/boundary_v31.png; cached votes only).
replay-v31:
	$(PY) -m analysis.replay_v31 tables > /dev/null
	$(PY) -m analysis.v31_extras > /dev/null
	$(PY) -m analysis.results_page > /dev/null

# The mechanism analyses (approve gate, rule-evading siblings, structured
# evidence, state expiry, judge agreement, replay fidelity) on the v3.1 runs
# (results/v31_mechanisms.md; logs and cached votes only, about 15 minutes).
v31-mechanisms:
	$(PY) -m analysis.v31_mechanisms > /dev/null

# Live v2.9 calibration run vs its replay (results/b2_live.json).
b2:
	$(PY) -m analysis.b2_live > /dev/null

# The boundary for gpt-oss-120b and Llama-3.1-8B (results/primaries_v29.md,
# docs/figures/primaries_boundary.png) and TAMAS (results/tamas.md,
# docs/figures/tamas.png); both read the cached Local4 votes.
primaries-tables:
	$(PY) -m analysis.primaries_tables > /dev/null

primaries-v31:
	$(PY) -m analysis.primaries_tables --v31 > /dev/null

# the reported primaries (defense-freeze-v3.2, cache/replay_rep)
primaries-v32:
	$(PY) -m analysis.primaries_tables --v32 > /dev/null

# the reported boundary, ablation and judged fractions (cache/replay_rep)
reported:
	$(PY) -m analysis.replay_reported tables > /dev/null
	$(PY) -m analysis.v31_extras > /dev/null
	$(PY) -m analysis.results_page > /dev/null

tamas-tables:
	$(PY) -m analysis.tamas_tables > /dev/null

check-payloads:
	$(PY) -m attacks.payload_schema --validate-all
	$(PY) -m attacks.payload_schema --assert-measurable
	$(PY) -m pytest -q -p no:cacheprovider tests/test_payload_hygiene.py

test:
	$(PY) -m pytest -q

freeze-check:
	scripts/check_freeze.sh
