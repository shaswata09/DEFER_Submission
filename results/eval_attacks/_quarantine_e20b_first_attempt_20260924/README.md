# E20b, first attempt — quarantined 2026-09-24

The attack pass ran 4 of its 30 trials: 13 of the 15 per-AP harness
processes died at startup within ~2s each, writing no JSONL and no
trial summary. `run_attack_paths.sh` pipes each process through
`grep ... || true`, which discards the exit status, and
`print_summary()` returns early on an empty result list, so the run
log said "complete".

The benign tail (20/20) therefore followed 4 attack incidents rather
than 30, which is not the carry-over condition E20b measures.

Re-run as `group_q235_div4_persistent3` via `scripts/rerun_e20b.sh`,
which counts produced rows per AP and refuses the benign tail if the
attack pass is short. Nothing from this directory reaches
`all_trials.csv`.
