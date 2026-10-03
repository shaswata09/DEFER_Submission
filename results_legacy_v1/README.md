# Legacy outputs (v1 harness)

Everything under `results_legacy_v1/` and `logs_legacy_v1/` was produced with the v1
harness (runs of April to May 2026, re-scored once in September 2026). The v1 harness
scored AP-7..AP-15 by mechanism names, leaked defense state across trials, ran the
primary at temperature 0 and logged no tool-call arguments for the undefended configs.

**Do not mix these numbers with v2 results.** Nothing here is reported in the paper,
with two exceptions:

- `asb/` — the ASB live runs. Their per-case `emitted_action` / `emitted_args` columns
  are reused by the v2 paired replay (`benchmarks/asb/run_e2e.py --replay-from`), but
  only if the E0 drift check passes.
- `injecagent/` — reported as is.

v2 outputs are written to `results/` and `logs/`.
