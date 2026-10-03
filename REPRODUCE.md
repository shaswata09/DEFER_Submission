# Reproducing the results

Everything below runs from a checkout at the freeze tag named in the run
headers. Runs write `logs/<domain>_eval_attacks_<group>[...]/*.jsonl`; every
table and PDF is rebuilt from those logs with no LLM calls.

## Freeze tags

| Tag | Commit | What it freezes |
|---|---|---|
| `defense-freeze-v2` | see `git show` | the defense stack used for the first full programme |
| `defense-freeze-v2.1` | `a369d18` | v2 plus one agent-output parser fix (`agents/base_agent.py`): a JSON array/scalar answer is free text instead of a crash. Frozen defense directories byte-identical to v2. |
| `defense-freeze-v2.2` | tagged on the T7 commit | v2.1 plus the tool-response / memory-channel measurability work (T1–T7 below). **No defense decision changed.** |
| `defense-freeze-v2.3` | tagged for the follow-up experiments | v2.2 plus one provenance-only change: `logging_utils/run_metadata.py::_scrubbed_command` redacts API keys and remote endpoint URLs out of the `command` field of the run header. **No defense decision changed** — `git diff defense-freeze-v2.2 defense-freeze-v2.3 -- host consensus memory configs domains/*/configs mcp_servers agents attacks/effects.py attacks/harness.py` is empty. |
| `defense-freeze-v2.4` | tagged for the follow-up experiments | v2.3 plus one **state-hygiene fix**: `reset_trial_state()` now clears the MMA store in every configuration, not only `agenticcyops`. Before this, the flat / ACL / judge-only arms shared one store across trials although the run header claimed `state_mode: isolated`, so memory-channel exposure decayed with variant order (AP-14 flat 12/12/12/9/6 by variant against 12 throughout for the defended arm). **No check, threshold or policy changed**, and the defended arm's behaviour is identical; results for the undefended arms on memory-seeded paths are not comparable across v2.3 and v2.4 and are re-run under E5.5. |
| `defense-freeze-v2.5` | tagged for the configuration-variant experiments | v2.4 plus four **configuration variants** on the agenticcyops stack (E1 `agenticcyops_noautoapprove`, E16 `agenticcyops_gate_permissive`, E17 `p2_judge`, E9 `agenticcyops_writejudge`). Each is a flag threaded onto the existing stack following the `symbolic_only` pattern; the orchestrator keeps the label for logs and maps it to the agenticcyops stack. **The deployed configuration is bit-identical** -- pinned by `test_deployed_config_is_unchanged` -- and only the auto-approve rule varies between gate modes, so no variant can weaken a deny or escalate path. `agenticcyops_writejudge` is registered but inert until E9 adds the critical-store marking. |
| `defense-freeze-v2.6` | `5cc913d` | v2.5 plus logging only: the auto-gate logs the L1 scores it decides on (`consensus/auto_gates.py`). **No defense decision changed.** |
| `defense-freeze-v2.7` | `f6f713d` | v2.6 plus the E16 permissive gate rule keyed on scope and proportionality (`consensus/auto_gates.py`). Active only under `agenticcyops_gate_permissive`; **the deployed configuration is unchanged.** |
| `defense-freeze-v2.8` | `150d53b` | v2.7 plus E9: stores marked `critical` in `domains/*/configs/memory_collections.json`, and writes to them routed to the panel. Active only under `agenticcyops_writejudge`; **the deployed configuration is unchanged.** |
| `defense-freeze-v2.9` | `6de80ad` | **Decision change (B1).** The risk scorer receives the incident evidence (alignment) and the replay ledger (precedent), which before sat at their 0.5 fallback in every run. Also logging: all five P3 scores, the deciding P2.2 branch, and no more overwritten action field in cross-incident ledger events. Used for the labeled calibration run (`q235_local2_v29`) and the gpt-oss-120b and Llama-3.1-8B runs. |
| `defense-freeze-v3.0` | `5d77b35` | **Decision change (panel input).** `consensus/panel_context.py` gives the panel the incident's structured evidence, the calling agent's scope, the targets' operating context, and the incident's earlier consequential decisions, and proposals carry the model's stated reasoning. No check, threshold, or quorum changed. Used only for the labeled `*_local2_v30` runs; it raises attack success (`results/replay_v3.md`), so it is not the reported configuration. |
| `defense-freeze-v3.1` | `3c9cfdb` | **The reported configuration.** v2.9's decision code (the v3.0 panel-input wiring reverted) plus the fixes of a code audit: harness faults deep-copied per incident (AP-15 faults fired in trial 1 only); P3-L0 validates the handoff into the current phase; implied actions and targets for single-action tools, so time policy, change conflict and impacts apply outside CyberOps; change-log tool and reversal pairs; intent-chain thresholds from config; "24/7" policies end at 24; early exit on the deciding mechanism; no config-integrity check in JUDGEONLY; P5-L3 receives the incident text; hoisted fields sanitized; case-insensitive votes; bulk cap counts executed actions; case-insensitive critical-asset match; AP-13 transfer payloads and benign schema values fixed; oracle fixes (handoff canaries are not leaks, post-execution rejections are executions, AP-6 replay needs the same call). Runs: `q235_local2_v31`. |
| `defense-freeze-v3.1.1` | `0242ceb` | v3.1 plus one oracle fix: a denial at interception step 6 counts as executed only with a `p1l2_reason` (the JUDGEONLY panel denial is also logged at step 6). **Scoring only; no decision changed.** The freeze guard's default. |
| `defense-freeze-v3.1.2` | tagged on the logger commit | v3.1.1 plus one logging change: the logger writes paths inside the checkout repo-relative (`./...`), so no log carries the absolute path of the machine that ran it (before, a config-integrity event's `changed_files` did). **Logging only; no decision changed.** |
| `defense-freeze-v3.1.3` | tagged on the rename commit | v3.1.2 with the project renamed from AgenticCyOps to DEFER in docstrings, help text, and one config file's comment and description, which no code reads. **Naming only; no decision, log field, or identifier changed** (the `agenticcyops` configuration label and the `AGENTICCYOPS_HMAC_KEY` variable keep their names). |
| `defense-freeze-v3.1.4` | `23b7b4c` | v3.1.3 plus the harness and scoring fixes of the second audit (2026-10-02), **no defense check changed**: the AP-9 handoff fields are rendered into the next agent's handoff summary (before, only P3-L0 read them; no model or judge saw AP-9); tool hiding follows P2 (JUDGEONLY and a run without P2 see every tool); the oracle reads a single-action tool's implied action as its operation, needs a distinct call per step of an unordered chain, attributes a NOJUDGE block to the call's own layer, and scores an unanswered memory operation as an error; 31 auto-derived effect specs repaired (`scripts/fix_effect_specs.py`). Used for the AP-9 and JUDGEONLY re-runs outside CyberOps (`q235_local2_v314`). |
| `defense-freeze-v3.2` | `dc0c2c6` | **Decision change.** v3.1.4 plus the high-severity defense fixes of the second audit: the handoff deflation check reads the phase's claims (not tool results or earlier phases) as whole, non-negated words, with the severity under every field name; parameter rules follow the tool schemas (T8 `reset`, T10 `push`, short reason codes); the wildcard check reads scoping arguments only and the criticality check state-changing tools only; one target and action map for the validator, the ledger and the hoist (`host/tool_semantics.py`); nested and multi-incident triggers name their incident ids. Used for every CyberOps run reported (`*_v32`). The freeze guard's default. |

### What changed between `defense-freeze-v2.1` and `defense-freeze-v2.2`

The diff in the decision directories is **empty**:

```
git diff defense-freeze-v2.1 defense-freeze-v2.2 -- consensus memory configs domains/*/configs
```

`mcp_servers/` and `agents/` are unchanged. `logging_utils/run_metadata.py`
changed in one provenance-only way: `git_dirty` now ignores tracked changes
under `results/`, `logs/`, `data/` (a run writing its own output does not make
the source "dirty"), so a run launched from committed source records
`git_dirty=false`. No decision depends on it. The other frozen paths that
differ are:

| Path | Change | Decision impact |
|---|---|---|
| `host/orchestrator.py` | **logging only** (+25/−4): `injection_served` events where the host applies a tool-response, handoff, or proposal injection; `result_ids` / `sanitized_ids` on the `memory_read` allow event. Every hunk is inside an `if self.logger:` block. | none |
| `attacks/harness.py` | `resolve_tool` before the port lookup; an undeliverable injection is `outcome=error` / `blocked_by=injection_not_delivered` and the incident is not run; seeded memory records carry `doc_id`; `alert_text` served at trial start; memory exposure emitted after the trial; `exposed`/`channel` results columns; `refuse_if_dirty` guard. | none (harness, not defense) |
| `attacks/effects.py` | `exposed` flag on the verdict; new `mem_read` effect kind; `TOOL_ALIASES` imported from the payload schema. | none (oracle) |

Unfrozen paths changed in the same span: `attacks/payload_schema.py`
(`TOOL_ALIASES`, `resolve_tool`, stricter `validate_payload`, `--validate-all`,
`--assert-measurable`), `attacks/build_channel_p5_variants.py` (generator),
`analysis/parse_logs.py`, `scripts/run_revision.sh`, `scripts/run_attack_paths.sh`,
`Makefile`, tests, and the AP-2 / AP-3 / AP-4 / AP-14 payload files
(`domains/*/payloads/`).

Payload changes (all four domains unless noted):

* AP-2 / AP-3: `meta.injection.tool` names the registered tool id (12 variants
  previously used a `_response` suffix or an alias and were never delivered).
* AP-14: a memory-channel attack in every domain — a planted record in an
  analyze-readable store, leading with the read query's phrasing so it ranks
  in the top-3, with an operational next step that names a unique canary.
* AP-4 v1–v5: canary planted in a store the report phase cannot read
  (`p5_target=store_policy`) or, legal v4/v5, in a summary-only store
  (`field_filter`); healthcare keeps `mem_write` and gains a canary.
* AP-4 v6 / v7 (new, every domain): P5 read families — an unauthorised store
  read (`store_policy`) and a broad "dump" query (`query_scope`), scored with
  the `mem_read` effect kind; `channel=alert_text`, no canary.
* AP-2 legal: canary on all five `exfil` variants.

## Environment

* Python env `agenticcyops` (conda). `make test` runs the suite.
* `.env` (git-ignored) holds API keys, `SEED`, and `REMOTE_5090_URL` /
  `REMOTE_5090_API_KEY` for the Llama-3.1-8B node. Never commit it.
* Model weights under `models/` (see `scripts/run_revision.sh preflight`).
* vLLM profiles (`scripts/vllm_profiles.sh start q235|mid`): `q235` serves
  Qwen3-235B (TP=4) plus the V1/V5 validators; `mid` serves Llama-4-Scout,
  Mistral-Small, DeepSeek-R1-Distill-32B, Qwen3-14B plus V1/V5.

## Gates that run before every stage

```
make check-payloads      # --validate-all, --assert-measurable, hygiene test
scripts/check_freeze.sh  # HEAD after the tag, frozen dirs identical and clean
```

The harness itself refuses a non-smoke run when the tree has uncommitted
tracked changes (`git_dirty=true` in the header).

## Stages (scripts/run_revision.sh)

All runs: isolated state, primary temperature 0.7, three trials per variant,
seed recorded per trial, freeze check on.

| Stage | Profile | What | Incidents |
|---|---|---|---|
| `e2b-main` | q235 | `q235_div4`, four domains, flat / acl_hardened / agenticcyops, AP-2/3/4/14 | 792 |
| `e3b` | q235 | `q235_div4` CyberOps, agenticcyops minus P5, minus P4, llm_judge, symbolic_only, AP-2/3/4/14 | 264 |
| `e2b-others` | mid | `scout_div4`, `mistral_div3p`, `llama8b_div4`; CyberOps + finance; three configs; AP-2/3/4/14 | 1,188 |

The other eleven attack paths keep their v2.1 results (no defense decision
changed); the superseded v2.1 rows for AP-2/3/4/14 are archived under
`results/eval_attacks/_superseded_v2.1/` and excluded from `all_trials.csv`.

## The reported runs at `defense-freeze-v3.1`

All local (Qwen3-235B or the named primary; live panel local2 = Mistral-Small +
Gemma-4, two of two; Local4 offline afterwards from `cache/replay_v31`), RUN_TAG-labeled,
freeze guard on, decision code equal to `defense-freeze-v3.1.1` (and to v3.1.3, which renames only).

| Launcher | Groups | What | Trials |
|---|---|---|---|
| `scripts/run_v31.sh` | `q235_local2_v31` | the boundary: five configurations, four domains, all paths (plus the 24 E2 siblings) and the benign scenarios | 5,385 |
| `scripts/run_v31_completion.sh A` | `q235_local2_disabled_P{1..5}_v31` | leave-one-out, CyberOps, all paths and benign | 1,500 |
| | `q235_local2_v31persist`, `..._v31persist2` | persistent state: 2 variants x 1 trial per path, then the benign scenarios; four domains, and CyberOps reversed | 205 |
| | `llama8b_local2_v31` | Llama-3.1-8B boundary, CyberOps | 1,500 |
| `scripts/run_v31_completion.sh B` | `oss120_local2_v31` | gpt-oss-120b boundary, CyberOps | 1,500 |

Afterwards (no model calls except the Local4 votes):

```
python -m analysis.replay_v31 build                  # rounds -> cache/replay_v31
python -m analysis.replay_run query --validator L1_mistral --url ... --replay-dir cache/replay_v31   # x4 judges
make replay-v31 primaries-v31 v31-mechanisms figures
```

## The reported runs after the second audit (2026-10-02)

`scripts/run_v32.sh` (phases A-C, tmux) runs from two clean worktrees:

| Freeze tag | Groups | What |
|---|---|---|
| `defense-freeze-v3.2` | `q235_local2_v32` | CyberOps boundary, five configurations, all paths (with the E2 siblings) and benign |
| | `q235_local2_disabled_P{1..5}_v32` | leave-one-out, CyberOps |
| | `llama8b_local2_v32`, `oss120_local2_v32` | the other two primaries, CyberOps |
| `defense-freeze-v3.1.4` | `q235_local2_v314` | healthcare, finance, legal: JUDGEONLY on every path and benign, AP-9 under the other four configurations |

The reported boundary is the virtual group `q235_local2_rep` (`analysis/reported.py`):
CyberOps from v3.2, the other domains from v3.1 with their AP-9 and JUDGEONLY cells
from v3.1.4. Persistent state stays at v3.1. Afterwards:

```
make parse                                   # every run re-scored with the current oracle
python -m analysis.replay_v31 build          # the v3.1 rounds, rebuilt as the v3.1 host built them
python -m analysis.replay_reported build     # the reported rounds -> cache/replay_rep
python -m analysis.replay_run query --replay-dir cache/replay_rep --validator L1_mistral --url ...   # x4, and replay_v31
make replay-tables replay-v31 reported primaries-v32 v31-mechanisms tamas-tables figures
```

## Tables and reports

```
make paper-tables    # parse_logs -> statistical_tests -> generate_tables  -> results/paper_tables.md
make paper-reports   # per-run attack_report.pdf, results/revision_report.pdf, ASB asb_analytics.pdf
```

`exposed` in `all_trials.csv` is true when the trial has at least one
`injection_served` event (the model was shown the adversarial content). It
never changes the outcome or the ASR denominator; attempt rates are reported
both plain and *given exposure*.
