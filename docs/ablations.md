# Ablation Studies

> **Reported ablation.** The paper's leave-one-out arms are the v3.1 runs
> `q235_local2_disabled_P{1..5}_v31` (CyberOps, all 75 variants, launched by
> `scripts/run_v31_completion.sh A` through `scripts/run_attack_paths.sh` with
> `DISABLE_PRINCIPLES=P<i>`), re-judged under Local4. Results: README, "Results at a
> glance"; figure `paper/figs/ablation.pdf`. The tooling below is the earlier,
> development-time workflow.

Two paths, both driven by [scripts/run_ablations.sh](../scripts/run_ablations.sh):

| Mode | Cost | What you get |
|---|---|---|
| **`postonly`** (recommended first) | ~30s, no LLM | **Upper-bound** −Pn ASR per principle, derived from the existing `results.csv` of the full-stack run. Defensible paper claim: "removing Pn would increase ASR by AT MOST X pp." |
| **`rerun`** | hours, $$ | **Exact** counterfactual via `attacks.harness --disable-principles`. Required for tight (lower-bound) numbers and for single-principle isolation. |

The production attack-runner [scripts/run_attack_paths.sh](../scripts/run_attack_paths.sh) only runs the canonical trio (`flat / acl_hardened / agenticcyops`); ablations live exclusively here.

---

## A. Post-hoc upper bound (`postonly`)

After any production agenticcyops run finishes, derive the upper-bound −Pn ASR per principle without re-running:

```bash
./scripts/run_ablations.sh postonly A cyberops
# or interactively:
./scripts/run_ablations.sh
```

**Outputs:**
- `results/eval_attacks/group_A/cyberops/ablation_from_logs.csv`
- `results/eval_attacks/group_A/ablation_from_logs.md`

**Output for the Group A cyberops run (scoring v2, 305 measurable agenticcyops trials of 375):**

| ablation | Pn caught | upper-bound ASR | Δ vs full |
|---|---:|---:|---:|
| baseline (full P1-P5) | — | 0.98% | — |
| −P1 | 0 | 0.98% | +0.00pp |
| −P2 | 82 | 27.87% | +26.89pp |
| −P3 | 96 | 32.46% | +31.48pp |
| −P4 | 25 | 9.18% | +8.20pp |
| −P5 | 5 | 2.62% | +1.64pp |

Pooled over the large-primary groups (A to E) and all four domains, 5,176 measurable
trials: −P3 +26.2pp, −P2 +16.0pp, −P4 +8.2pp, −P5 +1.6pp, −P1 +0.0pp. Agent refusals
(47% of measurable trials) and not-measurable trials are not attributed to any
principle. P1 never blocks an attack in this testbed because every attack uses
registered tools, so its necessity is not demonstrated here.

**Status (2026-09-19):** no `rerun` ablation and no `llm_judge` run exists on disk.
Every ablation figure in the repository is the post-hoc upper bound above.

The upper bound is worst-case (assumes every Pn-catch becomes a success when Pn is disabled, even though some would have been caught by Pn+1/Pn+2 downstream). For a *tight* number you need the `rerun` path.

**What it cannot do:**
- "P3-only" (single-principle isolation) — no observation in logs of a trial against P3 alone
- "Exact −P3 ASR" — we don't know whether P3-catches would have been caught by P4/P5

---

## B. Exact counterfactual (`rerun`)

Invokes `attacks.harness` with the appropriate `--disable-principles` and/or `--config llm_judge` flags.

```bash
# Single leave-one-out
./scripts/run_ablations.sh rerun A cyberops P3

# Multiple in one invocation
./scripts/run_ablations.sh rerun A cyberops "P3 P5"

# Single-principle isolation (P2-only = disable everything else)
./scripts/run_ablations.sh rerun A cyberops single_P2

# LLM-judge baseline (P1 + consensus, no P2/P3/P4/P5)
./scripts/run_ablations.sh rerun A cyberops llm_judge

# Combined sweep
./scripts/run_ablations.sh rerun A cyberops "P1 P2 P3 P4 P5 llm_judge"
```

**Token vocabulary:**

| token | What it does |
|---|---|
| `P1` ... `P5` | leave-one-out: full agenticcyops minus that principle |
| `single_P1` ... `single_P5` | single-principle isolation: agenticcyops with only that principle active |
| `llm_judge` | P1 identity + P3-L6 consensus only (skips P2/P3-L0..L5/P4/P5) |

**Outputs (per ablation):**
- `logs/<domain>_eval_attacks_<G>_disabled_<set>/<config>_<ts>.jsonl` — JSONL audit
- `results/eval_attacks/group_<G>_disabled_<set>/<domain>/results.csv` — per-trial outcome
- `results/eval_attacks/group_<G>_disabled_<set>/<domain>/summary.csv` — pivot

**Cost expectations:**

| Ablation | Wall-clock | LLM cost |
|---|---|---|
| P1, P2, P4, P5 (no consensus path change) | ~30-60 min | very low |
| P3 (consensus path lighter / heavier depending on disable) | ~1h | low-medium |
| single_P3 (consensus is the only catcher) | ~1.5h | medium |
| llm_judge (consensus on every action) | ~2h | medium-high |

---

## C. Recommended order

1. **Production run** of `agenticcyops` via `./scripts/run_attack_paths.sh`
2. **Postonly ablation** to get upper-bound numbers immediately
3. **Selective rerun** only for the ablations that matter most for the paper (typically `−P3`, `−P5`, `single_P3`, `llm_judge`) — skip the others if upper bounds already make the point

---

## D. Mechanism string reference

The `Mechanism` column emitted into `results.csv` carries the layer that fired. The post-hoc analyzer prefix-matches on `P1_*`, `P2_*`, `P3_*`, `P4_*`, `P5_*` to attribute each catch:

| Prefix | Layer (within agenticcyops) |
|---|---|
| `P1_*` | Authenticated interface — identity, response integrity, config integrity |
| `P2_*` | Capability scoping — manifest, parameter validator, output classifier |
| `P3_*` | Verified execution — operational context, intent chain, consensus, accumulation, sanitization, handoff |
| `P4_*` | Memory integrity — similarity, drift, contradiction, replay, schema, metadata |
| `P5_*` | Access isolation — phase ACL, query scope, broad-query block, sanitization, injection sanitization |

Non-Pn outcomes (also reported in postonly's "Context" section):
- `agent_refused` — model emitted Final Answer instead of any tool call
- `none` — no defense layer fired and no refusal (= attack succeeded)
- `acl_no_deny` (acl_hardened only), `flat_no_defense` (flat only)
