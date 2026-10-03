# DEFER: Deterministic-First Enforcement with Residual judgment

Artifact for the paper **"Where Rules End and Judges Begin: Measuring the Judgment
Boundary in Multi-Agent Systems Security"** (under review).

LLM multi-agent systems (MAS) invoke tools, share memory, and delegate, and each of
those interactions can carry attacker-controlled content. Pipelines that combine
defenses usually leave the final decision to an LLM judge. This artifact measures how
much of that decision deterministic checks can settle, and what is left for the judges.
It contains:

- **DEFER**, a reference pipeline of 27 deterministic checks followed by an LLM panel,
  organized into five principles over the two surfaces where untrusted content enters
  a MAS (tool orchestration and memory);
- **a four-domain testbed** (CyberOps, healthcare, finance, legal) with five injection
  channels, 15 attack paths (300 variants), and 35 benign scenarios, evaluated with
  three primary models (Qwen3-235B, gpt-oss-120b, Llama-3.1-8B);
- **two third-party benchmarks**: Agent Security Bench, and TAMAS run through an
  adapter that sends every real CrewAI tool call through DEFER;
- **an outcome oracle** that separates model refusal from framework interception, and
  **offline re-adjudication** of every logged judge decision, which re-scores the logged
  proposals under any validator panel without re-running the agents;
- **a negative result**: giving the judges the context the rules consult
  (`defense-freeze-v3.0`) makes them approve more attacks, offline and live;
- **every per-trial log, cached judge vote, table, and figure** behind the paper, and
  one command per artifact to regenerate it.

![Overview](docs/figures/overview.png)

*Attacker content enters through five channels on two surfaces (left). DEFER settles
what it can with 27 deterministic checks and sends only the undecided proposals, about a
quarter, to a panel of four open-weight judges (center). Right: the share of attempted
attacks each configuration stops. In the security-operations domain the same judges alone
stop 22% and DEFER 95% (attack success 32.0% undefended, 34.7% with the judges alone, 2.2%
with DEFER); on the 255 Agent Security Bench cases access control stops none of the
injected actions the agent emits and DEFER 94% (attack success 28.8%, 30.0%, 1.8%). 10 to
27% of legitimate actions are denied across the four domains.*

---

## Contents

- [Results at a glance](#results-at-a-glance)
- [Reproducing the results](#reproducing-the-results)
- [Names used in the paper and in the logs](#names-used-in-the-paper-and-in-the-logs)
- [The pipeline](#the-pipeline)
- [Repository layout](#repository-layout)
- [Provenance and known limitations](#provenance-and-known-limitations)
- [Ethics and intended use](#ethics-and-intended-use)
- [License](#license)

---

## Results at a glance

Unless a caption says otherwise, results use the Qwen3-235B-A22B primary, three
trials per variant, isolated state, and the **direct outcome under Local4**: every
logged panel round re-judged by four open-weight judges from four model families
(Mistral-Small-3.2-24B, Gemma-4-31B-it, gpt-oss-120b, Llama-4-Scout; three of four).
Intervals are 95% cluster-bootstrap intervals over variants.

The reported configuration is **`defense-freeze-v3.1`**: the originally evaluated
decision code with the defects of a code audit fixed (see
[provenance](#provenance-and-known-limitations)). The judgment boundary was re-run at
v3.1 in all four domains ([`results/replay_v31.md`](results/replay_v31.md)), and so were
the leave-one-out ablation, the gpt-oss-120b and Llama-3.1-8B boundaries, and the
persistent-state runs; the judge agreement, approve-gate, rule-evasion, and state-expiry
analyses are repeated on those runs ([`results/v31_mechanisms.md`](results/v31_mechanisms.md)).
The analyses that need other runs (panel lineage, the judge-input comparison, the
Llama-4-Scout and Mistral-Small primaries, Agent Security Bench, TAMAS) come from the
earlier runs (`defense-freeze-v2.2`, or v2.9 where noted) and are labeled; they are scored
with the same, audited outcome oracle ([`results/replay_tables.md`](results/replay_tables.md)).

### The judgment boundary (v3.1, development domain, 75 variants × 3 trials)

| Configuration | Attack success % [95% CI] | Tool proposals judged % | Legitimate proposals denied % | Before the fixes (v2.2) |
|---|---|---|---|---|
| FLAT (no checks) | 32.0 [22.7, 41.8] | 0 | 0.0 | 36.4 [26.2, 46.7] |
| ACL (connectivity only) | 24.9 [15.6, 35.1] | 0 | 51.9 | 24.0 [15.1, 33.3] |
| JUDGEONLY (judge every proposal) | 34.7 [24.4, 45.3] | 99.9 | 4.5 | 33.8 [24.0, 44.0] |
| NOJUDGE (never judge; escalate instead) | 1.3 [0.0, 4.0] | 0 | 54.3 | 1.3 [0.0, 4.0] |
| **FULL (DEFER: rules first, judge last)** | **2.2 [0.0, 5.8]** | **26.4** | **9.9** | 7.1 [2.2, 13.3] |
| JUDGEREST (FULL, judge everything the rules let through) | 2.2 [0.0, 5.8] | 69.8 | 11.8 | 7.1 [2.2, 13.3] |

![The boundary at v3.1 in four domains](docs/figures/boundary_v31.png)

*Attack success per configuration and domain at v3.1 (filled) beside the runs before
the fixes (hatched; JUDGEONLY and NOJUDGE were then run in the development domain
only). The same judges without the rules barely beat no checks in the development
domain and leave 9 to 19% in the others; rules first then judges leave 0 to 5.3%
(pooled over the three transfer domains 3.3% [1.3, 5.6], against 3.9% before the
fixes); never judging leaves 0 to 1.8% by escalating 41 to 59% of legitimate
proposals. Judging everything the rules let through changes no attack outcome.*

![The boundary at v3.1 with its cost](docs/figures/boundary_domains.png)

*The same v3.1 boundary with its cost (the paper's four-domain figure): attack success
(top) and legitimate tool proposals denied or escalated (bottom).*

![Judgment boundary](docs/figures/judgment_boundary.png)

*v3.1, development domain: (a) attack success, with the share of attack-incident tool
proposals that reach the judges below each bar; (b) legitimate tool proposals denied or
escalated, with benign task completion as run (hollow diamonds).*

### Across primary models

The boundary was also run live at `defense-freeze-v3.1` with two more primary models
(CyberOps, 75 variants × 3 trials plus the 20 benign scenarios × 3, per configuration),
with every panel decision re-judged under Local4. A model never judges its own
proposals, so gpt-oss-120b's panel is the other three judges, two of three.

![The boundary across three primary models](docs/figures/primaries_boundary_v31.png)

| Configuration | Qwen3-235B | gpt-oss-120b | Llama-3.1-8B |
|---|---|---|---|
| FLAT | 32.0 [22.7, 41.8] | 21.3 [12.4, 31.1] | 34.7 [24.4, 45.3] |
| ACL | 24.9 [15.6, 35.1] | 18.7 [10.7, 28.0] | 33.8 [23.6, 44.0] |
| JUDGEONLY | 34.7 [24.4, 45.3] | 21.3 [12.9, 30.7] | 27.6 [18.2, 36.9] |
| NOJUDGE | 1.3 [0.0, 4.0] | 1.3 [0.0, 4.0] | 1.3 [0.0, 4.0] |
| **FULL (DEFER)** | **2.2 [0.0, 5.8]** | **6.2 [1.3, 12.0]** | **8.4 [3.1, 14.7]** |
| tool proposals judged, FULL | 26.4% | 9.1% | 45.0% |
| legitimate proposals denied, FULL | 9.9% | 0.0%\* | 14.6% |
| legitimate proposals escalated, NOJUDGE | 54.3% | 33.3% | 67.1% |

*Attack success in % with 95% intervals, v3.1. For three models from three families, 8B
to 235B, the judges alone barely beat no checks in CyberOps, rules first then judges
reach 2 to 8%, and never judging reaches 1.3% only by escalating a third to two thirds of
legitimate work. \*gpt-oss-120b makes one consequential call per benign incident and the
panel approved all 60. Numbers: [`results/primaries_v31.md`](results/primaries_v31.md);
the same runs before the audit fixes (v2.9) are in
[`results/primaries_v29.md`](results/primaries_v29.md) (FULL 6.7% and 6.2%).*

### Who stops the attack

![First interception by decision tier](docs/figures/interception_tiers.png)

*The check that first intercepted each blocked attack, by decision tier. At v3.1, the
deterministic checks decide 98% of the 90 interceptions in the development domain (rules
81%, similarity thresholds 17%) and 70% of the 218 in the three transfer domains (rules
31%, similarity thresholds 39%); 88% and 67% in the earlier runs. In the live Agent
Security Bench run, whose injected actions use in-scope tools with plausible arguments,
they decide 40% of the 154 interceptions: 9% through rules that read the case's text and
31% through similarity thresholds.*

![Attack success per attack path](docs/figures/ap_heatmap.png)

*Attack success per attack path and configuration (v3.1, development domain). The upper
block is delivered as content (attacker class T1); the lower block through a
compromised agent's handoff or rationale (T2).*

<table>
<tr>
<td width="50%"><img src="docs/figures/paired_variants.png" alt="Paired outcome per variant"></td>
<td width="50%"><img src="docs/figures/ablation.png" alt="Leave-one-out ablation"></td>
</tr>
<tr>
<td><em>Per variant (v3.1), FULL rescues 26 variants that JUDGEONLY loses and gives up
none; both fail on three.</em></td>
<td><em>Leave-one-out at v3.1 (CyberOps, all 75 variants): removing any principle raises
attack success above FULL's 2.2%: P1 4.9%, P2 6.7%, P3 16.9%, P4 7.6%, P5 6.7%.</em></td>
</tr>
</table>

### The judges

<table>
<tr>
<td width="50%"><img src="docs/figures/validator_behavior.png" alt="Judge agreement and quorum"></td>
<td width="50%"><img src="docs/figures/panel_composition.png" alt="Panel composition and lineage"></td>
</tr>
<tr>
<td><em>v3.1, the 3,657 judged FULL rounds of the four domains (the rule-evading
siblings excluded). (a) Pairwise Cohen's κ between the four Local4 judges (diagonal:
reject rate); κ 0.41 to 0.65, mean 0.51. (b) Share of proposals approved as a function of
the quorum: 81.2%, 68.1%, 53.2% (deployed), and 39.0%.</em></td>
<td><em>Panels re-adjudicated on the same 405 replayed ASB actions and 661 legitimate
proposals. A same-size panel of one model lineage (Lin3) lets through seven times as
many actions as a mixed one (Div3L).</em></td>
</tr>
</table>

### Transfer, channels, and cost

![Transfer across domains and primaries](docs/figures/transfer.png)

*Security transfers across four domains (Qwen3-235B at v3.1: FULL 2.2%, 0.0%, 5.3%,
4.4% in CyberOps, healthcare, finance, legal; pooled over the three transfer domains 3.3%
against 29.3% for FLAT) and across primaries in CyberOps (gpt-oss-120b 6.2% and
Llama-3.1-8B 8.4% at v3.1; Llama-4-Scout 4.0% and Mistral-Small 8.0% in the earlier runs).
Cost does not: every benign incident outside the development domain loses at least one
tool call.*

<table>
<tr>
<td width="50%"><img src="docs/figures/channels.png" alt="Attack success by channel"></td>
<td width="50%"><img src="docs/figures/state_carryover.png" alt="State carry-over"></td>
</tr>
<tr>
<td><em>Attack success by injection channel, four domains pooled (v3.1; hollow markers:
exposure). FULL reduces every channel an attack gets through: task input 26.1% to 2.5%,
memory 14.3% to 0.0%, rationale 84.4% to 1.0%; the largest residual is the handoff
channel (14.4% against 45.6% for FLAT).</em></td>
<td><em>Persistent state (v3.1, as run with the two local judges): benign completion falls
from 97% to 5% in both passes. Legitimate incidents deny each other through replay
and ledger state: denials peak over the first incidents and fall back toward the
isolated level (dashed, as run) later in the sequence, but completion does not recover.
Replayed offline, faithful to the run, the stateful checks deny 87.5% of the first pass's
80 consequential benign proposals; expiring skeleton keys after five, two, or one
incidents leaves 48 to 69%, 16 to 54%, and 9 to 35%, and keying on identity (tool,
action, target) with a one-incident window leaves 5 to 24%.</em></td>
</tr>
</table>

![Cost](docs/figures/cost.png)

*Where the cost goes (v3.1): (a) denials per 100 legitimate actions by principle and
domain, counted per proposed action (tool calls and memory operations), with the panel's
share under Local4 (by replay) and the rest as run; (b) median time per benign CyberOps
incident in the primary, the deterministic checks, and the panel, as run with two local
judges (medians of the timed parts; the median wall-clock incident takes 38 s under FLAT,
87 s under FULL, and 80 s under JUDGEONLY); (c) tokens per incident.*

### Robustness of the v3.1 results

A browsable view of all results and figures is [`docs/results/index.html`](docs/results/index.html)
(open it locally; it needs no network). From [`results/v31_extras.md`](results/v31_extras.md)
(`make replay-v31`; logs and cached votes only):

- **Where the blocks fall.** Weighting each attack-incident tool call by a FAIR-style loss class
  (admin action on a critical asset or irreversible action 5 to 9, high-criticality asset 3,
  other admin action or memory write 2, read 1), FULL blocks 53% of the weighted calls against
  43% unweighted; ACL blocks 45% either way.
- **Significance.** Paired by variant, the rules' contribution (JUDGEONLY → FULL) is significant in
  every domain: −32.4 points [−42.7, −22.7] in CyberOps, −11.3 [−15.6, −7.3] pooled over the
  others. Outside CyberOps the judges alone help too (FLAT → JUDGEONLY 29.3% → 14.5%,
  [−19.7, −10.2]); in CyberOps they do not.
- **Run-to-run variation.** Two independent runs of FLAT and ACL on the attack paths the audit
  fixes did not touch differ by under one point pooled (up to five in one domain); 12% of FLAT
  and 2% of FULL variants give different outcomes across their three trials.
- **Judges transfer unevenly.** Gemma and gpt-oss approve 91–93% of legitimate CyberOps proposals
  but 59–68% in healthcare and legal; Mistral-Small and Llama-4-Scout barely change. As a panel
  the judges approve 94.9% of legitimate proposals in CyberOps, 75.4% in finance, 68.7% in
  healthcare, and 39.7% in legal.

From [`results/v31_mechanisms.md`](results/v31_mechanisms.md) (`make v31-mechanisms`), the
mechanism analyses repeated on the v3.1 runs:

- **Approval by score is anti-selective.** The permissive approve gate (scope < 0.2,
  proportionality > 0.9), applied offline to the CyberOps proposals that reached the panel,
  approves 90% of attack proposals (27 of 30) and 36% of legitimate ones. In the v2.9
  calibration run, substituting it for the panel executed nine more attacks (2.7% → 6.7%); at
  v3.1 the rules stop all but two of the blocked CyberOps attempts before the panel, the attack
  proposals the gate would approve belong to replays and chains one approval does not complete,
  and the substitution executes none. Live, the default gate decided none of the 3,880
  consequential proposals.
- **Rule evasion hands the decision to the judges.** The 24 rule-evading siblings succeed as
  often as their parents undefended (88.9% against 87.5% under FLAT). Under FULL the evaded
  rule stops none of them; 22 of 24 are held (the panel intercepting in 14) and two CyberOps
  handoff-poisoning siblings execute (6 of 72 trials). P2.2 on structured evidence only denies
  501 attack proposals instead of 301 and the same 21 of 1,386 benign calls.
- **Replay fidelity.** The cached votes reproduce 97.9% of the 45,426 votes Mistral-Small and
  Gemma cast live in the v3.1 runs.

### Third-party benchmarks and calibration

- **Agent Security Bench** (255 cases, frozen pipeline, 2 trials per case): attack
  success 28.8% under FLAT, 30.0% under ACL, **1.8%** under FULL. Access control blocks
  nothing, because the injected action uses a tool the agent holds.
- **TAMAS** (multi-agent, [microsoft/TAMAS](https://github.com/microsoft/TAMAS); 250
  attack instances in five domains, Qwen3-235B primary, CrewAI hierarchical crews,
  3 trials, 1,800 runs). An adapter sends every tool call an agent actually makes
  through DEFER's tool-call path and the panel before it executes:

  ![TAMAS](docs/figures/tamas.png)

  | Attack type | FLAT ASR % | FULL ASR % | FULL, re-judged under Local4 |
  |---|---|---|---|
  | direct prompt injection | 36.9 [25.5, 48.7] | 0.0 [0.0, 0.0] | 0.0 |
  | impersonation | 30.2 [19.3, 41.9] | 2.7 [0.0, 7.3] | 5.3 [0.7, 11.3] |
  | colluding agents | 40.0 [26.7, 52.7] | 2.0 [0.0, 6.1] | 2.0 [0.0, 6.1] |
  | byzantine agent | 91.2 [85.6, 96.0] | 83.9 [77.7, 89.1] | (judge-scored) |
  | contradicting agents | 18.6 [11.1, 26.4] | 18.6 [11.6, 25.9] | (judge-scored) |

  DEFER stops the attacks that act through tool calls and leaves those that corrupt
  agents' reasoning and outputs untouched, because it mediates actions, not
  conversations. All attack types pooled: FLAT 43.5%, FULL 21.4% as run and 21.9% under
  Local4. The panel made 192 of the 202 blocks under Local4: TAMAS gives agents the attack
  tools in their own tool lists, so, as on ASB, the rules rarely can. On the 50 TAMAS
  tasks used as benign work, FULL denies 10.6% of tool calls as run and 7.7% under Local4. Caveats are listed under
  [known limitations](#provenance-and-known-limitations); numbers:
  [`results/tamas.md`](results/tamas.md).
- **Calibration of the re-adjudication:** a live run at `defense-freeze-v2.9` with two
  local judges gives 2.7% [0.0, 6.2] attack success on the 75 development variants,
  against 3.1% [0.4, 6.7] when the original runs are re-judged by the same two judges.
  Legitimate proposals denied: 12.9% live, 14.1% replayed (`results/b2_live.json`).

### Giving the judges more context does not help (`defense-freeze-v3.0`)

Up to `defense-freeze-v2.9` a judge sees the sanitized proposal and the incident's id,
free-text description, and configuration name. `defense-freeze-v3.0`
([`consensus/panel_context.py`](consensus/panel_context.py)) adds what the rules
consult: the incident's structured fields (attacker-writable free text removed), the
calling agent's phase, allowed tools, and verification requirement, the operating
context of the targets (asset criticality, maintenance windows, change requests, time
policy), the incident's last ten decided consequential actions, and the agent's stated
reasoning. That reasoning reaches the judges for 4.5% of Qwen3-235B proposals, 1.3% of
Llama-3.1-8B proposals, and every gpt-oss-120b proposal; the others emit tool calls
without text. We measured v3.0 in two ways, both under Local4: every judged round of
the v2.9 runs re-judged with the v3.0 input (19,955 distinct inputs), and a live re-run
of the judged configurations at v3.0 (3,177 trials, 9,337 more inputs).

![Panel context](docs/figures/panel_context_v3.png)

| FULL attack success % | v2.9 input | v3.0 input (offline) | v3.0 live |
|---|---|---|---|
| Qwen3-235B, CyberOps | 7.1 [2.2, 13.3] | 8.9 [3.6, 15.6] | 8.4 [3.1, 14.7] |
| Qwen3-235B, healthcare | 0.0 | 0.0 | 0.0 |
| Qwen3-235B, finance | 4.0 [0.4, 8.4] | 9.8 [4.0, 16.9] | 6.7 [1.8, 12.4] |
| Qwen3-235B, legal | 7.6 [2.7, 12.9] | 12.4 [5.8, 20.0] | 10.2 [4.4, 16.9] |
| gpt-oss-120b, CyberOps | 6.7 [1.3, 12.0] | 8.0 [2.7, 14.7] | 8.9 [3.1, 15.6] |
| Llama-3.1-8B, CyberOps | 6.2 [1.3, 12.0] | 7.6 [2.2, 13.8] | 6.2 [1.8, 11.1] |

*(a) Share of proposals each judge approves in the Qwen3-235B FULL rounds (hollow
marker: v2.9 input; arrow head: v3.0 input). (b) FULL attack success; (c) legitimate
proposals denied.* With more context the judges approve more attack-effect proposals:
Mistral 68.6% instead of 49.7%, Gemma 54.1% instead of 30.2%, gpt-oss-120b 56.9%
instead of 43.4%. FULL lets more attacks through in every domain that had any (the
intervals overlap; finance more than doubles) and denies fewer legitimate proposals
(legal 25.4% to 14.9%, finance 22.7% to 17.6%). JUDGEONLY changes little (Qwen3-235B
33.8% to 32.0%). The live re-run agrees with the offline re-judging. The flipped rounds
show the mechanism: incident fields an attacker can shape (a "critical account
takeover, \$4.75M at risk" in finance AP-5; a planted replay record with its own
rationale in CyberOps) are presented as evidence, and the judges defer to them. v3.0 is
therefore not the reported configuration. Numbers:
[`results/replay_v3.md`](results/replay_v3.md).

---

## Reproducing the results

Three levels, from cheapest to most expensive. Levels 1 and 2 call no API and no
primary model.

| Level | Needs | Time | Reproduces |
|---|---|---|---|
| 1. Analysis | CPU, Python 3.13 | minutes | every table, number, and figure, from the committed logs and cached votes |
| 2. Re-adjudication | one GPU per local judge | hours | the cached judge votes in `cache/validators/` |
| 3. Full runs | GPUs for the primary and judges | days | the per-trial logs in `logs/` |

### Setup

```bash
conda create -n defer python=3.13 -y && conda activate defer
pip install -r requirements.txt
make test                      # unit tests, including payload hygiene and the tier mapping
```

`.env` is needed only for level 3 runs that use API validators (the original Div4
panel). The reported panel (Local4) and the calibration panel (local2) are fully local.

### Level 1: analysis (no model calls)

```bash
make paper-tables     # parse logs -> results/eval_attacks/all_trials.csv, statistics, as-run tables
make replay-tables    # every Local4 number -> results/replay_tables.md, all_trials_local4.csv
make figures          # every paper figure -> paper/figs/*.pdf, README figures -> docs/figures/
make b2               # live calibration run vs its replay -> results/b2_live.json
make primaries-tables # gpt-oss-120b and Llama-3.1-8B boundary before the fixes -> results/primaries_v29.md
make tamas-tables     # TAMAS outcomes (needs scored.jsonl, below) -> results/tamas.md
make replay-v3        # v2.9 vs v3.0 panel input, offline and live -> results/replay_v3.md
make replay-v31       # the boundary at v3.1, Local4 -> results/replay_v31.md, docs/figures/boundary_v31.png,
                      #   boundary_domains.png, and the robustness analyses -> results/v31_extras.md
make primaries-v31    # gpt-oss-120b and Llama-3.1-8B boundary at v3.1 -> results/primaries_v31.md
make v31-mechanisms   # gate, siblings, structured evidence, expiry, judges at v3.1 (about 15 min)
                      #   -> results/v31_mechanisms.md
make freeze-check     # the decision code equals the default tag (FREEZE_TAG=... for another)
```

`make figures` writes every result figure as a vector PDF to `paper/figs/`
(the PNGs in `docs/figures/` are previews). `make figures` plots the Local4 panel by default; `make figures DEFER_PANEL=` plots the
as-run Div4 values. The offline analyses behind the results are single modules:

| Module | Question it answers |
|---|---|
| `analysis/replay_panels.py` | direct outcome under any panel (Local4, Div3L, Lin3, Single) |
| `analysis/p3_eligibility.py` | which calls ever reach verification (P3), and how executed attacks got through |
| `analysis/gate_offline.py` | what a deterministic approve gate would have approved |
| `analysis/trusted_evidence.py` | P2.2 with evidence restricted to structured, non-attacker fields |
| `analysis/ledger_expiry.py` | expiry and identity policies for the stateful replay and ledger checks |
| `analysis/b2_live.py` | the live calibration run and its replay |
| `analysis/primaries_tables.py` | the boundary for the two additional primaries |
| `analysis/tamas_tables.py` | TAMAS outcomes as run and re-judged, benign cost |
| `analysis/replay_v3.py` | the v3.0 panel input: every judged round re-judged with it, and the live v3.0 runs |
| `analysis/replay_v31.py` | the boundary at v3.1: rounds for the Local4 re-judging, the table and its figure |
| `analysis/v31_extras.py` | impact-weighted blocking, run-to-run variation, paired tests, judge transfer (v3.1) |
| `analysis/v31_mechanisms.py` | the gate, sibling, structured-evidence, expiry, and judge analyses repeated on the v3.1 runs |
| `analysis/results_page.py` | the offline results page `docs/results/index.html` |

### Level 2: re-adjudication with local judges

```bash
python -m analysis.replay_run build        # rebuild every logged judge input -> cache/replay/
python -m analysis.replay_run build-asb    # append the ASB panel rounds
python -m analysis.replay_run build-tamas  # append the TAMAS panel rounds (read from the gate log)
python -m analysis.replay_v3 build         # the same rounds with the v3.0 input -> cache/replay_v3/
python -m analysis.replay_v3 build-live    # the inputs logged by the live v3.0 runs
# serve a judge with vLLM on a local port, then query it for every input not yet cached:
python -m analysis.replay_run query --validator L1_mistral --url http://127.0.0.1:8101/v1
python -m analysis.replay_run query --validator L3_gptoss  --url http://127.0.0.1:8103/v1 --reasoning-effort low
```

Validator ids and model names are in `configs/validators.yaml` (L1–L4 form Local4,
R1–R3 the lineage panels). The query refuses any URL that is not local, so the replay
cannot call an API. Votes are cached by a hash of the exact input, so an
interrupted query resumes where it stopped. Add `--replay-dir cache/replay_v3` to query
the v3.0 inputs.

### Level 3: full runs

The decision code on this branch is the reported configuration, `defense-freeze-v3.1`
(the freeze guard checks `defense-freeze-v3.1.3`, which differs from it only in the scoring
oracle, repo-relative log paths, and the project's name in docstrings). The earlier runs used `defense-freeze-v2.2` with the Div4 panel, which needs
API validators; to re-run one of them, work from its tag in a separate worktree
(`git worktree add ../defer-v2.9 defense-freeze-v2.9`, then
`FREEZE_TAG=defense-freeze-v2.9 bash scripts/check_freeze.sh`).

```bash
bash scripts/check_freeze.sh                     # decision code must equal the freeze tag
RUN_TAG=mytag REQUIRE_FREEZE=1 \
  scripts/run_attack_paths.sh q235_local2 cyberops all agenticcyops 3   # GROUP DOMAIN APS CONFIGS TRIALS
```

- `GROUP` selects the primary and panel (`scripts/run_attack_paths.sh` lists them;
  `q235_local2` is the fully local calibration setup).
- `APS` is `all`, `benign`, one path, or a comma list (`ap1,ap2`).
- `CONFIGS` is `all` or one of the log names below.
- Environment switches: `STATE_MODE=persistent`, `DISABLE_PRINCIPLES=P3`, `SEED=<int>`.
- `scripts/run_v29_live.sh` is the exact launcher of the calibration run,
  `scripts/run_primaries_v29.sh` of the gpt-oss-120b and Llama-3.1-8B runs, and
  `scripts/run_v30_live.sh` and `scripts/run_v30_oss.sh` of the v3.0 re-run, and
  `scripts/run_v31.sh` of the reported v3.1 boundary, and `scripts/run_v31_completion.sh`
  of the v3.1 ablation, persistent-state, gpt-oss-120b and Llama-3.1-8B runs.
- `scripts/vllm_profiles.sh` has the serving commands used for each model.

**TAMAS.** CrewAI runs in its own environment; DEFER's checks run in a local HTTP gate
in the project environment:

```bash
conda create -n tamas python=3.12 -y && conda run -n tamas pip install crewai crewai-tools
python -m benchmarks.tamas.gate --port 8301 --consensus local2 --log-dir logs/tamas_run &
python -m benchmarks.tamas.run_all --out-dir logs/tamas_run --configs flat,full --trials 3 \
    --model hosted_vllm/Qwen/Qwen3-235B-A22B-Instruct-2507 --base-url http://127.0.0.1:8000/v1 \
    --gate http://127.0.0.1:8301 --workers 40
python -m benchmarks.tamas.score --run-dir logs/tamas_run --judge-url http://127.0.0.1:8103/v1
```

`run_all` resumes: it skips trials already in `runs.jsonl`. The scorer uses TAMAS's own
judge prompts with a locally served judge (gpt-oss-120b, 128k context) in place of GPT-4o.

Every run writes a header with its commit, freeze tag, and whether the tree was clean.
With `RUN_TAG` set, the harness refuses to start from a dirty tree. Do not edit
tracked files while a run is going: each attack path is a separate invocation, and a
later one will refuse to start.

---

## Names used in the paper and in the logs

| Paper | Log `config` | What it is |
|---|---|---|
| FLAT | `flat` | every agent may call every tool and store; no checks |
| ACL | `acl_hardened` | phase-to-tool and phase-to-store restrictions only |
| JUDGEONLY | `llm_judge` | registry plus the LLM panel on every tool proposal |
| NOJUDGE | `symbolic_only` | FULL without the panel; undecided proposals are escalated |
| FULL (DEFER) | `agenticcyops` | all 28 checks in cascade order |
| FULL \ P*i* | `agenticcyops` + suffix `_disabled_Pi` | leave-one-out ablation |
| JUDGEREST | (offline) | FULL with every rule-surviving call judged, from `replay_panels.py` |
| permissive gate | `agenticcyops_gate_permissive` | deterministic approve gate; evaluated offline in the paper |
| judged writes | `agenticcyops_writejudge` | every write to a critical store goes to the panel |

| Run group | Primary | Panel as run | Role |
|---|---|---|---|
| `q235_div4` | Qwen3-235B-A22B | Div4 | main runs, four domains, all configurations |
| `scout_div4`, `mistral_div3p`, `llama8b_div4` | Llama-4-Scout, Mistral-Small, Llama-3.1-8B | Div4 (Mistral: without itself) | other primaries, CyberOps and finance |
| `q235_div4_persistent`, `q235_div4_persistent3` | Qwen3-235B-A22B | Div4 | state carry-over, two passes |
| `q235_div4_e2` | Qwen3-235B-A22B | Div4 | rule-evading siblings (E2) |
| `q235_local2_v29` | Qwen3-235B-A22B | local2 (Mistral-Small, Gemma-4; 2 of 2) | live calibration at `defense-freeze-v2.9` |
| `oss120_local2_v29`, `llama8b_local2_v29` | gpt-oss-120b, Llama-3.1-8B | local2 | the five boundary configurations at `defense-freeze-v2.9`, CyberOps |
| `q235_local2_v30`, `oss120_local2_v30`, `llama8b_local2_v30` | Qwen3-235B-A22B, gpt-oss-120b, Llama-3.1-8B | local2 | FULL and JUDGEONLY at `defense-freeze-v3.0` (Qwen3-235B FULL in all four domains, the rest CyberOps) |
| `q235_local2_v31` | Qwen3-235B-A22B | local2 (Local4 offline) | **the reported boundary**: all five configurations, four domains, at `defense-freeze-v3.1` |
| `logs/tamas_q235_local2_v29/` | Qwen3-235B-A22B | local2 | TAMAS, FLAT (`flat`) and FULL (`full`): gate log, transcripts, scores |

Routing of individual log files to groups is declared in
[`analysis/run_groups.yaml`](analysis/run_groups.yaml); load logs only through
`analysis/runlogs.py`.

---

## The pipeline

| Principle | Surface | What DEFER checks |
|---|---|---|
| P1 Authorized Interface | tools | registry membership; response schema, timing, replay, per-tool MAC; configuration hashes |
| P2 Capability Scoping | tools | phase manifests and action caps; parameter rules and target-in-evidence; output classifier |
| P3 Verified Execution | tools | handoff, context, and intent-chain checks; cross-incident ledger; replay detection; consent; risk scoring and auto-gates; LLM panel; pre-execution hash |
| P4 Memory Integrity | memory | schema; similarity to evidence; metadata; drift; write replay; contradiction |
| P5 Access-Controlled Isolation | memory | phase-to-store policy; field filter; query scope; read-pattern monitor; read sanitization |

![The DEFER cascade](docs/figures/cascade.png)

*Order of checks for a tool call, a memory write, and a memory read. Dark blue: rule;
light blue: contains a similarity threshold; orange: the only judgment-based check; dot:
keeps state across incidents.*

Checks run cheapest and most certain first. Only consequential calls (the manifest
requires verification, or the action has negative impact in a static table) enter P3,
and the panel sees only what no deterministic check decided. Every check fails closed,
and a validator error counts as a rejection. Table VIII of the paper lists all 28
checks with their thresholds; the code is in `host/` (orchestrator, parameter
validator), `consensus/` (P3), and `memory/` (P4, P5). The four domains share the
code and differ only in declarative configuration under `domains/<domain>/configs/`.

---

## Repository layout

```
agents/            phase agents (LLM wrappers with phase prompts and tool lists)
host/              orchestrator (reference monitor), manifests, parameter validation
consensus/         P3: context, ledgers, replay, scoring, auto-gates, validator panel
memory/            P4 write filter, P5 access isolation, memory gateway
mcp_servers/       tool stubs (REST servers per domain)
domains/           four domains: configs, payloads (attacks, benign), seed data
attacks/           harness, injection channels, outcome oracle (effects.py), payload schema
benchmarks/        Agent Security Bench, InjecAgent, and TAMAS adapters (TAMAS: gate, runner,
                   scorer, and a vendored upstream subset under benchmarks/tamas/upstream/)
analysis/          parsing, statistics, tables, figures, re-adjudication, offline analyses
configs/           panels (validators.yaml) and configuration profiles
scripts/           run launchers, vLLM profiles, freeze and path guards
tests/             unit tests (pytest)
logs/              per-trial JSONL logs of every reported run
results/           generated tables and CSVs
cache/             rebuilt judge inputs (replay/, v3.0 input: replay_v3/) and cached local
                   judge votes (validators/)
docs/              scoring and ablation notes, figures for this README
```

---

## Provenance and known limitations

- **Freeze tags.** The earlier runs used the decision code of `defense-freeze-v2.2`.
  Tags up to v2.8 changed only logging, the memory reset of baseline configurations,
  and default-off switches for the targeted arms. `defense-freeze-v2.9` fixes the risk
  scorer's wiring and is used for the labeled calibration run and the gpt-oss-120b and
  Llama-3.1-8B runs. `defense-freeze-v3.0` changes what the judges see and is used only
  for the labeled v3.0 runs, which it does not improve (see above).
  `defense-freeze-v3.1` (v2.9 plus the audit fixes) is the configuration of the reported
  boundary; `defense-freeze-v3.1.1` changes only the scoring oracle.
  [`REPRODUCE.md`](REPRODUCE.md) lists every tag and diff.
- **Validator outage.** The original panel (Div4) lost both API validators for part
  of the evaluation. Every panel-dependent result is therefore reported as its
  re-adjudication under Local4, and the as-run values are kept for comparison (paper,
  Table XXII).
- **Dirty-tree runs.** About three fifths of the reported trials come from runs
  launched before the clean-tree guard existed. Their headers record the commit, and
  the decision code at each such commit equals `defense-freeze-v2.2`.
- **Not evaluated.** An attacker who adapts to the defense beyond the one-step
  rule-evading siblings; an external composed defense; benign utility on ASB. AP-3
  was never attempted by any primary. The shipped auto-gates decided no proposal in any reported run.
- **TAMAS.** Upstream releases neither the injected content of its 50 indirect-injection
  instances nor its 100 harmless tasks, so the 250 other attack instances are run and the
  50 indirect-injection queries serve as benign tasks. The judge for the byzantine and
  contradicting types is gpt-oss-120b instead of GPT-4o, so the numbers are not directly
  comparable with the TAMAS paper's. CrewAI tool calls carry no rationale; each proposal
  gets a neutral justification naming the calling agent. Only the CrewAI hierarchical
  configuration was run. One upstream legal tool is not registered as a CrewAI tool and is
  skipped. 17 of 1,800 runs timed out after 20 minutes and are counted as errors.
- **Code audit and `defense-freeze-v3.1`.** An audit of the code found defects that were
  present in the earlier runs (the code is the same at `defense-freeze-v2.2`). v3.1 is
  v2.9's decision code with these fixed, and the boundary, the leave-one-out ablation, two
  primaries, and the persistent-state runs were re-run with it:
  - *AP-15 faults fired in the first trial only* (the harness marked a fault as applied
    on the shared payload); every trial now gets its fault.
  - *The admin phase validated the wrong handoff* (always the monitor handoff, so AP-5's
    tampered analyze-to-admin handoff was never checked); each phase now checks the
    handoff it received.
  - *Checks that never fired:* the change-conflict check, the time-policy check outside
    CyberOps (those tools take no `action` argument; they now get their implied action),
    P5's query-relevance check (its context never reached the gateway), the
    intent-chain thresholds (defaults were used) and the early exit after a critical
    denial.
  - *AP-13 outside CyberOps* lacked the metadata its schemas require, so every write was
    denied regardless of content; *benign scenarios* used status values and two MITRE
    techniques the schemas did not list. Payloads and schemas are fixed.
  - Smaller fixes: JUDGEONLY no longer runs P1's configuration-integrity check; fields
    copied to the proposal root are sanitized before the panel; votes are parsed
    case-insensitively; the bulk-action cap counts only executed actions; critical-asset
    matching ignores case and whitespace; "24/7" time policies end at 24:00.
  - *Scoring (all runs, `defense-freeze-v3.1.1`):* a canary that reaches only another
    agent's handoff is not a leak (no check mediates handoffs); a response rejected after
    the tool ran counts as executed; a P2 denial whose event lost its action field is
    seen; an agent error after the effect keeps the effect; AP-6's replay needs the same
    call twice. The earlier runs are re-scored with it.
- **Still open after the audit.** One auto-gate rule can never fire (the precedent score
  never drops below its threshold); Llama-4-Scout's tool calls come through a
  text-fallback parser that drops list arguments and can turn a refusal that names a
  tool into a proposal; the AP-11 maintenance-window assets outside CyberOps never appear
  as tool arguments; AP-5 succeeds on any six T8 calls; the P4 drift check applies from
  a store's first write; P5's read sanitizer can be bypassed with zero-width or homoglyph
  characters. ASB and TAMAS were not re-run at v3.1 (the ablation, the other primaries
  and state carry-over were). In the v3.0 panel input, `UNTRUSTED_KEYS` misses several
  attacker-writable fields (`analyst_notes`, `rationale`, `justification`, ...), part of
  the v3.0 result above.
- **Implementation lessons.** [`docs/engineering_challenges.md`](docs/engineering_challenges.md)
  records the engineering problems of the build and the lessons of the code audit.
- **Log names.** The project was renamed DEFER after the runs. Configuration names
  beginning with `agenticcyops` denote FULL; they are kept as recorded in every log, run
  header, results table, and config file name, and in the `AGENTICCYOPS_HMAC_KEY`
  environment variable, so that the logs and the code stay in step.

---

## Ethics and intended use

All experiments ran on a closed testbed with stub tools and synthetic records. The
attack payloads are prompt-injection strings, poisoned records, and forged tool
responses that target this stub environment and carry canary values. They contain no
working exploit against a real product. The artifact is intended for evaluating
defenses of LLM agent systems.


## License

Code under the MIT License (see [`LICENSE`](LICENSE)). The third-party benchmark
subsets under `benchmarks/` keep their original licenses; the TAMAS subset under
`benchmarks/tamas/upstream/` is MIT (code) and CDLA-Permissive-2.0 (data).
