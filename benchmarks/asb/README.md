# Agent Security Bench (ASB) Benchmark Integration

**Fourth third-party adversarial benchmark for the DEFER
P1-P5 stack.**  Joins TAMAS (Eval D), DEFER in-house attack
paths (Eval A), and InjecAgent (Eval G) as an independent
adversarial evaluation.

Source:
[agiresearch/ASB](https://github.com/agiresearch/ASB) — ICLR 2025 —
[arXiv 2410.02644](https://arxiv.org/abs/2410.02644).  MIT-licensed,
used unmodified, vendored under [data/](data/).

## Status

| Phase | Scope | Status |
|---|---|---|
| 1 | Scaffold + `domains/general/` neutral domain | done |
| 2 | Upstream ingest + per-case JSON conversion | scripts in place; data ingest pending |
| 3 | Symbolic static sweep through P1-P5 | runner ready (`run_static.py`); awaits Phase 2 |
| 4 | Analytics (PDF + CSV) | will reuse `analysis/injecagent_analytics.py` pattern |

Adaptive (white-box) and live-LLM modes are intentionally out of
scope, mirroring the InjecAgent treatment.

## What ASB tests

ASB covers four attack families across **10 scenarios** (e-commerce,
autonomous driving, finance, academic advising, counseling, legal
advice, …) and **400+ tools**.

| Attack family | What it tests | Maps to our defense |
|---|---|---|
| **DPI** Direct Prompt Injection | Adversarial input in the *user query* | P3-L6 consensus, P2-L3 output classifier |
| **IPI** Indirect Prompt Injection | Adversarial content in *tool observations* (overlaps InjecAgent) | P5-L5 sanitisation, P2-L2 target-in-evidence, P3-L6 |
| **MP** Memory Poisoning | Adversarial writes to the agent's memory | P4 memory integrity (similarity / drift / contradiction / replay) |
| **PoT** Plan-of-Thought Backdoor | Trigger-time emission of a malicious tool call by a backdoored agent | P1-L1 identity, P3-L7 execution verification, P3-L6 consensus |

## Threat model alignment

Our middleware does **not** defend against training-time agent
compromise.  We measure whether the *runtime malicious actions* a
backdoored agent emits get caught at the action layer — the same
evaluation we apply to DPI / IPI.  Paper text needs this disclaimer
explicitly.

## Domain framing

ASB scenarios (e-commerce, autonomous driving, …) don't map cleanly
to our four enterprise domains (cyberops, healthcare, finance,
legal).  Forcing them in would either be artificial or require
building eight new domain-config trees from scratch.

Instead we run all ASB scenarios through a single
[**`general` neutral domain**](../../domains/general/) — minimal but
valid configs that exercise the *domain-invariant* defense layers:

| Defense layer | Active under `general` domain? |
|---|---:|
| P1-L1 component identity | ✓ (registry-based, domain-invariant) |
| P2-L1 wildcard / criticality / parameter rules | ⚠ wildcards yes, rules empty |
| P2-L2 target-in-evidence (cosine) | ✓ |
| P2-L3 output classifier | ⚠ generic PII patterns only |
| P3-L0.5 operational context | ✗ (no incidents, no maintenance windows) |
| P3-L6 LLM consensus | ✓ |
| P4 memory integrity | ✓ (similarity / drift / replay / contradiction) |
| P5 access isolation | ⚠ generic ACL only |

Paper claim: **lower-bound on full-stack performance.**

## Run flow

```bash
# 1.  Vendored upstream (one-time)
./benchmarks/asb/scripts/ingest_upstream.sh

# 2.  Convert YAML matrices -> per-case JSON
python -m benchmarks.asb.scripts.convert_cases

# 3.  Symbolic sweep (no live LLM)
python -m benchmarks.asb.run_static
# or just one attack family:
python -m benchmarks.asb.run_static --attacks DPI

# 4.  Analytics (when available)
python -m analysis.asb_analytics
```

## Layout

```
benchmarks/asb/
├── data/
│   ├── upstream/                 # mirror of agiresearch/ASB at a pinned commit
│   ├── cases/{dpi,ipi,mp,pot}.json   # converted per-case JSON (Phase 2)
│   ├── tools.json                # canonical ASB_* tool catalogue
│   ├── ATTRIBUTION.md
│   └── LICENSE_ASB               # copied from upstream LICENSE
├── harness/
│   └── tool_loader.py            # ASB_* in-memory registry (mirror of IA_*)
├── scripts/
│   ├── ingest_upstream.sh
│   └── convert_cases.py
├── run_static.py                 # symbolic-only sweep (no LLM)
└── README.md                     # this file
```

## Tool isolation guarantee

Identical to InjecAgent's pattern:

- Tools are namespaced with **`ASB_<scenario>_<tool>`** prefix in an
  in-memory registry only — never written to
  `configs/component_registry.json` or any domain's `configs/` tree.
- Cannot collide with native domain tools (`T*`, `H*`, `F*`, `L*`)
  or InjecAgent's `IA_*` tools.
- Stub implementations only; tool calls produce fabricated responses
  matching the upstream observation templates.

## Paper framing

- Report as **"ASB-static ASR on DEFER (general domain)"**
  with the explicit disclaimer that domain-tuned layers
  (P3-L0.5, P5 sensitive patterns) aren't exercised.
- The upstream paper's headline 84.30% ASR is the *attacker
  ceiling* against vanilla agents — report it as comparison context,
  not as a like-for-like number against our middleware.
- We do not reproduce ASB's 11 in-paper defenses; our value-add is
  measuring the DEFER middleware specifically.
- PoT backdoor framing: "we measure post-deployment runtime defense
  against backdoor-triggered actions; we do not detect the
  training-time compromise itself."
