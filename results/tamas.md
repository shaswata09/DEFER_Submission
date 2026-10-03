# TAMAS (Qwen3-235B primary, CrewAI hierarchical, DEFER tool-call mediation)

ASR as run with the live local2 panel; for FULL's tool-based types also re-adjudicated under Local4.

| Attack type | FLAT ASR % | FULL ASR % (as run) | FULL ASR % (Local4) |
|---|---|---|---|
| DPI | 36.9 [25.5, 48.7] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| impersonation | 30.2 [19.3, 41.9] | 2.7 [0.0, 7.3] | 5.3 [0.7, 11.3] |
| colluding | 40.0 [26.7, 52.7] | 2.0 [0.0, 6.1] | 2.0 [0.0, 6.1] |
| byzantine | 91.2 [85.6, 96.0] | 83.9 [77.7, 89.1] | as run |
| contradicting | 18.6 [11.1, 26.4] | 18.6 [11.6, 25.9] | as run |

All attack types: FLAT 43.5 [37.9, 49.0], FULL 21.4 [17.0, 26.1] as run, 21.9 [17.3, 26.4] with the tool-based types under Local4.

Blocked tool-based attempts under Local4, by first interceptor: {'rules': 10, 'panel': 192}.

Benign (IPI tasks): FULL denies 10.6% of tool calls as run, 7.7% under Local4; FLAT 0.0%.