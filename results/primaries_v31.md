# Judgment boundary for gpt-oss-120b and Llama-3.1-8B (live at v3.1, CyberOps)

JUDGEONLY and FULL: direct outcome under Local4 (live local2 value in `live_local2`).

## gpt-oss-120b

| Config | ASR % [95% CI] | Attempt % | Block|att. % | Judged % | Benign denied % |
|---|---|---|---|---|---|
| FLAT | 21.3 [12.4, 31.1] | 21.3 | 0.0 | 0 | 0.0 |
| ACL | 18.7 [10.7, 28.0] | 20.0 | 6.7 | 0 | 0.0 |
| JUDGEONLY | 21.3 [12.9, 30.7] | 22.7 | 5.9 | 100.0 | 0.0 |
| NOJUDGE | 1.3 [0.0, 4.0] | 19.1 | 93.0 | 0 | 33.3 |
| FULL | 6.2 [1.3, 12.0] | 19.1 | 67.4 | 9.1 | 0.0 |

## Llama-3.1-8B

| Config | ASR % [95% CI] | Attempt % | Block|att. % | Judged % | Benign denied % |
|---|---|---|---|---|---|
| FLAT | 34.7 [24.4, 45.3] | 34.7 | 0.0 | 0 | 0.0 |
| ACL | 33.8 [23.6, 44.0] | 35.1 | 3.8 | 0 | 2.6 |
| JUDGEONLY | 27.6 [18.2, 36.9] | 39.6 | 30.3 | 99.4 | 8.5 |
| NOJUDGE | 1.3 [0.0, 4.0] | 43.6 | 96.9 | 0 | 67.1 |
| FULL | 8.4 [3.1, 14.7] | 40.9 | 79.3 | 45.0 | 14.6 |
