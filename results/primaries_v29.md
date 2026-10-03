# Judgment boundary for gpt-oss-120b and Llama-3.1-8B (live at v2.9, CyberOps)

JUDGEONLY and FULL: direct outcome under Local4 (live local2 value in `live_local2`).

## gpt-oss-120b

| Config | ASR % [95% CI] | Attempt % | Block|att. % | Judged % | Benign denied % |
|---|---|---|---|---|---|
| FLAT | 21.8 [13.3, 31.1] | 21.8 | 0.0 | 0 | 0.0 |
| ACL | 17.8 [9.8, 27.1] | 19.1 | 7.0 | 0 | 0.0 |
| JUDGEONLY | 22.7 [13.8, 32.0] | 24.4 | 7.3 | 100.0 | 0.0 |
| NOJUDGE | 1.3 [0.0, 4.0] | 19.1 | 93.0 | 0 | 33.3 |
| FULL | 6.7 [1.3, 12.0] | 18.7 | 64.3 | 24.6 | 0.0 |

## Llama-3.1-8B

| Config | ASR % [95% CI] | Attempt % | Block|att. % | Judged % | Benign denied % |
|---|---|---|---|---|---|
| FLAT | 33.3 [23.6, 43.6] | 33.3 | 0.0 | 0 | 0.0 |
| ACL | 32.0 [22.2, 42.2] | 33.3 | 4.0 | 0 | 1.1 |
| JUDGEONLY | 27.6 [18.2, 37.3] | 39.6 | 30.3 | 100.0 | 6.6 |
| NOJUDGE | 1.3 [0.0, 4.0] | 44.4 | 97.0 | 0 | 65.5 |
| FULL | 6.2 [1.3, 12.0] | 40.0 | 84.4 | 40.5 | 12.4 |
