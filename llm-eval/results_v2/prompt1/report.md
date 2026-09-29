## Juliet (labels independent of every model): 117 findings, 50 real, 67 false positives

| model | answered | real bugs kept | false positives dismissed | balanced accuracy | uncertain | no valid answer | median time | total time | median output tokens | API-equivalent cost |
|---|---|---|---|---|---|---|---|---|---|---|
| nb-floor | 117/117 | 64.0% | 67.2% | 65.6% | 0.0% | 0.0% | n/a | n/a | n/a | local |
| qwen3.5-9b-nothink | 117/117 | 42.0% | 82.1% | 62.0% | 0.0% | 0.0% | 3s | 7 min | 109 | local |
| gemma-4-12b-nothink | 117/117 | 86.0% | 43.3% | 64.6% | 0.0% | 0.0% | 4s | 8 min | 102 | local |
| gemma-4-e4b-nothink | 117/117 | 80.0% | 34.3% | 57.2% | 9.4% | 0.0% | 2s | 4 min | 101 | local |
| claude | 117/117 | 84.0% | 100.0% | 92.0% | 0.0% | 0.0% | 7s | 14 min | 246 | $5.59 |

## As a filter: 117 findings, 50 real, 67 false positives

| model | real bugs auto-dismissed (95% CI) | false positives auto-dismissed (95% CI) | sent to a human |
|---|---|---|---|
| nb-floor | 18/50 (24-50%) | 45/67 (55-77%) | 46.2% |
| qwen3.5-9b-nothink | 29/50 (44-71%) | 55/67 (71-89%) | 28.2% |
| gemma-4-12b-nothink | 7/50 (7-26%) | 29/67 (32-55%) | 69.2% |
| gemma-4-e4b-nothink | 6/50 (6-24%) | 23/67 (24-46%) | 75.2% |
| claude | 8/50 (8-29%) | 67/67 (95-100%) | 35.9% |

## False positives dismissed, by kind

`fp_paired`: the same sink as a real bug, made safe by its source or a check. `fp_other`: other in-family lines in safe code. `fp_offtarget`: a rule unrelated to the test case's weakness.

| model | fp_offtarget (n=20) | fp_other (n=12) | fp_paired (n=35) |
|---|---|---|---|
| nb-floor | 95.0% | 58.3% | 54.3% |
| qwen3.5-9b-nothink | 75.0% | 91.7% | 82.9% |
| gemma-4-12b-nothink | 50.0% | 58.3% | 34.3% |
| gemma-4-e4b-nothink | 45.0% | 66.7% | 17.1% |
| claude | 100.0% | 100.0% | 100.0% |

## Auto-dismiss only above a confidence threshold

Real bugs lost / false positives removed, when an FP verdict removes a finding only if its confidence is at least the threshold. Picked on the test set itself, so optimistic.

| model | >= 0.0 | >= 0.8 | >= 0.9 | >= 0.95 |
|---|---|---|---|---|
| nb-floor | 18 / 45 | 18 / 42 | 18 / 41 | 18 / 39 |
| qwen3.5-9b-nothink | 29 / 55 | 29 / 55 | 29 / 55 | 29 / 55 |
| gemma-4-12b-nothink | 7 / 29 | 7 / 29 | 7 / 29 | 7 / 29 |
| gemma-4-e4b-nothink | 6 / 23 | 6 / 23 | 6 / 23 | 5 / 9 |
| claude | 8 / 67 | 8 / 67 | 5 / 58 | 1 / 27 |

