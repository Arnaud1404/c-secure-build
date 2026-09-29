## Juliet (labels independent of every model): 117 findings, 50 real, 67 false positives

| model | answered | real bugs kept | false positives dismissed | balanced accuracy | uncertain | no valid answer | median time | total time | median output tokens | API-equivalent cost |
|---|---|---|---|---|---|---|---|---|---|---|
| nb-floor | 117/117 | 64.0% | 67.2% | 65.6% | 0.0% | 0.0% | n/a | n/a | n/a | local |
| qwen3.5-9b-nothink | 117/117 | 88.0% | 53.7% | 70.9% | 0.0% | 0.0% | 3s | 6 min | 83 | local |
| gemma-4-12b-nothink | 117/117 | 82.0% | 76.1% | 79.1% | 0.9% | 0.0% | 6s | 21 min | 92 | local |
| gemma-4-e4b-nothink | 117/117 | 96.0% | 35.8% | 65.9% | 2.6% | 0.0% | 2s | 5 min | 96 | local |
| gemma-4-e4b | 117/117 | 88.0% | 82.1% | 85.0% | 0.0% | 0.0% | 19s | 42 min | 841 | local |
| claude | 117/117 | 98.0% | 98.5% | 98.3% | 0.0% | 0.0% | 7s | 13 min | 231 | $5.20 |

## As a filter: 117 findings, 50 real, 67 false positives

| model | real bugs auto-dismissed (95% CI) | false positives auto-dismissed (95% CI) | sent to a human |
|---|---|---|---|
| nb-floor | 18/50 (24-50%) | 45/67 (55-77%) | 46.2% |
| qwen3.5-9b-nothink | 6/50 (6-24%) | 36/67 (42-65%) | 64.1% |
| gemma-4-12b-nothink | 8/50 (8-29%) | 51/67 (65-85%) | 49.6% |
| gemma-4-e4b-nothink | 2/50 (1-13%) | 24/67 (25-48%) | 77.8% |
| gemma-4-e4b | 6/50 (6-24%) | 55/67 (71-89%) | 47.9% |
| claude | 1/50 (0-10%) | 66/67 (92-100%) | 42.7% |

## False positives dismissed, by kind

`fp_paired`: the same sink as a real bug, made safe by its source or a check. `fp_other`: other in-family lines in safe code. `fp_offtarget`: a rule unrelated to the test case's weakness.

| model | fp_offtarget (n=20) | fp_other (n=12) | fp_paired (n=35) |
|---|---|---|---|
| nb-floor | 95.0% | 58.3% | 54.3% |
| qwen3.5-9b-nothink | 75.0% | 50.0% | 42.9% |
| gemma-4-12b-nothink | 80.0% | 100.0% | 65.7% |
| gemma-4-e4b-nothink | 60.0% | 25.0% | 25.7% |
| gemma-4-e4b | 80.0% | 91.7% | 80.0% |
| claude | 95.0% | 100.0% | 100.0% |

## Auto-dismiss only above a confidence threshold

Real bugs lost / false positives removed, when an FP verdict removes a finding only if its confidence is at least the threshold. Picked on the test set itself, so optimistic.

| model | >= 0.0 | >= 0.8 | >= 0.9 | >= 0.95 |
|---|---|---|---|---|
| nb-floor | 18 / 45 | 18 / 42 | 18 / 41 | 18 / 39 |
| qwen3.5-9b-nothink | 6 / 36 | 6 / 36 | 6 / 36 | 6 / 35 |
| gemma-4-12b-nothink | 8 / 51 | 8 / 51 | 8 / 51 | 5 / 41 |
| gemma-4-e4b-nothink | 2 / 24 | 2 / 24 | 2 / 24 | 2 / 22 |
| gemma-4-e4b | 6 / 55 | 6 / 55 | 6 / 55 | 6 / 54 |
| claude | 1 / 66 | 1 / 66 | 1 / 64 | 0 / 18 |

