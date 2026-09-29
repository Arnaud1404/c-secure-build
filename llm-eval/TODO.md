# v2 benchmark and local triage model

Claude budget: at most 50% of the 5-hour window (93% left at start). No usage
readout exists in the CLI, so runs are capped in API-equivalent dollars.

1. [x] v2 items: Juliet flow variants 01-18 only (source and sink in one function), 7 CWEs
2. [x] Split by functional variant (family): test 25%, train 75%, seeded
3. [x] Line-level labels: TP only at a FLAW / POTENTIAL FLAW statement in bad(); FP in good*(); off-target FP stratum; drop the rest
4. [x] Context: file preamble + flagged function only; random per-item names; line numbers from 1
5. [x] Leak checks on the test set (name, position, length baselines)
6. [x] Cumulative dollar cap in run_eval.py for the Claude backend
7. [x] Claude on v2 test (ceiling): 98.3% balanced with few-shot
8. [~] Local runs on v2 test (few-shot prompt):
    - [x] No thinking: Qwen3.5 9B 70.9%, Gemma 4 12B 79.1%, Gemma 4 E4B 65.9% (floor 65.6%)
    - [x] Gemma 4 E4B thinking: 85.0%, 19 s median
    - [~] Gemma 4 12B thinking: paused at 74/117 on 2026-09-28 22:31. Resume: `llm-eval/harness/run_v2.sh --skip-claude --thinking on --models gemma-4-12b`
    - [-] Qwen3.5 9B thinking: dropped by the user
9. [~] Report and chart: results_v2/report.md, results_v2/chart.html (harness/chart_v2.py). Rebuild both after the 12B run.
10. [~] Distillation, single model, 8 GB:
    - E4B: 4-bit load is 3.8 GB, but the per-layer embedding table (5.6 GB bf16) is copied to the GPU on every forward (peak 9.45 GB). Fix to try: run that lookup on the CPU and move only the rows to the GPU. train_sft.py needs this before it can train E4B.
    - Fallback student: Qwen3.5-4B (fits without tricks; needs a baseline run first).
    - Teacher: 168/390 Claude answers in results_v2/teacher/claude_train.jsonl. Resume (from llm-eval/): `python3 harness/run_eval.py run --items eval_v2/teacher_pool.jsonl --backend claude --claude-model claude-opus-5-5 --effort medium --model claude-teacher --out results_v2/teacher/claude_train.jsonl`
    - Base checkpoint downloaded and hashed: ~/llm/models/hf/gemma-4-E4B-it-qat-q4_0-unquantized
10b. [ ] Cheap single-model levers: verdict probability from llama-server as confidence; per-finding examples (same rule/CWE, matched TP/FP pair)
10c. [ ] Order check: rerun ~20 items in reverse order and compare verdicts; shuffle test order for future runs
11. [ ] README, completion report

Prompt history (results_v2/):
- prompt1/: TP meant "a weakness of the kind the rule describes". Claude dismissed real overflows when the rule named another weakness.
- prompt2/: production definition of TP, stopped after 21 Claude items.
- current: production definition, decision checklist, 9 worked examples from train (harness/fewshot.json), context 16384.
