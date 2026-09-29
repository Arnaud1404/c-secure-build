# LLM triage: model comparison

Compares three local models, each with thinking on and off, as triage for this repo's flawfinder and semgrep findings, on a labeled set built from Juliet C/C++ 1.3 and the repo's own code. No model is used to produce the Juliet labels.

## Pinned inputs

| Input | Source | SHA-256 |
|---|---|---|
| llama.cpp b11218 (commit `33c923db1`), CUDA 13.4 x64 | github.com/ggml-org/llama.cpp releases | `5cbee21c…2fd1c` (binary), `e1a4debc…36abb` (cudart) |
| Juliet C/C++ 1.3 | samate.nist.gov/SARD/test-suites/112 | `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb` |
| Qwen3.5-9B Q4_K_M | `unsloth/Qwen3.5-9B-GGUF`, `Qwen3.5-9B-Q4_K_M.gguf` | `03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8` |
| gemma-4-12B-it QAT Q4_0 | `google/gemma-4-12B-it-qat-q4_0-gguf`, `gemma-4-12b-it-qat-q4_0.gguf` | `93567e57a8fe10b23569b9d9ec38cd005deedf71e29477c421a4b83f418a538b` |
| gemma-4-E4B-it QAT Q4_0 | `google/gemma-4-E4B-it-qat-q4_0-gguf`, `gemma-4-E4B_q4_0-it.gguf` | `676c35070db6dbe52f93e9c864ee0fba4eddea94b9c875d9cb10daff453fbaee` |

All three models are Apache-2.0 per their model cards (`Qwen/Qwen3.5-9B` README line 3 and `LICENSE`; `google/gemma-4-12B-it` and `google/gemma-4-E4B-it` README lines 3 and 22).

## Reproduce

```bash
# Tools and data, outside the repo
D=~/llm/llama.cpp/b11218; mkdir -p $D/dl ~/llm/juliet ~/llm/models
B=https://github.com/ggml-org/llama.cpp/releases/download/b11218
curl -sSL -o $D/dl/llama.tgz  $B/llama-b11218-bin-ubuntu-cuda-13.4-x64.tar.gz
curl -sSL -o $D/dl/cudart.tgz $B/cudart-llama-b11218-bin-ubuntu-cuda-13.4-x64.tar.gz
(cd $D && tar -xzf dl/llama.tgz && tar -xzf dl/cudart.tgz)
curl -sSL -o ~/llm/juliet/juliet-c-cpp-1.3.zip \
  https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
(cd ~/llm/juliet && unzip -q juliet-c-cpp-1.3.zip)
curl -sSL -o ~/llm/models/Qwen3.5-9B-Q4_K_M.gguf \
  https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/main/Qwen3.5-9B-Q4_K_M.gguf
curl -sSL -o ~/llm/models/gemma-4-12b-it-qat-q4_0.gguf \
  https://huggingface.co/google/gemma-4-12B-it-qat-q4_0-gguf/resolve/main/gemma-4-12b-it-qat-q4_0.gguf
curl -sSL -o ~/llm/models/gemma-4-E4B_q4_0-it.gguf \
  https://huggingface.co/google/gemma-4-E4B-it-qat-q4_0-gguf/resolve/main/gemma-4-E4B_q4_0-it.gguf
sha256sum ~/llm/juliet/*.zip ~/llm/models/*.gguf   # compare with the table above

# Step 1: eval set (needs the toolchain image: make image, or make CONTAINER=podman image)
python3 llm-eval/harness/build_items.py sample --juliet ~/llm/juliet --out llm-eval/work
llm-eval/harness/scan.sh podman
python3 llm-eval/harness/build_items.py items --work llm-eval/work \
  --proposals llm-eval/eval/real_label_proposals.json --out llm-eval/eval

# Run every model (one at a time) with thinking on, then off, and write results/report.md
llm-eval/harness/run_all.sh
llm-eval/harness/run_nothink.sh
```

`serve.sh` runs `llama-server -m MODEL -ngl 99 -c 16384 --jinja -fa on -ctk q8_0 -ctv q8_0 -np 1 --cache-ram 0 --reasoning-format deepseek -lv 4 --port 8080` and exits non-zero unless the log shows every layer offloaded to the GPU. `-lv 4` only raises log verbosity, so the offload line is printed.

llama-server keeps earlier prompt states in RAM (`--cache-ram`, 8192 MiB by default). With 7.6 GiB, WSL's default of half the host RAM, the kernel killed the 12B server, so `serve.sh` now disables that cache; it only saved re-reading the shared system prompt, which the slot keeps anyway. The runs here also used `memory=12GB` and `swap=8GB` in `%UserProfile%\.wslconfig`. `run_eval.py` stops on a failed request instead of recording it, so rerunning resumes where it stopped.

`report.md` scores a missing or invalid answer as wrong. Besides the hit rates it gives balanced accuracy, median and total time, and median output tokens, then a filter view where only an FP verdict removes a finding (with 95% Wilson intervals), split by whether the flagged function holds both source and sink.

## v2 set (use this one)

The v1 set above has label problems: more than half its items need code the model never sees, labels are per test case rather than per line, and names and line positions leak the label. `build_v2.py` fixes that:

- Juliet flow variants 01 to 18 only, minus any function that is, or calls, a Sink, Source or helper. Source and sink are always in the function shown.
- Train and test are split by functional variant (25% of families to test), so no test family has a near-copy in train.
- TP only when the flagged line is under a `FLAW` or `POTENTIAL FLAW` region in `bad()`, array declarations excluded. FP in `good*()` functions, in three kinds: `fp_paired` (the same sink made safe), `fp_other`, and `fp_offtarget` (a rule unrelated to the test case). Anything else is dropped.
- The model sees the file preamble and the flagged function, numbered from 1, with label-bearing names replaced by random per-item names.

Test: 117 findings (50 TP, 67 FP). `baseline.py` trains a bag-of-tokens naive Bayes on the train split; its 65.6% balanced accuracy is the floor a model has to beat to show it reads the code.

The prompt defines TP as production triage needs it: the line is part of a real defect, even when the rule names the weakness imprecisely. It adds a short decision checklist and nine worked examples from train families (`harness/fewshot.json`; `RUN_EVAL_FEWSHOT=none` leaves them out).

```bash
python3 llm-eval/harness/build_v2.py sample --juliet ~/llm/juliet --out llm-eval/work_v2
WORK=llm-eval/work_v2 TARGETS=juliet llm-eval/harness/scan.sh podman
(cd llm-eval/harness && python3 build_v2.py items --work ../work_v2 --out ../eval_v2)
python3 llm-eval/harness/baseline.py --train llm-eval/eval_v2/train.jsonl \
  --test llm-eval/eval_v2/test.jsonl --out llm-eval/results_v2/nb-floor_primary.jsonl
llm-eval/harness/run_v2.sh [--skip-claude] [--thinking on|off|both]
python3 llm-eval/harness/stats.py --items llm-eval/eval_v2/test.jsonl --results llm-eval/results_v2 \
  --models nb-floor qwen3.5-9b qwen3.5-9b-nothink gemma-4-12b gemma-4-12b-nothink \
  gemma-4-e4b gemma-4-e4b-nothink claude --out llm-eval/results_v2/report.md
```

`results_v2/report.md` holds the current numbers. `results_v2/prompt1/` keeps the runs with the earlier prompt, for comparison.

## Optional: Claude backend

`run_eval.py run ... --backend claude [--claude-model claude-sonnet-5]` sends the same prompt and schema through `claude -p` (no tools, no session saved). The code leaves the machine, so use it only on public code such as Juliet and this repo.
