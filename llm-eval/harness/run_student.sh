#!/usr/bin/env bash
# Converts a LoRA adapter from train_sft.py to GGUF with the pinned llama.cpp
# converter, then runs the v2 test with it on top of the pinned base GGUF,
# thinking off and without few-shot examples (the student was trained without them).
# Usage: run_student.sh ADAPTER_DIR NAME BASE_HF_DIR BASE_GGUF
set -eu

adapter="$1"
name="$2"
base_hf="$3"
base_gguf="$4"
cd "$(dirname "$0")/../.." || exit 1
H=llm-eval/harness
R=llm-eval/results_v2
venv="$HOME/llm/train-venv/bin/python"
src="$HOME/llm/llama.cpp/src-b11218"
lora_gguf="$adapter/adapter.gguf"

if [ ! -f "$lora_gguf" ]; then
    "$venv" "$src/convert_lora_to_gguf.py" --base "$base_hf" --outtype f16 \
        --outfile "$lora_gguf" "$adapter"
fi

LORA="$lora_gguf" "$H/serve.sh" "$base_gguf" "$R/server_$name.log"
set +e
RUN_EVAL_FEWSHOT=none python3 "$H/run_eval.py" run --items llm-eval/eval_v2/test.jsonl \
    --model "$name" --thinking off --out "$R/${name}_primary.jsonl" >> "$R/run_$name.log" 2>&1
rc=$?
kill "$(cat "$R/server_$name.log.pid")"
rm -f "$R/server_$name.log.pid"
echo "$name done rc=$rc"
exit "$rc"
