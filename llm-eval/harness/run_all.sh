#!/usr/bin/env bash
# One run per model, one model at a time, then the table.
set -eu

cd "$(dirname "$0")/../.."
H=llm-eval/harness
R=llm-eval/results
ITEMS=llm-eval/eval/items.jsonl
mkdir -p "$R"

for pair in qwen3.5-9b:Qwen3.5-9B-Q4_K_M gemma-4-12b:gemma-4-12b-it-qat-q4_0 \
        gemma-4-e4b:gemma-4-E4B_q4_0-it; do
    name="${pair%%:*}"
    "$H/serve.sh" "$HOME/llm/models/${pair#*:}.gguf" "$R/server_$name.log"
    python3 "$H/run_eval.py" run --items "$ITEMS" --model "$name" --source juliet \
        --out "$R/${name}_primary.jsonl" || true
    kill "$(cat "$R/server_$name.log.pid")"
    rm -f "$R/server_$name.log.pid"
    sleep 5
done

python3 "$H/stats.py" --items "$ITEMS" --results "$R" \
    --models qwen3.5-9b gemma-4-12b gemma-4-e4b claude --out "$R/report.md"
