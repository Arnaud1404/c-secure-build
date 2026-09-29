#!/usr/bin/env bash
# Same as run_all.sh with thinking off, then the table with every run.
set -eu

cd "$(dirname "$0")/../.."
H=llm-eval/harness
R=llm-eval/results
ITEMS=llm-eval/eval/items.jsonl

for pair in qwen3.5-9b:Qwen3.5-9B-Q4_K_M gemma-4-12b:gemma-4-12b-it-qat-q4_0 \
        gemma-4-e4b:gemma-4-E4B_q4_0-it; do
    name="${pair%%:*}"
    "$H/serve.sh" "$HOME/llm/models/${pair#*:}.gguf" "$R/server_$name-nothink.log"
    python3 "$H/run_eval.py" run --items "$ITEMS" --model "$name-nothink" --source juliet \
        --thinking off --out "$R/${name}-nothink_primary.jsonl" || true
    kill "$(cat "$R/server_$name-nothink.log.pid")"
    rm -f "$R/server_$name-nothink.log.pid"
    sleep 5
done

python3 "$H/stats.py" --items "$ITEMS" --results "$R" --out "$R/report.md" \
    --models qwen3.5-9b qwen3.5-9b-nothink gemma-4-12b gemma-4-12b-nothink \
    gemma-4-e4b gemma-4-e4b-nothink claude
