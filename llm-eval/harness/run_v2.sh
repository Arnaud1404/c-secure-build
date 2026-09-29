#!/usr/bin/env bash
# v2 benchmark: Claude as the ceiling, then every local model with thinking
# on and off, one at a time. Rerunning resumes each run where it stopped.
# Usage: run_v2.sh [--skip-claude] [--thinking on|off|both] [--models "qwen3.5-9b gemma-4-e4b ..."]
set -u

skip_claude=0
modes="on off"
only=""
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-claude) skip_claude=1 ;;
        --thinking)
            shift
            case "${1:-}" in
                on|off) modes="$1" ;;
                both) modes="on off" ;;
                *) echo "--thinking takes on, off or both" >&2; exit 2 ;;
            esac ;;
        --models) shift; only="${1:-}" ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

cd "$(dirname "$0")/../.." || exit 1
H=llm-eval/harness
R=llm-eval/results_v2
ITEMS=llm-eval/eval_v2/test.jsonl
mkdir -p "$R"

if [ "$skip_claude" = 0 ]; then
    python3 "$H/run_eval.py" run --items "$ITEMS" --backend claude \
        --claude-model claude-opus-5-5 --effort medium --model claude \
        --max-cost-usd 8 --out "$R/claude_primary.jsonl" >> "$R/run_claude.log" 2>&1
    echo "$(date +%T) claude rc=$?"
fi

for spec in gemma-4-e4b:gemma-4-E4B_q4_0-it qwen3.5-9b:Qwen3.5-9B-Q4_K_M \
        gemma-4-12b:gemma-4-12b-it-qat-q4_0; do
    base="${spec%%:*}"
    if [ -n "$only" ] && [[ " $only " != *" $base "* ]]; then
        continue
    fi
    for thinking in $modes; do
        name="$base"
        [ "$thinking" = off ] && name="$base-nothink"
        echo "$(date +%T) start $name"
        if ! "$H/serve.sh" "$HOME/llm/models/${spec#*:}.gguf" "$R/server_$name.log"; then
            echo "$(date +%T) serve failed for $name"
            continue
        fi
        python3 "$H/run_eval.py" run --items "$ITEMS" --model "$name" \
            --thinking "$thinking" --out "$R/${name}_primary.jsonl" >> "$R/run_$name.log" 2>&1
        echo "$(date +%T) end $name rc=$?"
        kill "$(cat "$R/server_$name.log.pid")" 2> /dev/null
        rm -f "$R/server_$name.log.pid"
        sleep 5
    done
done
echo "$(date +%T) all runs done"
