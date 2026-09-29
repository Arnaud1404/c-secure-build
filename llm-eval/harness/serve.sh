#!/usr/bin/env bash
# Starts llama-server with the settings shared by both models, then checks
# that every layer is on the GPU. Usage: [LORA=adapter.gguf] serve.sh MODEL.gguf LOGFILE [PORT]
# Only one model at a time: they cannot share 8 GB.
set -eu

model="$1"
logfile="$2"
port="${3:-8080}"
build="${LLAMA_DIR:-$HOME/llm/llama.cpp/b11218}"
export LD_LIBRARY_PATH="$build/cudart-llama-b11218-bin-ubuntu-cuda-13.4-x64:$build/llama-b11218:/usr/lib/wsl/lib"

if curl -s "http://127.0.0.1:$port/health" > /dev/null 2>&1; then
    echo "ERROR: something already listens on port $port" >&2
    exit 1
fi

lora=()
if [ -n "${LORA:-}" ]; then
    [ -f "$LORA" ] || { echo "ERROR: LORA=$LORA does not exist" >&2; exit 1; }
    lora=(--lora "$LORA")
fi

"$build/llama-b11218/llama-server" -m "$model" "${lora[@]}" \
    -ngl 99 -c 16384 --jinja -fa on -ctk q8_0 -ctv q8_0 \
    -np 1 --cache-ram 0 --reasoning-format deepseek -lv 4 --port "$port" \
    > "$logfile" 2>&1 &
echo "$!" > "$logfile.pid"

for _ in $(seq 1 180); do
    if curl -s "http://127.0.0.1:$port/health" | grep -q '"ok"'; then
        break
    fi
    if ! kill -0 "$(cat "$logfile.pid")" 2> /dev/null; then
        echo "ERROR: llama-server exited, see $logfile" >&2
        exit 1
    fi
    sleep 1
done

offload="$(grep -oE 'offloaded [0-9]+/[0-9]+ layers to GPU' "$logfile" | tail -1)"
echo "pid $(cat "$logfile.pid"): ${offload:-no offload line found}"
if [ -z "$offload" ]; then
    exit 3
fi
done_layers="$(echo "$offload" | grep -oE '[0-9]+/[0-9]+' | cut -d/ -f1)"
all_layers="$(echo "$offload" | grep -oE '[0-9]+/[0-9]+' | cut -d/ -f2)"
if [ "$done_layers" != "$all_layers" ]; then
    echo "SPILL: only $offload" >&2
    exit 4
fi
