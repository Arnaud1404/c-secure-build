#!/usr/bin/env bash
set -e

BIN_PATH="./bin/c-secure-shell"
PAYLOAD_PATH="./tests/payload.txt"

echo "[*] Rebuilding binary without ASan for Valgrind compatibility..."
make clean > /dev/null 2>&1
make SANITIZE=0 > /dev/null 2>&1

if [[ ! -f "$BIN_PATH" ]]; then
    echo "[!] Fatal: Binary not found at $BIN_PATH"
    exit 1
fi

if [[ ! -f "$PAYLOAD_PATH" ]]; then
    echo "[!] Fatal: Payload file not found at $PAYLOAD_PATH"
    exit 1
fi

echo "[*] Executing Valgrind memory gate..."

# Suspend fail-fast to capture valgrind error code
set +e

valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --error-exitcode=1 \
         --quiet \
         "$BIN_PATH" < "$PAYLOAD_PATH" > /dev/null 2>&1

EXIT_CODE=$?

set -e

if [[ $EXIT_CODE -eq 1 ]]; then
    echo "[+] GATE PASSED: Valgrind successfully intercepted the intentional memory leak."
    exit 0
else
    echo "[-] GATE FAILED: Valgrind failed to detect the leak, or returned unexpected code: $EXIT_CODE"
    exit 1
fi