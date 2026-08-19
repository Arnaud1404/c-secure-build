#!/usr/bin/env bash
set -e

VALGRIND_LEAK_DETECTED_EXIT_CODE=1
VALGRIND_NO_LEAK_EXIT_CODE=0

BIN_PATH="./bin/c-secure-shell"
PAYLOAD_PATH="./tests/vuln_shell_commands.txt"

make clean > /dev/null 2>&1
make VALGRIND=1 > /dev/null 2>&1

if [[ ! -f "$BIN_PATH" ]]; then
    echo "ERROR: Binary not found at $BIN_PATH"
    exit 1
fi

if [[ ! -f "$PAYLOAD_PATH" ]]; then
    echo "ERROR: Payload file not found at $PAYLOAD_PATH"
    exit 1
fi

set +e

valgrind --leak-check=full \
         --show-leak-kinds=all \
         --errors-for-leak-kinds=all \
         --track-origins=yes \
         --error-exitcode="$VALGRIND_LEAK_DETECTED_EXIT_CODE" \
         --quiet \
         "$BIN_PATH" < "$PAYLOAD_PATH" > /dev/null 2>&1

EXIT_CODE=$?

set -e

if [[ $EXIT_CODE -eq "$VALGRIND_LEAK_DETECTED_EXIT_CODE" ]]; then
    exit 0
fi

echo "ERROR: Valgrind gate failed (exit code: $EXIT_CODE)"
exit 1