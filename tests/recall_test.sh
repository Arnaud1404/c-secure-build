#!/usr/bin/env bash
# Checks how the recall builtin parses its slot argument.
# Usage: tests/recall_test.sh BINARY
# Failures and sanitizer reports go to stderr; exits 1 if any case fails.
set -u

if [ "$#" -ne 1 ]; then
    echo "usage: $0 BINARY" >&2
    exit 2
fi

bin="$1"
failed=0
passed=0

# One shell session per case, so every case starts with empty history.
# record_history runs before the builtin, so slot 0 holds the command itself.
expect() {
    local input="$1" want="$2" out status
    out="$(printf '%s\n' "$input" | "$bin")"
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "FAIL: '$input' exited with $status" >&2
        failed=1
        return
    fi
    if printf '%s\n' "$out" | sed 's/c-sec> //g' | grep -Fxq -- "$want"; then
        passed=$((passed + 1))
    else
        echo "FAIL: '$input': expected '$want', got:" >&2
        printf '%s\n' "$out" >&2
        failed=1
    fi
}

expect "recall" "recall"
expect "recall 0" "recall 0"
expect "recall 1" "recall: empty slot"
expect "recall +1" "recall: empty slot"
expect "recall 3" "recall: empty slot"
expect "recall 4" "recall: slot out of range"
expect "recall -1" "recall: slot out of range"
expect "recall abc" "recall: slot must be a number"
expect "recall 2x" "recall: slot must be a number"
expect "recall 0x1" "recall: slot must be a number"
# Fits in a long but not in an int: atoi had undefined behavior here.
expect "recall 4294967296" "recall: slot must be a number"
# Does not fit in a long: strtol sets ERANGE.
expect "recall 99999999999999999999999" "recall: slot must be a number"

echo "recall_test: $passed passed"
exit "$failed"
