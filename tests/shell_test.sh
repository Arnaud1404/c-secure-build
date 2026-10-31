#!/usr/bin/env bash
# Checks the shell's behaviour across commands: history, the recall ring, and
# argument limits.
# Usage: tests/shell_test.sh BINARY
# Failures and sanitizer reports go to stderr; exits 1 if any case fails.
set -u

if [ "$#" -ne 1 ]; then
    echo "usage: $0 BINARY" >&2
    exit 2
fi

bin="$1"
failed=0
passed=0

# Sets $out to the session's output, without prompts. A sanitizer report makes
# the shell exit non-zero, which fails the case.
session() {
    local name="$1" input="$2" status
    out="$(printf '%s\n' "$input" | "$bin" | sed 's/c-sec> //g'; exit "${PIPESTATUS[1]}")"
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "FAIL: $name: exited with $status" >&2
        failed=1
        return 1
    fi
}

expect() {
    local name="$1" input="$2" want="$3"
    session "$name" "$input" || return
    if printf '%s\n' "$out" | grep -Fxq -- "$want"; then
        passed=$((passed + 1))
    else
        echo "FAIL: $name: expected '$want', got:" >&2
        printf '%s\n' "$out" >&2
        failed=1
    fi
}

expect_absent() {
    local name="$1" input="$2" unwanted="$3"
    session "$name" "$input" || return
    if printf '%s\n' "$out" | grep -Fxq -- "$unwanted"; then
        echo "FAIL: $name: did not expect '$unwanted'" >&2
        failed=1
    else
        passed=$((passed + 1))
    fi
}

# Six commands in four slots: slot 2 still holds the third.
expect "ring wrap" \
    "$(printf 'recall 9\nrecall 8\nrecall 7\nrecall 6\nrecall 5\nrecall 2')" \
    "recall 7"

expect "history shows the previous command" \
    "$(printf 'recall 1\nhistory')" \
    "recall 1"

# last_command holds 31 characters and a terminator.
long="recall $(printf 'x%.0s' {1..40})"
expect "history truncates a long line" \
    "$(printf '%s\nhistory' "$long")" \
    "${long:0:31}"

expect "a failed exec leaves the shell running" \
    "$(printf 'no-such-command-xyz\nrecall 0')" \
    "no-such-command-xyz"

# MAX_ARGS is 64, with one entry kept for the NULL terminator.
words() { printf ' w%.0s' $(seq 1 "$1"); }
expect "63 arguments run" "echo$(words 62)" "w$(words 61)"
expect "64 arguments are refused" "echo$(words 63)" "too many arguments"
expect_absent "64 arguments do not run truncated" "echo$(words 63)" "w$(words 61)"

# A seekable stdin shares its offset with the child: exit() there rewinds it
# during stdio cleanup, and the shell then reads its commands a second time.
script="$(mktemp)"
printf 'no-such-command-xyz\nrecall 0\n' > "$script"
count="$("$bin" < "$script" 2> /dev/null | grep -c 'no-such-command-xyz')"
rm -f "$script"
if [ "$count" -eq 1 ]; then
    passed=$((passed + 1))
else
    echo "FAIL: a failed exec replayed the input: $count matches" >&2
    failed=1
fi

# Reading a directory fails with EISDIR, which must not look like a clean EOF.
# Checking the message too, since a crash would also exit non-zero.
err="$("$bin" < / 2>&1 > /dev/null)"
status=$?
if [ "$status" -eq 1 ] && printf '%s\n' "$err" | grep -q 'getline failed'; then
    passed=$((passed + 1))
else
    echo "FAIL: a read error exited with $status: $err" >&2
    failed=1
fi

echo "shell_test: $passed passed"
exit "$failed"
