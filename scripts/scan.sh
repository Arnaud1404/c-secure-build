#!/usr/bin/env bash
set -eu

cd "$(dirname "$0")/.."

if [ -d .venv/bin ]; then
    PATH="$PWD/.venv/bin:$PATH"
    export PATH
fi

for tool in flawfinder semgrep clang jq; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "ERROR: $tool not found" >&2
        exit 2
    fi
done

mkdir -p .security
rm -f .security/*.sarif

blocked=0

flawfinder --sarif --quiet src/ > .security/flawfinder.sarif || true
flawfinder --quiet --error-level=4 src/ > /dev/null || blocked=1

semgrep --config .semgrep/rules/ --sarif \
    --output .security/semgrep.sarif --quiet src/ || true
semgrep --config .semgrep/rules/ --severity=ERROR --error --quiet src/ \
    > /dev/null || blocked=1

clang --analyze -Xclang -analyzer-output=sarif -std=c17 \
    -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L \
    -o .security/clangsa.sarif src/*.c || true

if jq --arg prefix "file://$(pwd)/" \
    '(.. | objects | select(has("uri")) | .uri) |= ltrimstr($prefix)' \
    .security/clangsa.sarif > .security/clangsa.tmp; then
    mv .security/clangsa.tmp .security/clangsa.sarif
else
    rm -f .security/clangsa.tmp
fi

[ "$(jq '[.runs[].results[]] | length' .security/clangsa.sarif)" -eq 0 ] \
    || blocked=1

if [ "$blocked" -ne 0 ]; then
    echo "BLOCKED: see .security/*.sarif"
    exit 1
fi

echo "scan clean"
