#!/usr/bin/env bash
# Two passes per tool:
# - One unfiltered, for the SARIF report
# - One filtered, whose exit code gates.
# Keeping them separate means the gate can be narrow (error only)
# without deleting the lower-severity findings from the report.
set -eu

cd "$(dirname "$0")/.."
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
[ "$(jq '[.runs[].results[]] | length' .security/clangsa.sarif)" -eq 0 ] \
    || blocked=1

if [ "$blocked" -ne 0 ]; then
    echo "BLOCKED: see .security/*.sarif"
    exit 1
fi

echo "scan clean"
