#!/usr/bin/env bash
set -eu

cd "$(dirname "$0")/.."

if [ -d .venv/bin ]; then
    PATH="$PWD/.venv/bin:$PATH"
    export PATH
fi

for tool in flawfinder semgrep valgrind; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "ERROR: $tool not found" >&2
        exit 2
    fi
done

# An engine that could not run has not cleared the code, it has only failed
# to look at it. That is exit 2, never a clean scan.
broken() {
    echo "ERROR: $1" >&2
    echo "Nothing was scanned. This is not a finding." >&2
    exit 2
}

blocked=0

# The dynamic gate first: it rebuilds the tree, and make clean removes
# .security with it, so the SARIF reports have to be written after this.
make clean > /dev/null 2>&1
make VALGRIND=1 > /dev/null 2>&1

# The block policy lives here on purpose, not in a test script a historical
# commit could freeze with the opposite polarity.
#
# Any non-zero exit blocks. Valgrind returns its own --error-exitcode for
# findings but passes the client's status through otherwise, so a crashing
# target and a leaking target are not distinguishable by exit code alone.
# Blocking on both is the conservative reading.
valgrind_tmp="$(mktemp)"
valgrind --leak-check=full --show-leak-kinds=all \
    --errors-for-leak-kinds=all --error-exitcode=1 --quiet \
    ./bin/c-secure-shell < tests/vuln_shell_commands.txt \
    > /dev/null 2> "$valgrind_tmp" || blocked=1

mkdir -p .security
rm -f .security/*.sarif
mv "$valgrind_tmp" .security/valgrind.log

# Report pass: unfiltered, so the SARIF keeps every low-severity finding
# whether or not anything blocks. Neither engine exits non-zero on findings
# without being asked to, so a non-zero exit here is the engine failing.
flawfinder --sarif --quiet src/ > .security/flawfinder.sarif \
    || broken "flawfinder could not write its SARIF report"
[ -s .security/flawfinder.sarif ] \
    || broken "flawfinder wrote an empty SARIF report"

semgrep --config .semgrep/rules/ --sarif \
    --output .security/semgrep.sarif --quiet src/ \
    || broken "semgrep could not write its SARIF report"
[ -s .security/semgrep.sarif ] \
    || broken "semgrep wrote an empty SARIF report"

# Block pass, at each tool's own error threshold. Exit 1 is "findings at or
# above it"; anything else is the engine failing, which is not a verdict.
probe=0
flawfinder --quiet --error-level=4 src/ > /dev/null || probe=$?
case "$probe" in
    0) ;;
    1) blocked=1 ;;
    *) broken "the flawfinder block pass failed with exit $probe" ;;
esac

probe=0
semgrep --config .semgrep/rules/ --severity=ERROR --error --quiet src/ \
    > /dev/null || probe=$?
case "$probe" in
    0) ;;
    1) blocked=1 ;;
    *) broken "the semgrep block pass failed with exit $probe" ;;
esac

if [ "$blocked" -ne 0 ]; then
    echo "BLOCKED: see .security/*.sarif and .security/valgrind.log"
    cat .security/valgrind.log
    exit 1
fi

echo "scan clean"
