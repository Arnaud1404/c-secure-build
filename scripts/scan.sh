#!/usr/bin/env bash
set -eu

cd "$(dirname "$0")/.."

# A host .venv mounted into the image cannot run there.
if [ -d .venv/bin ] && [ "${SCAN_TOOLCHAIN:-}" != image ]; then
    PATH="$PWD/.venv/bin:$PATH"
    export PATH
fi

for tool in flawfinder semgrep valgrind; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "ERROR: $tool not found" >&2
        exit 2
    fi
done

# Exit 2: an engine failed to run, so nothing was checked.
broken() {
    echo "ERROR: $1" >&2
    echo "Nothing was scanned. This is not a finding." >&2
    exit 2
}

# Exit 1 from a block pass is findings; anything else is the engine failing.
verdict() {
    case "$2" in
        0) ;;
        1) blocked=1 ;;
        *) broken "the $1 block pass failed with exit $2" ;;
    esac
}

blocked=0

# Dynamic passes first: make clean also removes .security.
# Valgrind cannot run an ASan binary, so each gets its own build. A report
# and a crash look the same by exit code, so any non-zero exit blocks.
make clean > /dev/null 2>&1
make > /dev/null 2>&1

asan_tmp="$(mktemp)"
# UBSan only warns unless told to halt.
ASAN_OPTIONS=detect_leaks=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    ./bin/c-secure-shell < tests/vuln_shell_commands.txt \
    > /dev/null 2> "$asan_tmp" || blocked=1

make clean > /dev/null 2>&1
make VALGRIND=1 > /dev/null 2>&1

valgrind_tmp="$(mktemp)"
valgrind --leak-check=full --show-leak-kinds=all \
    --errors-for-leak-kinds=all --error-exitcode=1 --quiet \
    ./bin/c-secure-shell < tests/vuln_shell_commands.txt \
    > /dev/null 2> "$valgrind_tmp" || blocked=1

mkdir -p .security
rm -f .security/*.sarif
mv "$valgrind_tmp" .security/valgrind.log
mv "$asan_tmp" .security/asan.log

# Report pass, unfiltered. These exit 0 on findings, so non-zero is a failure.
flawfinder --sarif --quiet src/ > .security/flawfinder.sarif \
    || broken "flawfinder could not write its SARIF report"
[ -s .security/flawfinder.sarif ] \
    || broken "flawfinder wrote an empty SARIF report"

semgrep --config .semgrep/rules/ --sarif \
    --output .security/semgrep.sarif --quiet src/ \
    || broken "semgrep could not write its SARIF report"
[ -s .security/semgrep.sarif ] \
    || broken "semgrep wrote an empty SARIF report"

# Block pass, at each tool's own error threshold.
probe=0
flawfinder --quiet --error-level=4 src/ > /dev/null || probe=$?
verdict flawfinder "$probe"

probe=0
semgrep --config .semgrep/rules/ --severity=ERROR --error --quiet src/ \
    > /dev/null || probe=$?
verdict semgrep "$probe"

if [ "$blocked" -ne 0 ]; then
    echo "BLOCKED: see .security/*.sarif, .security/asan.log and .security/valgrind.log"
    cat .security/asan.log .security/valgrind.log
    exit 1
fi

echo "scan clean"
