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

blocked=0

# The dynamic gate first: it rebuilds the tree, and make clean removes
# .security with it, so the SARIF reports have to be written after this.
make clean > /dev/null 2>&1
make VALGRIND=1 > /dev/null 2>&1

# The block policy lives here on purpose, not in a test script a historical
# commit could freeze with the opposite polarity.
valgrind_tmp="$(mktemp)"
valgrind --leak-check=full --show-leak-kinds=all \
    --errors-for-leak-kinds=all --error-exitcode=1 --quiet \
    ./bin/c-secure-shell < tests/vuln_shell_commands.txt \
    > /dev/null 2> "$valgrind_tmp" || blocked=1

mkdir -p .security
rm -f .security/*.sarif
mv "$valgrind_tmp" .security/valgrind.log

flawfinder --sarif --quiet src/ > .security/flawfinder.sarif || true
flawfinder --quiet --error-level=4 src/ > /dev/null || blocked=1

semgrep --config .semgrep/rules/ --sarif \
    --output .security/semgrep.sarif --quiet src/ || true
semgrep --config .semgrep/rules/ --severity=ERROR --error --quiet src/ \
    > /dev/null || blocked=1

if [ "$blocked" -ne 0 ]; then
    echo "BLOCKED: see .security/*.sarif and .security/valgrind.log"
    cat .security/valgrind.log
    exit 1
fi

echo "scan clean"
