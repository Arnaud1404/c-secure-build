#!/usr/bin/env bash
# Runs today's gate on the v2-vulnerable source and checks that every planted
# defect is still reported, by the engines the README's matrix credits.
# Run it in the pinned image: the scanners and Valgrind come from there.
# Usage: tests/detection_test.sh
# Exits 1 if the gate passes or a defect goes unreported, 2 if it cannot run.
set -u

cd "$(dirname "$0")/.." || exit 2

work="$(mktemp -d)" || exit 2
trap 'rm -rf "$work"' EXIT

# A copy, so the scan cannot touch the checkout's own build or reports.
tar --exclude=./.git --exclude=./.security --exclude=./bin --exclude=./obj \
    --exclude=./.venv -cf - . | tar -xf - -C "$work" || exit 2
cp src/vuln_shell.c.bak "$work/src/hardened_shell.c" || exit 2
cd "$work" || exit 2

code=0
./scripts/scan.sh > scan.log 2>&1 || code=$?
if [ "$code" -ne 1 ]; then
    tail -20 scan.log >&2
    if [ "$code" -eq 0 ]; then
        echo "FAIL: the gate passed the v2-vulnerable source" >&2
        exit 1
    fi
    echo "ERROR: the gate could not run (exit $code)" >&2
    exit 2
fi

# Prints "engine line" for each error-level SARIF result. Semgrep puts the
# level on the rule, Flawfinder on the result.
error_lines() {
    python3 - "$1" << 'EOF'
import json
import sys

run = json.load(open(f".security/{sys.argv[1]}.sarif"))["runs"][0]
rule_level = {r["id"]: r.get("defaultConfiguration", {}).get("level")
              for r in run["tool"]["driver"].get("rules", [])}
for result in run["results"]:
    if (result.get("level") or rule_level.get(result["ruleId"])) == "error":
        print(sys.argv[1], result["locations"][0]["physicalLocation"]["region"]["startLine"])
EOF
}

reports="$(error_lines flawfinder && error_lines semgrep)" || exit 2

failed=0
expect() {
    if printf '%s\n' "$2" | grep -qE "$3"; then
        echo "ok: $1"
    else
        echo "FAIL: $1" >&2
        failed=1
    fi
}

# Line numbers are those of src/vuln_shell.c.bak, which docs/ also cites.
expect "C1 strcpy, Flawfinder" "$reports" '^flawfinder 29$'
expect "C1 strcpy, Semgrep" "$reports" '^semgrep 29$'
expect "C2 format string, Flawfinder" "$reports" '^flawfinder 39$'
expect "C2 format string, Semgrep" "$reports" '^semgrep 39$'
expect "C3 leak, Valgrind" "$(cat .security/valgrind.log)" 'definitely lost'
expect "C3 leak, LeakSanitizer" "$(cat .security/asan.log)" 'LeakSanitizer'
expect "C4 uninitialised read, Valgrind" "$(cat .security/valgrind.log)" \
    'Conditional jump or move depends on uninitialised value'

exit "$failed"
