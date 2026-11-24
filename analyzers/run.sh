#!/usr/bin/env bash
# shellcheck disable=SC2016  # the sh -c bodies are single-quoted on purpose
# Runs every static analyser of the image on one C file and keeps each raw
# report under OUTDIR/<tool>.*, with the tool's exit code in OUTDIR/status.
# Parsing and scoring happen later, so nothing here judges a finding.
# Usage: analyzers/run.sh FILE.c OUTDIR   (inside c-secure-build-analyzers)
# Exits 2 if a tool is missing or crashed or timed out, 0 otherwise.
set -u

if [ "$#" -ne 2 ] || [ ! -f "$1" ]; then
    echo "usage: $0 FILE.c OUTDIR" >&2
    exit 2
fi
src="$(realpath "$1")" || exit 2
out="$2"
mkdir -p "$out" || exit 2
out="$(realpath "$out")" || exit 2
rules="$(realpath "$(dirname "$0")/../.semgrep")" || exit 2

# Per tool, in seconds. ESBMC and EVA are the slow ones on CASTLE-sized files.
limit="${ANALYZER_TIMEOUT:-120}"

work="$(mktemp -d)" || exit 2
trap 'rm -rf "$work"' EXIT
: > "$out/status" || exit 2
failed=0

# Exit codes that mean "found something" differ per tool, so only a missing
# binary (127), a timeout (124) or a signal (>128) counts as a failed run.
record() {
    printf '%s %s\n' "$1" "$2" >> "$out/status"
    if [ "$2" -eq 124 ] || [ "$2" -eq 127 ] || [ "$2" -gt 128 ]; then
        echo "$1 did not finish (exit $2)" >&2
        failed=1
    fi
}

run() {
    local name="$1"
    shift
    local code=0
    (cd "$work" && timeout "$limit" "$@") > "$out/$name.log" 2>&1 || code=$?
    record "$name" "$code"
}

run flawfinder sh -c 'flawfinder --sarif --quiet "$1" > "$2"' _ "$src" "$out/flawfinder.sarif"

run semgrep semgrep --metrics=off --config "$rules/rules/" --config "$rules/local/" \
    --sarif --output "$out/semgrep.sarif" "$src"

run cppcheck cppcheck --enable=warning,portability --inconclusive --xml \
    --output-file="$out/cppcheck.xml" "$src"

run clang-sa clang --analyze --analyzer-output sarif -o "$out/clang-sa.sarif" "$src"

# -fanalyzer only reports; -c and /dev/null keep it from linking.
run gcc-fanalyzer sh -c 'gcc -std=c17 -fanalyzer -fanalyzer-checker=taint \
    -fdiagnostics-format=sarif-stderr -c "$1" -o /dev/null 2> "$2"' \
    _ "$src" "$out/gcc-fanalyzer.sarif"

# Starvation only matters for programs with locks, but costs little to run.
run infer infer run --no-progress-bar --results-dir "$work/infer-out" \
    --pulse --liveness --starvation -- clang -c "$src" -o /dev/null
cp "$work/infer-out/report.json" "$out/infer.json" 2>/dev/null \
    || { echo "infer wrote no report.json" >&2; failed=1; }

# Bounded: loops unrolled 10 times, deeper paths go unchecked.
run esbmc esbmc "$src" --unwind 10 --no-unwinding-assertions \
    --memory-leak-check --overflow-check --multi-property

run frama-c-eva frama-c -eva -eva-no-show-progress "$src" -then -report

exit "$failed"
