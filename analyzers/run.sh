#!/usr/bin/env bash
# shellcheck disable=SC2016  # the sh -c bodies are single-quoted on purpose
# Runs every static analyser of the image on one C file and keeps each raw
# report under OUTDIR/<tool>.*, with the tool's exit code in OUTDIR/status.
# Flags follow the CASTLE wrappers (CASTLE-Source, wrappers/*/run.py) where
# CASTLE ran the tool; analyzers/README.md lists each choice and its source.
# Parsing and scoring happen later, so nothing here judges a finding.
# Usage: analyzers/run.sh FILE.c OUTDIR [COMPILE]   (inside c-secure-build-analyzers)
#   COMPILE is the program's build command, as in CASTLE's "compile" field,
#   naming the file by its basename. Default: gcc NAME.c -o NAME.
# Exits 2 if a tool is missing or crashed or timed out, 0 otherwise.
set -u

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ] || [ ! -f "$1" ]; then
    echo "usage: $0 FILE.c OUTDIR [COMPILE]" >&2
    exit 2
fi
src="$(realpath "$1")" || exit 2
base="$(basename "$src")"
compile="${3:-gcc $base -o ${base%.c}}"
out="$2"
mkdir -p "$out" || exit 2
out="$(realpath "$out")" || exit 2
rules="$(realpath "$(dirname "$0")/../.semgrep")" || exit 2

# Per tool, in seconds. ESBMC has its own 10 s budget inside this one.
limit="${ANALYZER_TIMEOUT:-120}"

work="$(mktemp -d)" || exit 2
trap 'rm -rf "$work"' EXIT
: > "$out/status" || exit 2
printf '%s\n' "$compile" > "$out/compile" || exit 2
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

# Each tool gets a fresh directory holding only the source, so build outputs
# and tool caches of one run cannot reach the next.
run() {
    local name="$1"
    shift
    local code=0 dir="$work/$name"
    if ! mkdir "$dir" || ! cp "$src" "$dir/$base"; then
        record "$name" 127
        return
    fi
    (cd "$dir" && timeout "$limit" "$@") > "$out/$name.log" 2>&1 || code=$?
    record "$name" "$code"
}

run flawfinder sh -c 'flawfinder --sarif --quiet "$1" > "$2"' _ "$base" "$out/flawfinder.sarif"

# CASTLE ran Semgrep Pro with --config auto, which needs an account and the
# registry. This is Semgrep CE with the repository's rules, offline.
run semgrep semgrep --metrics=off --config "$rules/rules/" --config "$rules/local/" \
    --sarif --output "$out/semgrep.sarif" "$base"

run cppcheck cppcheck --enable=all --language=c --quiet \
    '--template={severity},{line},{cwe},{message}' --output-file="$out/cppcheck.txt" "$base"

run clang-sa sh -c 'scan-build --keep-going sh -c "$1"' _ "$compile"

run gcc-fanalyzer sh -c '$1 -Wall -Wextra -fanalyzer 2> "$2"' _ "$compile" "$out/gcc-fanalyzer.txt"

# Not in CASTLE: the taint checker is off by default in GCC.
run gcc-fanalyzer-taint sh -c '$1 -Wall -Wextra -fanalyzer -fanalyzer-checker=taint 2> "$2"' \
    _ "$compile" "$out/gcc-fanalyzer-taint.txt"

# Not in CASTLE. Starvation only matters for programs with locks. -c stops
# at the object file: Infer's link step looks for objects its capture never wrote.
run infer sh -c 'infer run --no-progress-bar --results-dir infer-out \
    --pulse --liveness --starvation -- $1 -c && cp infer-out/report.json "$2"' \
    _ "$compile" "$out/infer.json"

run esbmc esbmc --overflow --no-unwinding-assertions --memory-leak-check --timeout 10 \
    --multi-property "$base" --show-stacktrace

# Not in CASTLE.
run frama-c-eva frama-c -eva -eva-no-show-progress "$base" -then -report

exit "$failed"
