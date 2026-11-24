#!/usr/bin/env bash
# Checks that every analyser in the image runs to completion on the sample,
# and that ESBMC and Frama-C EVA, the two sound-ish tools, flag its line 12.
# Usage: analyzers/test.sh   (inside c-secure-build-analyzers)
# Exits 1 if a check fails, 2 if the run itself cannot start.
set -u

cd "$(dirname "$0")/.." || exit 2
out="$(mktemp -d)" || exit 2
trap 'rm -rf "$out"' EXIT

./analyzers/run.sh analyzers/samples/heap_oob.c "$out" || {
    echo "FAIL: an analyser did not finish" >&2
    cat "$out/status" >&2
    exit 1
}

fail=0
for tool in flawfinder semgrep cppcheck clang-sa gcc-fanalyzer gcc-fanalyzer-taint \
    infer esbmc frama-c-eva; do
    grep -q "^$tool " "$out/status" || { echo "FAIL: $tool did not run" >&2; fail=1; }
done
[ -s "$out/infer.json" ] || { echo "FAIL: infer wrote no report" >&2; fail=1; }
grep -q 'array bounds violated.*heap_oob.c line 12' "$out/esbmc.log" \
    || { echo "FAIL: esbmc missed line 12" >&2; fail=1; }
grep -q 'heap_oob.c:12: Warning' "$out/frama-c-eva.log" \
    || { echo "FAIL: frama-c eva missed line 12" >&2; fail=1; }

[ "$fail" -eq 0 ] && echo "analyzers: 9 runs finished, esbmc and eva flag line 12"
exit "$fail"
