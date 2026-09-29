#!/usr/bin/env bash
# Runs the repo's flawfinder and semgrep configs over llm-eval/work in the
# pinned toolchain image. Usage: [WORK=dir] [TARGETS="juliet real"] scan.sh [docker|podman]
set -eu

cd "$(dirname "$0")/../.."
runtime="${1:-docker}"
work="${WORK:-llm-eval/work}"
targets="${TARGETS:-juliet real}"
mkdir -p "$work/sarif"

if [ "$runtime" = podman ]; then
    run_as=--userns=keep-id
else
    run_as="--user $(id -u):$(id -g)"
fi

# shellcheck disable=SC2086,SC2016  # $TARGETS expands inside the container
"$runtime" run --rm $run_as -v "$PWD:/src" -w "/src/$work" \
    -e TARGETS="$targets" c-secure-build-toolchain sh -c '
        flawfinder --sarif --quiet $TARGETS > sarif/flawfinder.sarif &&
        semgrep --config /src/.semgrep/rules/ --sarif \
            --output sarif/semgrep.sarif --quiet $TARGETS'

for f in "$work"/sarif/*.sarif; do
    [ -s "$f" ] || { echo "ERROR: $f is empty" >&2; exit 2; }
done
echo "SARIF written to $work/sarif"
