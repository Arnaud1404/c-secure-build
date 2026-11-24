#!/usr/bin/env bash
# Agent tool: runs every analyser on ./target.c in the current directory and
# prints each tool's exit code, then the reports' names under ./analyzers-out.
# It takes no arguments because agy allow rules match whole command lines, so
# one fixed line ("bash tools/run_analyzers.sh") is what the settings allow.
# An optional ./compile file holds the program's build command (CASTLE field).
# Needs Docker and the c-secure-build-analyzers image (make analyzers-image).
set -u

[ -f target.c ] || { echo "no target.c in $(pwd)" >&2; exit 2; }
image="${ANALYZERS_IMAGE:-c-secure-build-analyzers}"

# A copy of this script in a scratch workspace finds the repository through
# C_SECURE_BUILD; the one in agent-eval/tools/ finds it two levels up.
repo="${C_SECURE_BUILD:-$(dirname "$0")/../..}"
[ -f "$repo/analyzers/run.sh" ] || { echo "no analyzers/run.sh under $repo" >&2; exit 2; }
repo="$(cd "$repo" && pwd)" || exit 2
here="$(pwd)"
user=(--user "$(id -u):$(id -g)")
# Git Bash hands Docker Desktop a /c/... path it cannot mount, and Docker
# Desktop maps file ownership itself, so there: C:/... paths and no --user.
if pwd -W > /dev/null 2>&1; then
    here="$(pwd -W)"
    repo="$(cd "$repo" && pwd -W)" || exit 2
    user=()
fi
compile="$(cat compile 2>/dev/null || true)"

code=0
MSYS_NO_PATHCONV=1 docker run --rm "${user[@]}" -v "$repo:/src:ro" -v "$here:/work" "$image" \
    ./analyzers/run.sh /work/target.c /work/analyzers-out ${compile:+"$compile"} || code=$?
cat analyzers-out/status 2>/dev/null
ls analyzers-out 2>/dev/null
exit "$code"
