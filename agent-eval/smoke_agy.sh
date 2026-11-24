#!/usr/bin/env bash
# Checks that agy can run headless as the harness will: in a scratch
# workspace holding only target.c and tools/, with agy-settings.json as its
# only command allowance, no model set, JSON out.
# Usage: agent-eval/smoke_agy.sh   (needs agy, Docker and c-secure-build-analyzers)
# Exits 1 if agy fails or a check does not hold, 2 if it cannot start.
set -u

here="$(cd "$(dirname "$0")" && pwd)" || exit 2
agy="${AGY:-agy}"
command -v "$agy" > /dev/null 2>&1 || [ -x "$agy" ] || { echo "agy not found; set AGY" >&2; exit 2; }

ws="$(mktemp -d)" || exit 2
trap 'rm -rf "$ws"' EXIT
cp "$here/../analyzers/samples/heap_oob.c" "$ws/target.c" || exit 2
mkdir "$ws/tools" && cp "$here/tools/run_analyzers.sh" "$ws/tools/" || exit 2
settings="$here/agy-settings.json"
if pwd -W > /dev/null 2>&1; then
    settings="$(cd "$here" && pwd -W)/agy-settings.json"
fi
export C_SECURE_BUILD="$here/.."

prompt='Run the shell command "bash tools/run_analyzers.sh" exactly once, with no
other command. Then read analyzers-out/esbmc.log and reply with one line:
the line number of target.c that ESBMC reports, or "none".'

# accept-edits: file edits pass, and any command off the allow list is
# denied, whatever the user's own agy permission preset says.
cd "$ws" || exit 2
"$agy" -p "$prompt" --mode accept-edits --settings "$settings" \
    --output-format json > result.json 2> agy.log
code=$?

fail=0
[ "$code" -eq 0 ] || { echo "FAIL: agy exited $code" >&2; tail -5 agy.log >&2; fail=1; }
python3 - result.json <<'PY' || fail=1
import json, sys

with open(sys.argv[1], encoding="utf-8") as f:
    lines = f.read().strip().splitlines()
result = json.loads(lines[-1])
ok = True
if result.get("status") != "SUCCESS":
    print("FAIL: status", result.get("status"), file=sys.stderr)
    ok = False
if result.get("denied_actions"):
    print("FAIL: denied", result["denied_actions"], file=sys.stderr)
    ok = False
if "12" not in result.get("response", ""):
    print("FAIL: answer", repr(result.get("response")), file=sys.stderr)
    ok = False
print("agy:", repr(result.get("response", "").strip()),
      result.get("usage", {}).get("total_tokens"), "tokens")
sys.exit(0 if ok else 1)
PY
[ -f analyzers-out/status ] || { echo "FAIL: the tool did not run" >&2; fail=1; }
exit "$fail"
