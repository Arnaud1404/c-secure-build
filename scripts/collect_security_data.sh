#!/usr/bin/env bash
# Regenerates the full before/after security dataset for this repository.
#
# For every git ref given on the command line (default: v0-vulnerable and
# HEAD) this script checks the ref out into a temporary worktree and runs:
#
#   - scripts/scan.sh            (flawfinder + semgrep reports, Valgrind gate)
#   - the two static per-engine block probes scan.sh uses
#   - a raw Valgrind run with --error-exitcode, for a readable log
#   - an AddressSanitizer/UBSan build plus one run against the payload
#   - a python3 extraction of every SARIF result into findings.tsv
#
# It also writes the v0..HEAD patch for src/vuln_shell.c, tool versions,
# and a README into the output directory (.security-report by default).
#
# Usage: scripts/collect_security_data.sh [REF...] [-o OUTDIR]
set -eu

REPO_ROOT="$(git rev-parse --show-toplevel)"
OUT_DIR="$REPO_ROOT/.security-report"
REFS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) OUT_DIR="$2"; shift 2 ;;
        *)  REFS+=("$1"); shift ;;
    esac
done

if [ "${#REFS[@]}" -eq 0 ]; then
    REFS=(v0-vulnerable HEAD)
fi

if [ -d "$REPO_ROOT/.venv/bin" ]; then
    PATH="$REPO_ROOT/.venv/bin:$PATH"
    export PATH
fi

mkdir -p "$OUT_DIR"
DATA_ROOT="$(cd "$OUT_DIR" && pwd -P)"

for REF in "${REFS[@]}"; do
    SLUG="$(printf '%s' "$REF" | tr '/' '-')"
    DIR="$DATA_ROOT/$SLUG"
    rm -rf "$DIR"
    mkdir -p "$DIR/sarif"

    WORKTREE="$(mktemp -d "${TMPDIR:-/tmp}/c-secure-build-data.XXXXXX")"

    git -C "$REPO_ROOT" worktree add --detach "$WORKTREE" "$REF" > /dev/null 2>&1
    git -C "$REPO_ROOT" --no-pager show -s --format='%H %ci %s' "$REF" \
        > "$DIR/commit.txt"

    # The gate script and rule pack under test are the current ones; the
    # code under test is the ref's. Without this, every ref would be
    # scanned with whatever scan.sh and rules were frozen in its own
    # commit — including a rule that was since deleted on purpose.
    cp "$REPO_ROOT/scripts/scan.sh" "$WORKTREE/scripts/scan.sh"
    rm -rf "$WORKTREE/.semgrep/rules"
    cp -R "$REPO_ROOT/.semgrep/rules" "$WORKTREE/.semgrep/rules"

    echo "== $REF: static gate (scan.sh)"
    set +e
    (cd "$WORKTREE" && ./scripts/scan.sh) \
        > "$DIR/gate.txt" 2>&1
    echo "scan_exit=$?" >> "$DIR/gate.txt"

    (cd "$WORKTREE" && flawfinder --quiet --error-level=4 src/ > /dev/null 2>&1)
    echo "flawfinder_block_exit=$?" > "$DIR/gate-probes.txt"
    (cd "$WORKTREE" && semgrep --config .semgrep/rules/ \
        --severity=ERROR --error --quiet src/ > /dev/null 2>&1)
    probe_status=$?
    # Exit 2 is semgrep failing to run (OOM under load, worker crash), not
    # findings. Retry once so a flaky runner cannot masquerade as a signal.
    if [ "$probe_status" -eq 2 ]; then
        sleep 2
        (cd "$WORKTREE" && semgrep --config .semgrep/rules/ \
            --severity=ERROR --error --quiet src/ > /dev/null 2>&1)
        probe_status=$?
    fi
    echo "semgrep_block_exit=$probe_status" >> "$DIR/gate-probes.txt"
    set -e

    cp "$WORKTREE"/.security/*.sarif "$DIR/sarif/" 2>/dev/null || true

    : > "$DIR/findings.tsv"
    for SARIF in "$DIR"/sarif/*.sarif; do
        [ -f "$SARIF" ] || continue
        echo "=== $(basename "$SARIF")" >> "$DIR/findings.tsv"
        python3 -c '
import json, sys

data = json.load(open(sys.argv[1]))
for run in data.get("runs", []):
    tool = run.get("tool", {}).get("driver", {}).get("name", "?")
    for r in run.get("results", []):
        loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
        uri = loc.get("artifactLocation", {}).get("uri", "-")
        line = loc.get("region", {}).get("startLine", 0)
        text = (r.get("message", {}).get("text") or "").replace("\n", " ")[:160]
        print("\t".join([tool, r.get("ruleId", ""), r.get("level", ""),
                         uri, str(line), text]))
' "$SARIF" >> "$DIR/findings.tsv" 2>/dev/null || true
    done

    echo "== $REF: raw Valgrind log"
    set +e
    (cd "$WORKTREE" && make clean > /dev/null 2>&1 && make VALGRIND=1 > /dev/null 2>&1)
    (cd "$WORKTREE" && valgrind --leak-check=full --show-leak-kinds=all \
        --errors-for-leak-kinds=all --track-origins=yes --error-exitcode=7 \
        ./bin/c-secure-shell < tests/vuln_shell_commands.txt > /dev/null) \
        2> "$DIR/valgrind.log"
    echo "valgrind_exit=$?" >> "$DIR/valgrind.log"
    set -e

    echo "== $REF: AddressSanitizer build and run"
    set +e
    (cd "$WORKTREE" && make clean > /dev/null 2>&1 && make > /dev/null 2>&1)
    (cd "$WORKTREE" && ASAN_OPTIONS=detect_leaks=1 \
        ./bin/c-secure-shell < tests/vuln_shell_commands.txt > /dev/null) \
        2> "$DIR/asan.log"
    echo "asan_exit=$?" >> "$DIR/asan.log"
    set -e

    {
        echo "flawfinder: $(flawfinder --version 2> /dev/null || echo missing)"
        echo "semgrep:    $(semgrep --version 2> /dev/null || echo missing)"
        echo "valgrind:   $(valgrind --version 2> /dev/null || echo missing)"
    } > "$DIR/versions.txt"

    git -C "$REPO_ROOT" worktree remove --force "$WORKTREE" > /dev/null 2>&1 || \
        rm -rf "$WORKTREE"
done

# With exactly two refs, ship the patch between them (the default pair
# keeps the historical filename).
if [ "${#REFS[@]}" -eq 2 ]; then
    A_SLUG="$(printf '%s' "${REFS[0]}" | tr '/' '-')"
    B_SLUG="$(printf '%s' "${REFS[1]}" | tr '/' '-')"
    git -C "$REPO_ROOT" --no-pager diff "${REFS[0]}" "${REFS[1]}" -- src/vuln_shell.c \
        > "$DATA_ROOT/diff-${A_SLUG}-to-${B_SLUG}.patch"
fi

cat > "$DATA_ROOT/README.txt" <<'EOF'
Security dataset generated by scripts/collect_security_data.sh.

Per-ref directories contain: gate.txt (scan.sh verdict + exit code),
gate-probes.txt (per-engine static block exit codes), sarif/ (raw
SARIF), findings.tsv (extracted table of every result), valgrind.log
(raw run with --error-exitcode=7), asan.log (AddressSanitizer/UBSan
run), versions.txt, commit.txt.

Read docs/security-report-v0-vulnerable.md for the analysis.
Reproduce with: scripts/collect_security_data.sh
EOF

echo "dataset written to $DATA_ROOT"