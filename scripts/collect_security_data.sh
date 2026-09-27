#!/usr/bin/env bash
# Builds the before/after dataset: gate verdicts, SARIF, sanitizer and
# Valgrind logs for each ref, plus the patch between two refs.
#
# Usage: scripts/collect_security_data.sh [REF...] [-o OUTDIR]
#        (default refs: v2-vulnerable HEAD)
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
    REFS=(v2-vulnerable HEAD)
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

    # Today's gate and rules, the ref's code.
    cp "$REPO_ROOT/scripts/scan.sh" "$WORKTREE/scripts/scan.sh"
    rm -rf "$WORKTREE/.semgrep/rules"
    cp -R "$REPO_ROOT/.semgrep/rules" "$WORKTREE/.semgrep/rules"

    echo "== $REF: gate (scan.sh)"
    set +e
    (cd "$WORKTREE" && ./scripts/scan.sh) \
        > "$DIR/gate.txt" 2>&1
    scan_status=$?
    set -e
    echo "scan_exit=$scan_status" >> "$DIR/gate.txt"

    # Above 1 the gate did not run, so there is no number to publish.
    if [ "$scan_status" -gt 1 ]; then
        echo "ERROR: the gate could not run at $REF (exit $scan_status)." >&2
        echo "See $DIR/gate.txt. Refusing to write a partial dataset." >&2
        exit 1
    fi

    set +e
    (cd "$WORKTREE" && flawfinder --quiet --error-level=4 src/ > /dev/null 2>&1)
    ff_probe=$?
    (cd "$WORKTREE" && semgrep --config .semgrep/rules/ \
        --severity=ERROR --error --quiet src/ > /dev/null 2>&1)
    sg_probe=$?
    # Exit 2 is semgrep crashing, not findings. Retry once.
    if [ "$sg_probe" -eq 2 ]; then
        sleep 2
        (cd "$WORKTREE" && semgrep --config .semgrep/rules/ \
            --severity=ERROR --error --quiet src/ > /dev/null 2>&1)
        sg_probe=$?
    fi
    set -e

    echo "flawfinder_block_exit=$ff_probe" > "$DIR/gate-probes.txt"
    echo "semgrep_block_exit=$sg_probe" >> "$DIR/gate-probes.txt"

    for PROBE in "flawfinder:$ff_probe" "semgrep:$sg_probe"; do
        if [ "${PROBE#*:}" -gt 1 ]; then
            echo "ERROR: the ${PROBE%%:*} block probe failed at $REF" >&2
            echo "with exit ${PROBE#*:}, which is not a verdict." >&2
            exit 1
        fi
    done

    cp "$WORKTREE"/.security/*.sarif "$DIR/sarif/"
    for ENGINE in flawfinder semgrep; do
        if [ ! -s "$DIR/sarif/$ENGINE.sarif" ]; then
            echo "ERROR: $ENGINE produced no SARIF at $REF." >&2
            exit 1
        fi
    done

    : > "$DIR/findings.tsv"
    for SARIF in "$DIR"/sarif/*.sarif; do
        [ -f "$SARIF" ] || continue
        echo "=== $(basename "$SARIF")" >> "$DIR/findings.tsv"
        python3 -c '
import json, sys

data = json.load(open(sys.argv[1]))
for run in data.get("runs", []):
    driver = run.get("tool", {}).get("driver", {})
    tool = driver.get("name", "?")
    # Semgrep puts the level on the rule, not the result.
    levels = {}
    for rule in driver.get("rules", []):
        if rule.get("id") is not None:
            levels[rule["id"]] = rule.get("defaultConfiguration", {}).get(
                "level", "")
    for r in run.get("results", []):
        rule_id = r.get("ruleId", "")
        loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
        uri = loc.get("artifactLocation", {}).get("uri", "-")
        line = loc.get("region", {}).get("startLine", 0)
        text = (r.get("message", {}).get("text") or "").replace("\n", " ")[:160]
        print("\t".join([tool, rule_id, r.get("level") or levels.get(rule_id, ""),
                         uri, str(line), text]))
' "$SARIF" >> "$DIR/findings.tsv"
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

# Both paths, or the diff across the rename shows a deleted file.
if [ "${#REFS[@]}" -eq 2 ]; then
    A_SLUG="$(printf '%s' "${REFS[0]}" | tr '/' '-')"
    B_SLUG="$(printf '%s' "${REFS[1]}" | tr '/' '-')"
    git -C "$REPO_ROOT" --no-pager diff -M "${REFS[0]}" "${REFS[1]}" \
        -- src/vuln_shell.c src/hardened_shell.c \
        > "$DATA_ROOT/diff-${A_SLUG}-to-${B_SLUG}.patch"
fi

cat > "$DATA_ROOT/README.txt" <<'EOF'
Security dataset generated by scripts/collect_security_data.sh.

Per-ref directories contain: gate.txt (scan.sh verdict + exit code),
gate-probes.txt (per-engine static block exit codes), sarif/ (raw
SARIF), findings.tsv (extracted table of every result), valgrind.log
(raw run with --error-exitcode=7), asan.log (AddressSanitizer/UBSan
run), versions.txt, commit.txt.

Read docs/security-report-v2-vulnerable.md for the analysis.
Reproduce with: scripts/collect_security_data.sh
EOF

echo "dataset written to $DATA_ROOT"