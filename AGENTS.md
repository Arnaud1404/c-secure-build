# AGENTS.md

Instructions for coding agents working in this repository. Humans: see `README.md`.

## What the repo is

- `src/hardened_shell.c`: a small POSIX shell, the scan target. Four bugs were planted at tag `v2-vulnerable` and fixed at `v2-patched`.
- `scripts/scan.sh`: the security gate (flawfinder, semgrep, Valgrind, ASan/UBSan). Exit 0 clean, 1 finding, 2 could not run.
- `.githooks/pre-commit`: runs the build and the gate, blocks the commit on failure.
- `llm-eval/`: offline comparison of local LLMs as triage for the gate's findings. Not wired into the gate.

## Commands

Run them in the pinned toolchain (Linux, the devcontainer, or `make docker-scan`). Native Windows has no ASan or Valgrind.

```bash
make                 # hardened build, ASan + UBSan
make test            # rebuilds with sanitizers, runs tests/recall_test.sh and tests/shell_test.sh
make scan            # security gate; make reports a gate exit 1 as 2
make docker-scan     # same gate inside the pinned image
make hooks           # install the pre-commit hook
```

A change is done when `make test` and `make scan` both pass.

## Rules

- C17, `-Wall -Wextra -Werror -pedantic`. No warning is silenced with a pragma or by removing a flag.
- Check every allocation, I/O call and return code. No undefined behaviour.
- Banned APIs are listed in `.semgrep/local/banned-apis.yaml`. Do not add exceptions to pass the gate.
- Never weaken the gate to make a commit pass: no `--no-verify`, no lowered thresholds, no rules removed.
- Do not touch the `v2-vulnerable` and `v2-patched` tags; CI expects the first to fail and the second to pass.
- Pin every new dependency: image digest and apt versions in `Dockerfile`, Python versions in `requirements.txt`, actions by commit SHA in `.github/workflows/ci.yml`.
- `.semgrep/rules/` is vendored third-party content (see its `NOTICE.md`). Change local rules in `.semgrep/local/`.

## Workflow

1. One task per branch, one logical change per commit, conventional subject (`fix:`, `feat:`, `docs:`), no body.
2. Before editing, read the file's header comment and the related test.
3. A bug fix comes with a case in `tests/` that fails before the fix.
4. Update `README.md` when a command, an exit code or the pipeline diagram changes.
5. A human reviews every diff; CI must be green before merge.
