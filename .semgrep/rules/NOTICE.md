# Third-Party Rules: 0xdea/semgrep-rules

Everything in this directory except this file, `LICENSE`, and `NOTICE.md`
itself is vendored, unmodified, from:

* **Source:** <https://github.com/0xdea/semgrep-rules>
* **Author:** Marco Ivaldi ("raptor") <raptor@0xdeadbeef.info>
* **Version:** 2.0.0 (per upstream `CHANGELOG.md`)
* **License:** MIT (`LICENSE` in this directory is the upstream file,
  unmodified)
* **Scope vendored:** `rules/c/` only (49 rules, C/C++). Upstream's
  `rules/noisy/` is intentionally excluded: upstream buckets it separately
  because those rules are marginal/high-false-positive by design, which
  does not fit this project's blocking pre-commit gate.

Each rule's `metadata.author` field carries its own attribution. This file
covers the MIT notice for the directory and records which upstream version
the snapshot is.

## Known gaps

This ruleset has no rule for:

* Unchecked return values on `fork()` or `execvp()` (no rule references
  `fork` anywhere in the pack; `raptor-command-injection` explicitly notes
  in a comment that `execvp` path/argument injection is unimplemented).
* A missing `free()` on an allocation path (memory leak). The pack's
  closest rules are the inverse: `raptor-double-free` (freeing twice) and
  `raptor-incorrect-use-of-free` (freeing non-heap memory).
* A read of an uninitialised heap value. No rule in the pack models
  allocator initialisation, so `malloc` where `calloc` was meant reads as
  an ordinary allocation.

The `fork`/`execvp` gap is still present in `hardened_shell.c` and is not
caught by Semgrep as configured here.

The other two gaps were measured. `v2-vulnerable` plants a
leak (`C3`) and an uninitialised read (`C4`), and neither Semgrep nor
Flawfinder reports either one at any severity; the Valgrind gate in
`scripts/scan.sh` blocks on both, and its ASan pass on `C3`. See
`docs/security-report-v2-vulnerable.md`.

The missing-`free()` gap was briefly closed by a local rule written for
this project's planted leak, then removed. A rule written to match the
planted bug only shows that it matches it.

## Known false positive

`raptor-mismatched-memory-management` flags `free(input_buffer)` in
`src/hardened_shell.c`. `input_buffer` is allocated by `getline()`, which is
malloc-compatible, but the rule's tracked-allocator list does not include
`getline`, so it cannot trace the origin and flags the `free()` as
unpaired. The rule's own metadata acknowledges it "might generate many
false positives."

## Verifying this snapshot

```sh
semgrep --validate --config .semgrep/rules/   # 49 rules, 0 config errors
semgrep --test .semgrep/rules/                # 49/49: runs upstream's own
                                              # ruleid:/ok: fixtures.
```
