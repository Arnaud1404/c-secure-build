# Third-Party Rules: 0xdea/semgrep-rules

Everything in this directory except this file, `LICENSE`, `NOTICE.md`
itself, and `local/` is vendored, unmodified, from:

* **Source:** <https://github.com/0xdea/semgrep-rules>
* **Author:** Marco Ivaldi ("raptor") <raptor@0xdeadbeef.info>
* **Version:** 2.0.0 (per upstream `CHANGELOG.md`)
* **License:** MIT (`LICENSE` in this directory is the upstream file,
  unmodified)
* **Scope vendored:** `rules/c/` only (49 rules, C/C++). Upstream's
  `rules/noisy/` is intentionally excluded: upstream buckets it separately
  because those rules are marginal/high-false-positive by design, which
  does not fit this project's blocking pre-commit gate.

Each rule's `metadata.author` field already carries individual attribution;
this file exists to satisfy the MIT license's notice requirement at the
directory level and to record where the snapshot came from and which
version it is pinned to, consistent with how this repo pins `semgrep`
itself in `requirements.txt`.

## Known gaps

This ruleset has no rule for:

* Unchecked return values on `fork()` or `execvp()` (no rule references
  `fork` anywhere in the pack; `raptor-command-injection` explicitly notes
  in a comment that `execvp` path/argument injection is unimplemented).
* A missing `free()` on an allocation path (memory leak). The pack's
  closest rules are the inverse: `raptor-double-free` (freeing twice) and
  `raptor-incorrect-use-of-free` (freeing non-heap memory).

The `fork`/`execvp` gap is still present in `vuln_shell.c` and is not
caught by Semgrep as configured here. The missing-`free()` gap is closed
by `local/missing-free-malloc.yaml`, this project's own rule — see
`local/` above.

## Known false positive

`raptor-mismatched-memory-management` flags `free(input_buffer)` in
`src/vuln_shell.c`. `input_buffer` is allocated by `getline()`, which is
malloc-compatible, but the rule's tracked-allocator list does not include
`getline`, so it cannot trace the origin and flags the `free()` as
unpaired. The rule's own metadata acknowledges it "might generate many
false positives."

## Verifying this snapshot

```sh
semgrep --validate --config .semgrep/rules/   # 50 rules (49 vendored +
                                               # 1 local), 0 config errors
semgrep --test .semgrep/rules/                # 49/49: runs upstream's own
                                               # ruleid:/ok: fixtures.
                                               # local/ has no fixture, so
                                               # it's silently skipped here,
                                               # not tested by this command.
```
