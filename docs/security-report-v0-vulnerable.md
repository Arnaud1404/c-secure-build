# Security report: `v0-vulnerable` vs HEAD

Generated locally on Debian 13 (trixie) with flawfinder 2.0.20, semgrep 1.173.0 and valgrind 3.24.0, via `scripts/collect_security_data.sh`. Every number below can be regenerated with that one command; the raw SARIF, Valgrind and ASan logs ship next to this file in the release asset. HEAD moves, so its exact SHA is recorded in `.security-report/HEAD/commit.txt` rather than pinned here.

| Ref | Commit | Static gate | Flawfinder probe | Semgrep probe | Valgrind | ASan run |
|---|---|---|---|---|---|---|
| `v0-vulnerable` | `72d0268` (2026-08-23) | **BLOCKED, exit 1** | exit 0 (report only) | exit 0 (report only) | **128 B reachable leak = 1 error (exit 7 with `--error-exitcode=7`) — blocks** | clean, exit 0 |
| `HEAD` (main) | see `HEAD/commit.txt` | **scan clean, exit 0** | exit 0 | exit 0 | "All heap blocks were freed", exit 0 | clean, exit 0 |

The gate flips exactly as the README claims, and the single blocking signal is Valgrind's still-reachable-leak error — a general-purpose dynamic analyzer with no rule written for this bug. The first version of this pipeline blocked on a local semgrep rule aimed at the leak instead; that rule was removed on purpose, because a rule written for the bug proves the rule, not the pipeline.

## What each engine caught at `v0-vulnerable`

15 findings total: flawfinder 5, semgrep 10. Line numbers refer to the 110-line file at the tag.

| Engine | Rule | Line | Verdict |
|---|---|---|---|
| Valgrind | still-reachable leak (CWE-401) | 18 | **True positive — defect B1.** This is the finding that blocks the commit. |
| Semgrep | `raptor-memory-address-exposure` (INFO) | 108 | **True positive — defect B3.** `%p` of a heap pointer printed to stderr. |
| Semgrep | `raptor-interesting-api-calls` (WARNING) | 18, 23, 32, 36, 48, 53 | Audit candidates (`malloc`, `strncpy`, `strtok_r`, `execvp`, `fork`). By design, not defects. |
| Semgrep | `raptor-signed-unsigned-conversion` (WARNING) | 18, 23 | False positive: `LEAK_BUFFER_SIZE - 1` is the positive constant 127 widened to `size_t`. |
| Semgrep | `raptor-mismatched-memory-management` (INFO) | 106 | False positive: `free(input_buffer)` on a `getline` buffer is correct `malloc`/`free` pairing. |
| Flawfinder | `FF1008` strncpy "doesn't always \\0-terminate" [MS-banned] | 23 | **Latent risk — defect B2.** Manually terminated on the next line, so flagged, not blocking (note level). |
| Flawfinder | `FF1016` printf format string (CWE-134) | 76, 82 | False positives: both format strings are constants. |
| Flawfinder | `FF1017` fprintf format string (CWE-134) | 108 | The same line as defect B3; as a format-string candidate it is a weak signal, but it points at the right line. |
| Flawfinder | `FF1022` strlen over-read (CWE-126) | 90 | False positive: `getline` guarantees NUL termination. |

At HEAD only 8 findings remain (flawfinder 3, semgrep 5), all of the false-positive / audit-candidate classes above. The three true positives disappear with the 21 deleted lines.

## All bugs in the vulnerable shell

### Planted defects (removed between the tag and HEAD)

1. **B1 — Memory leak, CWE-401** (`src/vuln_shell.c:18`). `trigger_memory_leak()` mallocs 128 bytes into the file-scoped `globally_leaked_ptr` and nothing ever frees it. Caught dynamically by Valgrind — `128 bytes in 1 blocks are still reachable ... trigger_memory_leak (vuln_shell.c:18)`, counted as 1 error, and this error is the gate blocker. Deliberately *not* caught by LeakSanitizer: the pointer lives in static storage, so the block stays reachable from a global root and LSan's default root set silences it. ASan run: clean. Statically, only audit-candidate warnings point at the line (`interesting-api-calls` on the `malloc`); the vendored pack has double-free and wrong-free rules but no never-freed rule.
2. **B2 — Unsafe copy, CWE-676** (`src/vuln_shell.c:23`). `strncpy` into the fresh buffer, flagged `FF1008` [MS-banned] plus `interesting-api-calls`. The manual `globally_leaked_ptr[LEAK_BUFFER_SIZE - 1] = '\0'` on the next line makes this a latent-risk flag rather than a live overflow — exactly the kind of finding a lexical engine is supposed to force a human to look at.
3. **B3 — Information exposure, CWE-209 / CWE-497** (`src/vuln_shell.c:108`). `fprintf(stderr, "Leaked pointer usage: %p\n", ...)` prints a heap address to stderr. Caught statically by `raptor-memory-address-exposure` (whose rule text names the ASLR-defeat consequence) and confirmed live at runtime: both the Valgrind log (`Leaked pointer usage: 0x4a70040`) and the ASan log (`0x50c000000040`) captured the address being printed.

### Structural bugs and limitations (present at the tag; most survive at HEAD)

4. **Silent argument truncation.** `parse_input` stops at `MAX_ARGS - 1` = 63 tokens; anything past that is dropped without a diagnostic, so a too-long command can execute with the wrong arguments.
5. **Child exit status discarded.** `waitpid(pid, NULL, 0)` throws the status away; a command that fails (or crashes) is indistinguishable from one that succeeds.
6. **Fork failure kills the shell.** On `pid == -1` the parent calls `exit(EXIT_FAILURE)`, so a transient `EAGAIN` under process pressure terminates the whole REPL instead of reporting the error and continuing.
7. **No signal handling.** SIGINT/SIGTERM keep their defaults, so Ctrl-C tears down the shell (and its child) rather than being managed; `waitpid` is not retried on `EINTR`.
8. **Unbounded input-buffer growth.** The `getline` buffer grows to the longest line seen and is never shrunk until exit; in a long-lived REPL the peak is retained (small, but unbounded over time).
9. **Command injection is the feature.** `execvp(args[0], args)` resolves through the inherited `PATH` with no canonicalization or allowlist — inherent to a shell, listed for completeness.

### Gate mechanics worth knowing

- **The block comes from exactly one place: the Valgrind gate.** Flawfinder's probe (`--error-level=4`) exits 0 at the tag — all five of its findings are note-level — and no vendored semgrep rule above WARNING fires on this code. The vendored pack's ERROR-severity rules (strcpy/strcat, double-free, use-after-free, format strings, gets, scanf) match none of the planted defects; the only ERROR hit the tag ever produced came from a local rule written for the leak, and that rule is gone.
- **Valgrind needs `--error-exitcode` to matter.** Memcheck reports the reachable leak and prints `ERROR SUMMARY: 1`, but without `--error-exitcode` it still exits 0 (it propagates the client's exit status). `scripts/scan.sh` sets `--error-exitcode=1` alongside `--errors-for-leak-kinds=all`, which is what turns the reachable leak into a gate signal. The flags live in the gate itself, not in a test script a historical commit could freeze with the opposite polarity — the tag's own `tests/mem_check.sh` expected the leak rather than blocking on it.
- **ASan is the control group.** LSan's global-root suppression stays silent on B1, which is why the pipeline runs four engines instead of trusting one.
- **An earlier draft of this report was not backed by its own dataset.** The two report passes in `scripts/scan.sh` ended in `|| true`, so a semgrep that exited 2 wrote no SARIF and the gate still printed `scan clean`. That happened: the published `HEAD/` directory shipped without `semgrep.sarif`, and the eight findings claimed above for HEAD were three in the data. The gate now exits 2 when either engine fails to produce a non-empty report, and the collector refuses to write a partial dataset. Every count in this report is regenerated under those rules and matches `findings.tsv`. The lesson is the one the pipeline exists to teach, turned on the pipeline itself: an engine that cannot run has not cleared the code, it has only failed to look at it.

## Reproduce and retrieve

```bash
scripts/collect_security_data.sh        # rebuilds .security-report/ (v0-vulnerable + HEAD)
```

CI publishes the same dataset automatically whenever a `v*` tag is pushed (job `security-data release` in `.github/workflows/ci.yml`), attaching `security-data-<tag>.zip` to a release on that tag.

The second vulnerable iteration, which blocks on the static engines instead of the dynamic one, is written up in [`security-report-v1-vulnerable.md`](security-report-v1-vulnerable.md).

