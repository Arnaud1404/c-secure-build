# Security report: `v1-vulnerable` vs HEAD

Generated locally on Debian 13 (trixie) with flawfinder 2.0.20, semgrep 1.173.0 and valgrind 3.24.0, via `scripts/collect_security_data.sh v1-vulnerable HEAD`. HEAD moves, so its exact SHA is recorded in `.security-report/HEAD/commit.txt` rather than pinned here.

## Why a second vulnerable tag

At `v0-vulnerable` the gate blocked, and the whole block came from Valgrind. Both static probes exited 0:

```
.security-report/v0-vulnerable/gate-probes.txt
flawfinder_block_exit=0
semgrep_block_exit=0
```

That is a real result — a general-purpose dynamic analyzer caught a leak no vendored rule matched — but it left half the gate as an untested claim. The README sells four engines; only one had ever refused a commit. `v1-vulnerable` plants defects the *static* engines block on, so the other path has evidence behind it too.

| Ref | Commit | Static gate | Flawfinder probe | Semgrep probe | Valgrind | ASan run |
|---|---|---|---|---|---|---|
| `v0-vulnerable` | `72d0268` (2026-08-23) | **BLOCKED, exit 1** | exit 0 | exit 0 | **blocks** (exit 7) | clean, exit 0 |
| `v1-vulnerable` | `b27a04d` (2026-09-02) | **BLOCKED, exit 1** | **exit 1 — blocks** | **exit 1 — blocks** | **blocks** (exit 7) | **abort, exit 134** |
| `HEAD` (main) | see `HEAD/commit.txt` | **scan clean, exit 0** | exit 0 | exit 0 | clean, exit 0 | clean, exit 0 |

Every engine in the gate has now demonstrably refused a commit, on one tag or the other.

## The planted defects

The tagged file is 112 lines. Both defects are reachable from the REPL's own input.

### C1 — Buffer overflow, CWE-120 / CWE-787 (`src/vuln_shell.c:16`)

```c
static char last_command[HISTORY_SIZE];        /* 32 bytes, line 11 */

static void record_history(const char* input) {
  strcpy(last_command, input);                 /* line 16 */
}
```

`record_history()` is called from the main loop (line 89) with the raw `getline` buffer, before `parse_input` tokenizes it. Any typed line longer than 31 characters writes past the end of a 32-byte global.

### C2 — Externally-controlled format string, CWE-134 (`src/vuln_shell.c:21`)

```c
static void show_history(const char* format) {
  printf(format, last_command);                /* line 21 */
}
```

Reached by the `history` builtin (line 99), which hands its first argument straight through as the format:

```c
show_history(parsed_args[1] == NULL ? "%s" : parsed_args[1]);
```

So `history %p` prints an address. The payload does exactly that, and the ASan run captured it: `0x560b3cac1c20`, the load address of a global under PIE.

### Why the compiler does not catch either one first

This is the part worth knowing, because a planted defect the build rejects never reaches a scanner, and both compilers build this file cleanly under `-Wall -Wextra -Werror -pedantic -Wformat -Wformat-security`.

- **C2 survives `-Wformat-security`** because that warning fires on a non-literal format with *no* arguments. `show_history` passes one. The warning that would catch it, `-Wformat-nonliteral`, is not in `CFLAGS`.
- **C1 survives `-Wstringop-overflow`** because the source is a `const char*` parameter whose length GCC cannot see at compile time. `-D_FORTIFY_SOURCE=3` does not go away, though: it moves the check to runtime, where it aborts.

Neither is an argument for adding `-Wformat-nonliteral`; it is noisy on correct code, which is why it is not in `-Wall`. It is an argument for not assuming the build is the whole gate.

## What each engine caught at `v1-vulnerable`

14 findings total: flawfinder 6, semgrep 8. **Four are at `error`**, and those four are what block.

| Engine | Rule | Line | Level | Verdict |
|---|---|---|---|---|
| Flawfinder | `FF1001` `strcpy` [MS-banned] (CWE-120) | 16 | **error** | **True positive — C1.** Blocks: `--error-level=4`. |
| Semgrep | `raptor-insecure-api-strcpy-strcat` | 16 | **error** | **True positive — C1.** Blocks: `--severity=ERROR --error`. |
| Flawfinder | `FF1016` printf format string (CWE-134) | 21 | **error** | **True positive — C2.** Non-literal format, so rated level 4 rather than the level 2 a constant gets. |
| Semgrep | `raptor-format-string-bugs` | 21 | **error** | **True positive — C2.** |
| Semgrep | `raptor-interesting-api-calls` | 16, 30, 34, 46, 51 | warning | Audit candidates (`strcpy`, `strtok_r`, `fork`, `execvp`). By design, not defects. |
| Flawfinder | `FF1013` statically-sized array (CWE-119!/CWE-120) | 11 | note | Points at `last_command` itself. Correct in hindsight, but it fires on every fixed-size array. |
| Flawfinder | `FF1016` printf format string | 72, 78 | note | False positives: both formats are constants. |
| Flawfinder | `FF1022` `strlen` over-read (CWE-126) | 86 | note | False positive: `getline` guarantees NUL termination. |
| Semgrep | `raptor-mismatched-memory-management` | 109 | note | False positive: `free()` on a `getline` buffer. Written up in `.semgrep/rules/NOTICE.md`. |

Note the contrast with `v0-vulnerable`, where all 15 findings sat at `warning` or below and the static probes therefore passed. Severity, not finding count, is what the gate reads.

## What the dynamic engines actually did

This is where the result is more interesting than "Valgrind blocked it too."

**Valgrind blocked, but not as Memcheck.** `last_command` is a global. Memcheck instruments the heap and does not track writes past the end of a static object, so the out-of-bounds write itself is invisible to it. What fired was Valgrind's own replacement for glibc's fortified `strcpy`:

```
*** strcpy_chk: buffer overflow detected ***: program terminated
   at 0x484D51C: VALGRIND_PRINTF_BACKTRACE (valgrind.h:6818)
   by 0x4853369: __strcpy_chk (vg_replace_strmem.c:1619)
   by 0x109223: strcpy (string_fortified.h:81)
   by 0x109223: record_history (vuln_shell.c:16)
   by 0x109223: main (vuln_shell.c:89)
```

That is `_FORTIFY_SOURCE=3`'s check running inside Valgrind's `vg_replace_strmem.c`, not a Memcheck bounds finding. Take the hardening flag away and Valgrind would have nothing to say about C1.

**The 240-byte still-reachable block is a consequence, not a defect.** `valgrind.log` reports `240 bytes in 1 blocks are still reachable ... getdelim`. That is the `getline` buffer, unfreed because the process aborted at line 16 and never reached the `free()` at the end of `main`. It is not a second planted leak, and it disappears at HEAD.

**ASan reported nothing; glibc got there first.** The ASan build aborts with exit 134 and a single line:

```
*** buffer overflow detected ***: terminated
```

No `global-buffer-overflow` report, no redzone trace. glibc's `__strcpy_chk` aborts before AddressSanitizer's instrumentation gets to describe the write. The hardening flag preempts the sanitizer, which is good for a shipped binary and worse for a diagnosis: had this been a real investigation, the useful output would have needed a build with `_FORTIFY_SOURCE` disabled.

This is the mirror image of `v0-vulnerable`, where LeakSanitizer's global-root suppression stayed silent and Valgrind was the one with something to say. Neither dynamic engine dominates the other. That is the argument for running both.

## The hook rejects this commit

The tag exists only because `git commit --no-verify` created it. The unforced attempt was made first and rejected:

```
$ git commit -m "test: this commit must be rejected"
pre-commit: build, security gate
BLOCKED: see .security/*.sarif and .security/valgrind.log
*** strcpy_chk: buffer overflow detected ***: program terminated
BLOCKED: the security gate found something. See .security/*.sarif.
$ git log --oneline -1
341221c fix: make the gate and the collector fail closed   # nothing landed
```

This is also the first commit the hook has ever refused for real, for an unglamorous reason: `.githooks/pre-commit` was `100644` in the index. The repository has `core.fileMode=false` set locally, so `chmod +x` on the working copy changed nothing git would record, and a fresh clone running `make hooks` got a `core.hooksPath` pointing at a file git silently skips. Fixed with `git update-index --chmod=+x`. `scripts/collect_security_data.sh` had the same problem, which meant the CI release job could only ever have failed with "permission denied".

## Reproduce and retrieve

```bash
scripts/collect_security_data.sh v1-vulnerable HEAD
```

The v0 analysis, and the reasoning for freezing each vulnerable state as a tag rather than a branch, are in [`security-report-v0-vulnerable.md`](security-report-v0-vulnerable.md).
