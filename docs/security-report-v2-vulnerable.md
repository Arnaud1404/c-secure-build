# Security report: `v2-vulnerable` vs `main`

Generated locally on Debian 13 (trixie) with flawfinder 2.0.20, semgrep 1.173.0 and valgrind 3.24.0, via `scripts/collect_security_data.sh v2-vulnerable main`. `main` moves, so its exact SHA is recorded in `.security-report/main/commit.txt` rather than pinned here.

## Why this tag exists

`v1-vulnerable` planted two defects, and both static engines blocked on both of them. That made the dynamic half of the pipeline decorative: nothing in the fixture justified running Valgrind or AddressSanitizer at all. `.semgrep/rules/NOTICE.md` claimed the missing-`free()` gap was "caught by the Valgrind gate in `scripts/scan.sh` instead", but the leak it referred to had been deleted from the source nine days before that sentence was written.

`v2-vulnerable` keeps the two static defects and adds two more that neither static engine can see. Each engine in the gate now has at least one defect only it, or only its half of the pipeline, reports.

| Ref | Commit | Static gate | Flawfinder probe | Semgrep probe | Valgrind | ASan run |
|---|---|---|---|---|---|---|
| `v2-vulnerable` | `b8eb690` (2026-09-03) | **BLOCKED, exit 1** | **exit 1 — blocks** | **exit 1 — blocks** | **blocks** (exit 7) | **leak, exit 1** |
| `main` | see `main/commit.txt` | **scan clean, exit 0** | exit 0 | exit 0 | clean, exit 0 | clean, exit 0 |

## The engine matrix

This is the whole point of the tag. Every cell below was measured, not assumed.

| Defect | Flawfinder | Semgrep (49 rules) | Valgrind | ASan + UBSan |
|---|---|---|---|---|
| C1 `strcpy` into a 32-byte global | **error, blocks** | **error, blocks** | fortify abort, not Memcheck | fortify preempts the report |
| C2 externally-controlled format | **error, blocks** | **error, blocks** | silent | silent |
| C3 heap blocks leaked | silent | silent | **definitely lost** | **LeakSanitizer** |
| C4 branch on uninitialised heap | silent | silent | **conditional jump** | **silent, exit 0** |

C4 is the row that earns the pipeline. It is the only defect in the set that exactly one engine reports, and it is the answer to "you already run AddressSanitizer, why also run Valgrind". ASan does not detect uninitialised reads at all; that is MemorySanitizer, which cannot be combined with `-fsanitize=address`.

## The planted defects

The tagged file is 152 lines. All four defects are reachable from the REPL's own input.

### C1 — Buffer overflow, CWE-120 / CWE-787 (`src/vuln_shell.c:29`)

Unchanged from `v1-vulnerable`. `record_history()` `strcpy`s the raw `getline` buffer into a 32-byte global.

### C2 — Externally-controlled format string, CWE-134 (`src/vuln_shell.c:39`)

Unchanged from `v1-vulnerable`. The `history` builtin hands its first argument straight through as the format.

### C3 — Missing release of memory, CWE-401 (`src/vuln_shell.c:32`)

```c
static char* history[HISTORY_SLOTS];     /* 4 slots, line 13 */

int slot = history_count % HISTORY_SLOTS;
history[slot] = strdup(input);           /* line 32: overwrites without freeing */
slot_used[slot] = 1;
history_count++;
```

The recall table is a four-slot ring. Once it wraps, each `strdup` overwrites the only surviving pointer to the previous string. The payload issues six commands, so three blocks become unreachable while the process is still running.

That "while still running" is what makes this defect usable. Blocks still referenced by a live global at exit are reported as *still reachable*, which is the weakest leak class and is what any program that exits without freeing produces, including correct ones. LeakSanitizer ignores still-reachable blocks by default. Overwriting the pointer makes them **definitely lost**, so both dynamic engines report the same 24 bytes in 3 objects.

### C4 — Use of uninitialised variable, CWE-457 (`src/vuln_shell.c:50`)

```c
static int* slot_used;

slot_used = malloc(HISTORY_SLOTS * sizeof(int));   /* line 19: not calloc */

if (!slot_used[slot] || history[slot] == NULL)     /* line 50 */
```

`history_init()` allocates the occupancy flags with `malloc` rather than `calloc`, so every slot the session has not yet written holds an indeterminate value. `recall 3` after two commands reads one of them.

**The flag is tested before the pointer on purpose.** The first version of this defect made the *pointer* table itself the uninitialised allocation, and `recall_slot()` dereferenced whatever it found. Under Valgrind that reads as a clean uninitialised-value report, but under ASan the slot holds the `0xbe` malloc fill pattern, so the dereference became a wild-pointer SEGV at the second command:

```
==56253==ERROR: AddressSanitizer: SEGV on unknown address (pc ... bp 0xbebebebebebebebe ...)
    #5 in recall_slot src/vuln_shell.c:52
```

That killed the run before C1, C2 and C3 were ever reached, and traded a precise finding for a crash. Testing an `int` flag keeps the read genuinely uninitialised while leaving the pointer table (a `static` array, so zero-initialised) safe to consult.

### Why the compiler catches none of them

Both compilers build this file cleanly under `-Wall -Wextra -Werror -pedantic -Wformat -Wformat-security`, which is the precondition for a planted defect to reach a scanner at all.

- **C1 and C2** as documented in the `v1-vulnerable` report.
- **C4 survives `-Wmaybe-uninitialized`** because the allocation and the read sit behind a file-scope pointer. An earlier draft put `malloc` and the read in the same function; GCC 14 inlined it and rejected the build with `‘p[3]’ may be used uninitialized`. Routing through a global is what GCC cannot follow, and is also how the bug occurs in real code.
- **C3 is not a compiler diagnostic** in any configuration. Reachability of a heap block at exit is a whole-program property.

## What each engine caught at `v2-vulnerable`

23 findings total: flawfinder 10, semgrep 13. **Four are at `error`**, and those four are what block. Severity, not finding count, is what the gate reads.

| Engine | Rule | Line | Level | Verdict |
|---|---|---|---|---|
| Flawfinder | `FF1001` `strcpy` [MS-banned] (CWE-120) | 29 | **error** | **True positive — C1.** Blocks: `--error-level=4`. |
| Semgrep | `raptor-insecure-api-strcpy-strcat` | 29 | **error** | **True positive — C1.** Blocks: `--severity=ERROR --error`. |
| Flawfinder | `FF1016` printf format string (CWE-134) | 39 | **error** | **True positive — C2.** |
| Semgrep | `raptor-format-string-bugs` | 39 | **error** | **True positive — C2.** |
| Semgrep | `raptor-unchecked-ret-malloc` | 32 | warning | Fires on the `strdup` *return value*, not on the leak. Adjacent, not the defect. |
| Semgrep | `raptor-integer-wraparound` | 19 | warning | False positive on the `malloc` size expression. |
| Semgrep | `raptor-interesting-api-calls` | 19, 29, 62, 66, 78, 83 | warning | Audit candidates. By design, not defects. |
| Semgrep | `raptor-insecure-api-ato` | 138 | note | `atoi` on the slot argument. Real but not the planted defect. |
| Semgrep | `raptor-mismatched-memory-management` | 148, 149 | note | False positives on `getline`/`malloc` buffers. Written up in `.semgrep/rules/NOTICE.md`. |
| Flawfinder | `FF1013`, `FF1016`, `FF1022`, `FF1047` | 12, 46, 51, 53, 106, 112, 120, 138 | note | Fixed-size arrays, constant formats, `strlen` over-read, `atoi`. |

**Nothing at any severity points at C3 or C4.** Line 32 draws a warning about the unchecked `strdup` return, which is a different bug that happens to share a line. Line 50 draws nothing at all. That is the measurement the tag exists to produce.

## What the dynamic engines did

**Valgrind reports both new defects and names the origin of C4.**

```
Conditional jump or move depends on uninitialised value(s)
   at 0x109417: recall_slot (vuln_shell.c:50)
   by 0x109417: main (vuln_shell.c:138)
 Uninitialised value was created by a heap allocation
   at 0x4844818: malloc (vg_replace_malloc.c:446)
   by 0x1091CF: history_init (vuln_shell.c:19)

24 bytes in 3 blocks are definitely lost in loss record 1 of 2
   at 0x4844818: malloc (vg_replace_malloc.c:446)
   by 0x49227E9: strdup (strdup.c:42)
   by 0x1092A1: record_history (vuln_shell.c:32)
```

The origin line comes from `--track-origins=yes`, which the dataset collector passes and `scripts/scan.sh` does not. The gate blocks either way; the pre-commit output just names the branch without naming the allocation.

**ASan reports C3 and is silent on C4.**

```
ERROR: LeakSanitizer: detected memory leaks
Direct leak of 24 byte(s) in 3 object(s) allocated from:
    #1 in record_history src/vuln_shell.c:32
SUMMARY: AddressSanitizer: 24 byte(s) leaked in 3 allocation(s).
```

Same 24 bytes, same 3 objects, same line as Valgrind, which is a useful corroboration. And nothing whatsoever about line 50. Exit 1.

**The payload deliberately stops short of triggering C1 at runtime.** Feeding the 200-character line that overflows `last_command` aborts the process through glibc's `__strcpy_chk` before LeakSanitizer's exit-time check ever runs, so ASan reported no leak at all and exited 134 with a single `*** buffer overflow detected ***`. The abort masked the two defects this tag exists to demonstrate. C1 and C2 are still blocked by both static engines at `error`, and their runtime behaviour is documented at `v1-vulnerable`, so nothing is lost by leaving the trigger out of the payload.

That trade is worth stating plainly: a hardening flag that stops an exploit also destroys the diagnosis. `_FORTIFY_SOURCE=3` is right for a shipped binary and actively unhelpful for an investigation, which is why a real triage build would disable it.

## CI expects this tag to block

`v1-vulnerable` turned the Actions run red, and for the wrong structural reason. The `Enforce the gate` step only ran `if: steps.gate.outputs.code != '0'`, so:

- gate blocks the fixture (exit 1) → step runs → job red, despite the pipeline working exactly as designed
- gate stops detecting the planted defects (exit 0) → step **skipped** → job **green**

The regression the fixture exists to catch was the one case it could not report. The gate now derives its expected verdict from the ref: a `*-vulnerable` tag must block, every other ref must come back clean, and exit 2 is a broken scanner in both directions. A missing gate output is read as 2.

## The hook rejects this commit

The tag exists only because `git commit --no-verify` created it. The unforced attempt was made first and rejected:

```
$ git commit -m "test: this commit must be rejected"
pre-commit: build, security gate
BLOCKED: see .security/*.sarif and .security/valgrind.log
==59651== Conditional jump or move depends on uninitialised value(s)
==59651==    at 0x109417: recall_slot (vuln_shell.c:50)
==59651== 24 bytes in 3 blocks are definitely lost in loss record 1 of 2
BLOCKED: the security gate found something. See .security/*.sarif.
$ git log --oneline -1
6e84423 fix: assert the gate blocks at vulnerable tags instead of failing open   # nothing landed
```

Note which findings did the blocking. At `v1-vulnerable` the hook's Valgrind output was a fortified `strcpy` abort, a consequence of C1 that the static engines had already caught. Here it is C3 and C4, neither of which anything else in the pipeline can see.

## Reproduce and retrieve

```bash
scripts/collect_security_data.sh v2-vulnerable main
```
