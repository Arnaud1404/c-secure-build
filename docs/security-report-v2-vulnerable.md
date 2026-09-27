# Security report: `v2-vulnerable` vs `v2-patched`

Generated locally against glibc 2.41, with flawfinder 2.0.20, semgrep 1.173.0 and valgrind 3.24.0, via `scripts/collect_security_data.sh v2-vulnerable v2-patched`. Both refs are frozen tags, so every number below is reproducible rather than measured against a moving branch. A rerun on 27 September 2026 gave the same numbers with glibc 2.43 and valgrind 3.27.1. The log excerpts are from the first run.

Every `src/vuln_shell.c:N` cited below resolves against [`src/vuln_shell.c.bak`](../src/vuln_shell.c.bak), a byte-for-byte mirror of `v2-vulnerable:src/vuln_shell.c` that CI asserts still matches the tag. The `.bak` suffix keeps it out of the gate, since neither static engine parses that extension as C. The patched version is [`src/hardened_shell.c`](../src/hardened_shell.c), which `main` builds.

## Why this tag exists

An earlier fixture planted two defects, and both static engines caught both of them. That left Valgrind and AddressSanitizer with nothing to prove: every defect in the tree was already blocked before they ran. `.semgrep/rules/NOTICE.md` claimed the missing-`free()` gap was "caught by the Valgrind gate in `scripts/scan.sh` instead", but the leak it referred to had been deleted from the source nine days before that sentence was written.

`v2-vulnerable` keeps the two static defects and adds two more that neither static engine can see, so every engine now has at least one defect only it, or only its half of the pipeline, reports.

| Ref | Commit | Gate (`scan.sh`) | Flawfinder block pass | Semgrep block pass | Valgrind | ASan run |
|---|---|---|---|---|---|---|
| `v2-vulnerable` | `319ddf6` | **BLOCKED, exit 1** | **exit 1, blocks** | **exit 1, blocks** | **blocks** (exit 7) | **leak, exit 1** |
| `v2-patched` | `40b8ce7` | **scan clean, exit 0** | exit 0 | exit 0 | clean, exit 0 | clean, exit 0 |

Valgrind exits 7 here because the collector passes `--error-exitcode=7`; `scripts/scan.sh` passes 1 and blocks on any non-zero. Both numbers mean the same verdict.

## The engine matrix

I measured every cell below.

| Defect | Flawfinder | Semgrep (49 rules) | Valgrind | ASan + UBSan |
|---|---|---|---|---|
| C1 `strcpy` into a 32-byte global | **error, blocks** | **error, blocks** | not triggered | not triggered |
| C2 externally-controlled format | **error, blocks** | **error, blocks** | silent | silent |
| C3 heap blocks leaked | silent | silent | **definitely lost** | **LeakSanitizer** |
| C4 branch on uninitialised heap | silent | silent | **conditional jump** | **silent, exit 0** |

C4 is the row that justifies running both dynamic engines: the only defect exactly one engine reports, and the answer to "you already run AddressSanitizer, why also run Valgrind". ASan does not detect uninitialised reads at all; that is MemorySanitizer, which cannot combine with `-fsanitize=address`.

C1's two dynamic cells say **not triggered**: the test input never types a line long enough to overflow the buffer, and that is on purpose. Valgrind reports three errors here, all of them C3 and C4, and ASan reports the leak alone. [Why the input stops short of C1](#why-the-input-stops-short-of-c1) measures what happens when it does type that line.

## The planted defects

The tagged file is 152 lines. All four are reachable from the REPL's own input.

### C1: buffer overflow, CWE-120 / CWE-787 (`src/vuln_shell.c:29`)

```c
static char last_command[HISTORY_SIZE];        /* 32 bytes, line 12 */

static void record_history(const char* input) {
  strcpy(last_command, input);                 /* line 29 */
}
```

The main loop calls `record_history` at line 123 with the raw `getline` buffer, before anything splits it, so any typed line longer than 31 characters writes past the end of a 32-byte global.

### C2: externally-controlled format string, CWE-134 (`src/vuln_shell.c:39`)

```c
static void show_history(const char* format) {
  printf(format, last_command);                /* line 39 */
}
```

The `history` builtin hands its first argument straight through as the format:

```c
show_history(parsed_args[1] == NULL ? "%s" : parsed_args[1]);
```

So `history %p` prints an address. The test input does exactly that.

### C3: missing release of memory, CWE-401 (`src/vuln_shell.c:32`)

```c
static char* history[HISTORY_SLOTS];     /* 4 slots, line 13 */

int slot = history_count % HISTORY_SLOTS;
history[slot] = strdup(input);           /* line 32: overwrites without freeing */
slot_used[slot] = 1;
history_count++;
```

A four-slot ring. Once it wraps, each `strdup` overwrites the only surviving pointer to the previous string. The test input is seven lines, and `record_history` runs before the builtin dispatch, so `exit` is recorded like any other input: seven `strdup`s into four slots leave the first three blocks unreachable while the process is still running. Those three are `pwd`, `recall 3` and `history %p`, 24 bytes in total, which is the figure both dynamic engines report below.

That "while still running" is what makes the defect usable. Both engines report a block a live global still points at as *still reachable*, the weakest leak class, which correct programs produce too and LeakSanitizer ignores by default. Overwriting the pointer makes the blocks **definitely lost**, so both engines report the same 24 bytes in 3 objects.

### C4: use of uninitialised variable, CWE-457 (`src/vuln_shell.c:50`)

```c
static int* slot_used;

slot_used = malloc(HISTORY_SLOTS * sizeof(int));   /* line 19: not calloc */

if (!slot_used[slot] || history[slot] == NULL)     /* line 50 */
```

The occupancy flags come from `malloc` rather than `calloc`, so every slot the session has not written yet holds whatever was already in that memory. `recall 3` after two commands reads one of them.

**The code tests the flag before the pointer on purpose.** An earlier version made the *pointer* table the uninitialised allocation, and `recall_slot()` dereferenced whatever it found. Valgrind reads that as a clean uninitialised-value report. Under ASan, though, the slot holds the `0xbe` malloc fill pattern:

```
==56253==ERROR: AddressSanitizer: SEGV on unknown address (pc ... bp 0xbebebebebebebebe ...)
    #5 in recall_slot src/vuln_shell.c:52
```

That killed the run before C1, C2 and C3 were reached, trading a precise finding for a crash. Testing an `int` flag keeps the read genuinely uninitialised. The pointer table stays safe to consult, since it is a `static` array and so zero-initialised.

### Why the compiler catches none of them

Both compilers build this file cleanly under `-Wall -Wextra -Werror -pedantic -Wformat -Wformat-security`, which is the precondition for reaching a scanner at all.

- **C1 survives `-Wstringop-overflow`** because the source is a `const char*` parameter whose length GCC cannot know while compiling. `-D_FORTIFY_SOURCE=3` moves that check to run time, where it stops the program instead.
- **C2 survives `-Wformat-security`**, which only fires on a non-literal format with *no* arguments. `show_history` passes one. The warning that would catch it is `-Wformat-nonliteral`, which is not in `CFLAGS` and not in `-Wall` either, because it is noisy on correct code.
- **C4 survives `-Wmaybe-uninitialized`** because the allocation and the read sit behind a file-scope pointer. An earlier draft put `malloc` and the read in one function; GCC 14 inlined it and rejected the build with `‘p[3]’ may be used uninitialized`. Routing through a global is what GCC cannot follow, and is also how the bug occurs in real code.
- **C3 is not a compiler diagnostic** in any configuration. Reachability of a heap block at exit is a whole-program property.

## What each engine caught at `v2-vulnerable`

23 findings total: flawfinder 10, semgrep 13. **Four at `error`**, and those four are what block.

| Engine | Rule | Line | Level | Verdict |
|---|---|---|---|---|
| Flawfinder | `FF1001` `strcpy` [MS-banned] (CWE-120) | 29 | **error** | **True positive, C1.** Blocks: `--error-level=4`. |
| Semgrep | `raptor-insecure-api-strcpy-strcat` | 29 | **error** | **True positive, C1.** Blocks: `--severity=ERROR --error`. |
| Flawfinder | `FF1016` printf format string (CWE-134) | 39 | **error** | **True positive, C2.** |
| Semgrep | `raptor-format-string-bugs` | 39 | **error** | **True positive, C2.** |
| Semgrep | `raptor-unchecked-ret-malloc` | 32 | warning | Fires on the `strdup` *return value*, not on the leak. Adjacent, not the defect. |
| Semgrep | `raptor-integer-wraparound` | 19 | warning | False positive on the `malloc` size expression. |
| Semgrep | `raptor-interesting-api-calls` | 19, 29, 62, 66, 78, 83 | warning | Audit candidates. By design, not defects. |
| Semgrep | `raptor-insecure-api-ato` | 138 | note | `atoi` on the slot argument. Real but not the planted defect. |
| Semgrep | `raptor-mismatched-memory-management` | 148, 149 | note | False positives on `getline`/`malloc` buffers. Written up in `.semgrep/rules/NOTICE.md`. |
| Flawfinder | `FF1013`, `FF1016`, `FF1022`, `FF1047` | 12, 46, 51, 53, 106, 112, 120, 138 | note | Fixed-size arrays, constant formats, `strlen` over-read, `atoi`. |

**Nothing at any severity points at C3 or C4.** Line 32 draws a warning about the unchecked `strdup` return, a different bug that shares a line. Line 50, the branch C4 is about, draws nothing at all, and that is the measurement the tag exists to produce.

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

The origin line comes from `--track-origins=yes`, which the collector passes and `scripts/scan.sh` does not. The gate blocks either way; the pre-commit output names the branch without naming the allocation.

**ASan reports C3 and is silent on C4.**

```
ERROR: LeakSanitizer: detected memory leaks
Direct leak of 24 byte(s) in 3 object(s) allocated from:
    #1 in record_history src/vuln_shell.c:32
SUMMARY: AddressSanitizer: 24 byte(s) leaked in 3 allocation(s).
```

Same 24 bytes, same 3 objects, same line as Valgrind, which is useful corroboration. And nothing about line 50. Exit 1.

## Why the input stops short of C1

Typing the 200-character line that overflows `last_command` kills the process on the spot, before the leak and the uninitialised read ever happen. Both measurements below come from this same tag, run again with that line put back into the input.

**Valgrind stops the program, but not as Memcheck.** `last_command` is a global. Memcheck watches the heap and does not track writes past the end of a global, so the overflow itself is invisible to it. What fired is Valgrind's own stand-in for glibc's hardened `strcpy`:

```
*** strcpy_chk: buffer overflow detected ***: program terminated
   at 0x484D51C: VALGRIND_PRINTF_BACKTRACE (valgrind.h:6818)
   by 0x4853369: __strcpy_chk (vg_replace_strmem.c:1619)
   by 0x10927F: strcpy (string_fortified.h:81)
   by 0x10927F: record_history (vuln_shell.c:29)
   by 0x10927F: main (vuln_shell.c:123)
```

Exit 7, and the rest of the run never happens: no conditional jump for C4, no definitely-lost blocks for C3, only three still-reachable ones left by a process that died early. Take `-D_FORTIFY_SOURCE=3` away and Valgrind has nothing to say about C1 at all.

**ASan says almost nothing, because glibc gets there first.** The same input against the ASan build gives exit 134 and a single line of output, from glibc rather than from ASan:

```
*** buffer overflow detected ***: terminated
```

No `global-buffer-overflow` report, no description of the write. glibc's `__strcpy_chk` calls `abort()` before AddressSanitizer's instrumentation can say anything, and since an abort is not a clean exit, LeakSanitizer's end-of-run check never runs either. The leak goes unreported too.

One defect hides the other three, so the long line stays out of the input. Both static engines still block C1 at `error`, so nothing about it goes unproven. The general point is worth keeping. A hardening flag that stops an attack also destroys the evidence. That is the right trade for a shipped binary and the wrong one for a program you are trying to debug.

## What the fix changed

`v2-patched` repairs all four **in place**: the `history`/`recall` feature still works, I deleted nothing to make the gate pass, and the whole remediation is **15 insertions, 9 deletions**.

| Defect | Fix | Why that fix |
|---|---|---|
| C1 | `strcpy` → `snprintf(last_command, sizeof(last_command), "%s", input)` | Always NUL-terminates. `strncpy` would not when the source fills the buffer. |
| C2 | `show_history(const char*)` → `show_history(void)`, format is a literal | The call site stops forwarding `parsed_args[1]` entirely. Removing the channel beats sanitising it. |
| C3 | `free(history[slot])` before the overwrite, plus a free loop at exit | The ring makes the blocks unreachable at the overwrite, so freeing at exit alone comes too late. |
| C4 | `malloc` → `calloc` | The read is legitimate; the allocation was the bug. |

Re-measured with the same three tools on the same test input:

| | `v2-vulnerable` | `v2-patched` |
|---|---|---|
| findings total | 23 | **23** |
| at `error` | 4 | **0** |
| at `warning` | 8 | 8 |
| at `note` | 11 | 15 |
| gate / flawfinder / semgrep | 1 / 1 / 1 | **0 / 0 / 0** |
| Valgrind / ASan | 7 / 1 | **0 / 0** |

**The finding count does not move**, and all four `error`-level results are gone:

| Gone | Appeared |
|---|---|
| `FF1001` `strcpy` (error, C1) | `FF1019` (note) |
| `raptor-insecure-api-strcpy-strcat` (error, C1) | `raptor-signed-unsigned-conversion` (warning) |
| `raptor-format-string-bugs` (error, C2) | `raptor-mismatched-memory-management` ×2 (note) |
| `raptor-integer-wraparound` (warning, false positive on the `malloc` size) | |

One finding changed severity instead of disappearing. `FF1016`, the printf format string at C2, drops from **error to note**: the call still hands a format to `printf`, but the format is a literal now, and Flawfinder rates a constant format at level 2 rather than the level 4 a non-literal gets. That is the fourth `error` accounted for, and the fourth new `note`.

So the three levels move like this: `error` loses three findings outright and downgrades a fourth, `warning` loses `raptor-integer-wraparound` and gains `raptor-signed-unsigned-conversion`, and `note` gains the `FF1016` downgrade plus three new hits.

The two new `raptor-mismatched-memory-management` hits are the `getline`/`free` false positive already in `.semgrep/rules/NOTICE.md`; the free loop gave that rule two more places to fire. Fixing four real defects made the raw count go *up* in one rule and stay flat overall, which is the point: "how many findings did you fix" is not a question the numbers answer.

## CI expects this tag to block

The first vulnerable fixture turned the Actions run red, and for the wrong reason. The `Enforce the gate` step only ran `if: steps.gate.outputs.code != '0'`, so:

- gate blocks the fixture (exit 1) → step runs → job red, despite the pipeline working as designed
- gate stops detecting the planted defects (exit 0) → step **skipped** → job **green**

The regression the fixture exists to catch was the one case it could not report. The gate now derives its expected verdict from the ref: a `*-vulnerable` tag must block, every other ref must come back clean, and exit 2 is a broken scanner in both directions. A missing gate output is read as 2.

## The hook rejects this commit

The tag exists only because `git commit --no-verify` created it. I ran the unforced commit first, and the hook rejected it:

```
$ git commit -m "test: this commit must be rejected"
pre-commit: build, security gate
BLOCKED: see .security/*.sarif and .security/valgrind.log
==59651== Conditional jump or move depends on uninitialised value(s)
==59651==    at 0x109417: recall_slot (vuln_shell.c:50)
==59651== 24 bytes in 3 blocks are definitely lost in loss record 1 of 2
BLOCKED: the security gate found something. See .security/*.sarif.
$ git log --oneline -1
e21b852 fix: assert the gate blocks at vulnerable tags instead of failing open   # nothing landed
```

The log the hook prints is Valgrind's, and it names C3 and C4, which neither static engine sees. Valgrind is not repeating what the static engines already said. C1 and C2 blocked in the same run, through the two SARIF block passes.

That hook ran the three-engine gate. Since `3279ea5`, `scripts/scan.sh` also runs the ASan build on the test input and blocks on any report, so the same commit today would also print LeakSanitizer's report of C3 above Valgrind's log.

## Reproduce

```bash
scripts/collect_security_data.sh v2-vulnerable v2-patched
```
