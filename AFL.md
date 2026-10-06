# Fuzzing c-secure-build with AFL++: guide and worksheet

Goal: fuzz the `v2-vulnerable` shell with AFL++, see which of the four planted defects
(C1 to C4) a fuzzer finds, under which sanitizer, and why. Then fuzz `v2-patched` as a
control. Budget: about 2 h 30, of which roughly 1 h is fuzzers running on their own.

Fill in the worksheet yourself, **before** reading the reference run at the bottom. The
point is to be able to say, honestly, "I ran it myself, here is what it found and what it
missed."

Checked on 2026-10-06 in a `fedora:44` container with the Fedora packages listed below
(AFL++ 4.35c, clang 22.1.8). Not run directly on your WSL host.

---

## 0. Safety first: the shell runs whatever it reads

`execute_command` passes every line that is not a builtin to `fork` + `execvp`. Fuzzing it
as is would run random programs with random arguments on your machine.

Fix: a fuzzing-only stub, injected at compile time without touching the source.
`-Dexecvp=fuzz_execvp` renames every `execvp` in the translation unit, including the
`<unistd.h>` prototype, and `stub_exec.c` provides the replacement. The child exits with
127 ("command not found") through `_exit`, so no atexit handler or LeakSanitizer pass runs
in the child. The `fork`/`waitpid` structure stays as it is.

This is the first rule of writing a fuzzing harness: **neutralize side effects** (network,
files, process creation) so the only thing being tested is the parsing code.

## 1. Install (about 5 min)

The Fedora package is named `american-fuzzy-lop`, but it ships AFL++ (4.35c on Fedora 44).
There is no `aflplusplus` package.

```sh
sudo dnf install american-fuzzy-lop american-fuzzy-lop-clang clang compiler-rt llvm
afl-fuzz -h | head -3          # sanity check
```

- `american-fuzzy-lop-clang`: `afl-clang-fast` (LLVM instrumentation).
- `compiler-rt`: the ASan/UBSan/MSan runtimes for clang.
- `llvm`: `llvm-symbolizer`, without which sanitizer reports have no function names.

Why clang and not `afl-gcc-fast`: on Fedora 44, the packaged GCC plugin was built for GCC
16.0.1 and refuses to load under GCC 16.2.1. Clang mode works out of the box, and it is the
only way to get MemorySanitizer, which is clang-only.

## 2. Workspace outside the repo (about 5 min)

Nothing below writes inside the repo.

```sh
mkdir -p ~/fuzz/c-secure-build && cd ~/fuzz/c-secure-build
git -C ~/github/c-secure-build show v2-vulnerable:src/vuln_shell.c > vuln_shell.c
git -C ~/github/c-secure-build show v2-patched:src/vuln_shell.c   > patched_shell.c

cat > stub_exec.c <<'EOF'
/* Fuzzing only: the shell runs every non-builtin line through execvp,
 * so the fuzzer would launch random programs. The child exits as if the
 * command were not found, without running atexit handlers. */
#include <unistd.h>

int fuzz_execvp(const char* file, char* const argv[]) {
  (void)file;
  (void)argv;
  _exit(127);
}
EOF
```

## 3. Build four targets (about 5 min)

```sh
FLAGS="-std=c17 -O1 -g -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -Dexecvp=fuzz_execvp"

AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast $FLAGS vuln_shell.c    stub_exec.c -o vuln-asan
AFL_USE_MSAN=1                 afl-clang-fast $FLAGS vuln_shell.c    stub_exec.c -o vuln-msan
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast $FLAGS patched_shell.c stub_exec.c -o patched-asan
AFL_USE_MSAN=1                 afl-clang-fast $FLAGS patched_shell.c stub_exec.c -o patched-msan

printf 'ls -la /\nexit\n' | ./vuln-asan; echo " exit=$?"   # expect two prompts, no listing, exit=0
```

Flag choices you should be able to justify:

| Choice | Why |
|---|---|
| no `_FORTIFY_SOURCE` | the project's Makefile sets `=3`, but `__strcpy_chk` aborts before ASan can report, which hides the diagnosis (same lesson as the gate's diagnostic build) |
| `-O1` | keeps reports readable and stays fast; `-O2` can inline enough to blur stack traces |
| ASan and MSan in **separate** binaries | they cannot be combined in one binary: each takes over the memory layout and the shadow |
| `afl-clang-fast` | compile-time coverage instrumentation (edges), so the fuzzer knows when an input reaches new code |

## 4. Seeds and dictionary (about 5 min)

```sh
mkdir -p seeds
printf 'pwd\n'                > seeds/01
printf 'recall 3\n'           > seeds/02
printf 'history\n'            > seeds/03
printf 'recall 0\nrecall 1\n' > seeds/04

cat > shell.dict <<'EOF'
"history"
"recall"
"exit"
" "
"\x0a"
"%s"
"%n"
"%p"
EOF
```

- **At most 4 lines per seed.** A fifth line wraps the 4-slot ring and leaks (C3). With leak
  detection on (campaign B), that seed would crash during calibration and AFL++ would
  refuse to start. That is also why `tests/vuln_shell_commands.txt` (7 lines) is not used
  as a seed.
- **Dictionary**: tokens AFL++ splices into inputs. Without `"history"`, reaching C2 takes
  much longer, because random byte flips rarely spell a keyword.

## 5. One-time host setup (WSL)

On this machine, `/proc/sys/kernel/core_pattern` pipes crashes to `systemd-coredump`.
AFL++ refuses to start in that case, because a crash handled by an external program can
be mistaken for a timeout. Pick one:

```sh
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1   # no system change, used below
# or, until the next WSL restart:
echo core | sudo tee /proc/sys/kernel/core_pattern
```

`AFL_SKIP_CPUFREQ=1` silences the CPU frequency-scaling check, which is meaningless under
WSL.

## 6. Campaigns

Each `afl-fuzz` uses one core, and you have 12, so B, C and D can run side by side in
separate terminals. `-V <seconds>` stops a campaign on its own. Start A with the full-screen
UI to see it at least once; add `AFL_NO_UI=1` to the others if you run them in the
background.

```sh
export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

# A. ASan + UBSan, AFL++ defaults (15 min)
afl-fuzz -i seeds -o out-A -x shell.dict -V 900 -- ./vuln-asan

# B. Same binary, leak detection on (15 min)
#    A custom ASAN_OPTIONS must contain abort_on_error=1 and symbolize=0, or afl-fuzz refuses it.
ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=1 \
  afl-fuzz -i seeds -o out-B -x shell.dict -V 900 -- ./vuln-asan

# C. MSan (15 min)
afl-fuzz -i seeds -o out-C -x shell.dict -V 900 -- ./vuln-msan

# D. Control: patched source, strictest settings (10 min each)
ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=1 \
  afl-fuzz -i seeds -o out-D-asan -x shell.dict -V 600 -- ./patched-asan
afl-fuzz -i seeds -o out-D-msan -x shell.dict -V 600 -- ./patched-msan
```

Numbers to read, live in the UI or afterwards in `out-*/default/fuzzer_stats`:

```sh
grep -E 'execs_done|execs_per_sec|corpus_count|bitmap_cvg|saved_crashes|saved_hangs' out-A/default/fuzzer_stats
```

If an MSan campaign aborts at start with "Fork server crashed with signal 6", rerun it
once. In the test container, MSan sometimes failed to disable ASLR at startup.

## 7. Triage: crash files are not bugs

AFL++ saves one file per crash **reaching a new path**, not per bug. Replay every file with
symbolized reports and count distinct root causes:

```sh
classify() {  # $1 = binary, $2 = crashes dir
  for f in "$2"/id*; do
    ASAN_OPTIONS=detect_leaks=1 "$1" < "$f" 2>&1 >/dev/null \
      | grep -m1 -oE '(AddressSanitizer|LeakSanitizer|MemorySanitizer): [a-zA-Z-]+|runtime error: .*'
  done | sort | uniq -c
}
classify ./vuln-asan out-A/default/crashes
classify ./vuln-asan out-B/default/crashes
classify ./vuln-msan out-C/default/crashes
```

Then read one full report per class (`./vuln-asan < FILE`) and find the source line in
frame `#0`/`#1`.

Minimize one crash to its essence:

```sh
afl-tmin -i "$(ls out-A/default/crashes/id* | head -1)" -o min.txt -- ./vuln-asan
cat -v min.txt; wc -c < min.txt
```

---

## Worksheet

### W1. Predictions (before starting the campaigns)

Write Y/N for "a crash of this class gets saved", plus one word of why.

| Defect | A: ASan default | B: ASan + leaks | C: MSan | D: patched |
|---|---|---|---|---|
| C1 `strcpy` into 32-byte global | | | | |
| C2 format string in `history` | | | | |
| C3 leak on ring overwrite | | | | |
| C4 branch on uninitialized `slot_used` | | | | |

### W2. Results

| | A | B | C | D-asan | D-msan |
|---|---|---|---|---|---|
| run time | | | | | |
| execs/s | | | | | |
| corpus_count | | | | | |
| bitmap_cvg | | | | | |
| saved_crashes (files) | | | | | |
| distinct bugs (after triage) | | | | | |
| which of C1 to C4 | | | | | |
| time to first crash (`time:` in the file name, ms) | | | | | |

### W3. Questions (answer in two or three sentences, out loud)

1. Campaign A ran with ASan, yet found no leak even though the inputs easily exceed 4
   lines. Why? (Hint: `strings $(command -v afl-fuzz) | grep detect_leaks`.)
2. Which defect does A find first and most often? Why is it the "shallowest" for a fuzzer?
3. `afl-tmin` shrinks a C1 crash to how many bytes? Why exactly that number, given
   `HISTORY_SIZE 32`?
4. How many crash files did A save, and how many distinct bugs did you count? Explain the
   gap.
5. In C, MSan finds C4. Can ASan ever find it? Which tool in the gate already does, and
   why could the gate not just use MSan instead? (Careful with your CV line "seul Valgrind
   la détecte": it is true of the gate's tools, not of every tool in existence.)
6. In C, a long line may crash in `record_history` instead of C4. Run
   `nm -n vuln-msan | grep -E ' (slot_used|last_command|history_count|history)$'`
   and explain the crash from what sits right after `last_command`. Why does the ASan
   build report this neatly instead?
7. D found nothing in 10 minutes. Does that prove `v2-patched` is bug-free? What does it
   prove?
8. Compare to the gate: which defects did the static tools see that the fuzzer also found,
   and which did only the fuzzer, or only Valgrind, see?
9. The shell forks the target for every input. What would a persistent-mode harness
   (`__AFL_LOOP`) change, and what would it require from `main`'s global state?
10. syzkaller vs what you just did: what plays the role of the input, of the coverage
    instrumentation, and of the bug oracle? (Your rump answers the last one.)
11. Where would an LLM help in this workflow: dictionary, harness, triage? Which one did
    your Juliet measurement already test?

### W4. Your lines for the interview (fill with **your** numbers only)

> « J'ai lancé AFL++ sur la version vulnérable de mon shell, avec une souche qui
> neutralise `execvp`. En ___ minutes, ___ fichiers de crash, ___ bogues distincts :
> ___. Il a fallu activer la détection de fuites pour voir C3, que AFL++ coupe par
> défaut, et un build MSan séparé pour C4. Sur la version corrigée, ___ crash en ___
> minutes : ça ne prouve pas l'absence de bogue, seulement que ces chemins-là sont
> propres. »

## Cleanup

```sh
rm -rf ~/fuzz/c-secure-build                 # when done
# if you changed core_pattern, a WSL restart restores it: wsl --shutdown (from Windows)
```

---

## Reference run (spoilers: fill W1 to W3 first)

<details>
<summary>Results from the test container, 2026-10-06, short campaigns</summary>

Fedora 44 container, AFL++ 4.35c, clang 22.1.8, same flags, seeds and dictionary as above.
Campaigns were 1.5 to 3 minutes, much shorter than yours, so your counts will differ.

| | A (180 s) | B (120 s) | C (120 s) | D-asan (120 s) | D-msan (90 s) |
|---|---|---|---|---|---|
| execs/s | 324 | 155 | 315 | 166 | 313 |
| saved_crashes | 8 | 9 | 5 | 0 | 0 |
| triage | 7 C1, 1 C2 | 7 C3, 2 C1 | 4 C4, 1 SEGV in `record_history` (long line) | none | none |
| first crash | 0.7 s (C1) | | | | |

Observations:

- A never reports C3: `afl-fuzz` sets `detect_leaks=0` unless you pass your own
  `ASAN_OPTIONS`.
- C1 dominates: any line of 32 bytes or more overflows. `afl-tmin` reduced a 61-byte crash
  to 32 bytes of `0`. 32 characters plus the NUL that `strcpy` writes makes 33 bytes in a
  32-byte buffer.
- C2 came from `history %ssss...%s`. `history %n` alone did not crash when replayed by
  hand (not investigated).
- B is about half as fast as A: the leak check runs at every exit.
- In C, two crash files sometimes failed to replay inside the container ("unable to
  disable ASLR"). On the WSL host, both replayed: one as a SEGV, one as C4.
- D: 0 crashes under both ASan with leaks and MSan.

</details>
