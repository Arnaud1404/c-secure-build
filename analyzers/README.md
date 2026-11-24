# analyzers/

The image `c-secure-build-analyzers` holds nine static analysis runs for the CASTLE comparison. `run.sh` runs them on one C file and keeps the raw reports. Nothing here parses or scores a finding.

```bash
make analyzers-image                       # 6.7 GB; Frama-C and cppcheck build from source
make docker-analyzers                      # builds, then runs test.sh in the image
docker run --rm -v "$PWD:/src" c-secure-build-analyzers \
    ./analyzers/run.sh FILE.c OUT/ "gcc FILE.c -o FILE -lsqlite3"
```

The third argument is the program's build command, copied from the `compile` field of `CASTLE-C250.json`. It defaults to `gcc NAME.c -o NAME`. `OUT/status` holds one `tool exit-code` line per run, and `OUT/compile` the command used.

## Versions

Latest stable release of each tool on 24 November 2026. The base is Ubuntu 26.10 (snapshot `20261124T000000Z`), the only Ubuntu release that ships GCC 16.2. It is supported until July 2027, which covers this work. The gate image stays on 24.04 so the v2 tags keep their results.

| Tool | Version | Source |
|---|---|---|
| flawfinder | 2.0.20 | PyPI, `requirements.txt` |
| Semgrep CE | 1.187.0 | PyPI, `requirements.txt` |
| cppcheck | 2.22.0 | GitHub source tarball, built with the match compiler |
| Clang static analyzer (scan-build) | 23.1.6 | LLVM release tarball, clang and scan-build only |
| GCC `-fanalyzer` | 16.2.0 | Ubuntu 26.10 `gcc-16`, linked as `gcc` and `cc` |
| Infer | 1.3.0 | GitHub release (bundles its own clang 21) |
| ESBMC | 8.8 | GitHub release, released 23 November 2026 |
| Frama-C EVA | 33.0 (Arsenic) | opam, on Ubuntu's OCaml 5.4.1, opam-repository at commit `a305f52` |

Downloads are checked by SHA-256 in the Dockerfile. Ubuntu has no current Frama-C or cppcheck package: Frama-C 25 and cppcheck 2.21 were the alternatives. `versions.sh` prints the versions from inside the image.

CASTLE published its figures with older releases (ESBMC 7.8, and Ubuntu 24.04 packages for the others). With these versions, its Table 3 is a reference point, not something this image reproduces.

## Flags, and where they come from

Where CASTLE ran a tool, `run.sh` copies the flags from its wrapper in [CASTLE-Source](https://github.com/CASTLE-Benchmark/CASTLE-Source) (`wrappers/<tool>/`). That keeps our per-tool numbers comparable with the paper's. The other tools use the defaults written below.

- cppcheck: `--enable=all --language=c --quiet --template={severity},{line},{cwe},{message}`, as in CASTLE. CASTLE's parser then drops the `information` and `style` lines, and scoring should do the same.
- Clang: `scan-build --keep-going` around the build command, as in CASTLE.
- GCC: the build command plus `-Wall -Wextra -fanalyzer`, as in CASTLE. A second run, `gcc-fanalyzer-taint`, adds `-fanalyzer-checker=taint`, which CASTLE did not use and GCC leaves off by default.
- ESBMC: `--overflow --no-unwinding-assertions --memory-leak-check --timeout 10 --multi-property --show-stacktrace`, from CASTLE's `run.py`. The wrapper's readme gives `--unwind 1 --timeout 100` instead. `run.py` is what produced the reports, so that is the version used here.
- Semgrep: CASTLE ran Semgrep Pro with `--config auto`, which needs an account and network access to the registry. Here it is Semgrep CE with this repository's rules (`.semgrep/`), offline. Expect lower recall than CASTLE reports.
- flawfinder: `--sarif --quiet`. CASTLE has no wrapper for it.
- Infer: `--pulse --liveness --starvation` on the build command with `-c` appended, because Infer's link step cannot find the objects it captured. Not in CASTLE.
- Frama-C: `-eva -then -report`. Not in CASTLE.

Every run gets 120 s (`ANALYZER_TIMEOUT`). A timeout, a missing binary or a signal makes `run.sh` exit 2. Other exit codes are recorded as they are, because each tool uses them differently.

## Build-time libraries

Of the 250 CASTLE programs, 20 link against OpenSSL, 12 against SQLite, 9 against the MySQL client and 5 against curl. The image installs their headers, so the tools that compile the file do not stop on a missing include.

## Smoke test

`test.sh` runs everything on `samples/heap_oob.c`, a heap write one past the end on line 12. It requires all nine runs to finish, Infer to write a report, and ESBMC and EVA to flag line 12. On that file cppcheck also flags line 12, Semgrep flags the `malloc` on line 6, and flawfinder, Clang, GCC and Infer report nothing.
