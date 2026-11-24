#!/bin/sh
# Prints the version of every analyser in the image, for the report.
set -u
flawfinder --version | sed 's/^/flawfinder /'
semgrep --version | sed 's/^/semgrep /'
cppcheck --version
clang --version | head -1
gcc --version | head -1
infer --version | head -1
esbmc --version | head -1
printf 'frama-c %s\n' "$(frama-c -version)"
