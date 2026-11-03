#!/usr/bin/env bash
# Checks that the linked binary carries the protections listed in the README.
# Some of them (BIND_NOW, CET) are also Ubuntu toolchain defaults, so a pass
# says what the binary has, not which flag put it there.
# Build it with `make ASAN=0` first: the default build adds the sanitizers and
# drops FORTIFY, so it is not the hardened binary.
# Usage: tests/hardening_test.sh BINARY
# Exits 1 if a protection is missing.
set -u

if [ "$#" -ne 1 ]; then
    echo "usage: $0 BINARY" >&2
    exit 2
fi

bin="$1"
failed=0

check() {
    if printf '%s\n' "$2" | grep -qE "$3"; then
        echo "ok: $1"
    else
        echo "FAIL: $1" >&2
        failed=1
    fi
}

header="$(readelf -hW "$bin")" || exit 2
segments="$(readelf -lW "$bin")" || exit 2
dynamic="$(readelf -dW "$bin")" || exit 2
symbols="$(readelf --dyn-syms -W "$bin")" || exit 2

check "PIE" "$header" 'Type:[[:space:]]+DYN'
check "RELRO segment" "$segments" 'GNU_RELRO'
check "BIND_NOW, so RELRO covers the GOT" "$dynamic" '\(FLAGS\).*BIND_NOW|\(BIND_NOW\)'
check "stack canary" "$symbols" '__stack_chk_fail'
check "FORTIFY: checked printf calls" "$symbols" '__(sn)?printf_chk'
check "non-executable stack" "$segments" 'GNU_STACK([[:space:]]+0x[0-9a-f]+){5}[[:space:]]+RW[[:space:]]'
if [ "$(uname -m)" = x86_64 ]; then
    check "CET: IBT and SHSTK" "$(readelf -nW "$bin")" 'IBT, SHSTK'
fi

exit "$failed"
