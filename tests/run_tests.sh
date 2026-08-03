#!/bin/sh
# Runs every test binary under the emulator.
#
# The PE programs also run natively on Windows, so those are checked by diffing
# the emulated output against the real thing - the strongest check available.
# The ELF programs cannot run here, so their output is compared with a recorded
# expectation instead.
set -e
cd "$(dirname "$0")/.."
emu=./x86emu.exe
[ -x "$emu" ] || emu=./build/x86emu.exe
[ -x "$emu" ] || { echo "build the emulator first"; exit 1; }

tmp="${TMPDIR:-/tmp}"
pass=0
fail=0

check_native() {                # check_native <exe>
    exe=$1
    # `|| rc=$?` keeps a non-zero guest exit from tripping `set -e`.
    nrc=0; "$exe" > "$tmp/native.out" 2>&1 || nrc=$?
    erc=0; "$emu" "$exe" > "$tmp/emu.out" 2>&1 || erc=$?
    if cmp -s "$tmp/native.out" "$tmp/emu.out" && [ "$nrc" = "$erc" ]; then
        echo "  ok    $exe (matches native, exit $nrc)"
        pass=$((pass + 1))
    else
        echo "  FAIL  $exe (native exit $nrc, emulated exit $erc)"
        diff "$tmp/native.out" "$tmp/emu.out" | head -20 || true
        fail=$((fail + 1))
    fi
}

check_expected() {              # check_expected <exe> <expected-exit> <expected-file>
    exe=$1; want_rc=$2; want=$3
    erc=0; "$emu" "$exe" > "$tmp/emu.out" 2>&1 || erc=$?
    if cmp -s "$want" "$tmp/emu.out" && [ "$erc" = "$want_rc" ]; then
        echo "  ok    $exe (matches expectation, exit $erc)"
        pass=$((pass + 1))
    else
        echo "  FAIL  $exe (exit $erc, expected $want_rc)"
        diff "$want" "$tmp/emu.out" | head -20 || true
        fail=$((fail + 1))
    fi
}

echo "PE guests (emulated output vs. native execution)"
for exe in tests/bin/*.exe; do
    [ -f "$exe" ] || continue
    check_native "$exe"
done

echo "ELF guests (emulated output vs. recorded expectation)"
for exe in tests/bin/hello_elf32 tests/bin/hello_elf64; do
    [ -f "$exe" ] || continue
    check_expected "$exe" 7 tests/expected/hello_elf.out
done

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
