#!/bin/sh
# Runs every test binary under the emulator.
#
# The PE programs also run natively on Windows, so those are checked by diffing
# the emulated output against the real thing - the strongest check available.
# The ELF programs cannot run here, so their output is compared with a recorded
# expectation instead.
set -e
cd "$(dirname "$0")/.."
# EMU lets you point at a different build, e.g. one compiled for another host.
emu=${EMU:-}
[ -n "$emu" ] || { emu=./x86emu; [ -x "$emu" ] || emu=./x86emu.exe; }
[ -x "$emu" ] || emu=./build/x86emu
[ -x "$emu" ] || { echo "build the emulator first"; exit 1; }
echo "emulator: $emu on $(uname -s) $(uname -m)"

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

# Built by tests/msvc/build.bat: a real Visual Studio toolchain, so the CRT
# startup runs before main and - with /MT - the C runtime itself executes inside
# the guest.
if ls tests/msvc/bin/*.exe >/dev/null 2>&1; then
    echo "MSVC guests (emulated output vs. native execution)"
    for exe in tests/msvc/bin/*.exe; do
        # Built, but not yet runnable, and each for a reason worth naming:
        #   exc_*        needs C++ exception unwinding
        #   cpp_*_MD*    imports std::cout as *data* from msvcp140.dll, which
        #                needs the real DLL loaded rather than hooked
        case "$exe" in
            *exc_*) continue;;
            *cpp_msvc_MD*) continue;;
        esac
        check_native "$exe"
    done
fi

echo "ELF guests (emulated output vs. recorded expectation)"
for exe in tests/bin/hello_elf32 tests/bin/hello_elf64; do
    [ -f "$exe" ] || continue
    check_expected "$exe" 7 tests/expected/hello_elf.out
done
# Built by tests/linux/build.sh: gcc against a real glibc, linked statically, so
# the libc runs inside the guest and only the kernel interface is emulated.
for bits in 64 32; do
    exe=tests/bin/hello_gcc$bits
    want=tests/expected/hello_gcc$bits.out
    if [ -f "$exe" ] && [ -f "$want" ]; then
        check_expected "$exe" 3 "$want"
    fi
done

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
