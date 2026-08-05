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

# Built by tests/dll/build.sh: a program plus a DLL the emulator loads for real -
# mapped, relocated, its imports bound and its DllMain run - rather than hooking.
if ls tests/dll/bin/*/usedll.exe >/dev/null 2>&1; then
    echo "Dynamic loading (emulated output vs. native execution)"
    for exe in tests/dll/bin/*/usedll.exe; do
        check_native "$exe"
    done
fi

# Built by tests/hosted/build.sh: ordinary mingw programs with the real CRT,
# the Win32 API, child processes and pipes.  Also native-diffable.
if ls tests/hosted/bin/*.exe >/dev/null 2>&1; then
    echo "Hosted Windows guests (emulated output vs. native execution)"
    for exe in tests/hosted/bin/*.exe; do
        check_native "$exe"
    done
fi

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
# These cannot run natively on a Windows host, so each has a recorded output and
# a recorded exit code in tests/expected/.  hello_elf* are hand-assembled by
# tools/gen_elf_tests.cpp; *_gcc* are gcc builds against a real static glibc,
# produced by tests/linux/build.sh.
for exe in tests/bin/hello_elf32 tests/bin/hello_elf64 tests/bin/*_gcc32 tests/bin/*_gcc64; do
    [ -f "$exe" ] || continue
    name=$(basename "$exe")
    want=tests/expected/$name.out
    want_rc_file=tests/expected/$name.exit
    if [ ! -f "$want" ]; then
        echo "  skip  $exe (no recorded output at $want)"
        continue
    fi
    want_rc=0
    [ -f "$want_rc_file" ] && want_rc=$(cat "$want_rc_file")
    check_expected "$exe" "$want_rc" "$want"
done

# A real CPython, if one is installed for the guest architecture: the strongest
# test there is, since the same interpreter runs natively for comparison.  Set
# PYTHON to point at one, or let this find the usual place.
python_exe=${PYTHON:-}
if [ -z "$python_exe" ]; then
    for candidate in /c/Python313/python.exe /c/Python312/python.exe                      "$LOCALAPPDATA/Programs/Python/Python313/python.exe"; do
        [ -x "$candidate" ] && python_exe=$candidate && break
    done
fi
if [ -n "$python_exe" ] && [ -x "$python_exe" ]; then
    echo "CPython (emulated output vs. native execution)"
    nrc=0; "$python_exe" tests/python/smoke.py > "$tmp/native.out" 2>&1 || nrc=$?
    erc=0; "$emu" "$python_exe" tests/python/smoke.py > "$tmp/emu.out" 2>&1 || erc=$?
    if cmp -s "$tmp/native.out" "$tmp/emu.out" && [ "$nrc" = "$erc" ]; then
        echo "  ok    tests/python/smoke.py (matches native, exit $nrc)"
        pass=$((pass + 1))
    else
        echo "  FAIL  tests/python/smoke.py (native exit $nrc, emulated exit $erc)"
        diff "$tmp/native.out" "$tmp/emu.out" | head -20 || true
        fail=$((fail + 1))
    fi
else
    echo "CPython: skipped (no interpreter found; set PYTHON=/path/to/python.exe)"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
