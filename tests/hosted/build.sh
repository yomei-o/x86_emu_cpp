#!/bin/sh
# Builds the *hosted* Windows test programs: ordinary mingw-w64 executables that
# link the real C runtime and call the Win32 API directly.
#
# These differ from tests/build_pe_tests.sh, whose programs are freestanding
# (-nostdlib, own entry point, hand-made import libraries) in order to test the
# instruction decoder and import hooking in isolation.  The programs here test
# the opposite end: everything a real toolchain drags in - CRT startup, stdio,
# processes, pipes, exception tables - and each one runs natively on Windows too,
# so the check is a byte-for-byte diff against the real thing.
set -e
cd "$(dirname "$0")/../.."
out=tests/hosted/bin
mkdir -p $out

CC=${CC:-gcc}
CXX=${CXX:-g++}
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "$CC not found; skipping the hosted tests"
    exit 0
fi

echo "== building hosted test programs"
for src in tests/hosted/*.c tests/hosted/*.cpp; do
    [ -f "$src" ] || continue
    case "$src" in
        *.cpp)
            base=$(basename "$src" .cpp)
            # -static so libstdc++ and libgcc's unwinder live in the image: what
            # is under test is the emulator's unwinding, not DLL loading.
            cc="$CXX -static"
            ;;
        *)
            base=$(basename "$src" .c)
            cc="$CC"
            ;;
    esac
    # -O1 keeps the inline assembly in insns.c intact while still being readable
    # in a disassembly when something goes wrong.
    $cc -O1 -o "$out/${base}64.exe" "$src"
    echo "   $out/${base}64.exe"
    # 32-bit as well where the toolchain can do it; w64devkit cannot.
    if $cc -m32 -O1 -o "$out/${base}32.exe" "$src" 2>/dev/null; then
        echo "   $out/${base}32.exe"
    fi
done
echo "done"
