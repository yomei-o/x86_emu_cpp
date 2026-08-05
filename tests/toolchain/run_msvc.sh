#!/bin/sh
# Runs the Visual Studio toolchain *inside* the emulator and checks the result
# against the same toolchain run natively.
#
# This is the strongest test in the tree, and not because compilers are large: it
# is the strongest because the answer is checkable to the byte.  cl.exe is
# deterministic apart from the timestamp it stamps into the object header, so an
# emulated build that differs from a native one anywhere else has a real bug -
# and one that is otherwise invisible, since a compiler with a subtly wrong hook
# still prints nothing and exits 0.  Noticing that `.chks64` was missing from the
# object is how the absence of CNG hashing turned up.
#
# The second case exercises the process machinery for real: `cl hello.c` writes a
# response file, spawns link.exe as a child, waits for it, and deletes the file.
#
# Skips itself when no Visual Studio is installed, which is why it is a separate
# script rather than part of run_tests.sh.
set -e
cd "$(dirname "$0")/../.."
emu=./x86emu
[ -x "$emu" ] || emu=./x86emu.exe

# Paths reach the guest as strings and the guest resolves them itself, so
# everything here has to be spelled the way Windows spells it.  A shell-style
# /c/... prefix means nothing to cl.exe, and what it does instead of failing
# cleanly is report an internal compiler error from its include cache.
program_files=$(echo "${PROGRAMFILES:-C:/Program Files}" | tr '\\' /)
program_files_x86="C:/Program Files (x86)"

find_msvc() {
    for root in "$program_files/Microsoft Visual Studio"/*/*/VC/Tools/MSVC/*; do
        [ -x "$root/bin/Hostx64/x64/cl.exe" ] && echo "$root" && return 0
    done
    return 1
}
find_sdk() {
    for inc in "$program_files_x86/Windows Kits/10/Include"/*; do
        [ -d "$inc/ucrt" ] && echo "$inc" && return 0
    done
    return 1
}

msvc=$(find_msvc) || { echo "MSVC toolchain: skipped (no Visual Studio found)"; exit 0; }
sdk_inc=$(find_sdk) || { echo "MSVC toolchain: skipped (no Windows SDK found)"; exit 0; }
sdk_lib=$(echo "$sdk_inc" | sed 's|/Include/|/Lib/|')

export INCLUDE="$msvc/include;$sdk_inc/ucrt;$sdk_inc/shared;$sdk_inc/um;$sdk_inc/winrt"

# The scratch directory sits inside the tree rather than under /tmp, because the
# guest must be able to open it by the name we hand it, and a shell's idea of
# /tmp is not a path Windows resolves.
rm -rf tests/toolchain/.work
mkdir -p tests/toolchain/.work/build
here=$(pwd -W 2>/dev/null || pwd)
work="$here/tests/toolchain/.work"
cat > "$work/build/hello.c" <<'EOF'
#include <stdio.h>
int main(void) {
    printf("hello from cl\n");
    return 0;
}
EOF

pass=0
fail=0
report() {
    if [ "$1" = ok ]; then
        echo "  ok    $2"
        pass=$((pass + 1))
    else
        echo "  FAIL  $2"
        fail=$((fail + 1))
    fi
}

# Both architectures of the same toolset: x64 (Hostx64/x64) and x86
# (Hostx86/x86).  The 32-bit cl is not a smaller test - it is a different
# guest entirely (PE32, int 0x80-era CRT conventions, 32-bit NT structures),
# and every bug it has found so far was invisible to the 64-bit run.
run_arch() {
    arch=$1
    export LIB="$msvc/lib/$arch;$sdk_lib/ucrt/$arch;$sdk_lib/um/$arch"
    cl="$msvc/bin/Host$arch/$arch/cl.exe"
    [ "$arch" = x64 ] && cl="$msvc/bin/Hostx64/x64/cl.exe"
    [ "$arch" = x86 ] && cl="$msvc/bin/Hostx86/x86/cl.exe"
    [ -x "$cl" ] || { echo "  skip  $arch (no cl.exe)"; return 0; }
    echo "MSVC toolchain, $arch (emulated cl.exe/link.exe vs. native)"

# Both builds happen in the same directory, because the object records the
# absolute path of its own source in .debug$S: compiling one file from two
# directories legitimately produces two different objects.  The only byte that
# may differ is the COFF TimeDateStamp at offset 4, which differs between any two
# builds including two native ones.
(cd "$work/build" && "$here/$emu" "$cl" -nologo -c hello.c >/dev/null 2>&1)
mv "$work/build/hello.obj" "$work/emulated.obj"
(cd "$work/build" && "$cl" -nologo -c hello.c >/dev/null 2>&1)
mv "$work/build/hello.obj" "$work/native.obj"
if cmp -s -n 4 "$work/emulated.obj" "$work/native.obj" &&
   cmp -s -i 8 "$work/emulated.obj" "$work/native.obj"; then
    report ok "cl -c hello.c (object identical to native, timestamp aside)"
else
    report FAIL "cl -c hello.c (object differs from native)"
fi

# Compile and link, which makes cl spawn link.exe as a child process, then run
# what came out - under the emulator, not natively.  That is the stronger check
# and the portable one: nothing in this script then depends on the host being
# Windows, which is the point of emulating the toolchain in the first place.
(cd "$work/build" && rm -f hello.exe && "$here/$emu" "$cl" -nologo hello.c >/dev/null 2>&1)
if [ -f "$work/build/hello.exe" ]; then
    got=$("$emu" "$work/build/hello.exe" 2>&1 || true)
    if [ "$got" = "hello from cl" ]; then
        report ok "cl hello.c (linked through a child link.exe; the result runs)"
    else
        report FAIL "cl hello.c (linked, but the result printed <$got>)"
    fi
else
    report FAIL "cl hello.c (no executable produced)"
fi

# The same two checks for C++, which is a different exercise entirely: the front
# end becomes c1xx.dll, iostream headers push the compile beyond two billion
# instructions, and c2.dll throws C++ exceptions internally - it was the guest
# that found the chained-unwind-info bug.  This is the slow part of the suite
# (a couple of minutes); set X86EMU_SKIP_CPP=1 to leave it out.
if [ -z "$X86EMU_SKIP_CPP" ]; then
    cat > "$work/build/hi.cpp" <<'EOF'
#include <iostream>
#include <vector>
int main() {
    std::vector<int> v{3, 1, 2};
    int sum = 0;
    for (int x : v) sum += x;
    std::cout << "hello from C++ cl: " << sum << "\n";
    return 0;
}
EOF
    (cd "$work/build" && "$here/$emu" "$cl" -nologo -EHsc -MT -c hi.cpp >/dev/null 2>&1)
    mv "$work/build/hi.obj" "$work/emulated-cpp.obj" 2>/dev/null || true
    (cd "$work/build" && "$cl" -nologo -EHsc -MT -c hi.cpp >/dev/null 2>&1)
    mv "$work/build/hi.obj" "$work/native-cpp.obj"
    if [ -f "$work/emulated-cpp.obj" ] &&
       cmp -s -n 4 "$work/emulated-cpp.obj" "$work/native-cpp.obj" &&
       cmp -s -i 8 "$work/emulated-cpp.obj" "$work/native-cpp.obj"; then
        report ok "cl -c hi.cpp (C++ object identical to native, timestamp aside)"
    else
        report FAIL "cl -c hi.cpp (C++ object differs from native)"
    fi

    (cd "$work/build" && rm -f hi.exe && "$here/$emu" "$cl" -nologo -EHsc -MT hi.cpp >/dev/null 2>&1)
    if [ -f "$work/build/hi.exe" ]; then
        got=$("$emu" "$work/build/hi.exe" 2>&1 || true)
        if [ "$got" = "hello from C++ cl: 6" ]; then
            report ok "cl hi.cpp (C++ compiled, linked and run in the emulator)"
        else
            report FAIL "cl hi.cpp (linked, but the result printed <$got>)"
        fi
    else
        report FAIL "cl hi.cpp (no executable produced)"
    fi
fi

    rm -rf "$work/build"/*.obj "$work/build"/*.exe "$work"/*.obj
}

run_arch x64
run_arch x86

rm -rf tests/toolchain/.work
echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
