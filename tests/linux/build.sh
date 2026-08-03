#!/bin/sh
# Builds the statically linked Linux test binaries.  Run this on a Linux host (or
# under WSL); the compilers only have to *target* x86, they need not run on it.
#
#   CC64=x86_64-linux-gnu-gcc CC32=i686-linux-gnu-gcc sh tests/linux/build.sh
#
# Static linking is deliberate: a dynamically linked binary would need ld.so and
# a real libc on disk, whereas a static one talks straight to the kernel, which
# is the interface the emulator implements.
set -e
cd "$(dirname "$0")/../.."
out=tests/bin
mkdir -p $out

CC64=${CC64:-x86_64-linux-gnu-gcc}
CC32=${CC32:-i686-linux-gnu-gcc}
built=0

if command -v "$CC64" >/dev/null 2>&1; then
    if $CC64 -static -O1 -o $out/hello_gcc64 tests/linux/hello_gcc.c 2>$out/gcc64.log; then
        echo "   $out/hello_gcc64"
        rm -f $out/gcc64.log
        built=$((built + 1))
    else
        echo "   skip hello_gcc64 (no static x86-64 libc?); see $out/gcc64.log"
    fi
else
    echo "   skip hello_gcc64 ($CC64 not found)"
fi

if command -v "$CC32" >/dev/null 2>&1; then
    if $CC32 -static -O1 -o $out/hello_gcc32 tests/linux/hello_gcc.c 2>$out/gcc32.log; then
        echo "   $out/hello_gcc32"
        rm -f $out/gcc32.log
        built=$((built + 1))
    else
        echo "   skip hello_gcc32 (no static i686 libc?); see $out/gcc32.log"
    fi
else
    echo "   skip hello_gcc32 ($CC32 not found)"
fi

echo "built $built"
