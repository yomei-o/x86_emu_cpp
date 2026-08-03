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

# Every .c here is built for whichever targets have a static libc available.
build_one() {                   # build_one <compiler> <suffix> <source> <name>
    cc=$1; suffix=$2; src=$3; name=$4
    if ! command -v "$cc" >/dev/null 2>&1; then
        echo "   skip $name$suffix ($cc not found)"
        return 1
    fi
    if $cc -static -O1 -o "$out/$name$suffix" "$src" 2>"$out/$name$suffix.log"; then
        echo "   $out/$name$suffix"
        rm -f "$out/$name$suffix.log"
        return 0
    fi
    echo "   skip $name$suffix (no static libc for this target); see $out/$name$suffix.log"
    return 1
}

for src in tests/linux/*.c; do
    name=$(basename "$src" _gcc.c)
    build_one "$CC64" 64 "$src" "${name}_gcc" && built=$((built + 1))
    build_one "$CC32" 32 "$src" "${name}_gcc" && built=$((built + 1))
done

echo "built $built"
