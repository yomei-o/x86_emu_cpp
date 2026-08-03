#!/bin/sh
# Builds the PE test programs used to exercise the emulator.
#
# The programs are deliberately freestanding (-nostdlib, own entry point) and
# import printf/exit straight from msvcrt.dll.  That keeps the import table tiny
# and skips the CRT startup, so the test exercises the emulator's instruction
# decoding and its import hooking rather than a whole C runtime.
#
# Requires a mingw-w64 gcc.  32-bit output needs no 32-bit libraries because
# nothing is linked in: the import library is generated here with dlltool.
set -e
cd "$(dirname "$0")"
out=bin
mkdir -p $out

cat > $out/msvcrt.def <<'EOF'
LIBRARY msvcrt.dll
EXPORTS
printf
puts
putchar
malloc
free
strlen
memset
exit
EOF

echo "== generating import libraries"
dlltool -m i386   --as-flags=--32 -d $out/msvcrt.def -l $out/libmsvcrt32.a
dlltool -m i386:x86-64            -d $out/msvcrt.def -l $out/libmsvcrt64.a

build() {                       # build <bits> <source> <name>
    bits=$1; src=$2; name=$3
    if [ "$bits" = 32 ]; then
        mflag=-m32; emul=i386pe;  lib=$out/libmsvcrt32.a; entry=_start_
    else
        mflag=-m64; emul=i386pep; lib=$out/libmsvcrt64.a; entry=start_
    fi
    gcc $mflag -nostdlib -ffreestanding -fno-stack-protector -O1 -c "$src" -o "$out/$name.o"
    ld -m $emul --subsystem console -e $entry -o "$out/$name.exe" "$out/$name.o" "$lib"
    echo "   $out/$name.exe"
}

echo "== building test programs"
for src in *.c; do
    base=$(basename "$src" .c)
    build 32 "$src" "${base}32"
    build 64 "$src" "${base}64"
done

rm -f $out/*.o
echo "done"
