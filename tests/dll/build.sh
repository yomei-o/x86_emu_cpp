#!/bin/sh
# Builds the dynamic-loading test: a DLL and a program that uses it.
#
# Freestanding again (own entry point, imports straight from msvcrt.dll), because
# what is under test is the emulator's loader, not a C runtime.  Both the DLL and
# the program go in tests/dll/bin so the DLL sits next to the exe that needs it,
# which is where the loader looks first.
set -e
cd "$(dirname "$0")"
out=bin
mkdir -p $out

cat > $out/msvcrt.def <<'EOF'
LIBRARY msvcrt.dll
EXPORTS
printf
exit
EOF

echo "== generating import libraries"
dlltool -m i386   --as-flags=--32 -d $out/msvcrt.def -l $out/libmsvcrt32.a
dlltool -m i386:x86-64            -d $out/msvcrt.def -l $out/libmsvcrt64.a

cat > $out/kernel32.def <<'EOF'
LIBRARY kernel32.dll
EXPORTS
LoadLibraryA@4 == LoadLibraryA
GetProcAddress@8 == GetProcAddress
FreeLibrary@4 == FreeLibrary
EOF
cat > $out/kernel32_64.def <<'EOF'
LIBRARY kernel32.dll
EXPORTS
LoadLibraryA
GetProcAddress
FreeLibrary
EOF
dlltool -m i386   --as-flags=--32 -d $out/kernel32.def    -l $out/libkernel32_32.a
dlltool -m i386:x86-64            -d $out/kernel32_64.def -l $out/libkernel32_64.a

build() {                       # build <bits>
    bits=$1
    if [ "$bits" = 32 ]; then
        mflag=-m32; emul=i386pe;  crt=$out/libmsvcrt32.a; k32=$out/libkernel32_32.a
        entry=_start_; dllentry=_DllMain@12
    else
        mflag=-m64; emul=i386pep; crt=$out/libmsvcrt64.a; k32=$out/libkernel32_64.a
        entry=start_; dllentry=DllMain
    fi

    # The import library records the DLL's output name, so it has to be built as
    # testlib.dll from the start - one directory per bitness, which also puts the
    # DLL next to the program, where the loader looks first.
    mkdir -p "$out/$bits"
    gcc $mflag -nostdlib -ffreestanding -O1 -c testlib.c -o "$out/testlib$bits.o"
    ld -m $emul --shared -e $dllentry \
       --out-implib "$out/libtestlib$bits.a" \
       -o "$out/$bits/testlib.dll" "$out/testlib$bits.o" "$crt"

    gcc $mflag -nostdlib -ffreestanding -O1 -c usedll.c -o "$out/usedll$bits.o"
    ld -m $emul --subsystem console -e $entry -o "$out/$bits/usedll.exe" \
       "$out/usedll$bits.o" "$out/libtestlib$bits.a" "$crt" "$k32"
    echo "   $out/$bits/usedll.exe + testlib.dll"
}

echo "== building"
build 32
build 64
rm -f $out/*.o $out/*.def
echo done
