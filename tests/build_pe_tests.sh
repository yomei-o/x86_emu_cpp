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
sin
cos
tan
asin
acos
atan
atan2
exp
log
log10
pow
sqrt
sinh
cosh
tanh
fabs
ceil
floor
fmod
ldexp
frexp
modf
fopen
fclose
fread
fwrite
fseek
ftell
fputs
fgets
feof
remove
rename
EOF

# kernel32 for the tests that use threads.  The 32-bit stdcall names carry the
# argument-byte count, so the two definition files differ.
cat > $out/kernel32_32.def <<'EOF'
LIBRARY kernel32.dll
EXPORTS
CreateThread@24 == CreateThread
WaitForSingleObject@8 == WaitForSingleObject
CloseHandle@4 == CloseHandle
GetCurrentThreadId@0 == GetCurrentThreadId
CreateEventA@16 == CreateEventA
SetEvent@4 == SetEvent
InitializeCriticalSection@4 == InitializeCriticalSection
EnterCriticalSection@4 == EnterCriticalSection
LeaveCriticalSection@4 == LeaveCriticalSection
Sleep@4 == Sleep
GetExitCodeThread@8 == GetExitCodeThread
TlsAlloc@0 == TlsAlloc
TlsGetValue@4 == TlsGetValue
TlsSetValue@8 == TlsSetValue
CreateFileA@28 == CreateFileA
WriteFile@20 == WriteFile
ReadFile@20 == ReadFile
SetFilePointerEx@20 == SetFilePointerEx
GetFileSizeEx@8 == GetFileSizeEx
DeleteFileA@4 == DeleteFileA
GetFileAttributesA@4 == GetFileAttributesA
GetLastError@0 == GetLastError
GetFileType@4 == GetFileType
GetStdHandle@4 == GetStdHandle
EOF
cat > $out/kernel32_64.def <<'EOF'
LIBRARY kernel32.dll
EXPORTS
CreateThread
WaitForSingleObject
CloseHandle
GetCurrentThreadId
CreateEventA
SetEvent
InitializeCriticalSection
EnterCriticalSection
LeaveCriticalSection
Sleep
GetExitCodeThread
TlsAlloc
TlsGetValue
TlsSetValue
CreateFileA
WriteFile
ReadFile
SetFilePointerEx
GetFileSizeEx
DeleteFileA
GetFileAttributesA
GetLastError
GetFileType
GetStdHandle
EOF

echo "== generating import libraries"
dlltool -m i386   --as-flags=--32 -d $out/msvcrt.def -l $out/libmsvcrt32.a
dlltool -m i386:x86-64            -d $out/msvcrt.def -l $out/libmsvcrt64.a
dlltool -m i386   --as-flags=--32 -d $out/kernel32_32.def -l $out/libkernel32_32.a
dlltool -m i386:x86-64            -d $out/kernel32_64.def -l $out/libkernel32_64.a

build() {                       # build <bits> <source> <name>
    bits=$1; src=$2; name=$3
    if [ "$bits" = 32 ]; then
        mflag=-m32; emul=i386pe;  lib=$out/libmsvcrt32.a; entry=_start_
        k32=$out/libkernel32_32.a
    else
        mflag=-m64; emul=i386pep; lib=$out/libmsvcrt64.a; entry=start_
        k32=$out/libkernel32_64.a
    fi
    gcc $mflag -nostdlib -ffreestanding -fno-stack-protector -O1 -c "$src" -o "$out/$name.o"
    ld -m $emul --subsystem console -e $entry -o "$out/$name.exe" "$out/$name.o" "$lib" "$k32"
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
