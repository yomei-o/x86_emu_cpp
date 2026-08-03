#!/bin/sh
# Runs every guest binary under an emulator built for *this* host, and prints the
# host it ran on.  Point EMU at the emulator to use.
#
# The purpose is to show that the guest's OS and the host's OS are independent:
# the same Windows PE runs on Linux, and the same Linux ELF runs on Windows,
# because the emulator supplies the library and kernel interfaces itself.
set -e
cd "$(dirname "$0")/.."
EMU=${EMU:-./x86emu}
[ -x "$EMU" ] || { echo "no emulator at $EMU"; exit 1; }

echo "host: $(uname -s) $(uname -m)"
echo
for g in tests/bin/hello32.exe tests/bin/hello64.exe \
         tests/bin/arith32.exe tests/bin/arith64.exe \
         tests/bin/hello_elf32 tests/bin/hello_elf64; do
    [ -f "$g" ] || continue
    rc=0
    echo "--- $g"
    "$EMU" "$g" || rc=$?
    echo "    exit $rc"
done
