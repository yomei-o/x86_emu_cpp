#!/bin/sh
# Builds the emulator and the ELF test generator without needing CMake.
set -e
cd "$(dirname "$0")"
CXX=${CXX:-g++}
CXXFLAGS=${CXXFLAGS:--std=c++17 -O2 -Wall -Wextra}

echo "== x86emu"
$CXX $CXXFLAGS -Isrc -o x86emu src/*.cpp
echo "== gen_elf_tests"
$CXX $CXXFLAGS -o gen_elf_tests tools/gen_elf_tests.cpp
echo "done"
