#!/bin/sh
# Where the interpreter's time actually goes.
#
# Twice today a confident guess about that was wrong - removing a real redundancy
# made it 33% slower, and halving the compiler's size bought 15% - so the next
# change gets measured first.
#
# gprof rather than perf, because perf is not installed here.  It instruments
# every call, which distorts the small ones upward; treat the ordering as the
# answer and the percentages as a sketch.
set -e
cd "$(dirname "$0")/.."
GUEST=${GUEST:-tests/bin/isatest_gcc64}
[ -f "$GUEST" ] || { echo "no $GUEST"; exit 1; }

echo "== building with -pg"
mkdir -p build/prof
${CXX:-g++} -std=c++17 -O2 -pg -Isrc -o build/prof/x86emu src/*.cpp

echo "== running"
cd build/prof
./x86emu "../../$GUEST" > /dev/null 2>&1 || true
[ -f gmon.out ] || { echo "no gmon.out - the build may not have been instrumented"; exit 1; }

echo
gprof -b -p ./x86emu gmon.out 2>/dev/null | head -22
