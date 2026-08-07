#!/bin/sh
# Saving a running guest and putting it back.
#
# The check is that cutting a run in half changes nothing: run the program
# through, then run it again stopping partway to write a state, resume from that
# state in a *separate process*, and join the two halves' output.  If the state
# carries everything, the join is the whole run, byte for byte, and the exit code
# is the one the whole run gave.
#
# Where to cut is measured rather than guessed.  Fixed instruction counts were
# tried first and every one of them fell past the end of the shorter programs,
# so every case reported "skipped" and the suite passed while testing nothing.
# Each program's length is taken first and the cuts are a quarter, a half and
# three quarters of the way in - which also puts one cut inside the C library's
# startup and another inside main, which are different propositions.
set -e
cd "$(dirname "$0")/.."
emu=${EMU:-}
[ -n "$emu" ] || { emu=./x86emu; [ -x "$emu" ] || emu=./x86emu.exe; }
[ -x "$emu" ] || emu=./build/x86emu
[ -x "$emu" ] || { echo "build the emulator first"; exit 1; }

tmp="${TMPDIR:-/tmp}"
pass=0
fail=0

# The 32-bit guests are here because the claim is about the emulator, not about
# one word size: a saved state carries the guest's registers and address space,
# and a 32-bit guest has different ones.
for exe in tests/bin/hello_elf32 tests/bin/hello_elf64 tests/bin/hello_gcc32 \
           tests/bin/hello_gcc64 tests/bin/fileio_gcc64 tests/bin/thread_gcc64 \
           tests/bin/isatest_gcc64; do
    [ -f "$exe" ] || continue
    name=$(basename "$exe")

    whole_rc=0
    "$emu" "$exe" > "$tmp/state_whole.out" 2>/dev/null || whole_rc=$?
    # -m prints the memory map and, with it, the instruction count at exit.
    total=$("$emu" -m "$exe" 2>&1 >/dev/null |
            sed -n 's/.*after \([0-9][0-9]*\) instructions.*/\1/p' | tail -1)
    if [ -z "$total" ] || [ "$total" -lt 8 ]; then
        echo "  FAIL  $name (could not measure its length)"
        fail=$((fail + 1))
        continue
    fi

    for part in 4 2 1; do
        at=$((total / 4 * (4 - part)))
        [ "$at" -gt 0 ] || at=1
        rm -f "$tmp/state.bin"
        "$emu" --save-state "$tmp/state.bin" --save-at "$at" "$exe" \
            > "$tmp/state_head.out" 2>/dev/null || true
        if [ ! -f "$tmp/state.bin" ]; then
            echo "  FAIL  $name at $at of $total (no state was written)"
            fail=$((fail + 1))
            continue
        fi
        tail_rc=0
        "$emu" --load-state "$tmp/state.bin" "$exe" \
            > "$tmp/state_tail.out" 2>/dev/null || tail_rc=$?
        cat "$tmp/state_head.out" "$tmp/state_tail.out" > "$tmp/state_join.out"
        if cmp -s "$tmp/state_whole.out" "$tmp/state_join.out" &&
           [ "$tail_rc" = "$whole_rc" ]; then
            echo "  ok    $name cut at $at of $total ($(wc -c < "$tmp/state.bin") bytes, exit $tail_rc)"
            pass=$((pass + 1))
        else
            echo "  FAIL  $name cut at $at of $total (whole exit $whole_rc, resumed $tail_rc)"
            diff "$tmp/state_whole.out" "$tmp/state_join.out" | head -10 || true
            fail=$((fail + 1))
        fi
    done
done

echo
echo "state: $pass passed, $fail failed"
[ "$fail" = 0 ]
