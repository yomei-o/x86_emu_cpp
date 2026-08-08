#!/bin/sh
# How fast the interpreter is, before and after touching it.
#
# One number, taken the same way every time, on a machine with nothing else
# running.  Everything measured on this project today that was taken alongside
# another measurement disagreed with itself by a factor of two, so: nothing else
# running.
#
#   sh tools/bench.sh            # the current build
#   sh tools/bench.sh baseline   # ...and remember it as the thing to beat
set -e
cd "$(dirname "$0")/.."
[ -x ./x86emu ] || { echo "build the emulator first"; exit 1; }

# Is this build newer than the sources it came from?
#
# A build that failed leaves the previous binary in place, and measuring that
# reports the change as having done nothing - which is indistinguishable from
# the change being useless, and was believed once already today.
newest=$(ls -t src/*.cpp src/*.h 2>/dev/null | head -1)
if [ -n "$newest" ] && [ "$newest" -nt ./x86emu ]; then
    echo "x86emu is older than $newest - the build did not succeed"
    exit 1
fi

# isatest is the longest-running guest here that does nothing but arithmetic,
# which is what an interpreter's speed is about.  memtest is allocation and
# thread_gcc64 is scheduling; neither says much about decoding.
GUEST=${GUEST:-tests/bin/isatest_gcc64}
[ -f "$GUEST" ] || { echo "no $GUEST - run tests/linux/build.sh"; exit 1; }

runs=${RUNS:-3}
best=
for i in $(seq 1 "$runs"); do
    start=$(date +%s%N)
    ./x86emu "$GUEST" > /dev/null 2>&1 || true
    end=$(date +%s%N)
    ms=$(( (end - start) / 1000000 ))
    printf '  run %d: %d ms\n' "$i" "$ms"
    # The best of several, not the mean: the slow ones are the machine doing
    # something else, and what is being measured is the emulator.
    [ -z "$best" ] || [ "$ms" -lt "$best" ] && best=$ms
done

insns=$(./x86emu -m "$GUEST" 2>&1 >/dev/null |
        sed -n 's/.*after \([0-9][0-9]*\) instructions.*/\1/p' | tail -1)
printf '\n  best %d ms for %s instructions = %.1f M/s\n' \
    "$best" "${insns:-0}" "$(awk "BEGIN{print ${insns:-0}/($best/1000.0)/1000000}")"

if [ "$1" = baseline ]; then
    printf '%s %s\n' "$best" "$insns" > build/baseline.txt
    echo "  remembered as the thing to beat"
elif [ -f build/baseline.txt ]; then
    read -r was_ms was_insns < build/baseline.txt
    printf '  baseline was %s ms; this is %.2fx\n' "$was_ms" \
        "$(awk "BEGIN{print $was_ms/$best}")"
    [ "$insns" = "$was_insns" ] ||
        printf '  !! %s instructions now, %s then - not the same work\n' \
            "$insns" "$was_insns"
fi
