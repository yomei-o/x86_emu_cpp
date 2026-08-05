# Finding a wrong instruction by diffing against qemu

When a large guest misbehaves and there is no way to run it natively — a Linux
x86-64 binary on a Windows/ARM host, say — `qemu-x86_64` can stand in as the
reference. These scripts turn "the guest crashed somewhere in ninety million
instructions" into "control diverged at this address".

The method rests on one asymmetry: qemu logs the *start* of each translation
block it executes, and where those blocks begin is qemu's own business, so its
stream is a subsequence of what actually ran. Our stream records every execution
of an address that appears anywhere in qemu's set. Therefore **qemu's stream must
appear inside ours, in order**, and the first entry of qemu's that we never reach
is the moment we went somewhere it did not.

## 1. The reference stream

```sh
qemu-x86_64 -d exec,nochain -L "$SYSROOT" "$SYSROOT/usr/bin/prog" args 2>&1 \
  | awk -f seq.awk > qemu.seq
```

`nochain` matters: without it qemu logs only the blocks it had to enter through
the dispatcher, which is a small fraction of the executions.

## 2. Our stream

Build the emulator with an address census — a block in `Cpu::step()`, guarded by
a `-D` so it costs nothing normally, that reads a filter file of addresses at
startup and appends (binary, 8 bytes each) every execution of one of them:

```sh
sort -u qemu.seq > census_filter.txt
g++ -std=c++17 -O2 -DX86EMU_OPCODE_CENSUS -Isrc -o x86emu_census src/*.cpp
./x86emu_census --sysroot "$SYSROOT" "$SYSROOT/usr/bin/prog" args
```

## 3. Restrict both to the program's own text, then compare

Shared libraries are mapped at different bases by the two implementations, so
their addresses are noise; keep only the executable's range.

```sh
python cmp_seq.py ours.seq.bin qemu.seq
```

`cmp_syscalls.py` does the same job at the kernel interface, comparing our
`--trace-calls` output against `qemu-x86_64 -strace`. It is much cheaper and
worth trying first: a syscall answered implausibly shows up there immediately.

## What will waste your time

**A legitimate difference stops the comparison dead.** Anything that makes the
guest branch differently *for a good reason* — a `getrlimit` value, an
environment variable, a timestamp — sends it into code the reference never ran,
and no amount of resynchronisation window recovers. That is not a flaw in the
method: every such difference found so far was a bug in the emulator's answer,
and fixing it moved the divergence point forward. Expect to iterate, and read
each divergence before assuming it is the bug.
