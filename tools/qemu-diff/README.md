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

Dedupe consecutive repeats on qemu's side (`if (a != prev) print`): qemu
re-enters the block of a `rep`-prefixed instruction once per iteration, and the
emulator executes it once, so raw streams falsely diverge at every large
`rep stos`.

## 2. Our stream

The census is built in, enabled by environment variables (zero cost unset):

```sh
sort -u qemu.seq > census_filter.txt
X86EMU_CENSUS_FILTER=census_filter.txt X86EMU_CENSUS_OUT=ours.seq.bin \
  ./x86emu --sysroot "$SYSROOT" "$SYSROOT/usr/bin/prog" args
```

It records every execution of a filtered address, consecutive duplicates
collapsed. Mind the asymmetry: qemu logs only translation-block *entries*, so
per-address counts are comparable only for addresses that are always jump
targets — a mid-block address shows phantom extra executions on our side.

## 3. Restrict both to the program's own text, then compare

Shared libraries are mapped at different bases by the two implementations, so
their addresses are noise; keep only the executable's range.

```sh
python cmp_seq.py ours.seq.bin qemu.seq
```

`cmp_syscalls.py` does the same job at the kernel interface, comparing our
`--trace-calls` output against `qemu-x86_64 -strace`. It is much cheaper and
worth trying first: a syscall answered implausibly shows up there immediately.

## 4. When control flow matches and the data is still wrong

Sequence comparison bottoms out at address-dependent branches: a compiler
hashes and compares pointers constantly, and two implementations lay memory
out differently, so past a certain depth every "divergence" is just layout.
Two run-time switches remove that floor:

- `X86EMU_QEMU_LAYOUT=1` gives a 64-bit Linux guest qemu-x86_64's layout —
  stack below 0x4000800000, mmap climbing from 0x40008A6000, no reuse of
  freed ranges (qemu's cursor is monotonic; brk matches already). With every
  pointer numerically equal the comparison is exact, and a *data-only* bug
  shows up as: streams identical for millions of blocks, then the reference
  branches on a value we got wrong. Found MOVHLPS copying the wrong xmm half
  this way — 11.8M identical blocks, then one field read back NULL.
- `X86EMU_WATCH=<hexaddr>` then logs every guest write covering that address
  with the writing rip. Take the address from gdb against `qemu-x86_64 -g`;
  under the matched layout it is valid in our run too.

Also match the reference's environment or the comparison dies on legitimate
branches: `env -i` (plus whatever env the emulator seeds — a Linux guest gets
`PATH` now), `ulimit -S/-H -s` to our RLIMIT_STACK answer, and beware that
`qemu -L` silently falls back to the *host* filesystem for any path missing
under the sysroot.

## What will waste your time

**A legitimate difference stops the comparison dead.** Anything that makes the
guest branch differently *for a good reason* — a `getrlimit` value, an
environment variable, a timestamp — sends it into code the reference never ran,
and no amount of resynchronisation window recovers. That is not a flaw in the
method: every such difference found so far was a bug in the emulator's answer,
and fixing it moved the divergence point forward. Expect to iterate, and read
each divergence before assuming it is the bug.
