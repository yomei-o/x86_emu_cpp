# Where this is, and what to do next

Working notes for picking the project back up. The README describes what the
emulator *is*; this describes what is unfinished and what is known about it.

## State

Everything below is verified by diffing emulated output against native execution,
byte for byte, on both a Windows and a Linux host (`sh tests/run_tests.sh`,
37 tests):

- x86-32 and x86-64 integer, SSE/SSE2, x87
- PE32/PE32+ and ELF32/ELF64 loading; real DLLs with relocation, exports,
  forwarders, `DllMain`, static TLS; ELF dynamic linking through the real `ld.so`
- libc, math, files, Win32, UCRT hooks across three ABIs
- threads on both OSes (Windows `CreateThread`, Linux `clone` + a real `futex`)
- **processes on both OSes**: `CreateProcess` + pipes, `fork`/`execve`/`wait4`
- **a stock CPython 3.13 for Windows runs its own standard library**
- **mingw-w64 `gcc` compiles and links inside the emulator**, producing a binary
  byte-identical to the one it produces natively
- **Alpine's `as` and `ld` (dynamically linked, musl) build a working binary**

## Done 2026-08-05 (processes, threads, compilers)

`src/processes.{h,cpp}` is the new subsystem: one `Emulator` is one guest
process, and a `System` owns the process table and runs the emulators
round-robin at the same quantum the thread scheduler uses. `Emulator::run()`
builds one around itself, so every front end — CLI, wasm — gets processes without
knowing. Pipes are byte queues shared through `FileTable` entries (a descriptor's
`FILE*` is a `shared_ptr` now, so one file description can live in two processes);
an empty pipe blocks the *reading thread* on a wake predicate rather than the
emulator.

- **Windows**: `CreateProcessA/W` (command-line splitting by the real rules, PATH
  search, `STARTUPINFO` handle redirection, environment blocks), `CreatePipe`,
  `PeekNamedPipe`, `GetExitCodeProcess`, `TerminateProcess` on a child,
  `DuplicateHandle`. A child's handle is an ordinary waitable object whose state
  the `System` answers, so `WaitForSingleObject` needed no changes.
- **Linux**: `fork` copies the whole emulator (`Memory::clone_from`, the CPU
  context, the layout cursors, a cloned descriptor table); `vfork` and
  `CLONE_VFORK` also park the parent until the child execs or exits. `execve`
  swaps the process's emulator outside guest execution. `wait4`, `pipe`/`pipe2`,
  `dup3`, close-on-exec, `getppid`, `kill` are real.
- **Linux threads**: `clone(CLONE_VM|CLONE_THREAD)` with raw clone semantics
  (same RIP, `RAX=0`, caller's stack, `CLONE_SETTLS`), a `futex` that really
  waits, `set_tid_address`/`CLONE_CHILD_CLEARTID` so `pthread_join` completes.
- **`gcc hello.c -o hello.exe` works end to end** under the emulator: the driver
  spawns `cc1`, `as` and `ld` as separate emulated processes and the resulting
  executable is identical to the native build's. Needed `_setjmp`/`longjmp` (a
  register snapshot kept inside the guest's own `jmp_buf`), `_findfirst64`,
  `fgetpos`/`fsetpos`, `tmpfile`, `_pipe`, `_fullpath`, `strtok` and about thirty
  smaller CRT and kernel32 corners.
- **Five bugs the toolchain exposed**, each of the kind this project cares about
  (silent, and surfacing far from the cause): `BT`/`BTS`/`BTR`/`BTC` truncating a
  memory operand's bit offset; `munmap` as a no-op running the address space out;
  `fstat` giving every file the same inode, which made musl's `ld.so` think the
  second library was the first; `getrlimit` answering one value for every
  resource, which reconfigured GCC's garbage collector; `fflush` not flushing the
  guest's own buffer.

The remaining work is breadth, not architecture, with two exceptions named below:
x64 exception unwinding (for `cl.exe`) and whatever is wrong in the RTL path (for
a distro `cc1`).

## Next: the two things actually blocked

### 1. `cl.exe` needs x64 exception unwinding

Everything Microsoft's compiler imports is implemented (`src/hooks_win32c.cpp`:
the UCRT's wide-character half, file mappings, synchronous thread pools,
`_wspawnv` which runs its `_P_WAIT` child through `System::run_until_exit`). It
still never reaches `main`, because it *throws* during initialisation and lands
on `RtlPcToFileHeader`, which reports honestly that unwinding is not emulated.

So this is the SEH work, and it is worth doing for its own sake:

- x64: walk `.pdata`/`.xdata` (`RUNTIME_FUNCTION` → `UNWIND_INFO`), run the
  prologue's unwind codes backwards to recover the caller's context, and call the
  language handler (`__CxxFrameHandler3`/`4` for C++, `__C_specific_handler` for
  SEH) at each frame until one accepts.
- x86: the `fs:[0]` handler chain, which is much simpler and is what the 32-bit
  MSVC tests need.
- `tests/msvc/exc_msvc.cpp` is built and excluded, waiting for exactly this.

### 2. A distribution `cc1` faults in the first RTL pass

Given a sysroot of unpacked Alpine packages, that distribution's `as` and `ld`
run perfectly; its `cc1` does not. It gets *far*: `-version`, preprocessing (`-E`), an
empty translation unit, and `-fsyntax-only` all work, and with `-fdump-tree-all
-fdump-rtl-all` the dumps show it completes gimplification, every tree pass and
`255r.expand` — then faults reading `[rsi+0x28]` with `rsi == 0` at `0x7E18D1`,
i.e. a null pointer inside the first RTL pass after expand.

**The harness for finding it is the useful part, and it works.** WSL here has
`qemu-x86_64`, which runs the same `cc1` correctly, so there is a reference:

```sh
# every block qemu executes, in order (nochain, or it only logs unlinked entries)
qemu-x86_64 -d exec,nochain -L $ROOT $ROOT/usr/libexec/.../cc1 -quiet t.c -o /dev/null 2>&1 \
  | awk -f seq.awk > qemu.seq        # seq.awk: split on '/', print field 2
```

and on our side, a temporary build with an address census (a `-D` guarded block
in `Cpu::step` that appends every execution of an address listed in a filter file
to a binary stream). Then compare: qemu's stream must appear *inside* ours in
order, because where qemu starts a translation block is its own business. The
first entry of qemu's that we cannot reach is the instant of divergence.

Two things learned doing that, both of which cost hours:

- **Compare only the program's own address range.** Shared libraries land at
  different bases in the two implementations, so their addresses are noise.
- **A benign difference stops the comparison dead.** Anything that makes the
  guest take a different branch legitimately — a differing `getrlimit` answer,
  say — sends it down a path the reference never took, and no window of
  resynchronisation recovers. Both `getrlimit` divergences found this way were
  bugs in *our* answers, and fixing them moved the divergence point forward;
  expect to iterate.

Where it stands: after those fixes the first divergence is at `0x1ABA81B`
(`rep stosq` at the top of a small initialiser). The next step is a finer
comparison — qemu's `-d cpu` gives register state per block, which turns "we
branched differently" into "this instruction computed the wrong value" — for
which the volume needs bounding (qemu has no "start logging at instruction N",
so the practical route is comparing register state only at the ~2000 blocks
around the known divergence).

## Done 2026-08-03 (MSVC, browser CPython, Linux CPython)

- **Builds cleanly with MSVC** now (cl.exe and the VS 2022 CMake generator, 0/0
  warnings). The only blocker was two comments holding literal NUL bytes;
  `CMakeLists.txt` globs `src/*.cpp` and sets `/utf-8 /EHsc` + NOMINMAX.
- **CPython runs in the browser.** `emu_run_path(path, argv)` runs a program from
  MEMFS with a real argv; the page (`web/index.html` + `web/worker.js`, off the
  main thread) has one-click **Windows** and **Linux** CPython, both bundled
  (`web/py/`, `web/pylinux/*.gz` unpacked client-side). Headless proofs:
  `web/test_python.mjs`, `web/test_python_linux.mjs`, `web/test_python_linux_bundled.mjs`.
- **Linux CPython works** (the section below is now DONE). A *static* musl build
  was the key: no libc.so to supply, musl is linked in, only syscalls are emulated.
  Gaps closed: SSE2 `PACKSSDW` (0F 6B), `/proc/self/exe` readlink, real `getcwd`,
  `getdents64` + `openat` O_DIRECTORY routing, `fcntl` (FD_CLOEXEC no-ops).

## Next: CPython on Linux  — DONE 2026-08-03 (kept for the bring-up notes)

A Linux CPython is a different shape of problem from the Windows one:
there is no import table to hook, so everything goes through the kernel
interface in `src/syscalls.cpp`.

**Two concrete gaps, both measured.** A statically linked probe built with
`x86_64-linux-gnu-gcc -static` shows exactly what fails today:

```
readlink /proc/self/exe = -1        # we return -EINVAL
readdir entries = 0                 # openat(".", O_DIRECTORY) = -13
```

### 1. Directory descriptors and `getdents64`

`opendir(".")` issues `openat(AT_FDCWD, ".", O_RDONLY|O_DIRECTORY|O_CLOEXEC)`,
which `FileTable::open` rejects because `fopen` cannot open a directory. The
machinery for this already exists — `FileTable::open_directory()` was written for
Windows' `os.stat`, which has the same problem — so this is wiring, not design:

- in `open_flags_from_linux` (`src/syscalls_files.inc`), notice `O_DIRECTORY`
  (0200000) and route to `open_directory()`
- implement `getdents64` (x86-64 syscall 217, i386 220) over
  `Emulator::list_directory()`, which already exists and sorts for
  reproducibility. The `struct linux_dirent64` layout is
  `{u64 d_ino; s64 d_off; u16 d_reclen; u8 d_type; char d_name[]}`, records
  padded to 8 bytes, and the return value is the number of bytes written — zero
  means the end. The cursor is per-descriptor, so `FileTable::Entry` needs a
  listing plus an index, the way `find_handles_` does on the Windows side.
- `d_type` matters: `DT_DIR` is 4 and `DT_REG` is 8, and a libc that gets
  `DT_UNKNOWN` will `stat` every entry, which works but is slow.

### 2. A small virtual `/proc`

`readlink("/proc/self/exe")` is how a Unix runtime finds its own executable, and
CPython's `getpath` depends on it. On a Windows host that path does not exist at
all, so this cannot be passed through to the filesystem — it needs answering
inside the emulator.

Worth handling as a tiny table of synthetic paths rather than a special case in
`readlink`, because several of them come up:

| path | answer |
| --- | --- |
| `/proc/self/exe` | the program path (see `program_path()` in hooks_win32.cpp) |
| `/proc/self/cwd` | the working directory |
| `/proc/self/maps` | generated from `mem.regions()` |
| `/proc/self/fd/N` | the path behind descriptor N |
| `/proc/cpuinfo`, `/proc/meminfo` | short fixed text |
| `/dev/urandom`, `/dev/random` | the deterministic generator `getrandom` uses |
| `/dev/null` | discard on write, EOF on read |

The natural place is a check at the top of `FileTable::open`/`stat_path` plus a
`readlink` case in `syscalls_files.inc`.

### 3. Which CPython to try

In rough order of how much has to work first:

1. **A statically linked CPython** — fewest moving parts, and the only one that
   needs no dynamic linker. `python-build-standalone` publishes musl static
   builds; a self-built `--disable-shared` CPython with its extension modules
   listed in `Modules/Setup` as `*static*` also works. Try this first: if the two
   gaps above are closed it may simply run.
2. **A distribution CPython** — dynamically linked, so it needs the loader work
   below.

### 4. Syscalls a real CPython will want beyond those

Cheap to add, and most of them only need a plausible answer:
`statx` (newer glibc prefers it over `stat`), `pipe2`, `dup3`, `sigaltstack`,
`rt_sigreturn`, `membarrier`, `sched_yield`, `sysinfo`, `getcwd` (currently
returns `"."` — it should return the real one), `fchdir`, `renameat2`,
`utimensat`, `poll`/`ppoll`, `eventfd2`, `clock_nanosleep`.

Two need real behaviour rather than a plausible answer:

- **`futex`** currently returns 0. Once threads exist on Linux it has to block
  and wake, which the scheduler already supports — `begin_wait`/`signal_object`
  in `src/threads.cpp` are the model. A futex is a wait queue keyed by a guest
  address.
- **`clone`** creates a thread. `Emulator::create_thread()` does the work
  already; the syscall needs to map the `CLONE_*` flags onto it, honour
  `CLONE_SETTLS` (which is where the new thread's `fs_base` comes from) and write
  the child tid to both `parent_tid` and `child_tid` pointers when asked. Threads
  sharing memory is what we already do; `fork` (no `CLONE_VM`) is not supportable
  and should say so.

## Also next: our CPython, in the browser

The other goal. The WebAssembly build already runs every other guest, so this is
not a new port - it is plumbing files and argv through to it, and getting a
multi-second run off the main thread.

**The one thing that had to be true is true.** `web/build.sh` now passes
`-sFORCE_FILESYSTEM=1` and exports `FS`, and with that the emulator's whole file
layer works over the emscripten filesystem: `tests/bin/fileio64.exe` - a guest
that creates, writes, seeks, reads back and deletes its own file - runs to
completion under the wasm build and prints `file io ok`. So `fopen`, `fread`,
`fseek` and `unlink` inside the guest reach MEMFS, which means `load_library()`
can find a DLL there too.

### 1. Which CPython to put in the page

The **Windows embeddable package** is the right choice, and it is small:

- `python.exe`, `python313.dll`, `python313.zip`, `python313._pth`
- the standard library is *already* a zip, and CPython's `sys.path` includes
  `<prefix>/python313.zip` by default, so zipimport does the rest - no thousands
  of small files to materialise
- around 10 MB uncompressed, roughly 5 MB over the wire
- the PSF license file has to ship with it

Everything needed to load it already works: PE loading, DLL relocation, static
TLS, threads, and now a filesystem.

### 2. Getting the files in

`FS.writeFile('/py/python313.dll', bytes)` from JS, before running. Two ways to
obtain the bytes, and both are worth having:

- **fetched** from a prepared bundle next to the page, so it works on a first
  visit with no setup
- **dropped**, with `<input type="file" webkitdirectory>` - the visitor points at
  their own Python install and it runs. Nothing leaves the browser, which is the
  demo's whole character.

Preloading with `--preload-file` also works but bakes the download into the page
and makes the "drop your own" case impossible.

### 3. Two API changes

`emu_run(data, len, ...)` takes a single image in memory and hardcodes
`argv = {"program"}`. Both have to go:

- **`emu_run_path(path, argv_json, ...)`** - run a program already in the
  filesystem, with a real argument list, so the page can do `python -c "..."` or
  run a script. `Emulator::load()` already takes a path and an argv vector; the
  wasm entry point is what is narrow, not the emulator.
- keep the existing byte-array entry point for the small samples.

### 4. Off the main thread

CPython's startup is roughly 80 million instructions - about 3.6 s natively here,
and slower under wasm. A synchronous call that long freezes the tab.

**A Web Worker is the way**: `-sENVIRONMENT=web,worker,node` is already set, so
the module loads in a worker unchanged. The worker owns the emulator, the page
posts commands, `x86emuOutput` posts output lines back, and the console stays
live while the guest runs. That is also the natural place to put a "stop" button,
since the worker can be terminated.

The alternative - an `emu_step(max_insns)` that returns "still running" and is
driven from `requestAnimationFrame` - is more code and gives worse throughput,
but it does keep everything on one thread if that matters.

### 5. A REPL needs more than that

Interactive Python needs to *block* on stdin, which a worker cannot do without
either `SharedArrayBuffer` plus `Atomics.wait` (needs COOP/COEP response
headers - **GitHub Pages cannot set them**, so this route means self-hosting) or
Asyncify (`-sASYNCIFY`, which costs size and speed everywhere).

So: non-interactive first. `-c`, a script, or a textarea whose whole contents are
fed as a file. The emulator side needs an `input_source` callback next to
`output_sink` for that - `Emulator::write_raw` is the model.

### 6. Verify before touching the DOM

`web/test_node.mjs` drives the same wasm build headlessly and is where this
should be proven: populate MEMFS from node, call the new entry point, and diff
the output against the same script run by a native CPython. Exactly the check
that `tests/run_tests.sh` does for the native builds. The DOM wiring is the last
step, not the first.

## Next: dynamic linking (real libc.so), and the ARM/macOS question

**DONE 2026-08-03: Linux dynamic linking works, including a dynamic CPython.**
`elf_loader.cpp` accepts `ET_DYN` (PIE): biases the image to a load base, reads
`PT_INTERP`, maps the loader (`/lib/ld-musl-x86_64.so.1`) at `0x7f00_0000_0000`,
enters at the loader's entry, and adds `AT_BASE` to the auxv (`AT_ENTRY` still the
real program). `mmap` gained **MAP_FIXED + file-backed** mapping (read the file
region into the guest pages via FileTable — no host mmap, portable to wasm). The
real ld-musl relocates itself, the program, and any `dlopen`'d `.so`.
- `web/test_dynamic.mjs` — Alpine busybox through its real ld-musl (~170K insns).
- `web/test_python_linux_dynamic.mjs` — a *dynamic* musl CPython (ET_DYN,
  DT_NEEDED=libc.so, RPATH=$ORIGIN/../lib) prints its version + byte-exact sha256,
  exit 0, ~9.7e7 insns. So a stock distro-style dynamic Python runs — no `+static`
  build needed. (That build's `python3.13` embeds libpython, so its only DSO is
  libc; a build that keeps `libpython3.13.so` separate would exercise the
  file-backed mmap path more, and should also work.)

What remains here: glibc's `ld-linux-x86-64.so.2` is a harder loader than musl's
(IFUNC, `AT_HWCAP` CPU probing, richer TLS) — try it next if a glibc target is
wanted. Extension `.so`s loaded via `dlopen` (e.g. `_ssl`) will further exercise
file-backed mmap + cross-module symbol resolution done by the real ld.so.

**Windows is effectively already done** — a program's own DLLs load for real
(`modules.cpp`: relocation, exports, `DllMain`, static TLS); only the system libc
(`ucrtbase`/`msvcrt`) is *hooked*, by design, because loading a real `kernel32`
would mean emulating the NT kernel beneath it. Leave it hooked.

**Linux dynamic linking — the plan.** Two routes (route 2 preferred):

1. *Implement the dynamic linker ourselves* — parse `PT_DYNAMIC`/`DT_NEEDED`, map
   each `.so` (ET_DYN) at a base, apply relocations (`R_X86_64_RELATIVE`,
   `GLOB_DAT`, `JUMP_SLOT`), resolve symbols across modules. Bounded, but we own
   every detail.
2. *Load the real `ld.so` and let it link* — map `ld-musl-x86_64.so.1` (or
   `ld-linux-x86-64.so.2`), build a correct **auxv** (`AT_PHDR`, `AT_PHENT`,
   `AT_PHNUM`, `AT_BASE`, `AT_ENTRY`, `AT_HWCAP`, `AT_RANDOM`, `AT_PAGESZ`), jump to
   ld.so's entry, and the real loader mmaps + relocates the libraries itself. Gets
   *every* dynamic binary at once.

Either way, **libc.so's code runs in-guest and the syscall layer built today is
reused unchanged.** New mechanics needed:

- **Accept `ET_DYN`** in `elf_loader.cpp` (load at a base; apply base relocations).
- **File-backed `mmap` + `MAP_FIXED` + `mprotect`** — ld.so maps `.so` regions from
  a file descriptor; today's `mmap` is anonymous-oriented. This is the core piece.
- **auxv correctness** (route 2) or a **relocation engine** (route 1).
- **Multi-module TLS** (glibc uses TLS variant II heavily; `arch_prctl` exists but
  per-module TLS blocks are more).

**Order:** bring up **musl's `ld` first** (small, simple), then glibc (its `ld.so`
wants IFUNC resolution, `AT_HWCAP` CPU probing, and richer TLS — a step harder).
A dynamically-linked musl CPython from `python-build-standalone` (the non-`+static`
`install_only`, which is `ET_DYN` + `PT_INTERP=/lib/ld-musl-x86_64.so.1`) is the
natural first target; `pylinux/` already has one downloaded to test against.

**The ARM-Mac idea (why it's much bigger).** Running an Apple-Silicon macOS Python
on Windows is possible *in principle* — the design ("interpret an ISA + supply the
OS/library layer") generalizes — but it changes three axes at once: **AArch64**
interpreter (new `cpu`), **Mach-O** loader (incl. fat/universal), and **Darwin**
(XNU syscalls via `svc #0x80` **plus Mach traps** — `mach_msg`, ports). The killer
detail ties back to today's discussion: **macOS ships no static libc** — Apple does
not support static linking, so every macOS binary links `/usr/lib/libSystem.B.dylib`
(and Python.framework pulls in CoreFoundation). The static shortcut is unavailable,
so you must do dynamic linking of dylibs — either **hook libSystem** (Windows-style,
but a huge API surface) or **run dyld + emulate Mach traps** (needs real Apple
dylibs and the Mach layer). That OS layer is a bigger mountain than the ISA change.

**Recommended stepping stone:** add an **AArch64 interpreter and run a static
`aarch64-unknown-linux-musl` CPython first.** That reuses today's ELF loader *and*
syscall layer wholesale and keeps the static shortcut — it is "the ARM version of
what already works." Mach-O + Darwin/libSystem come only after that, if the macOS
target is really wanted.

## Also unfinished

- **C++ and SEH exception unwinding.** See "the two things actually blocked"
  above: this is what `cl.exe` needs, and `tests/msvc/exc_msvc.cpp` waits for it.
- **`_popen`/`_wsystem` and a shell.** Both fail cleanly (a guest that wants a
  pipe to a *command* needs a shell to interpret it, and there is none). A guest
  using them for a compiler driver would need `cmd.exe`-style parsing, or an
  emulated `sh`. Nothing yet has demanded it — `gcc` uses `CreateProcess`.
- **Per-process working directories.** `chdir` changes the *host's* directory, so
  every emulated process shares it. `CreateProcess` says so out loud when a child
  asks to start elsewhere (`lpCurrentDirectory ignored`) rather than quietly
  running in the wrong place. Fixing it means a cwd string per emulator and
  resolving relative paths against it in `FileTable`.
- **A `SIGCHLD`-driven guest.** Signals are never delivered; `wait4` works by
  blocking. A guest that installs a `SIGCHLD` handler and expects to be
  interrupted would wait forever.
- **`msvcp140.dll` and `/MD` C++.** The DLL loads and its `DllMain` runs, but
  `std::cout` is never constructed, so `tests/msvc/cpp_msvc_MD*` are excluded
  from the suite. `/MT` works fully. Not investigated; the trail starts with the
  `_initterm` calls made from that DLL's initialisation.
- **AVX.** `CPUID` deliberately does not advertise it, so nothing uses it. A guest
  built with `-march=native` on a modern machine would need it.
- **Performance.** A plain decode-and-execute switch, roughly 3.6 s for
  `sum(range(100000))` in CPython. A decoded-instruction cache keyed by address
  would be the first thing to try, then threaded dispatch.

## Practical notes

### Building and testing

```sh
sh build.sh                    # or cmake -B build && cmake --build build
sh tests/run_tests.sh          # 37 tests; PYTHON=... to point at an interpreter
EMU=/path/to/other/x86emu sh tests/run_tests.sh   # test a different build
sh tests/run_cross.sh          # every guest under one build, reporting the host
```

Test binaries are generated, not committed. Regenerate with
`tests/build_pe_tests.sh`, `tests/dll/build.sh`, `./gen_elf_tests tests/bin`,
`tests\msvc\build.bat` (Windows only), and `tests/linux/build.sh` (on Linux).

The browser demo needs `sh web/make_samples.sh` then
`EMCC=/path/to/emcc sh web/build.sh`; `node web/test_node.mjs` drives the same
wasm build headlessly. `web/x86emu.js` is committed so GitHub Pages can serve it,
so **rebuild and recommit it whenever `src/` changes**.

### This machine

- Windows 11 on **ARM64** — x86 binaries run natively through Windows' own
  emulation, which is what makes the native-diff tests possible.
- mingw-w64 g++ 14.2 (`w64devkit`), Visual Studio 2022 Community, emsdk at
  `/c/prog/emsdk/emsdk`, CPython 3.13 **x64** at `C:\Python313`.
- WSL `Ubuntu-20.04` is **aarch64**, with `x86_64-linux-gnu-gcc` for
  cross-compiling Linux guests. There is no `i686-linux-gnu-gcc`, so 32-bit Linux
  guests are not built and `tests/expected/hello_gcc32.out` does not exist.
- System32 holds ARM64 DLLs; the x64 CRT redistributable is under
  `VC/Redist/MSVC/*/x64/Microsoft.VC143.CRT` if a real `msvcp140.dll` is needed.

### Debugging, in order of usefulness

1. `--imports` — lists imports that resolved to a "not implemented" stub. This is
   how to bring up a new guest: read the list, implement what is on it.
2. `--trace-calls` — logs intercepted calls and syscalls. Several hooks log their
   arguments here (paths, in particular), which is usually what you want.
3. The fault report — names what the address was (null, a hook for an imported
   variable, inside the stack) and lists stack slots that look like return
   addresses. That crude backtrace found a buffer overrun in the emulator's own
   `FindFirstFileA`.
4. `--dump ADDR[:N]` — hex dump after loading, before the first instruction.
   Good for checking an image was mapped correctly.
5. `--map` — the guest memory map and the hook region's extent.
6. `--trace` — every instruction. Only for the last few hundred.

For a guest that prints its own diagnostics, use them: `PYTHONVERBOSE=2` was what
finally located CPython's import failure, and CPython's own traceback identified
the `getpath` line number.

### The lesson worth keeping

Every bug in this project was silent, and none of them surfaced where it was
made. `strchr(s, '\0')` returning NULL instead of the terminator presented as
"source code cannot contain null bytes" on source containing none. Not setting
`errno` presented as path resolution dying eight million instructions later.
Aligning the stack after writing arguments presented as a 32-bit `DllMain`
silently doing nothing.

What caught them was, in every case, the same two things: **diffing against
native execution byte for byte**, and **making the emulator name its own
failures** instead of guessing. When adding anything, add the test that would
have caught it being subtly wrong — not just absent.
