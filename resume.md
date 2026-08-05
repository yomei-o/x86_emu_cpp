# Where this is, and what to do next

Working notes for picking the project back up. The README describes what the
emulator *is*; this describes what is unfinished and what is known about it.

## State

Everything below is verified by diffing emulated output against native execution,
byte for byte, on both a Windows and a Linux host (`sh tests/run_tests.sh`,
40 tests):

- x86-32 and x86-64 integer, SSE/SSE2, x87
- PE32/PE32+ and ELF32/ELF64 loading; real DLLs with relocation, exports,
  forwarders, `DllMain`, static TLS; ELF dynamic linking through the real `ld.so`
- libc, math, files, Win32, UCRT hooks across three ABIs
- threads on both OSes (Windows `CreateThread`, Linux `clone` + a real `futex`)
- **C++ and SEH exception handling on x86 and x64**, against Microsoft's runtime
  and mingw's
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

## Done 2026-08-05 (later): exceptions, and cl.exe starts

**Throwing works** (`src/exceptions.cpp`), on both bitnesses and against two
independent language runtimes. The design is the same split real Windows uses:
the emulator supplies the kernel's half and the guest's own runtime the
language's half.

- x64: the PE loader exposes the exception directory; `RtlVirtualUnwind`
  interprets `UNWIND_INFO` (every unwind code, chained entries, frame registers,
  and codes whose prologue offset has not been reached yet, so a throw from
  inside a prologue unwinds correctly). `RaiseException` walks frames calling
  each language handler; `RtlUnwindEx` runs the second pass.
  `__C_specific_handler` (C's `__try`/`__except`/`__finally`) is here too.
- x86: the `fs:[0]` registration chain, walked directly.
- **The two things that were not obvious**, both of which cost real time:
  - `STATUS_UNWIND_CONSOLIDATE` (**0x80000029**, a warning-level status, not
    0xC000...) is what actually runs a C++ catch block on x64. MSVC's handler
    does not call the catch; it raises this code from the unwinder with a
    callback in parameter 0, and the unwinder must call that callback once the
    frames are gone and continue at the address it returns. Without it
    everything unwound correctly and then resumed *after* the catch: the program
    printed nothing and exited 0. A disassembly of `_UnwindNestedFrames` is what
    identified it - look for `lea rax,[callback]` stored into a local record
    whose `ExceptionInformation` also holds the EH magic `0x19930520`.
  - A handler that accepts **never returns**. Control goes back into its own
    function, so the emulator's nested interpreter loop keeps running the guest
    until the program ends. Leaving that nest is a host C++ throw
    (`UnwindTransfer`) caught in `run_slice`; on the 32-bit path, where the guest
    performs the jump itself, the tell is simply that the guest has halted by the
    time `call_guest` returns.
- Verified against native execution: `tests/msvc/bin/exc_msvc_MT32` and `MT64`
  (no longer excluded), and `tests/hosted/except.cpp` built with mingw - an
  independent language half - covering destructors through three frames,
  rethrow and catch-all.

**`cl.exe` starts.** It loads its localised resource DLL and prints its version
banner, usage and diagnostics. Getting there needed the resource directory
(`FindResource`/`LoadResource` over the real three-level tree), loading a DLL
named by full path, mapping a resource-only DLL (no relocation directory, so
either its preferred base or - since nothing in it uses an absolute address -
anywhere), and `SetThreadPreferredUILanguages`/`Get...` remembering what the
guest set, defaulting to the host's UI language so a Japanese install finds 1041
and an English one 1033. Also: `GetSystemInfo` was leaving
`dwAllocationGranularity` zero and cl divides by it.

That last fix has a bonus: **a DLL's dependencies are now searched for beside
it**, so CPython's `_hashlib.pyd` finds the OpenSSL it links against and the
smoke test's SHA-256 comes from real `libcrypto-3.dll` code running inside the
emulator - still byte-identical to native.

## The layering question, and the experiment that would settle it

Worth writing down because it comes up every time: *why hook the C runtime at all,
rather than only the layer below it?*

For a **statically linked** CRT that is exactly what happens already. A `/MT`
MSVC program, a static musl or glibc program, CPython's own bundled runtime - all
of them run their real library code as guest instructions, and the emulator only
answers at the bottom: kernel32 and a handful of ntdll calls on Windows, raw
syscalls on Linux. `iswupper` in those guests is the guest's own code.

Hooking is forced only when the guest **imports the CRT from a DLL** (`/MD`),
because then its import table names `api-ms-win-crt-string-l1-1-0.dll!iswupper`
and something has to answer. Two ways out, and the trade is the point:

1. *Hook it*, as now. Cheap, fast (the host's `snprintf` does the formatting,
   which is also why float output matches byte for byte), and it keeps the guest
   away from the NT layer entirely. The cost is a wide, shallow surface - this
   session added dozens of `_s` variants - and every hook is a chance to lie.
2. *Load the real `ucrtbase.dll`*. **An x64 one exists on this machine**:
   `C:\Program Files (x86)\Windows Kits\10\Redist\10.0.22621.0\ucrt\DLLs\x64\ucrtbase.dll`
   (System32's is ARM64 and useless here). Dropping `ucrtbase` and
   `api-ms-win-` from `is_system_library()` and pointing `-L` at that directory
   is a five-minute experiment.

The reason (2) has not been done is that `ucrtbase` talks to **ntdll's internals**,
not to kernel32: `RtlAllocateHeap`, `NtQueryInformationProcess`, the loader lock,
PEB fields, `LdrLoadDll`. That is the NT-kernel boundary this project has
deliberately not emulated, and it is a much deeper surface than the CRT's. The
same reasoning is why the boundary is *not* fixed: `vcruntime140.dll` moved from
hooked to loaded-for-real this session, because its exception ABI cannot be
hooked at all. Each library goes below the line when hooking it stops working.

If (2) is tried, the honest test is the existing `/MD` suite -
`tests/msvc/bin/*_MD*` - diffed against native, and the first thing to watch is
how far `DllMain` gets before it wants something from ntdll.

## Next: the three things actually blocked

### 1. `cl.exe` reaches `tbbmalloc` and faults there

It processes its command line, prints the source file name exactly as the real
one does, loads **c1.dll**, and c1 opens `hello.c`, enumerates the directory to
find it, hashes bytes for a temporary name, reserves and commits its arenas, and
loads `mspdbcore.dll`, `msvcp140_atomic_wait.dll` and **`tbbmalloc.dll`** —
Intel's scalable allocator — before faulting inside that last one:

```
<tbbmalloc or the module above it>+0x5834AD:  writes to 0x340AA1E30, unmapped
```

Two theories were tested and are *not* it: the address does not come from `rdi`
(which held our heap base), and moving the heap next to the image so that
32-bit-relative pointer compression can reach it changed nothing (the fault
address stayed byte-identical). So the wild pointer is computed from something
else inside the allocator.

Where to look next: tbbmalloc asks the system about memory in ways nothing else
here does — `VirtualAlloc` with `MEM_TOP_DOWN`, large pages, `GetSystemInfo`'s
granularity, `GetLogicalProcessorInformation` — and our answers to those are
either absent or a guess. Logging every allocation call it makes and comparing
the arithmetic it does on the results is the way in. Also worth trying:
`cl -Bt+` or setting `TBB_MALLOC_DISABLE_REPLACEMENT=1`, since a compiler that
falls back to the plain heap would sidestep the whole thing and prove the rest of
the pipeline.

**How it got this far**, which is the part worth remembering: hook after hook was
answering plausibly and lying, and each one was found by running it and reading
the failure rather than by guessing.

- `CryptAcquireContextW` returned success without writing `*phProv`. cl checked
  the handle, found zero and reported `D8000 unknown command line error` — for
  *any* argument, which is exactly what made this look like an option-parsing bug
  for a whole session. **An out parameter left unwritten is the quietest way for
  a hook to lie**, and worth auditing across the others.
- `VirtualAlloc` returned page-aligned memory; Windows aligns to the 64 KiB
  allocation granularity, and an arena allocator that masks low bits to find its
  base builds a wild pointer from anything less.
- `version.dll`'s `GetFileVersionInfo*` did not exist. A toolchain *delay-loads*
  them, and a missing procedure makes the delay-load helper raise `0xC06D007F`,
  which cl reports as "internal compiler error" naming nothing. `GetProcAddress`
  now logs the names it cannot find, which is how that was traced back.
- The **native file API** was missing entirely (`NtCreateFile` and the rest); a
  toolchain opens files that way. Two details there cost time: the ULONG
  parameters have to be masked out of the 64-bit slots they arrive in, and a
  directory path arrives with a trailing separator that Windows' `stat()`
  refuses.
- `vcruntime140.dll` is no longer treated as a system library. It owns the
  *language* half of exception handling, which no hook can stand in for, so it
  has to be the real DLL - and that works now that the unwinder is real. Supply
  it with `-L .../VC/Redist/MSVC/*/x64/Microsoft.VC143.CRT`.

What was ruled out along the way (do not spend time on these again):

- *Option parsing, `argv`, the option table.* All correct. cl matches by prefix
  with `wcsncmp` (fifty entries, right answers), `__p___wargv` hands over exactly
  the right strings, and the 300,000 instructions before the old error were cl
  building a hash map of its options - normal work, not a spin.
- *The message lookup.* `FindResource(type 6, name 501)` succeeded all along;
  bundle 501 is string ids 8000-8015, so cl really had chosen D8000 rather than
  failing to find another message's text.

Two techniques did all the work here, in this order:

1. **Diff the hook sequence** of a run that works against one that fails.
2. **Read the stack at the moment the guest reports an error**, which names the
   function that decided. `X86EMU_TRACE_RESOURCE=<string id>` prints
   `stack_trace()` and the instruction history when a given string resource is
   looked up; from there, disassembling the caller showed
   `xor ecx,ecx; call report_error` - literally "report error code 0" - and the
   branch into it was `cmpq $0,[global]; jne`, the global being the handle
   `CryptAcquireContextW` had never written.

For comparison, native cl answers `D8003 : source file not found` for `-nologo`,
`-c` and `-nonsenseoption`, and prints the option list for `-help`.

### 2. C++ with the runtime in a DLL (`/MD`)

`msvcp140.dll` and `vcruntime140.dll` now load and *run* for real when `-L`
points at the redistributable directory
(`VC/Redist/MSVC/*/x64/Microsoft.VC143.CRT`), which is new — and its `DllMain`
gets a long way: it runs its own initialiser tables, creates its critical
sections, and calls `__acrt_iob_func` a dozen times, which is the standard
streams being built.

Where it stops, exactly: inside that initialiser run (the `_initterm` call never
returns), at `msvcp140+0x97D6`, which is

```asm
    mov rax,[rcx+0x40]     ; rcx = std::cout, inside msvcp140
    mov r9,[rax]           ; faults: [cout+0x40] is NULL
```

so a pointer field of `std::cout` — by its offset, `ios_base`'s locale pointer —
is still zero while the object is being constructed. What that rules out: the
missing value does *not* come from `_get_current_locale` or `_create_locale`
(msvcp140 never calls them; it only takes `_lock_locales`/`_unlock_locales` and
reads locale data through `___lc_locale_name_func`, `__pctype_func` and
`localeconv`). The next step is to find which of those, or which *data* import,
feeds that field — and note that a UCRT data import bound to a hook address
yields code bytes rather than a plausible value, which is worth checking first.

Worth knowing before going further: msvcp140 was built against the real
`ucrtbase.dll` and reads its structures directly, not only through functions.
Some of this may be unreachable without loading a real UCRT too, which is a
bigger decision than it looks (see "Windows is effectively already done" below).

### 3. A distribution `cc1` faults in the first RTL pass

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

- **32-bit `__try`/`__except` in C code** (`_except_handler4_common`, the
  security-cookie variant MSVC generates). The 32-bit C++ path works; this one
  is still a stub.
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
- **`msvcp140.dll` and `/MD` C++** — see "the three things actually blocked"
  above; the DLL runs for real now, which is further than these notes used to
  describe.
- **AVX.** `CPUID` deliberately does not advertise it, so nothing uses it. A guest
  built with `-march=native` on a modern machine would need it.
- **Performance.** A plain decode-and-execute switch, roughly 3.6 s for
  `sum(range(100000))` in CPython. A decoded-instruction cache keyed by address
  would be the first thing to try, then threaded dispatch.

## Practical notes

### Building and testing

```sh
sh build.sh                    # or cmake -B build && cmake --build build
sh tests/run_tests.sh          # 40 tests; PYTHON=... to point at an interpreter
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

0. **Diff the hook sequence of a working run against a failing one.** Two
   `--trace-calls` runs, `grep -oE '^\[hook\] [A-Za-z_0-9]+'`, `diff`. It costs a
   minute and points straight at where the two runs part company; it is what
   localised both compiler failures. Only then reach for the rest.
1. `--imports` — lists imports that resolved to a "not implemented" stub. This is
   how to bring up a new guest: read the list, implement what is on it.
2. `--trace-calls` — logs intercepted calls and syscalls. Several hooks log their
   arguments here — paths, environment variables and what they resolved to,
   resource lookups — which is usually what you want. Adding one `log_call` to
   the hook under suspicion beats guessing.
3. The fault report — names what the address was (null, a hook for an imported
   variable, inside the stack) and lists stack slots that look like return
   addresses. That crude backtrace found a buffer overrun in the emulator's own
   `FindFirstFileA`.
4. `--dump ADDR[:N]` — hex dump after loading, before the first instruction.
   Good for checking an image was mapped correctly.
5. `--map` — the guest memory map and the hook region's extent.
6. `--history N` — the last N instruction addresses, printed after a fault, with
   straight-line runs collapsed. For a guest that *does not* fault,
   `X86EMU_TRACE_RESOURCE=<id>` dumps the same history when it looks up a given
   string resource, which is how to find the code that chose an error message.
7. `--trace` — every instruction. Only for the last few hundred.

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
