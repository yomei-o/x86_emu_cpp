# Where this is, and what to do next

Working notes for picking the project back up. The README describes what the
emulator *is*; this describes what is unfinished and what is known about it.

## State

Everything below is verified by diffing emulated output against native execution,
byte for byte, on both a Windows and a Linux host (`sh tests/run_tests.sh`,
41 checks):

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
- **MSVC `cl.exe` compiles and `link.exe` links, inside the emulator**, C and
  C++ both, and the object files are byte-identical to a native build apart from
  the timestamp (`sh tests/toolchain/run_msvc.sh`)
- **`/MD` C++ works**: msvcp140/vcruntime140 loaded for real via `-L`, iostreams
  and exceptions matching native output on x86 and x64

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
2. *Load the real `ucrtbase.dll`*. **This was tried**, and the result is written
   up below. It is not the wall it looked like, but it does not work yet either.

The boundary is *not* fixed, which is the useful part: `vcruntime140.dll` moved
from hooked to loaded-for-real this session because its exception ABI cannot be
hooked at all. Each library goes below the line when hooking it stops working.

### The UCRT experiment, and how far it got

An x64 `ucrtbase.dll` and the whole `api-ms-win-crt-*` forwarder set exist here:
`C:\Program Files (x86)\Windows Kits\10\Redist\10.0.22621.0\ucrt\DLLs\x64\`
(System32's is ARM64 and useless). Taking `ucrtbase` and `api-ms-win-crt-` off
`is_system_library()`'s list and pointing `-L` there:

- **The premise was wrong, in a good way.** `ucrtbase` imports *nothing* from
  ntdll: its whole import list is `api-ms-win-core-*`, which forward to kernel32
  and land back on the existing hooks. Letting it load does not drag the NT layer
  in. (`api-ms-win-core-*` must stay hooked; leaving the whole namespace loadable
  is fine, because those forwarders resolve to `kernel32.<name>`, kernel32 *is*
  on the list, and the import falls back to a hook by itself.)
- **It loads and runs.** `api-ms-win-crt-runtime` → `ucrtbase` → the rest of the
  forwarders all map, `ucrtbase`'s `DllMain` completes, and its lowio
  initialisation calls `GetStdHandle`+`GetFileType` three times, exactly as the
  real one does.
- **But nothing it prints comes out.** `hello_msvc_MD64` exits 0 and produces no
  output: no `WriteFile`, no `WriteConsoleW`, no error. 40/40 tests still pass
  (they do not depend on the UCRT being loadable), so this is silent rather than
  broken - which is worse, and why the change was reverted rather than kept.

Where to look when picking this up: the real UCRT decided that stdout is not
writable. Its lowio setup takes the three handles from `GetStdHandle` (we return
0x1000+fd) and `GetFileType` (we return CHAR for a terminal, DISK otherwise), and
before that it looks for *inherited* handle information in
`RTL_USER_PROCESS_PARAMETERS.RuntimeData` - which the emulator does not populate,
and which may be being read as garbage rather than as absent. Also worth checking
what `GetConsoleMode` returning 0 (deliberate, so a guest picks the plain
`WriteFile` path) does to the real UCRT's console detection, and whether
`GetFileInformationByHandle` is wanted.

Keep in mind the risk that made the revert right: removing a name from the list
changes behaviour only on machines where that file happens to be findable, so a
guest that ships its own `ucrtbase.dll` - some Python distributions do - would
have silently stopped printing.

## Done 2026-08-05 (afternoon): the MSVC toolchain end to end

`cl.exe -c hello.c` produces an object byte-identical to a native build, and
`cl.exe hello.c` spawns `link.exe` as a child process and produces a working
executable. Seven bugs stood between "cl starts" and that, and every one of them
was a hook that returned something plausible instead of something true. They are
worth reading as a set, because the shape repeats:

1. **`wcstol` never wrote its end pointer.** c2.dll calls
   `wcstol(arg, &end, 0)` on numeric options and then dereferences `end` to check
   the whole argument was consumed; it read a stale stack slot as a pointer. The
   whole wide `strto*` family now shares one implementation that counts *code
   units* consumed, since the end pointer has to land in the guest's UTF-16
   string and a UTF-8 round trip loses the correspondence.
2. **`SRWLOCK` is one pointer, and we used two.** The old code kept a recursion
   count in the word *after* the lock. `SRWLOCK_INIT` is a static zero and a guest
   may never call `InitializeSRWLock`, so that second word held whatever the guest
   had put there — the release path decremented a large number, never reached
   zero, never cleared the owner, and every other thread spun forever. Everything
   now fits in the one word: 0 free, `(tid << 1) | 1` exclusive, `count << 1`
   shared.
3. **`OpenSemaphoreW` and friends answered "yes, it exists" to everything.** A
   guest uses that failure to decide it is the first process here and to do the
   initialisation. There is now a per-process name table, so `CreateXxx` with a
   name returns the existing object with `ERROR_ALREADY_EXISTS` and `OpenXxx`
   fails when nothing created it.
4. **No CNG hashing at all.** `GetProcAddress(BCryptOpenAlgorithmProvider)` found
   nothing, so cl silently omitted the `.chks64` section — the object came out one
   section and two symbols short with no diagnostic anywhere. `src/digest.h` now
   has real MD5, SHA-1 and SHA-256 (checked against the published vectors) behind
   both the CryptoAPI and BCrypt entry points. The old CryptoAPI hashing returned
   FNV noise, which was fine for deriving a temporary file name and wrong the
   moment the digest became part of the output.
5. **`CreateFile` opened files in text mode.** `f.binary` was never set, so with
   newline translation on for Windows guests every binary file a Windows guest
   read through the Win32 API lost a byte per CRLF — silently, and only in the
   middle of large ones. `link.exe` reported `LIBCMT.lib` as a corrupt library,
   which is exactly what a static library with bytes missing from the middle is.
   The NT layer had the same omission.
6. **`strncpy_s` treated `_TRUNCATE` as a length.** `_TRUNCATE` is `(size_t)-1`
   and means the opposite of a length: "copy whatever fits and tell me you
   truncated". Reading it as a length made every such call overflow the capacity
   check and return `ERANGE`, and a failing `strncpy_s` leaves the destination
   untouched — so the caller read whatever was in its buffer before. link copies
   archive member names this way, and a garbage member name is reported as
   `LNK1127: the library is corrupt`.
7. **Views of a mapped file were never written back.** link does not write its
   output with `WriteFile` at all: it maps a view over the new executable, builds
   the whole image in memory, and unmaps. With `UnmapViewOfFile` as a stub that
   returned success, every link produced a zero-byte `.exe` and reported no error,
   because from the linker's point of view nothing had failed. `SetEndOfFile` was
   a no-op too, so the file kept the view's slack.

Two more were about encodings rather than lies:

- **Four stdio hooks resolved a stream and then wrote to `fd == 2 ? 2 : 1`
  anyway.** cl writes the linker's response file with `fputws`, so the file came
  out empty and its contents appeared in *our* output. There is now one
  `Emulator::write_stream`, and no hook that takes a stream resolves it by hand.
- **Wide stdio ignored the stream's encoding.** cl writes the response file with
  `fputws` on a *binary* stream, where MSVC emits the wide characters unchanged,
  and link reads it back with `ccs=unicode`. The two only agree if both halves are
  UTF-16. `FileTable::WideIo` now records what a stream puts on disk, parsed from
  the `ccs=` in the mode string, and `fputws`/`fgetws`/`fwprintf` honour it.

Plus one missing instruction pair: `PEXTRW`/`PINSRW` (`66 0F C5` / `66 0F C4`),
the only SSE2 instructions that move a *word* between the general and xmm
register files, which is why a compiler reaches for them when packing a PE header
field.

**What this says about testing.** None of the first seven produced a crash or a
message. A compiler with a subtly wrong hook exits 0 and writes a slightly
different file, so the only test that finds these is one that compares the
*output artifact* against a native build — `tests/toolchain/run_msvc.sh`. Byte
comparison against a real toolchain is worth more here than any number of
programs that print things.

## Done 2026-08-05 (evening): /MD C++, and C++ through the toolchain

### `/MD` C++: three lies, none of them where the investigation pointed

The stall was `std::cout`'s streambuf holding null pointers, and the earlier
analysis ("ios_base's locale pointer, maybe fed by a data import") was wrong in
a useful way - the null was not a locale and not a data import:

1. **`_get_stream_buffer_pointers` reported success and wrote three nulls.**
   It is supposed to return the *addresses of* a FILE's `_base`/`_ptr`/`_cnt`
   fields; msvcp140's `basic_streambuf` stores those addresses as its
   `_IPfirst`/`_IPnext`/`_IPcount` and dereferences them on every insertion.
   Handing out the real field addresses inside our synthetic FILE object (whose
   layout already matched the UCRT's for cl.exe's sake) was the whole fix: the
   fields hold zero, the streambuf finds no buffer room, and falls back to
   overflow() - which is a hook.  An out parameter filled with a *plausible
   null* is the same class of bug as one left unwritten.
2. **`atexit` dropped its argument.**  A /MD program's static destructors arrive
   through the imported `atexit`; the hook returned 0 and kept nothing, so every
   destructor was silently cancelled.  (/MT never noticed: its atexit is inside
   the image.)
3. **Two `exit` hooks, and the wrong one won.**  hooks.cpp's `exit` (registered
   first, so it shadows the hooks_win32.cpp one) did not run the atexit list.
   exit()-runs-handlers versus _exit()-does-not is the entire difference between
   those functions.

Also: onexit tables are now kept *per table* rather than pooled, because
msvcp140 registers 44 teardown functions on its own table and executes that
table from its DllMain - pooled, one module's teardown drags the others' along.

### C++ through the emulated toolchain: the chained-unwind bug

`cl -EHsc -MT hi.cpp` now builds a byte-identical object and a working
executable.  Two real bugs stood in the way:

- **Chained UNWIND_INFO applied no codes at all.**  On following a chained entry
  to its parent, the walker set `pc = parent's start` so that "the parent's
  codes all apply" - but the applicability test compares code offsets against
  `pc - function_start`, so a zero offset *disables* every code instead.  The
  fragment's frame never unwound and the walk read a garbage return address.
  c2.dll found it because a profile-optimised binary is full of split
  functions; no test program contains any.  The fix is an explicit
  `in_chained_parent` flag.  Symptom to remember: a C++ exception reported as
  "no handler accepted it" when the handler plainly exists.
- **oleaut32 is linked by ordinal, and a hooked module had no ordinals.**
  c1xx delay-loads oleaut32 and imports it by ordinal at load time too.  One
  shared table (`Emulator::well_known_ordinal`) now answers both bind_imports
  and GetProcAddress-by-ordinal, so the two can never disagree - the first
  attempt fixed only GetProcAddress, which made c1xx *enable* its VARIANT path
  and then call the still-unbound load-time slot.  BSTR/VariantInit/VariantClear
  are real implementations (length-prefixed wide strings) since c1xx frees what
  it allocates.

The default instruction cap moved from 500M to 100G: an iostream compile runs
beyond two billion instructions, so the old "possible infinite loop" net was
killing legitimate work.

## Next: the one thing actually blocked

### A distribution `cc1` faults in the first RTL pass

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
8. `X86EMU_TRACE_OPEN=1` — every path the guest opens, which answers "did it even
   look for that file?" in one line.
9. `X86EMU_KEEP_TEMP=1` — hex-dumps a temporary file as the guest deletes it. A
   toolchain that talks to itself through response files destroys the evidence on
   the way out, and this is the only way to read what one process actually handed
   the next. It is how the empty response file turned up.

For a guest that prints its own diagnostics, use them: `PYTHONVERBOSE=2` was what
finally located CPython's import failure, and CPython's own traceback identified
the `getpath` line number.

### The one artifact worth comparing

For any guest that *produces a file* rather than printing, build the same input
with the real tool and diff the two outputs. A compiler, assembler or linker with
a wrong hook does not crash: it exits 0 and writes something slightly different.
Every bug in the MSVC bring-up was invisible to "did it succeed?" and obvious to
"is the object identical?".

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
