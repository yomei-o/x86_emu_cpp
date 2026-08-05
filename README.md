# x86_emu_cpp

A small user-mode x86 emulator in C++17. It loads a Windows PE or Linux ELF
executable, interprets the machine code instruction by instruction, and prints
`hello` — because library calls like `printf` are intercepted and run natively on
the host.

**Both bitnesses** (x86-32 and x86-64), **both OSes**, and the two are
independent: a Windows `.exe` runs on Linux and a Linux binary runs on Windows,
because the emulator supplies the library and kernel interfaces itself. It also
compiles to WebAssembly, so the same emulator runs an `.exe` in a browser tab.

```console
$ ./x86emu C:/Python313/python.exe -c "print('hello from CPython')"
hello from CPython
```

That is a stock CPython 3.13 for Windows, interpreted instruction by instruction
- and it runs the same way on Linux, on an ARM64 host, where neither the guest's
OS nor its architecture is the host's.

No dependencies beyond a C++17 standard library.

## What actually runs

Verified by diffing emulated output against real native execution, byte for byte:

| guest | 32-bit | 64-bit |
| --- | --- | --- |
| mingw-w64 gcc, freestanding, imports from `msvcrt.dll` | ✅ | ✅ |
| Visual Studio 2022, `/MD` (CRT in `ucrtbase.dll`) | ✅ | ✅ |
| Visual Studio 2022, `/MT` (CRT statically linked, runs inside the guest) | ✅ | ✅ |
| C++ with iostreams, containers and static constructors (`/MT`) | ✅ | ✅ |
| a program plus its own DLL, loaded for real | ✅ | ✅ |
| threads, locks, events and per-thread storage | ✅ | ✅ |
| the Win32 file API (`CreateFile`/`ReadFile`/`WriteFile`) | ✅ | ✅ |
| directory enumeration (`FindFirstFile`/`FindNextFile`) | ✅ | ✅ |
| **a stock CPython 3.13**, running its own standard library | — | ✅ |
| gcc + glibc, `-static` (real libc inside the guest, kernel emulated) | — | ✅ |
| hand-assembled ELF using raw syscalls | ✅ | ✅ |
| child processes and pipes (`CreateProcess`, `CreatePipe`) | ✅ | ✅ |
| Linux processes (`fork`, `execve`, `pipe`, `wait4`) | — | ✅ |
| Linux threads (`clone`, `futex`) — a glibc `pthread` program | — | ✅ |
| **mingw-w64 `gcc` compiling and linking a program** | — | ✅ |
| **Alpine `as` and `ld` (musl, dynamically linked) building a binary** | — | ✅ |
| **C++ exceptions**: throw, unwind through destructors, rethrow, catch-all | ✅ | ✅ |
| C's `__try`/`__except`/`__finally` (`__C_specific_handler`) | — | ✅ |

Two of those deserve spelling out, because they are the whole point of having
processes:

```console
$ ./x86emu /c/prog/w64devkit/bin/gcc.exe hello.c -o hello.exe
$ ./hello.exe                       # runs natively - and byte-identical to
hello                               # what the same gcc produces on its own
$ ./x86emu hello.exe                # and back inside the emulator
hello
```

`gcc.exe` is a driver: it spawns `cc1.exe` to compile, `as.exe` to assemble and
`collect2.exe`/`ld.exe` to link, each a separate emulated process with its own
address space, talking through inherited handles and temporary files. The
executable that comes out is identical to the one the same toolchain builds
natively.

The Linux side does the same through `fork`/`execve`, with `--sysroot` pointing
at a directory of unpacked Alpine packages:

```console
$ ./x86emu --sysroot alpine/root alpine/root/usr/bin/as -o main.o main.s
$ ./x86emu --sysroot alpine/root alpine/root/usr/bin/ld -static -o main \
      alpine/root/usr/lib/crt1.o ... main.o alpine/root/usr/lib/libc.a
$ ./x86emu main
linked by the emulated toolchain
```

The Visual Studio and static-glibc cases matter because everything before `main`
is real: CPU feature probing, TLS setup, locale and stdio initialisation, table
walks of static initialisers, and the runtime's own `printf` doing its own
floating-point conversion.

CPython is the case that ties everything together. `tests/python/smoke.py` runs
under the emulator and is diffed against the same interpreter running natively -
bigint arithmetic, SHA-256 and MD5 digests, float formatting, regular
expressions, `namedtuple`, `lru_cache`, and file I/O all come out byte for byte
identical.

## How it works

```
  executable ──► loader ──► guest memory ──► interpreter ──► hook dispatch
   PE / ELF      map        sparse pages     cpu.cpp         host printf()
                 imports                     sse.cpp         or a syscall
                                             x87.cpp
```

**Loading.** `pe_loader.cpp` maps a PE image and `elf_loader.cpp` maps `PT_LOAD`
segments and builds the System V initial stack. Guest memory (`memory.h`) is a
hash map of 4 KiB pages created on demand; an access to an unmapped address
raises a fault instead of quietly reading zeroes.

DLLs are loaded for real, not just hooked (`modules.cpp`): mapped wherever they
fit and relocated to suit, their own imports bound recursively, their static
thread-local storage set up, and their TLS callbacks and `DllMain` run before the
program starts. Only the system libraries stay hooked, since loading a real
kernel32 would mean emulating the kernel underneath it. That distinction is what
lets a program use both its own DLL's exported *data* and the emulator's `printf`
in the same run.

**Interpreting.** `cpu.cpp` is a decode-and-execute loop covering the user-mode
integer subset compilers emit: the ALU group, ModRM/SIB addressing,
`Jcc`/`SETcc`/`CMOVcc`, shifts, rotates and `SHLD`/`SHRD`, `MUL`/`DIV` in all four
widths, string operations with `rep`, and the `0F` two-byte opcodes. Register
state is stored 64-bit wide; a mode flag decides the default operand size,
whether REX prefixes exist, how wide a stack slot is, and whether
`mod=00 rm=101` means RIP-relative or absolute.

`sse.cpp` adds SSE/SSE2 (plus the few SSE3/SSSE3/SSE4.1 opcodes compilers reach
for) and `x87.cpp` the floating-point stack. Neither is optional decoration: MSVC
and glibc both use SSE2 for ordinary `double` arithmetic and inside
`memcpy`/`strlen`, and a 32-bit CRT formats `%f` on the x87 stack. Anything
unimplemented raises an error naming the opcode and address rather than silently
doing nothing — which is what makes bringing up a new guest a matter of following
the messages.

**Hooking.** This is what makes a `hello` possible without emulating a C runtime.
Every function the emulator implements gets a unique fake address in an unused
region of the guest address space, and the PE loader writes those addresses into
the import table. The guest still executes its own `jmp [__imp_printf]` thunk — it
just lands in the hook region, where the CPU notices before fetching an
instruction, runs the host implementation, and performs the return itself:

```
guest:  call printf  ──► thunk: jmp [IAT]  ──► 0x7A0000A0   (a hook address)
                                                    │
host:                              hooks.cpp printf ◄┘  reads args per ABI,
                                                        formats, writes, sets EAX
```

Argument reading is ABI-aware (`Emulator::Args`), covering 32-bit cdecl/stdcall,
Microsoft x64 (`RCX, RDX, R8, R9` plus shadow space) and SysV x64
(`RDI, RSI, RDX, RCX, R8, R9`, with floating-point arguments in `XMM0-7`).
`printf` conversions are parsed out of the guest format string and handed to the
host `snprintf`, so padding, precision and rounding match a real libc. Hooks can
also call *back* into the guest (`Emulator::call_guest`), which is how `_initterm`
runs a C++ program's static constructors.

**Linux guests** have nothing to hook by name: a statically linked ELF talks
straight to the kernel. `syscalls.cpp` implements that interface instead, for both
`syscall` (x86-64) and `int 0x80` (i386) — the file calls, `brk`, `mmap`,
`arch_prctl` (which is where glibc's thread-local storage comes from),
`exit_group` and friends.

**Threads** (`threads.cpp`) are green threads: the emulator interprets one
instruction stream at a time and switches at a quantum boundary or the moment a
thread blocks. A guest thread owns a full CPU context, its own stack, its own
TEB, and its own copy of every module's static thread-local storage — that last
one being the classic way for threads to appear to work and then quietly corrupt
each other. Critical sections and SRW locks keep their state in the guest object
the caller owns, so a contended lock yields and the call is simply re-entered
when the thread runs again.

**Files, the environment and math** are shared across all of it. `files.h` maps
the small integer descriptors a guest sees onto host files, and the four
interfaces above it — C stdio, the POSIX descriptor calls, the Win32 file API and
the Linux syscalls — are translations over that one table. The guest inherits the
host's environment, because a runtime finds its own installation through it. Math
functions go to the host's libm, which is both simpler and more accurate than
letting the guest compute them on a double-precision x87 stack.

## Building

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
```

or without CMake:

```sh
sh build.sh          # or: g++ -std=c++17 -O2 -Isrc -o x86emu src/*.cpp
```

## Running

```
usage: x86emu [options] <program> [guest args...]

  -t, --trace          dump CPU state before every instruction
  -c, --trace-calls    log intercepted library calls and syscalls
  -m, --map            print the guest memory map after loading
  -n, --max-insns N    stop after N instructions (0 = unlimited)
  -d, --dump ADDR[:N]  hex dump N bytes of guest memory after loading
  -L, --libpath DIR    also look here for DLLs the guest imports
  -r, --sysroot DIR    treat DIR as a Linux guest's filesystem root
      --history N      on a fault, print the last N instruction addresses
      --imports        list imports with no implementation, then exit
```

`--sysroot` is what makes an unmodified distribution toolchain usable: every
absolute path a Linux guest opens (`/usr/lib/libgmp.so.10`, `/lib/ld-musl-x86_64.so.1`)
resolves inside that directory, so a tree of unpacked `.apk` or `.deb` files
behaves like the filesystem those binaries were built for.

`--history N` answers "how did it get there?" after a fault deep inside a large
guest, where `--trace` would produce gigabytes. It keeps a ring of the last N
instruction addresses and prints them, collapsing straight-line runs so what is
left is the branches and calls.

A fault reports what it can: what the address was (a null pointer, a hook for an
imported variable, inside the stack), the register state, and the stack slots that
look like return addresses. That last one is a crude backtrace rather than a real
unwind, and it is what found a 274-byte overrun in the emulator's own
`FindFirstFileA` - writing the wide form of `WIN32_FIND_DATA` into a narrow
caller's buffer, which overwrote the guest's return address.

`--imports` is how you bring up a new guest: it loads the program, binds every
import, and prints the ones that resolved to a "not implemented" stub. Working
through that list beats running and re-running.

`--trace-calls` is usually the fastest way to see what a guest is doing:

```console
$ ./x86emu -c tests/bin/hello_elf64
[sys] 1
hello from the ELF guest!
...
[exit] code 7 after 34 instructions
```

## Browser demo

**[Try it: yomei-o.github.io/x86_emu_cpp](https://yomei-o.github.io/x86_emu_cpp/)**

The emulator core has no OS dependencies, so it compiles to WebAssembly as is.
`web/index.html` is a page where dropping in a PE or ELF runs it and prints the
guest's output to a console view. The emulator runs in a **Web Worker**
(`web/worker.js`), so a multi-second guest never freezes the tab.

It also runs **CPython in the browser** — three stock 3.13 interpreters are bundled,
one click each: **Windows** (a PE reaching the hooked Win32/CRT), **Linux static**
(a static ELF straight to the syscall layer), and **Linux dynamic** (a PIE loaded
through its real `ld-musl` dynamic loader). They run locally over the in-browser
filesystem — nothing is uploaded — via `emu_run_path()`, which loads a program from
MEMFS with a real argv. Each is proven headlessly (`web/test_python*.mjs`): `python
-c ...` prints its version and a byte-exact `hashlib` digest. You can also point
*Load your own* at a Windows [embeddable CPython](https://www.python.org/downloads/windows/) folder.

```sh
sh web/make_samples.sh                     # bake the test binaries into the page
EMCC=/path/to/emcc sh web/build.sh         # produces a self-contained web/x86emu.js
node web/test_node.mjs                     # drives the same wasm build headlessly
```

Serve `web/` over http and open `index.html`. Nothing leaves the browser.

## Tests

```sh
sh build.sh
sh tests/build_pe_tests.sh      # mingw-w64 gcc + dlltool
sh tests/hosted/build.sh        # mingw-w64 gcc, with the real CRT
sh tests/dll/build.sh           # a program plus a DLL, for the loader
./gen_elf_tests tests/bin       # from tools/gen_elf_tests.cpp
tests\msvc\build.bat            # Visual Studio 2022 (Windows only)
sh tests/linux/build.sh         # gcc targeting x86 Linux, run on a Linux host
sh tests/run_tests.sh
```

```
emulator: ./x86emu on Linux aarch64
PE guests (emulated output vs. native execution)
  ok    tests/bin/arith32.exe (matches native, exit 0)
  ...
MSVC guests (emulated output vs. native execution)
  ok    tests/msvc/bin/fmt_msvc_MT32.exe (matches native, exit 0)
  ...
ELF guests (emulated output vs. recorded expectation)
  ok    tests/bin/hello_gcc64 (matches expectation, exit 3)

17 passed, 0 failed
```

Where a guest can also run natively, the check is a byte-for-byte diff against
real execution — the strongest signal available, and the reason the test programs
print so much:

- `tests/arith.c` — signed and unsigned division, shifts of every width, sign
  extension, 64-bit multiply/divide, so a mistake in flags or sign handling shows
  up as a differing line.
- `tests/insn.c` — inline assembly naming instructions directly (`SHLD`/`SHRD`,
  rotates, `BSF`/`BSR`, `ADC`/`SBB` chains, all sixteen `SETcc`, `CMPXCHG`,
  `XADD`, the `BT` group, `REP MOVSB`/`STOSB`/`SCASB`), so a failure says which
  instruction rather than which program.
- `tests/msvc/fmt_msvc.cpp` — floating-point formatting through a real Microsoft
  C runtime. The 32-bit `/MT` build does this on the x87 stack while switching
  the rounding mode around `FRNDINT`, which is exactly the case an emulator that
  ignores the control word gets wrong.
- `tests/hosted/insns.c` — the instruction forms a *compiler* uses that simpler
  programs never do: string moves running backwards with `DF` set (what a libc
  `memmove` does for an overlapping copy), `BT`/`BTS`/`BTR`/`BTC` on memory with
  bit offsets that fall outside the addressed word, 64-bit bit scans, and SSE2
  integer forms. Every one of those was added after it was found to be wrong.
- `tests/hosted/spawn.c` — a program that spawns *itself* twice: once with its
  stdout captured through a pipe, once with a pipe fed to its stdin. It checks
  both children's exit codes, so a missing wait or a lost pipe end shows up as a
  differing line rather than a hang.
- `tests/linux/proc_gcc.c` and `thread_gcc.c` — `fork` + `dup2` + `execve` +
  `waitpid`, and four glibc `pthread`s incrementing a mutex-guarded counter.

Any test whose output depends on how two processes' writes interleave would be
untestable this way, since nothing - real OS or cooperative scheduler - promises
an order. `spawn.c` therefore collects the child's bytes and prints them after
waiting, rather than as they arrive.

The freestanding PE tests are built with `-nostdlib` and their own entry point,
importing straight from `msvcrt.dll`, so a failure points at the emulator rather
than at a C runtime. The 32-bit import library is generated on the fly with
`dlltool`, so no 32-bit libraries need to be installed. The ELF binaries in
`tools/gen_elf_tests.cpp` are assembled by hand, which avoids needing a Linux
cross toolchain and keeps the syscall path under test explicit.

Cross-host checks use `tests/run_cross.sh`, which runs every guest under an
emulator built for the current host and prints which host that was.

## Layout

| file | what it does |
| --- | --- |
| `src/memory.{h,cpp}` | sparse paged guest memory, 64-bit addresses |
| `src/cpu.{h,cpp}` | the x86-32/x86-64 integer interpreter |
| `src/sse.cpp` | SSE/SSE2 and the XMM register file |
| `src/x87.cpp` | the x87 floating-point stack |
| `src/emulator.{h,cpp}` | address-space layout, hook dispatch, ABI glue, heap |
| `src/pe_loader.cpp` | PE32 / PE32+ mapping and IAT binding |
| `src/elf_loader.cpp` | ELF32 / ELF64 mapping and the initial process stack |
| `src/modules.cpp` | loading real DLLs: relocation, exports, DllMain, static TLS |
| `src/files.{h,cpp}` | the guest's file descriptor table |
| `src/hooks.cpp` | core libc hooks |
| `src/hooks_libc.cpp` | locale, errno, ctype, wide strings, conversions, qsort |
| `src/hooks_math.cpp` | the math library and its ABI plumbing |
| `src/hooks_files.cpp` | stdio, POSIX descriptors and the Win32 file API |
| `src/hooks_win32.cpp` | Win32 API and Universal CRT hooks |
| `src/hooks_win32b.cpp` | synchronisation, directories, handles, paths, setjmp |
| `src/hooks_win32c.cpp` | what the Visual C++ toolchain needs: the UCRT's wide-character dialect, file mappings, thread pools |
| `src/hooks_process.cpp` | `CreateProcess`, pipes, process handles |
| `src/exceptions.cpp` | the unwinder: `.pdata`/`.xdata` on x64, the `fs:[0]` chain on x86 |
| `src/processes.{h,cpp}` | the process table and the scheduler over it |
| `src/threads.cpp` | guest threads, the scheduler, and waitable objects |
| `src/guest_printf.cpp` | the printf engine and UTF-16 conversion |
| `src/syscalls.cpp` | the Linux kernel interface |
| `web/` | the WebAssembly front end and demo page |

## Current limits

Each of these fails with a message naming the instruction or import rather than
misbehaving quietly.

- **Threads and processes are cooperative.** One emulator interprets one
  instruction stream, so guest threads take turns at a quantum boundary or the
  moment they block, and so do whole processes: a `System` (`src/processes.cpp`)
  owns the process table and runs the emulators round-robin. That is a correct
  implementation rather than a shortcut — no program may assume anything about
  how its threads interleave — but it does mean the *order* in which two
  processes' output appears is not the host's order.
- **No AVX, and CPUID says so.** The emulator advertises exactly the features it
  implements (SSE2 and CMOV, not SSE4.2 or AVX), because a libc picks its
  `memcpy`/`strlen` from those bits and would otherwise jump into instructions
  that do not exist.
- **x87 is double precision.** The register stack holds host doubles rather than
  true 80-bit extended values, so a computation carried out entirely in extended
  precision on real hardware can differ in its last bits. Loads and stores of an
  80-bit memory operand do convert exactly.
- **C++ with the runtime in a DLL (`/MD`) does not work.** Its language half -
  `_CxxThrowException`, `__CxxFrameHandler4`, and `std::cout` itself - lives in
  `vcruntime140.dll` and `msvcp140.dll`. Those DLLs now load and run for real
  (`-L` the redistributable directory), which is progress, but the iostream
  objects are still never constructed. `/MT`, where the same code is linked into
  the image, works fully - exceptions included.
- **`cl.exe` starts but will not compile.** Microsoft's compiler now runs far
  enough to load its localised resource DLL and print its version banner, usage
  and error messages; given any argument it reports `D8000 unknown command line
  error` from a path that reads a few undocumented environment variables and
  gives up, before it ever opens the source file. So some hook is answering
  something it does not accept. `link.exe` is untried until then.
- **`gcc` works; `cc1` from a Linux distribution does not, yet.** The mingw
  toolchain compiles and links end to end, and Alpine's `as` and `ld` do too, but
  Alpine's `cc1` gets through parsing and RTL expansion and then faults on a null
  pointer in the first RTL pass. `resume.md` records the harness that localises
  this kind of bug — diffing our block-execution order against
  `qemu-x86_64 -d exec,nochain`.
- **No registry.** It answers "not present", which is a real answer: a runtime
  installed without registry entries has to cope, and they all do.
- Segmentation is flat: `fs:`/`gs:` resolve to a synthetic TEB/PEB on Windows and
  to whatever `arch_prctl`/`set_thread_area` set on Linux; every other segment
  base is zero.

### Running CPython

A stock CPython 3.13 for x64 runs its own standard library:

```console
$ ./x86emu C:/Python313/python.exe tests/python/smoke.py
version (3, 13, 7)
bigint 1606938044258990275541962092341162602522202993782792835301376 886041711
sha256 6d193b3da23041e26c65260e971964dfc229864f70a01881fbd7a6b5f7af5d3e
namedtuple Point(x=3, y=4) 5.0
fib 1548008755920
regex [('a', '1'), ('bb', '22'), ('ccc', '333')]
...
```

Byte for byte what the same interpreter prints natively. Getting there needed
`python313.dll` loaded and relocated, static TLS, the import machinery reading
real `.pyc` files, C extension modules compiled into the DLL, and threads for the
runtime's own locking.

Five bugs stood in the way, and every one of them was silent - which is the
recurring lesson of this project: an emulator's mistakes surface a long way from
where they are made.

- **`strchr(s, '\0')` returned NULL** instead of a pointer to the terminator.
  Searching for the terminator is defined to *find* it - it is how a caller asks
  where a string ends - and CPython's tokeniser uses exactly that idiom. The
  symptom was `SyntaxError: source code cannot contain null bytes` from `compile`,
  `eval`, `exec` and `-c`, on source that contained no null bytes.
- **Hooks were not setting the guest's `errno`.** A libc distinguishes "not
  found" from "permission denied" by errno and nothing else, and CPython's path
  search catches `FileNotFoundError` specifically - so a failed open that left
  errno at zero raised a plain `OSError`, escaped the handler, and killed path
  resolution eight million instructions in.
- **`FILE_FLAG_BACKUP_SEMANTICS` was read as "this is a directory".** It is not:
  a stat implementation passes that flag for every path it looks at, files
  included, precisely so that one code path covers both. Every `os.stat` on a
  file failed, which the import machinery reported as "module not found".
- **`FindFirstFileA` wrote the wide form of `WIN32_FIND_DATA`**, 274 bytes past
  the end of a narrow caller's stack buffer, over the return address. It
  presented as an inexplicable jump to address zero.
- **`call_guest` aligned the stack after writing the arguments**, moving the
  stack pointer away from them. 64-bit calls survived because their first four
  arguments are in registers; a 32-bit stdcall `DllMain` read its arguments from
  the wrong offsets and silently did nothing.

What CPython still cannot do here is start a subprocess: `platform.uname()` wants
`CreatePipe` and `CreateProcess`, which are not implemented.

`--imports` lists what any given guest still needs.

## License

MIT
