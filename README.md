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
$ ./x86emu hello.exe                        # a Visual Studio build, on Linux
hello
42 world ! 03.14
```

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
| gcc + glibc, `-static` (real libc inside the guest, kernel emulated) | — | ✅ |
| hand-assembled ELF using raw syscalls | ✅ | ✅ |

The Visual Studio and static-glibc cases matter because everything before `main`
is real: CPU feature probing, TLS setup, locale and stdio initialisation, table
walks of static initialisers, and the runtime's own `printf` doing its own
floating-point conversion.

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
      --imports        list imports with no implementation, then exit
```

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
guest's output to a console view.

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
| `src/hooks_win32b.cpp` | synchronisation, directories, handles, paths |
| `src/guest_printf.cpp` | the printf engine and UTF-16 conversion |
| `src/syscalls.cpp` | the Linux kernel interface |
| `web/` | the WebAssembly front end and demo page |

## Current limits

Each of these fails with a message naming the instruction or import rather than
misbehaving quietly.

- **Threads are cooperative, and Windows-only so far.** `CreateThread` works;
  Linux's `clone` does not. See below for what that costs.
- **No AVX, and CPUID says so.** The emulator advertises exactly the features it
  implements (SSE2 and CMOV, not SSE4.2 or AVX), because a libc picks its
  `memcpy`/`strlen` from those bits and would otherwise jump into instructions
  that do not exist.
- **x87 is double precision.** The register stack holds host doubles rather than
  true 80-bit extended values, so a computation carried out entirely in extended
  precision on real hardware can differ in its last bits. Loads and stores of an
  80-bit memory operand do convert exactly.
- **No SEH or C++ exception unwinding.** Installing a handler is fine; actually
  throwing is not (`tests/msvc/exc_msvc.cpp` is the test waiting for it).
- **No dynamic linking for ELF.** `ET_DYN`/PIE and anything needing `ld.so` are
  rejected at load time; statically linked `ET_EXEC` works. Windows DLLs *are*
  loaded for real.
- **No registry, processes or pipes.** The registry answers "not present", which
  is a real answer: a runtime installed without registry entries has to cope, and
  they all do.
- Segmentation is flat: `fs:`/`gs:` resolve to a synthetic TEB/PEB on Windows and
  to whatever `arch_prctl`/`set_thread_area` set on Linux; every other segment
  base is zero.

### Working towards CPython

A stock CPython 3.13 for x64 now runs its own standard library. `python313.dll`
is loaded and relocated, static TLS is set up, path configuration resolves from
the real installation, the import machinery finds and loads modules from
`Lib`, and execution reaches Python code in `site.py`, `os.py`, `collections`
and `functools`:

```console
$ ./x86emu C:/Python313/python.exe -c "print(1)"
  File "C:/Python313/Lib/functools.py", line 455, in <module>
    _CacheInfo = namedtuple("CacheInfo", [...])
```

What is left is a string-length bug rather than a missing capability: a source
string CPython builds at runtime and hands to `eval` arrives with a trailing NUL,
which the compiler rejects. It shows up both in `namedtuple` and in the `-c`
command itself, so the common factor is a wide-to-narrow conversion returning a
length that includes a terminator where the caller does not expect one.

Four bugs found on the way there, all of them silent, and each one a reminder
that an emulator's failures are rarely where they appear:

- **Hooks were not setting the guest's `errno`.** A libc distinguishes "not
  found" from "permission denied" by errno and nothing else, and CPython's path
  search catches `FileNotFoundError` specifically — so a failed open that left
  errno at zero raised a plain `OSError`, escaped the handler, and killed path
  resolution eight million instructions in.
- **`FindFirstFileA` wrote the wide form of `WIN32_FIND_DATA`**, 274 bytes past
  the end of a narrow caller's stack buffer, over the return address. It
  presented as an inexplicable jump to address zero.
- **`FILE_FLAG_BACKUP_SEMANTICS` was read as "this is a directory".** It is not:
  a stat implementation passes that flag for every path it looks at, files
  included, precisely so that one code path covers both. Every `os.stat` on a
  file was therefore failing.
- **`call_guest` aligned the stack after writing the arguments**, which moved the
  stack pointer away from them. 64-bit calls survived because their first four
  arguments are in registers; a 32-bit stdcall `DllMain` read its arguments from
  the wrong offsets and silently did nothing.

`--imports` lists what any given guest still needs.

## License

MIT
