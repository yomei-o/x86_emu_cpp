# x86_emu_cpp

A small user-mode x86 emulator in C++17. It loads a Windows PE or Linux ELF
executable, interprets the machine code instruction by instruction, and prints
`hello` — because library calls like `printf` are intercepted and run natively on
the host instead of being emulated.

Both bitnesses are supported: **x86-32** and **x86-64**.

```console
$ ./x86emu tests/bin/hello64.exe
hello from the guest!
integers : -42 3000000000 00007 +7 beef BEEF
strings  : [abc] [       abc] [abc       ] [abc]
chars    : x86
loop 1 of 3
loop 2 of 3
loop 3 of 3
```

No dependencies beyond a C++17 standard library. The emulator itself is
host-independent; only the optional CRLF handling is Windows-specific.

## How it works

```
  executable ──► loader ──► guest memory ──► interpreter ──► hook dispatch
   PE / ELF      map        sparse pages     cpu.cpp         host printf()
                 imports
```

**Loading.** `pe_loader.cpp` maps the image at its preferred `ImageBase` (so no
relocation processing is needed) and `elf_loader.cpp` maps `PT_LOAD` segments.
Guest memory (`memory.h`) is a hash map of 4 KiB pages created on demand; an
access to an unmapped address raises a fault instead of quietly reading zeroes.

**Interpreting.** `cpu.cpp` is a plain decode-and-execute loop covering the
user-mode integer subset that compilers actually emit: the ALU group, ModRM/SIB
addressing, `Jcc`/`SETcc`/`CMOVcc`, shifts and rotates, `MUL`/`DIV` in all four
widths, string operations with `rep`, and the usual `0F` two-byte opcodes.
Register state is stored 64-bit wide; a mode flag decides the default operand
size, whether REX prefixes exist, how wide a stack slot is, and whether
`mod=00 rm=101` means RIP-relative or absolute. Anything unimplemented raises an
error naming the opcode and address rather than silently doing nothing.

**Hooking.** This is the part that makes a `hello` possible without emulating a
C runtime. Every function the emulator implements gets a unique fake address in
an otherwise unused region of the guest address space, and the PE loader writes
those addresses into the import table. The guest still executes its own
`jmp [__imp_printf]` thunk — it just lands in the hook region, where the CPU
notices before fetching an instruction, runs the host implementation, and
performs the return itself:

```
guest:  call printf  ──► thunk: jmp [IAT]  ──► 0x7A0000A0   (a hook address)
                                                    │
host:                              hooks.cpp printf ◄┘  reads args per ABI,
                                                        formats, fwrite(), sets EAX
```

Argument reading is ABI-aware (`Emulator::Args`), covering 32-bit cdecl/stdcall,
Microsoft x64 (`RCX, RDX, R8, R9` plus shadow space) and SysV x64
(`RDI, RSI, RDX, RCX, R8, R9`). The `printf` conversions are parsed out of the
guest format string and handed to the host `snprintf`, so padding, precision and
rounding match a real libc.

**Linux guests** have nothing to hook by name: a statically linked ELF talks
straight to the kernel. `syscalls.cpp` implements that interface instead, for
both `syscall` (x86-64) and `int 0x80` (i386) — `write`, `writev`, `brk`, `mmap`,
`fstat`, `exit_group` and friends.

## Building

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Or without CMake:

```sh
g++ -std=c++17 -O2 -Isrc -o x86emu src/*.cpp
```

## Running

```
usage: x86emu [options] <program> [guest args...]

  -t, --trace          dump CPU state before every instruction
  -c, --trace-calls    log intercepted library calls and syscalls
  -m, --map            print the guest memory map after loading
  -n, --max-insns N    stop after N instructions (0 = unlimited)
```

`--trace-calls` is usually the fastest way to see what a guest is doing:

```console
$ ./x86emu -c tests/bin/hello_elf64
[sys] 1
hello from the ELF guest!
[sys] 1
count = 1
...
[exit] code 7 after 34 instructions
```

## Tests

The PE test programs run natively on Windows, so the strongest available check
is a byte-for-byte diff of emulated output against real execution. `arith.c`
exists for exactly that: it prints the results of signed and unsigned division,
shifts of every width, sign extension, 64-bit multiply/divide and bit twiddling,
so a mistake in flags or sign handling shows up as a differing line.

```sh
sh tests/build_pe_tests.sh      # needs mingw-w64 gcc + dlltool
./gen_elf_tests tests/bin       # from tools/gen_elf_tests.cpp
sh tests/run_tests.sh
```

```
PE guests (emulated output vs. native execution)
  ok    tests/bin/arith32.exe (matches native, exit 0)
  ok    tests/bin/arith64.exe (matches native, exit 0)
  ok    tests/bin/hello32.exe (matches native, exit 0)
  ok    tests/bin/hello64.exe (matches native, exit 0)
ELF guests (emulated output vs. recorded expectation)
  ok    tests/bin/hello_elf32 (matches expectation, exit 7)
  ok    tests/bin/hello_elf64 (matches expectation, exit 7)
```

The test programs are built freestanding (`-nostdlib`, own entry point) and
import `printf`/`exit` straight from `msvcrt.dll`, which keeps the import table
small and skips the CRT startup — so a failure points at the emulator rather than
at a C runtime. The 32-bit import library is generated on the fly with
`dlltool`, so no 32-bit libraries need to be installed. The ELF binaries are
assembled by hand by `tools/gen_elf_tests.cpp`, which avoids needing a Linux
cross toolchain and keeps the syscall path under test explicit.

## Layout

| file | what it does |
| --- | --- |
| `src/memory.{h,cpp}` | sparse paged guest memory, 64-bit addresses |
| `src/cpu.{h,cpp}` | the x86-32/x86-64 interpreter |
| `src/emulator.{h,cpp}` | address-space layout, hook dispatch, ABI glue, heap |
| `src/pe_loader.cpp` | PE32 / PE32+ mapping and IAT binding |
| `src/elf_loader.cpp` | ELF32 / ELF64 mapping and the initial process stack |
| `src/hooks.cpp` | host implementations of libc and Win32 functions |
| `src/syscalls.cpp` | the Linux kernel interface |
| `src/main.cpp` | command line front end |

## Current limits

These are the things a guest can hit today; each one fails with a message naming
the instruction or import rather than misbehaving quietly.

- **No x87 or SSE.** Floating point *arithmetic* in the guest is not emulated.
  `printf("%f", x)` does work when the value reaches the hook through integer
  registers or the stack, which is the case for 32-bit cdecl and for Microsoft
  x64 varargs (the ABI duplicates FP arguments into the integer registers), but
  not for SysV x64, where they travel in XMM registers.
- **No dynamic linking for ELF.** `ET_DYN`/PIE and anything needing `ld.so` are
  rejected at load time; statically linked `ET_EXEC` works.
- **PE data imports** are bound like function imports, so importing a variable
  (rather than a function) from a DLL yields a hook address instead of data.
- **No SEH, no threads, no real filesystem.** `_initterm` is a no-op, so C++
  static constructors in a CRT-linked binary would not run.
- Segmentation is flat: `fs:`/`gs:` resolve to a minimal synthetic TEB/PEB, and
  every other segment base is zero.

## License

MIT
