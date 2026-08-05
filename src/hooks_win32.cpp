// Windows-specific hooks: the Win32 API and the Universal CRT.
//
// A program built by a normal Visual Studio toolchain runs a great deal of code
// before main: it probes the CPU, sets up locale and stdio state, walks tables
// of initialisers, and installs exception handling.  Most of what it calls only
// has to answer plausibly, and that is what most of this file is.  The few that
// have to work properly are the stdio entry points (which is where the guest's
// printf output actually comes from), _initterm (which must call back into
// guest code), and the heap.
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "emulator.h"
#include "guest_printf.h"

#if defined(_WIN32)
#include <direct.h>
#else
#include <unistd.h>
#endif

namespace x86emu {
namespace {

// Values the CRT startup asks about via IsProcessorFeaturePresent.  Claiming
// SSE/SSE2 is honest - sse.cpp implements them - and everything else is safer
// answered "no", especially PF_FASTFAIL_AVAILABLE, whose "yes" would make the
// CRT report errors with an instruction we do not implement.
bool processor_feature(uint32_t feature) {
    switch (feature) {
        case 2:   // PF_COMPARE_EXCHANGE_DOUBLE
        case 6:   // PF_XMMI_INSTRUCTIONS_AVAILABLE  (SSE)
        case 10:  // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        case 12:  // PF_NX_ENABLED
            return true;
        default:
            return false;
    }
}

// Module names are compared lowercased, as the module table stores them.
std::string lowercase_name(const std::string& s) {
    std::string out;
    for (char c : s) out += static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
    return out;
}

void zero_fill(Emulator& e, uint64_t addr, size_t len) {
    if (!addr || !len) return;
    std::vector<uint8_t> zeros(len, 0);
    e.mem.write(addr, zeros.data(), zeros.size());
}

// Writes a UTF-16 string, returning the number of units including the NUL.
int write_utf16(Emulator& e, uint64_t dst, const std::string& s, int capacity_units) {
    std::u16string w = utf8_to_utf16(s);
    int needed = static_cast<int>(w.size()) + 1;
    if (dst == 0 || capacity_units <= 0) return needed;
    int n = needed < capacity_units ? needed : capacity_units;
    for (int i = 0; i < n; ++i)
        e.mem.write16(dst + static_cast<uint64_t>(i) * 2,
                      i < static_cast<int>(w.size()) ? w[i] : 0);
    return n;
}

// The program's path as Windows spells it: absolute, with backslashes.  A
// runtime locates its own installation from this, so a relative path or the
// wrong separator sends it looking in the wrong place.
std::string program_path(const Emulator& e) {
    std::string path = e.args().empty() ? "program.exe" : e.args()[0];
    bool absolute = (path.size() > 1 && path[1] == ':') ||
                    (!path.empty() && (path[0] == '/' || path[0] == '\\'));
    if (!absolute) {
        char cwd[4096];
#if defined(_WIN32)
        if (_getcwd(cwd, sizeof cwd)) path = std::string(cwd) + "/" + path;
#else
        if (getcwd(cwd, sizeof cwd)) path = std::string(cwd) + "/" + path;
#endif
    }
    for (char& c : path)
        if (c == '/') c = '\\';
    return path;
}

// SYSTEM_INFO, whose fields a guest does arithmetic with - cl.exe divides by
// dwAllocationGranularity, so leaving a field zero is not a harmless omission.
void write_system_info(Emulator& e, uint64_t p) {
    if (!p) return;
    bool w64 = e.is64();
    std::vector<uint8_t> zeros(w64 ? 48 : 36, 0);
    e.mem.write(p, zeros.data(), zeros.size());
    e.mem.write16(p + 0, w64 ? 9 : 0);       // PROCESSOR_ARCHITECTURE_AMD64 / INTEL
    e.mem.write32(p + 4, 0x1000);            // dwPageSize
    int ps = e.pointer_size();
    e.mem.write_sized(p + 8, ps, 0x10000);   // lpMinimumApplicationAddress
    e.mem.write_sized(p + 8 + ps, ps, w64 ? 0x00007FFFFFFEFFFFull : 0x7FFEFFFFull);
    e.mem.write_sized(p + 8 + 2 * ps, ps, 1);  // dwActiveProcessorMask
    uint64_t after_mask = p + 8 + 3 * ps;
    e.mem.write32(after_mask, 1);            // dwNumberOfProcessors
    e.mem.write32(after_mask + 4, w64 ? 8664 : 586);  // dwProcessorType
    e.mem.write32(after_mask + 8, 0x10000);  // dwAllocationGranularity
    e.mem.write16(after_mask + 12, 6);       // wProcessorLevel
    e.mem.write16(after_mask + 14, 0x3A09);  // wProcessorRevision
}

std::string command_line(const Emulator& e) {
    // A child process gets the parent's exact CreateProcess string; quoting
    // reconstructed from argv can never be more faithful than the original.
    if (!e.raw_command_line().empty()) return e.raw_command_line();
    std::string cmd;
    for (const auto& a : e.args()) {
        if (!cmd.empty()) cmd += ' ';
        // Real Windows quotes arguments containing spaces; match that so a
        // guest parsing its own command line sees what it expects.
        if (a.find(' ') != std::string::npos)
            cmd += '"' + a + '"';
        else
            cmd += a;
    }
    return cmd;
}

}  // namespace

// ---------------------------------------------------------------------------
// Win32
// ---------------------------------------------------------------------------

void Emulator::install_win32_hooks() {
    // In 32-bit code the Win32 API is stdcall: the callee pops the arguments.
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, is64() ? 0 : nargs * 4, std::move(fn));
    };
    auto ret0 = [&](const char* name, int nargs) {
        win32(name, nargs, [](Emulator& e) { e.set_result(0); });
    };
    auto ret1 = [&](const char* name, int nargs) {
        win32(name, nargs, [](Emulator& e) { e.set_result(1); });
    };

    // ---- process and module -------------------------------------------------
    win32("ExitProcess", 1, [](Emulator& e) {
        e.run_atexit();
        e.exit_process(static_cast<int>(e.arg_slot(0)));
    });
    // TerminateProcess lives with the process hooks: the handle may name a child.
    win32("GetCurrentProcess", 0, [](Emulator& e) { e.set_result(~0ull); });
    win32("GetCurrentThread", 0, [](Emulator& e) { e.set_result(~1ull); });
    win32("GetCurrentProcessId", 0, [](Emulator& e) { e.set_result(e.pid()); });
    win32("GetCurrentThreadId", 0, [](Emulator& e) { e.set_result(1234); });
    win32("GetModuleHandleA", 1, [](Emulator& e) {
        e.set_result(e.arg_slot(0) == 0 ? e.image().image_base : 0);
    });
    win32("GetModuleHandleW", 1, [](Emulator& e) {
        e.set_result(e.arg_slot(0) == 0 ? e.image().image_base : 0);
    });
    // (flags, name-or-address, out module).  The interesting flag is
    // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, which asks "which module is this
    // address in?" - a caller uses it to find *itself* from a function pointer,
    // so answering with the main image every time hands a DLL the wrong module.
    auto get_module_handle_ex = [](Emulator& e, bool wide) {
        constexpr uint64_t kFromAddress = 0x4;
        uint64_t flags = e.arg_slot(0), name_or_addr = e.arg_slot(1), out = e.arg_slot(2);
        uint64_t base = 0;
        if (flags & kFromAddress) {
            Emulator::Module* m = e.module_for(name_or_addr);
            base = m ? m->image.base : 0;
        } else if (!name_or_addr) {
            base = e.image().image_base;
        } else {
            std::string name = wide ? utf16_to_utf8(e, name_or_addr, -1)
                                    : e.mem.read_cstring(name_or_addr);
            if (Emulator::Module* m = e.module_by_name(lowercase_name(name)))
                base = m->image.base;
            else
                base = e.hooked_module_handle(name);
        }
        if (out) e.mem.write_sized(out, e.pointer_size(), base);
        if (!base) e.set_last_error(126);  // ERROR_MOD_NOT_FOUND
        e.set_result(base ? 1 : 0);
    };
    win32("GetModuleHandleExW", 3,
          [get_module_handle_ex](Emulator& e) { get_module_handle_ex(e, true); });
    win32("GetModuleHandleExA", 3,
          [get_module_handle_ex](Emulator& e) { get_module_handle_ex(e, false); });
    win32("GetModuleFileNameA", 3, [](Emulator& e) {
        std::string name = program_path(e);
        uint64_t buf = e.arg_slot(1), size = e.arg_slot(2);
        if (name.size() + 1 > size && size) name.resize(static_cast<size_t>(size - 1));
        if (buf) e.mem.write_cstring(buf, name);
        e.set_result(name.size());
    });
    win32("GetModuleFileNameW", 3, [](Emulator& e) {
        std::string name = program_path(e);
        int n = write_utf16(e, e.arg_slot(1), name, static_cast<int>(e.arg_slot(2)));
        e.set_result(static_cast<uint64_t>(n > 0 ? n - 1 : 0));
    });
    // A DLL the emulator implements itself has no base address to hand out, so
    // LoadLibrary reports success with a sentinel handle: the guest only uses the
    // result to call GetProcAddress, which resolves such names to hooks.
    auto load_library_hook = [](Emulator& e, bool wide) {
        std::string name = wide ? utf16_to_utf8(e, e.arg_slot(0), -1)
                                : e.mem.read_cstring(e.arg_slot(0));
        uint64_t base = e.load_library(name);
        if (base) {
            e.set_result(base);
            return;
        }
        e.set_result(e.hooked_module_handle(name));
    };
    win32("LoadLibraryA", 1, [load_library_hook](Emulator& e) { load_library_hook(e, false); });
    win32("LoadLibraryW", 1, [load_library_hook](Emulator& e) { load_library_hook(e, true); });
    win32("LoadLibraryExA", 3, [load_library_hook](Emulator& e) { load_library_hook(e, false); });
    win32("LoadLibraryExW", 3, [load_library_hook](Emulator& e) { load_library_hook(e, true); });
    win32("GetProcAddress", 2, [](Emulator& e) {
        uint64_t module = e.arg_slot(0);
        uint64_t name_or_ordinal = e.arg_slot(1);
        // An argument below 0x10000 is an ordinal, not a pointer.
        if (name_or_ordinal < 0x10000) {
            e.set_result(e.find_export_ordinal(module, static_cast<uint32_t>(name_or_ordinal)));
            return;
        }
        std::string symbol = e.mem.read_cstring(name_or_ordinal);
        uint64_t addr = e.find_export(module, symbol);
        if (!addr) {
            // Either a hooked module, or a real one that does not export it.  A
            // hook exists only if the emulator implements the function; asking
            // for one it does not know must fail rather than return a stub, since
            // a guest probing for an optional API expects NULL.
            addr = e.existing_hook(symbol);
        }
        // A guest that resolves a symbol *at run time* and finds nothing usually
        // says so in a way that names neither the symbol nor the reason - a
        // delay-load failure surfaces as an exception code, for instance - so the
        // name is worth recording here.
        if (!addr) e.log_call("GetProcAddress(%s) found nothing", symbol.c_str());
        e.set_result(addr);
    });
    ret1("FreeLibrary", 1);
    win32("GetCommandLineA", 0, [](Emulator& e) {
        e.set_result(e.alloc_guest_string(command_line(e)));
    });
    win32("GetCommandLineW", 0, [](Emulator& e) {
        std::u16string w = utf8_to_utf16(command_line(e));
        std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
        std::memcpy(raw.data(), w.data(), w.size() * 2);
        e.set_result(e.alloc_guest_data(raw.data(), raw.size()));
    });
    win32("GetEnvironmentStringsW", 0,
          [](Emulator& e) { e.set_result(e.environment_block(true)); });
    win32("GetEnvironmentStrings", 0,
          [](Emulator& e) { e.set_result(e.environment_block(false)); });
    win32("GetEnvironmentStringsA", 0,
          [](Emulator& e) { e.set_result(e.environment_block(false)); });
    ret1("FreeEnvironmentStringsW", 1);
    ret1("FreeEnvironmentStringsA", 1);
    // (name, buffer, size) -> characters written, or the size needed, or 0.
    auto get_environment_variable = [](Emulator& e, bool wide) {
        std::string name = wide ? utf16_to_utf8(e, e.arg_slot(0), -1)
                                : e.mem.read_cstring(e.arg_slot(0));
        uint64_t buf = e.arg_slot(1);
        uint64_t size = e.arg_slot(2);
        const std::string* value = e.getenv(name);
        // Which variables a guest reads is most of what it needs from its
        // environment, and a missing one is a common reason to fail obscurely.
        e.log_call("GetEnvironmentVariable(%s) = %s", name.c_str(),
                   value ? value->c_str() : "(not set)");
        if (!value) {
            e.set_last_error(203);  // ERROR_ENVVAR_NOT_FOUND
            e.set_result(0);
            return;
        }
        if (wide) {
            std::u16string w = utf8_to_utf16(*value);
            if (w.size() + 1 > size || !buf) {
                e.set_result(w.size() + 1);  // the size the caller must provide
                return;
            }
            for (size_t i = 0; i <= w.size(); ++i)
                e.mem.write16(buf + i * 2, i < w.size() ? w[i] : 0);
            e.set_result(w.size());
        } else {
            if (value->size() + 1 > size || !buf) {
                e.set_result(value->size() + 1);
                return;
            }
            e.mem.write_cstring(buf, *value);
            e.set_result(value->size());
        }
    };
    win32("GetEnvironmentVariableA", 3,
          [get_environment_variable](Emulator& e) { get_environment_variable(e, false); });
    win32("GetEnvironmentVariableW", 3,
          [get_environment_variable](Emulator& e) { get_environment_variable(e, true); });
    auto set_environment_variable = [](Emulator& e, bool wide) {
        std::string name = wide ? utf16_to_utf8(e, e.arg_slot(0), -1)
                                : e.mem.read_cstring(e.arg_slot(0));
        uint64_t value_ptr = e.arg_slot(1);
        if (!value_ptr) {
            e.unsetenv(name);
        } else {
            e.setenv(name, wide ? utf16_to_utf8(e, value_ptr, -1)
                                : e.mem.read_cstring(value_ptr));
        }
        e.set_result(1);
    };
    win32("SetEnvironmentVariableA", 2,
          [set_environment_variable](Emulator& e) { set_environment_variable(e, false); });
    win32("SetEnvironmentVariableW", 2,
          [set_environment_variable](Emulator& e) { set_environment_variable(e, true); });
    win32("ExpandEnvironmentStringsA", 3, [](Emulator& e) { e.set_result(0); });
    win32("ExpandEnvironmentStringsW", 3, [](Emulator& e) { e.set_result(0); });
    win32("GetStartupInfoA", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        zero_fill(e, p, e.is64() ? 104 : 68);
        if (p) e.mem.write32(p, e.is64() ? 104 : 68);  // cb
        e.set_result(0);
    });
    win32("GetStartupInfoW", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        zero_fill(e, p, e.is64() ? 104 : 68);
        if (p) e.mem.write32(p, e.is64() ? 104 : 68);
        e.set_result(0);
    });
    win32("GetSystemInfo", 1, [](Emulator& e) {
        write_system_info(e, e.arg_slot(0));
        e.set_result(0);
    });

    // ---- errors and diagnostics ---------------------------------------------
    win32("GetLastError", 0, [](Emulator& e) { e.set_result(e.last_error()); });
    win32("SetLastError", 1, [](Emulator& e) {
        e.set_last_error(e.arg_slot(0));
        e.set_result(0);
    });
    win32("IsProcessorFeaturePresent", 1, [](Emulator& e) {
        e.set_result(processor_feature(static_cast<uint32_t>(e.arg_slot(0))) ? 1 : 0);
    });
    ret0("IsDebuggerPresent", 0);
    ret0("IsDBCSLeadByteEx", 2);
    ret0("IsDBCSLeadByte", 1);
    // EncodePointer/DecodePointer obfuscate a stored function pointer against
    // tampering.  An identity transform is a valid implementation - the CRT only
    // requires that decode undoes encode.
    win32("EncodePointer", 1, [](Emulator& e) { e.set_result(e.arg_slot(0)); });
    win32("DecodePointer", 1, [](Emulator& e) { e.set_result(e.arg_slot(0)); });
    win32("EncodeSystemPointer", 1, [](Emulator& e) { e.set_result(e.arg_slot(0)); });
    win32("DecodeSystemPointer", 1, [](Emulator& e) { e.set_result(e.arg_slot(0)); });
    ret0("InitializeSListHead", 1);
    ret0("SetUnhandledExceptionFilter", 1);
    ret1("UnhandledExceptionFilter", 1);  // EXCEPTION_EXECUTE_HANDLER
    ret1("SetConsoleCtrlHandler", 2);
    win32("OutputDebugStringA", 1, [](Emulator& e) {
        std::fprintf(stderr, "[dbg] %s", e.mem.read_cstring(e.arg_slot(0)).c_str());
        e.set_result(0);
    });
    win32("OutputDebugStringW", 1, [](Emulator& e) {
        std::fprintf(stderr, "[dbg] %s", utf16_to_utf8(e, e.arg_slot(0), -1).c_str());
        e.set_result(0);
    });
    // The x64 unwinder implements these (exceptions.cpp, installed after this
    // file's hooks).  In 32-bit code, where exception handling is the fs:[0]
    // chain instead, they are still unimplemented and say so.
    if (!is64()) {
        // These three are x64-only; 32-bit code has no unwind tables.
        for (const char* name : {"RtlCaptureContext", "RtlLookupFunctionEntry",
                                 "RtlVirtualUnwind"}) {
            std::string n = name;
            add_hook(n, 0, [n](Emulator& e) {
                throw CpuError(e.cpu().rip, n + " has no meaning in 32-bit code");
            });
        }
        win32("RtlPcToFileHeader", 2, [](Emulator& e) {
            Module* m = e.module_for(e.arg_slot(0));
            uint64_t base = m ? m->image.base : 0;
            if (e.arg_slot(1)) e.mem.write32(e.arg_slot(1), static_cast<uint32_t>(base));
            e.set_result(base);
        });
    }

    // ---- console -------------------------------------------------------------
    // The file-handle side of the console (GetStdHandle, WriteFile, GetFileType)
    // lives in hooks_files.cpp, since those are the same operations a guest
    // performs on any file.
    ret1("SetStdHandle", 2);
    win32("WriteConsoleA", 5, [](Emulator& e) {
        uint64_t buf = e.arg_slot(1), len = e.arg_slot(2), written_ptr = e.arg_slot(3);
        std::string data(static_cast<size_t>(len), '\0');
        if (len) e.mem.read(buf, data.data(), len);
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        e.write_raw(fd == 2 ? 2 : 1, data.data(), data.size());
        if (written_ptr) e.mem.write32(written_ptr, static_cast<uint32_t>(len));
        e.set_result(1);
    });
    win32("WriteConsoleW", 5, [](Emulator& e) {
        uint64_t buf = e.arg_slot(1), units = e.arg_slot(2), written_ptr = e.arg_slot(3);
        std::string utf8 = utf16_to_utf8(e, buf, static_cast<int>(units));
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        e.write_raw(fd == 2 ? 2 : 1, utf8.data(), utf8.size());
        if (written_ptr) e.mem.write32(written_ptr, static_cast<uint32_t>(units));
        e.set_result(1);
    });
    // Failing here is deliberate: the CRT then treats stdout as a plain byte
    // stream and writes through WriteFile, which is a much simpler path than
    // console-specific handling.
    ret0("GetConsoleMode", 2);
    ret0("SetConsoleMode", 2);
    ret0("GetConsoleOutputCP", 0);

    // ---- memory --------------------------------------------------------------
    win32("GetProcessHeap", 0, [](Emulator& e) { e.set_result(0x00420000); });
    win32("HeapAlloc", 3, [](Emulator& e) {
        uint64_t flags = e.arg_slot(1), size = e.arg_slot(2);
        uint64_t p = e.heap_alloc(size);
        if (p && (flags & 0x8)) zero_fill(e, p, static_cast<size_t>(size));  // HEAP_ZERO_MEMORY
        e.set_result(p);
    });
    win32("HeapFree", 3, [](Emulator& e) {
        e.heap_free(e.arg_slot(2));
        e.set_result(1);
    });
    win32("HeapReAlloc", 4, [](Emulator& e) {
        e.set_result(e.heap_realloc(e.arg_slot(2), e.arg_slot(3)));
    });
    win32("HeapSize", 3, [](Emulator& e) { e.set_result(e.heap_block_size(e.arg_slot(2))); });
    win32("HeapCreate", 3, [](Emulator& e) { e.set_result(0x00420000); });
    ret1("HeapDestroy", 1);
    ret1("HeapSetInformation", 4);
    ret1("HeapValidate", 3);
    win32("LocalAlloc", 2, [](Emulator& e) { e.set_result(e.heap_alloc(e.arg_slot(1))); });
    win32("LocalFree", 1, [](Emulator& e) {
        e.heap_free(e.arg_slot(0));
        e.set_result(0);
    });
    // (address, size, type, protect).  The address it returns must be aligned to
    // the *allocation granularity*, 64 KiB, not to a page: a guest that keeps
    // metadata by masking an allocation's low bits - a compiler's arena
    // allocator does - computes a wild pointer otherwise.
    // (address, size, type, protect).  The two halves of this call have to work
    // *together*: a guest reserves a large region with a NULL address and then
    // commits pieces of it by passing addresses inside it.  Ignoring the address
    // and handing back a fresh region each time leaves the guest computing
    // pointers into the region it thinks it has - which is how a compiler's arena
    // ends up dereferencing 0x6BB00000000.
    //
    // Reserving does not create pages, so a 100 MB reservation costs nothing
    // until the guest commits parts of it; touching reserved-but-uncommitted
    // memory faults, exactly as it would on Windows.
    auto virtual_alloc = [](Emulator& e, uint64_t want, uint64_t size, uint32_t type) {
        constexpr uint32_t kCommit = 0x1000, kReserve = 0x2000;
        uint64_t addr;
        if (want) {
            addr = want & ~0xFFFull;
            uint64_t end = (want + size + 0xFFF) & ~0xFFFull;
            if (type & kCommit) e.mem.map(addr, end - addr);
        } else if ((type & kReserve) && !(type & kCommit)) {
            addr = e.reserve_pages(size, 0x10000);
        } else {
            addr = e.alloc_pages(size, 0x10000);
        }
        e.log_call("VirtualAlloc(want 0x%llX, %llu bytes, type 0x%X) = 0x%llX",
                   (unsigned long long)want, (unsigned long long)size, type,
                   (unsigned long long)addr);
        e.set_result(addr);
    };
    win32("VirtualAlloc", 4, [virtual_alloc](Emulator& e) {
        virtual_alloc(e, e.arg_slot(0), e.arg_slot(1), static_cast<uint32_t>(e.arg_slot(2)));
    });
    win32("VirtualAllocEx", 5, [virtual_alloc](Emulator& e) {
        virtual_alloc(e, e.arg_slot(1), e.arg_slot(2), static_cast<uint32_t>(e.arg_slot(3)));
    });
    ret1("VirtualFree", 3);
    ret1("VirtualProtect", 4);
    win32("VirtualQuery", 3, [](Emulator& e) {
        // Enough of a MEMORY_BASIC_INFORMATION for the CRT's "is this address in
        // my own image" checks.
        uint64_t addr = e.arg_slot(0), out = e.arg_slot(1);
        size_t size = e.is64() ? 48 : 28;
        zero_fill(e, out, size);
        if (out) {
            bool in_image = addr >= e.image().image_base &&
                            addr < e.image().image_base + e.image().image_size;
            int ps = e.pointer_size();
            e.mem.write_sized(out, ps, addr & ~0xFFFull);            // BaseAddress
            e.mem.write_sized(out + ps, ps, e.image().image_base);   // AllocationBase
            uint64_t p = e.is64() ? out + 20 : out + 8;
            e.mem.write32(p, in_image ? 0x02 : 0x04);                // AllocationProtect
            e.mem.write_sized(e.is64() ? out + 24 : out + 12, ps, 0x1000);  // RegionSize
            uint64_t rest = e.is64() ? out + 32 : out + 16;
            e.mem.write32(rest, 0x1000);                             // State = MEM_COMMIT
            e.mem.write32(rest + 4, in_image ? 0x02 : 0x04);         // Protect
            e.mem.write32(rest + 8, in_image ? 0x1000000 : 0x20000); // Type
        }
        e.set_result(size);
    });

    // ---- threads and synchronisation (single-threaded, so all no-ops) --------
    for (const char* n : {"EnterCriticalSection", "LeaveCriticalSection",
                          "DeleteCriticalSection", "InitializeCriticalSection"})
        win32(n, 1, [](Emulator& e) { e.set_result(0); });
    ret1("InitializeCriticalSectionAndSpinCount", 2);
    ret1("InitializeCriticalSectionEx", 3);
    ret1("TryEnterCriticalSection", 1);
    ret0("SwitchToThread", 0);
    ret0("Sleep", 1);
    ret1("SleepEx", 2);
    win32("TlsAlloc", 0, [](Emulator& e) { e.set_result(e.tls_alloc()); });
    win32("TlsGetValue", 1, [](Emulator& e) {
        e.set_result(e.tls_get(static_cast<uint32_t>(e.arg_slot(0))));
    });
    win32("TlsSetValue", 2, [](Emulator& e) {
        e.tls_set(static_cast<uint32_t>(e.arg_slot(0)), e.arg_slot(1));
        e.set_result(1);
    });
    ret1("TlsFree", 1);
    // Fls* is the fibre-local flavour of the same thing; the destructor callback
    // is irrelevant because nothing here ever unwinds a fibre.
    win32("FlsAlloc", 1, [](Emulator& e) { e.set_result(e.tls_alloc()); });
    win32("FlsGetValue", 1, [](Emulator& e) {
        e.set_result(e.tls_get(static_cast<uint32_t>(e.arg_slot(0))));
    });
    win32("FlsSetValue", 2, [](Emulator& e) {
        e.tls_set(static_cast<uint32_t>(e.arg_slot(0)), e.arg_slot(1));
        e.set_result(1);
    });
    ret1("FlsFree", 1);

    // ---- time ----------------------------------------------------------------
    auto file_time = [](Emulator& e) {
        // FILETIME counts 100 ns ticks since 1601; 11644473600 s to the epoch.
        uint64_t ticks = (static_cast<uint64_t>(std::time(nullptr)) + 11644473600ull) * 10000000ull;
        uint64_t p = e.arg_slot(0);
        if (p) e.mem.write64(p, ticks);
        e.set_result(0);
    };
    win32("GetSystemTimeAsFileTime", 1, file_time);
    win32("GetSystemTimePreciseAsFileTime", 1, file_time);
    win32("GetTickCount", 0, [](Emulator& e) {
        e.set_result(e.cpu().instructions_executed / 10000);
    });
    win32("GetTickCount64", 0, [](Emulator& e) {
        e.set_result(e.cpu().instructions_executed / 10000);
    });
    win32("QueryPerformanceCounter", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) e.mem.write64(p, e.cpu().instructions_executed);
        e.set_result(1);
    });
    win32("QueryPerformanceFrequency", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) e.mem.write64(p, 1000000);
        e.set_result(1);
    });
    ret0("GetTimeZoneInformation", 1);

    // ---- code pages and locale ------------------------------------------------
    win32("GetACP", 0, [](Emulator& e) { e.set_result(65001); });  // UTF-8
    win32("GetOEMCP", 0, [](Emulator& e) { e.set_result(437); });
    ret1("IsValidCodePage", 1);
    win32("GetCPInfo", 2, [](Emulator& e) {
        uint64_t p = e.arg_slot(1);
        zero_fill(e, p, 20);
        if (p) e.mem.write32(p, 1);  // MaxCharSize
        e.set_result(1);
    });
    win32("MultiByteToWideChar", 6, [](Emulator& e) {
        uint64_t src = e.arg_slot(2);
        int src_len = static_cast<int>(static_cast<int32_t>(e.arg_slot(3)));
        uint64_t dst = e.arg_slot(4);
        int dst_units = static_cast<int>(static_cast<int32_t>(e.arg_slot(5)));
        std::string s;
        if (src_len < 0) {
            s = e.mem.read_cstring(src);
        } else {
            s.resize(static_cast<size_t>(src_len));
            if (src_len) e.mem.read(src, s.data(), static_cast<uint64_t>(src_len));
        }
        std::u16string w = utf8_to_utf16(s);
        // A zero destination size is a request for the required length.
        if (dst_units == 0 || dst == 0) {
            e.set_result(static_cast<uint64_t>(w.size() + (src_len < 0 ? 1 : 0)));
            return;
        }
        int n = 0;
        for (; n < static_cast<int>(w.size()) && n < dst_units; ++n)
            e.mem.write16(dst + static_cast<uint64_t>(n) * 2, w[n]);
        if (src_len < 0 && n < dst_units) {
            e.mem.write16(dst + static_cast<uint64_t>(n) * 2, 0);
            ++n;
        }
        e.set_result(static_cast<uint64_t>(n));
    });
    win32("WideCharToMultiByte", 8, [](Emulator& e) {
        uint64_t src = e.arg_slot(2);
        int src_units = static_cast<int>(static_cast<int32_t>(e.arg_slot(3)));
        uint64_t dst = e.arg_slot(4);
        int dst_bytes = static_cast<int>(static_cast<int32_t>(e.arg_slot(5)));
        std::string utf8 = utf16_to_utf8(e, src, src_units);
        if (src_units < 0) utf8.push_back('\0');
        if (dst_bytes == 0 || dst == 0) {
            e.set_result(utf8.size());
            return;
        }
        size_t n = utf8.size() < static_cast<size_t>(dst_bytes) ? utf8.size()
                                                                : static_cast<size_t>(dst_bytes);
        if (n) e.mem.write(dst, utf8.data(), n);
        e.set_result(n);
    });
    win32("LCMapStringW", 6, [](Emulator& e) {
        // No case mapping: copy the input through unchanged.
        uint64_t src = e.arg_slot(2);
        int units = static_cast<int>(static_cast<int32_t>(e.arg_slot(3)));
        std::string s = utf16_to_utf8(e, src, units);
        int n = write_utf16(e, e.arg_slot(4), s, static_cast<int>(e.arg_slot(5)));
        e.set_result(static_cast<uint64_t>(n));
    });
    // (locale, flags, src, src_len, dest, dest_len, version, reserved, sort handle)
    // Only the case-mapping flags matter here; a path normaliser uses nothing
    // else, and returning failure makes it raise instead.
    win32("LCMapStringEx", 9, [](Emulator& e) {
        uint32_t flags = static_cast<uint32_t>(e.arg_slot(1));
        int src_len = static_cast<int>(static_cast<int32_t>(e.arg_slot(3)));
        std::string text = utf16_to_utf8(e, e.arg_slot(2), src_len);
        uint64_t dest = e.arg_slot(4);
        int dest_len = static_cast<int>(static_cast<int32_t>(e.arg_slot(5)));

        constexpr uint32_t kLowercase = 0x00000100;
        constexpr uint32_t kUppercase = 0x00000200;
        std::u16string mapped = utf8_to_utf16(text);
        // A negative source length means "NUL-terminated", and in that case the
        // result - and the returned count - include the terminator.  Callers rely
        // on this: CPython asks for the size, allocates it, and then takes the
        // string as size-1 characters.
        if (src_len < 0) mapped.push_back(0);
        for (char16_t& c : mapped) {
            // ASCII and Latin-1 are as far as this goes; a full case table would
            // need the host's locale data, which is not what a path comparison
            // depends on.
            if (flags & kLowercase) {
                if ((c >= 'A' && c <= 'Z') || (c >= 0xC0 && c <= 0xDE && c != 0xD7))
                    c = static_cast<char16_t>(c + 0x20);
            } else if (flags & kUppercase) {
                if ((c >= 'a' && c <= 'z') || (c >= 0xE0 && c <= 0xFE && c != 0xF7))
                    c = static_cast<char16_t>(c - 0x20);
            }
        }
        // A zero destination length asks for the size rather than the result.
        if (dest_len == 0 || dest == 0) {
            e.set_result(mapped.size());
            return;
        }
        if (static_cast<int>(mapped.size()) > dest_len) {
            e.set_last_error(122);  // ERROR_INSUFFICIENT_BUFFER
            e.set_result(0);
            return;
        }
        for (size_t i = 0; i < mapped.size(); ++i) e.mem.write16(dest + i * 2, mapped[i]);
        // The count excludes a terminator unless one was in the input.
        e.set_result(mapped.size());
    });
    win32("CompareStringW", 6, [](Emulator& e) {
        std::string a = utf16_to_utf8(e, e.arg_slot(2), static_cast<int>(static_cast<int32_t>(e.arg_slot(3))));
        std::string b = utf16_to_utf8(e, e.arg_slot(4), static_cast<int>(static_cast<int32_t>(e.arg_slot(5))));
        int c = a.compare(b);
        e.set_result(c < 0 ? 1u : c > 0 ? 3u : 2u);  // CSTR_LESS/EQUAL/GREATER
    });
    win32("GetStringTypeW", 4, [](Emulator& e) { e.set_result(1); });
    win32("GetLocaleInfoW", 4, [](Emulator& e) { e.set_result(0); });
    win32("GetUserDefaultLCID", 0, [](Emulator& e) { e.set_result(0x0409); });
    ret1("IsValidLocale", 2);
    ret1("EnumSystemLocalesW", 2);
    ret1("EnumSystemLocalesEx", 4);
    win32("lstrlenA", 1, [](Emulator& e) {
        e.set_result(e.mem.read_cstring(e.arg_slot(0)).size());
    });
}

// ---------------------------------------------------------------------------
// Universal CRT
// ---------------------------------------------------------------------------

void Emulator::install_ucrt_hooks() {
    // The UCRT is cdecl in both bitnesses.
    auto ucrt = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };
    auto ret0 = [&](const char* name) {
        ucrt(name, [](Emulator& e) { e.set_result(0); });
    };

    // ---- stdio ---------------------------------------------------------------
    // With a UCRT, printf is an inline function in <stdio.h> that builds a
    // va_list and calls this; the visible import is never "printf".
    ucrt("__stdio_common_vfprintf", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);                    // options
        uint64_t stream = a.next_ptr();
        uint64_t fmt = a.next_ptr();
        a.next_ptr();                     // locale
        uint64_t va = a.next_ptr();
        Args tail = Args::va_list_at(e, va);
        std::string s = format_guest(e, fmt, tail);
        int fd = e.host_fd(stream);
        e.write_text(fd == 2 ? 2 : 1, s);
        e.set_result(s.size());
    });
    ucrt("__stdio_common_vsprintf", [](Emulator& e) {
        Args a(e, 0);
        uint64_t options = a.next_int(8);
        uint64_t buf = a.next_ptr();
        uint64_t count = a.next_ptr();
        uint64_t fmt = a.next_ptr();
        a.next_ptr();                     // locale
        uint64_t va = a.next_ptr();
        Args tail = Args::va_list_at(e, va);
        std::string s = format_guest(e, fmt, tail);
        bool truncated = count && s.size() >= count;
        if (buf && count) {
            size_t n = truncated ? static_cast<size_t>(count - 1) : s.size();
            e.mem.write(buf, s.data(), n);
            e.mem.write8(buf + n, 0);
        }
        // _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR asks for the length the
        // output would have had; without it, truncation reports failure.
        if (options & 0x10)
            e.set_result(s.size());
        else
            e.set_result(truncated ? ~0ull : s.size());
    });
    ucrt("__stdio_common_vswprintf", [](Emulator& e) {
        Args a(e, 0);
        uint64_t options = a.next_int(8);
        uint64_t buf = a.next_ptr();
        uint64_t count = a.next_ptr();  // in wide characters
        uint64_t fmt = a.next_ptr();
        a.next_ptr();                   // locale
        uint64_t va = a.next_ptr();
        Args tail = Args::va_list_at(e, va);
        std::u16string s = utf8_to_utf16(format_guest(e, fmt, tail, true));
        bool truncated = count && s.size() >= count;
        if (buf && count) {
            size_t n = truncated ? static_cast<size_t>(count - 1) : s.size();
            for (size_t i = 0; i < n; ++i) e.mem.write16(buf + i * 2, s[i]);
            e.mem.write16(buf + n * 2, 0);
        }
        if (options & 0x10)
            e.set_result(s.size());
        else
            e.set_result(truncated ? ~0ull : s.size());
    });
    ucrt("__stdio_common_vfwprintf", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);                    // options
        uint64_t stream = a.next_ptr();
        uint64_t fmt = a.next_ptr();
        a.next_ptr();                     // locale
        uint64_t va = a.next_ptr();
        Args tail = Args::va_list_at(e, va);
        std::string s = format_guest(e, fmt, tail, true);
        int fd = e.host_fd(stream);
        e.write_text(fd == 2 ? 2 : 1, s);
        e.set_result(s.size());
    });
    ucrt("__acrt_iob_func", [](Emulator& e) {
        e.set_result(e.guest_file(static_cast<int>(e.arg_slot(0))));
    });
    ret0("_set_fmode");
    ucrt("__p__commode", [](Emulator& e) {
        static const uint32_t zero = 0;
        e.set_result(e.alloc_guest_data(&zero, sizeof zero));
    });
    ucrt("__p__fmode", [](Emulator& e) {
        static const uint32_t zero = 0;
        e.set_result(e.alloc_guest_data(&zero, sizeof zero));
    });

    // ---- startup and shutdown -------------------------------------------------
    // _initterm walks a table of initialiser pointers and calls each one; this is
    // what runs a C++ program's static constructors, so it has to re-enter the
    // guest rather than be stubbed out.
    ucrt("_initterm", [](Emulator& e) {
        uint64_t first = e.arg_slot(0), last = e.arg_slot(1);
        int ps = e.pointer_size();
        int called = 0;
        for (uint64_t p = first; p < last && !e.cpu().halted; p += ps) {
            uint64_t fn = e.mem.read_sized(p, ps);
            if (!fn) continue;
            ++called;
            e.call_guest(fn, {});
        }
        e.log_call("_initterm ran %d initialisers", called);
        e.set_result(0);
    });
    ucrt("_initterm_e", [](Emulator& e) {
        uint64_t first = e.arg_slot(0), last = e.arg_slot(1);
        int ps = e.pointer_size();
        uint64_t result = 0;
        int called = 0;
        for (uint64_t p = first; p < last && !e.cpu().halted; p += ps) {
            uint64_t fn = e.mem.read_sized(p, ps);
            if (!fn) continue;
            result = e.call_guest(fn, {}) & 0xFFFFFFFFull;
            ++called;
            if (result) break;  // a non-zero return aborts initialisation
        }
        e.log_call("_initterm_e ran %d initialisers, result %llu", called,
                   (unsigned long long)result);
        e.set_result(result);
    });
    ret0("_configure_narrow_argv");
    ret0("_configure_wide_argv");
    ret0("_initialize_narrow_environment");
    ret0("_initialize_wide_environment");
    ucrt("_get_initial_narrow_environment", [](Emulator& e) {
        const uint8_t empty[8] = {0};  // an empty char*[] terminated by NULL
        e.set_result(e.alloc_guest_data(empty, sizeof empty));
    });
    ucrt("_get_initial_wide_environment", [](Emulator& e) {
        const uint8_t empty[8] = {0};
        e.set_result(e.alloc_guest_data(empty, sizeof empty));
    });
    ucrt("__p___argc", [](Emulator& e) {
        uint32_t argc = static_cast<uint32_t>(e.args().size());
        e.set_result(e.alloc_guest_data(&argc, sizeof argc));
    });
    ucrt("__p___argv", [](Emulator& e) {
        // Build a real argv[] in guest memory and hand back a pointer to it.
        int ps = e.pointer_size();
        std::vector<uint64_t> ptrs;
        for (const auto& a : e.args()) ptrs.push_back(e.alloc_guest_string(a));
        std::vector<uint8_t> table((ptrs.size() + 1) * ps, 0);
        uint64_t argv = e.alloc_guest_data(table.data(), table.size());
        for (size_t i = 0; i < ptrs.size(); ++i)
            e.mem.write_sized(argv + i * ps, ps, ptrs[i]);
        std::vector<uint8_t> slot(ps, 0);
        uint64_t out = e.alloc_guest_data(slot.data(), slot.size());
        e.mem.write_sized(out, ps, argv);
        e.set_result(out);
    });
    ucrt("__p___wargv", [](Emulator& e) {
        // A wchar_t*[] of the arguments, and a pointer to that array.
        int ps = e.pointer_size();
        std::vector<uint64_t> ptrs;
        for (const auto& a : e.args()) {
            std::u16string w = utf8_to_utf16(a);
            std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
            std::memcpy(raw.data(), w.data(), w.size() * 2);
            ptrs.push_back(e.alloc_guest_data(raw.data(), raw.size()));
        }
        std::vector<uint8_t> table((ptrs.size() + 1) * ps, 0);
        uint64_t argv = e.alloc_guest_data(table.data(), table.size());
        for (size_t i = 0; i < ptrs.size(); ++i)
            e.mem.write_sized(argv + i * ps, ps, ptrs[i]);
        std::vector<uint8_t> slot(ps, 0);
        uint64_t out = e.alloc_guest_data(slot.data(), slot.size());
        e.mem.write_sized(out, ps, argv);
        for (size_t i = 0; i < e.args().size(); ++i)
            e.log_call("__p___wargv[%zu] = '%s' at 0x%llX", i, e.args()[i].c_str(),
                       (unsigned long long)ptrs[i]);
        e.set_result(out);
    });
    // `environ` and `_wenviron` are variables, so what a guest imports is the
    // address of a pointer to the block.
    ucrt("__p__environ", [](Emulator& e) {
        int ps = e.pointer_size();
        std::vector<uint8_t> slot(ps, 0);
        uint64_t out = e.alloc_guest_data(slot.data(), slot.size());
        e.mem.write_sized(out, ps, e.environment_vector());
        e.set_result(out);
    });
    ucrt("__p__wenviron", [](Emulator& e) {
        int ps = e.pointer_size();
        std::vector<uint64_t> ptrs;
        for (const auto& [k, v] : e.environment()) {
            std::u16string w = utf8_to_utf16(k + "=" + v);
            std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
            std::memcpy(raw.data(), w.data(), w.size() * 2);
            ptrs.push_back(e.alloc_guest_data(raw.data(), raw.size()));
        }
        std::vector<uint8_t> table((ptrs.size() + 1) * ps, 0);
        uint64_t block = e.alloc_guest_data(table.data(), table.size());
        for (size_t i = 0; i < ptrs.size(); ++i)
            e.mem.write_sized(block + i * ps, ps, ptrs[i]);
        std::vector<uint8_t> slot(ps, 0);
        uint64_t out = e.alloc_guest_data(slot.data(), slot.size());
        e.mem.write_sized(out, ps, block);
        e.set_result(out);
    });
    ucrt("_get_initial_wide_environment", [](Emulator& e) { e.set_result(0); });

    ucrt("_get_narrow_winmain_command_line", [](Emulator& e) {
        e.set_result(e.alloc_guest_string(command_line(e)));
    });
    ret0("__setusermatherr");
    ret0("_set_app_type");
    ret0("__set_app_type");
    ret0("_configthreadlocale");
    ret0("_set_new_mode");
    ret0("_controlfp_s");
    ret0("_set_invalid_parameter_handler");
    ret0("_set_thread_local_invalid_parameter_handler");
    ret0("_initialize_onexit_table");
    ret0("_crt_at_quick_exit");
    ret0("_query_app_type");
    ucrt("_register_onexit_function", [](Emulator& e) {
        // (table, function) - the table is the CRT's business, the function ours.
        uint64_t fn = e.arg_slot(1);
        if (fn) e.add_atexit(fn);
        e.set_result(0);
    });
    ucrt("_crt_atexit", [](Emulator& e) {
        uint64_t fn = e.arg_slot(0);
        if (fn) e.add_atexit(fn);
        e.set_result(0);
    });
    // msvcrt's older spelling; returns the function on success.
    ucrt("_onexit", [](Emulator& e) {
        uint64_t fn = e.arg_slot(0);
        if (fn) e.add_atexit(fn);
        e.set_result(fn);
    });
    // (onexit table begin/end pointers, function) - mingw's DLL-aware variant.
    ucrt("__dllonexit", [](Emulator& e) {
        uint64_t fn = e.arg_slot(0);
        if (fn) e.add_atexit(fn);
        e.set_result(fn);
    });
    ucrt("_execute_onexit_table", [](Emulator& e) {
        e.run_atexit();
        e.set_result(0);
    });
    auto do_exit = [](Emulator& e) {
        int code = static_cast<int>(static_cast<int32_t>(e.arg_slot(0)));
        e.run_atexit();
        e.exit_process(code);
    };
    ucrt("exit", do_exit);
    ucrt("_exit", [](Emulator& e) {
        e.exit_process(static_cast<int>(static_cast<int32_t>(e.arg_slot(0))));
    });
    ucrt("quick_exit", do_exit);
    ucrt("_cexit", [](Emulator& e) {
        e.run_atexit();
        e.set_result(0);
    });
    ucrt("_c_exit", [](Emulator& e) { e.set_result(0); });
    ucrt("terminate", [](Emulator& e) {
        std::fprintf(stderr, "[guest] terminate()\n");
        e.exit_process(3);
    });
    ucrt("_seh_filter_exe", [](Emulator& e) { e.set_result(1); });
    ucrt("__current_exception", [](Emulator& e) { e.set_result(0); });
    ucrt("__current_exception_context", [](Emulator& e) { e.set_result(0); });
    ucrt("__processing_throw", [](Emulator& e) { e.set_result(0); });
    ret0("_get_wide_winmain_command_line");

    // The language handlers themselves belong to the guest's runtime, and for a
    // statically linked CRT they are in the image.  What remains here is the
    // cases where the guest imports one, which only a /MD build does: the C one
    // the x64 unwinder implements (exceptions.cpp), and the C++ ones that live
    // in vcruntime140.dll and would need that DLL loaded for real.
    for (const char* name : {"_except_handler4_common", "_CxxThrowException",
                             "__CxxFrameHandler3", "__CxxFrameHandler4", "_purecall"}) {
        std::string n = name;
        add_hook(n, 0, [n](Emulator& e) {
            throw CpuError(e.cpu().rip,
                           n + ": this build imports its exception runtime from a DLL; "
                               "the emulator implements the kernel's half only");
        });
    }
}

}  // namespace x86emu
