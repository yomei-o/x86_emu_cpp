// Host implementations of the library functions the guest imports.
//
// Every hook reads its arguments through Emulator::Args (which knows the active
// calling convention), does the work with real host C++, and leaves the result
// in RAX/EAX.  The emulator performs the return, so a hook never touches RIP.
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "emulator.h"

namespace x86emu {
namespace {

// ---------------------------------------------------------------------------
// printf-family formatting
// ---------------------------------------------------------------------------

int64_t sign_extend(uint64_t v, int bytes) {
    switch (bytes) {
        case 1: return static_cast<int8_t>(v);
        case 2: return static_cast<int16_t>(v);
        case 4: return static_cast<int32_t>(v);
        default: return static_cast<int64_t>(v);
    }
}

std::string pad(const std::string& s, int width, bool left_align) {
    if (width <= 0 || static_cast<int>(s.size()) >= width) return s;
    std::string fill(static_cast<size_t>(width) - s.size(), ' ');
    return left_align ? s + fill : fill + s;
}

// Formats a guest format string, pulling the variadic arguments through `va`.
// Conversions are handed to the host's snprintf so that padding, precision and
// rounding match a real libc.
std::string format(Emulator& e, uint64_t fmt_ptr, Emulator::Args& va) {
    if (fmt_ptr == 0) return "(null)";
    const std::string fmt = e.mem.read_cstring(fmt_ptr);
    std::string out;

    size_t i = 0;
    while (i < fmt.size()) {
        if (fmt[i] != '%') {
            out += fmt[i++];
            continue;
        }
        ++i;
        if (i < fmt.size() && fmt[i] == '%') {
            out += '%';
            ++i;
            continue;
        }

        std::string flags;
        while (i < fmt.size() && std::strchr("-+ #0", fmt[i])) {
            flags += fmt[i++];
        }

        bool has_width = false;
        int width = 0;
        if (i < fmt.size() && fmt[i] == '*') {
            ++i;
            width = static_cast<int>(sign_extend(va.next_int(4), 4));
            has_width = true;
            if (width < 0) {  // a negative * width means left alignment
                flags += '-';
                width = -width;
            }
        } else {
            std::string digits;
            while (i < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[i])))
                digits += fmt[i++];
            if (!digits.empty()) {
                width = std::atoi(digits.c_str());
                has_width = true;
            }
        }

        bool has_prec = false;
        int prec = 0;
        if (i < fmt.size() && fmt[i] == '.') {
            ++i;
            has_prec = true;
            if (i < fmt.size() && fmt[i] == '*') {
                ++i;
                prec = static_cast<int>(sign_extend(va.next_int(4), 4));
                if (prec < 0) has_prec = false;
            } else {
                std::string digits;
                while (i < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[i])))
                    digits += fmt[i++];
                prec = digits.empty() ? 0 : std::atoi(digits.c_str());
            }
        }

        // Length modifiers.  `long` is 4 bytes everywhere except 64-bit Linux.
        int int_bytes = 4;
        for (bool more = true; more && i < fmt.size();) {
            if (fmt.compare(i, 2, "hh") == 0) {
                i += 2;
            } else if (fmt.compare(i, 2, "ll") == 0) {
                i += 2;
                int_bytes = 8;
            } else if (fmt.compare(i, 3, "I64") == 0) {
                i += 3;
                int_bytes = 8;
            } else if (fmt.compare(i, 3, "I32") == 0) {
                i += 3;
                int_bytes = 4;
            } else if (fmt[i] == 'h') {
                ++i;
            } else if (fmt[i] == 'l') {
                ++i;
                int_bytes = (e.is64() && e.os() == Os::Linux) ? 8 : 4;
            } else if (fmt[i] == 'j' || fmt[i] == 'z' || fmt[i] == 't' || fmt[i] == 'I') {
                ++i;
                int_bytes = e.pointer_size();
            } else if (fmt[i] == 'L' || fmt[i] == 'q') {
                ++i;
                int_bytes = 8;
            } else {
                more = false;
            }
        }
        if (i >= fmt.size()) break;
        char conv = fmt[i++];

        // Rebuilds the conversion spec for the host, forcing a `ll` length so
        // that one code path covers every guest integer width.
        auto host_spec = [&](const char* length, char cv) {
            std::string s = "%" + flags;
            if (has_width) s += std::to_string(width);
            if (has_prec) s += "." + std::to_string(prec);
            s += length;
            s += cv;
            return s;
        };
        std::vector<char> buf(static_cast<size_t>(64 + (has_width ? width : 0) +
                                                  (has_prec ? prec : 0)));

        switch (conv) {
            case 'd':
            case 'i': {
                long long v = static_cast<long long>(sign_extend(va.next_int(int_bytes), int_bytes));
                std::snprintf(buf.data(), buf.size(), host_spec("ll", 'd').c_str(), v);
                out += buf.data();
                break;
            }
            case 'u':
            case 'o':
            case 'x':
            case 'X': {
                unsigned long long v = va.next_int(int_bytes);
                if (int_bytes == 4) v &= 0xFFFFFFFFull;
                std::snprintf(buf.data(), buf.size(), host_spec("ll", conv).c_str(), v);
                out += buf.data();
                break;
            }
            case 'c': {
                char ch = static_cast<char>(va.next_int(4));
                out += pad(std::string(1, ch), has_width ? width : 0,
                           flags.find('-') != std::string::npos);
                break;
            }
            case 's': {
                uint64_t p = va.next_ptr();
                std::string s = p ? e.mem.read_cstring(p) : "(null)";
                if (has_prec && static_cast<int>(s.size()) > prec)
                    s.resize(static_cast<size_t>(prec));
                out += pad(s, has_width ? width : 0, flags.find('-') != std::string::npos);
                break;
            }
            case 'p': {
                uint64_t p = va.next_ptr();
                // msvcrt prints bare uppercase hex; glibc prints 0x-prefixed.
                if (e.os() == Os::Windows)
                    std::snprintf(buf.data(), buf.size(), e.is64() ? "%016llX" : "%08llX",
                                  static_cast<unsigned long long>(p));
                else
                    std::snprintf(buf.data(), buf.size(), "0x%llx",
                                  static_cast<unsigned long long>(p));
                out += buf.data();
                break;
            }
            case 'f':
            case 'F':
            case 'e':
            case 'E':
            case 'g':
            case 'G':
            case 'a':
            case 'A': {
                double d = va.next_double();
                buf.resize(buf.size() + 512);  // %f of a huge value is long
                std::snprintf(buf.data(), buf.size(), host_spec("", conv).c_str(), d);
                out += buf.data();
                break;
            }
            case 'n': {
                uint64_t p = va.next_ptr();
                if (p) e.mem.write32(p, static_cast<uint32_t>(out.size()));
                break;
            }
            default:
                // Unknown conversion: reproduce it literally, like most libcs.
                out += '%';
                out += conv;
                break;
        }
    }
    return out;
}

void write_out(Emulator& e, int fd, const std::string& s) {
    std::FILE* f = fd == 2 ? stderr : stdout;
    if (!s.empty()) std::fwrite(s.data(), 1, s.size(), f);
    (void)e;
}

// Resolves a guest FILE* to a host stream, defaulting to stdout when the guest
// obtained it from something we do not model (e.g. an imported _iob array).
int stream_fd(Emulator& e, uint64_t guest_file) {
    int fd = e.host_fd(guest_file);
    return fd < 0 ? 1 : fd;
}

}  // namespace

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void Emulator::install_library_hooks() {
    // cdecl / caller-cleanup: the C runtime.
    auto libc = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };
    // stdcall in 32-bit mode: the Win32 API pops its own arguments.
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, is64() ? 0 : nargs * 4, std::move(fn));
    };

    // ---- stdio ------------------------------------------------------------
    libc("printf", [](Emulator& e) {
        Args va(e, 1);
        std::string s = format(e, e.arg_slot(0), va);
        write_out(e, 1, s);
        e.set_result(s.size());
    });
    libc("puts", [](Emulator& e) {
        std::string s = e.mem.read_cstring(e.arg_slot(0));
        write_out(e, 1, s + "\n");
        e.set_result(static_cast<uint64_t>(s.size() + 1));
    });
    libc("putchar", [](Emulator& e) {
        char c = static_cast<char>(e.arg_slot(0));
        write_out(e, 1, std::string(1, c));
        e.set_result(static_cast<uint8_t>(c));
    });
    libc("fprintf", [](Emulator& e) {
        int fd = stream_fd(e, e.arg_slot(0));
        Args va(e, 2);
        std::string s = format(e, e.arg_slot(1), va);
        write_out(e, fd, s);
        e.set_result(s.size());
    });
    libc("fputs", [](Emulator& e) {
        std::string s = e.mem.read_cstring(e.arg_slot(0));
        write_out(e, stream_fd(e, e.arg_slot(1)), s);
        e.set_result(static_cast<uint64_t>(s.size()));
    });
    libc("fputc", [](Emulator& e) {
        char c = static_cast<char>(e.arg_slot(0));
        write_out(e, stream_fd(e, e.arg_slot(1)), std::string(1, c));
        e.set_result(static_cast<uint8_t>(c));
    });
    libc("putc", [](Emulator& e) {
        char c = static_cast<char>(e.arg_slot(0));
        write_out(e, stream_fd(e, e.arg_slot(1)), std::string(1, c));
        e.set_result(static_cast<uint8_t>(c));
    });
    libc("sprintf", [](Emulator& e) {
        Args va(e, 2);
        std::string s = format(e, e.arg_slot(1), va);
        e.mem.write_cstring(e.arg_slot(0), s);
        e.set_result(s.size());
    });
    libc("snprintf", [](Emulator& e) {
        uint64_t buf = e.arg_slot(0);
        uint64_t n = e.arg_slot(1);
        Args va(e, 3);
        std::string s = format(e, e.arg_slot(2), va);
        if (n > 0) {
            std::string t = s.substr(0, static_cast<size_t>(n - 1));
            e.mem.write_cstring(buf, t);
        }
        e.set_result(s.size());  // the length it *would* have taken
    });
    libc("_snprintf", [](Emulator& e) {
        uint64_t buf = e.arg_slot(0);
        uint64_t n = e.arg_slot(1);
        Args va(e, 3);
        std::string s = format(e, e.arg_slot(2), va);
        size_t take = s.size() < n ? s.size() : static_cast<size_t>(n);
        e.mem.write(buf, s.data(), take);
        if (take < n) e.mem.write8(buf + take, 0);
        e.set_result(s.size() < n ? s.size() : 0xFFFFFFFFull);
    });
    libc("fwrite", [](Emulator& e) {
        uint64_t ptr = e.arg_slot(0), size = e.arg_slot(1), count = e.arg_slot(2);
        int fd = stream_fd(e, e.arg_slot(3));
        uint64_t total = size * count;
        std::string data(static_cast<size_t>(total), '\0');
        if (total) e.mem.read(ptr, data.data(), total);
        write_out(e, fd, data);
        e.set_result(count);
    });
    libc("fflush", [](Emulator& e) {
        std::fflush(stdout);
        std::fflush(stderr);
        e.set_result(0);
    });
    libc("__acrt_iob_func", [](Emulator& e) { e.set_result(e.guest_file(static_cast<int>(e.arg_slot(0)))); });
    libc("__iob_func", [](Emulator& e) { e.set_result(e.guest_file(0)); });
    libc("_iob", [](Emulator& e) { e.set_result(e.guest_file(0)); });

    // ---- process control ---------------------------------------------------
    libc("exit", [](Emulator& e) { e.exit_process(static_cast<int>(e.arg_slot(0))); });
    libc("_exit", [](Emulator& e) { e.exit_process(static_cast<int>(e.arg_slot(0))); });
    libc("abort", [](Emulator& e) {
        std::fprintf(stderr, "[guest] abort()\n");
        e.exit_process(3);
    });
    libc("atexit", [](Emulator& e) { e.set_result(0); });
    libc("_initterm", [](Emulator& e) { e.set_result(0); });
    libc("__set_app_type", [](Emulator& e) { e.set_result(0); });
    libc("_amsg_exit", [](Emulator& e) { e.exit_process(static_cast<int>(e.arg_slot(0))); });
    libc("signal", [](Emulator& e) { e.set_result(0); });

    // ---- memory ------------------------------------------------------------
    libc("malloc", [](Emulator& e) { e.set_result(e.heap_alloc(e.arg_slot(0))); });
    libc("calloc", [](Emulator& e) {
        uint64_t total = e.arg_slot(0) * e.arg_slot(1);
        uint64_t p = e.heap_alloc(total);
        if (p) {
            std::vector<uint8_t> zeros(static_cast<size_t>(total), 0);
            if (total) e.mem.write(p, zeros.data(), total);
        }
        e.set_result(p);
    });
    libc("realloc", [](Emulator& e) { e.set_result(e.heap_realloc(e.arg_slot(0), e.arg_slot(1))); });
    libc("free", [](Emulator& e) {
        e.heap_free(e.arg_slot(0));
        e.set_result(0);
    });

    libc("memset", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        uint8_t v = static_cast<uint8_t>(e.arg_slot(1));
        uint64_t n = e.arg_slot(2);
        std::vector<uint8_t> block(static_cast<size_t>(n), v);
        if (n) e.mem.write(p, block.data(), n);
        e.set_result(p);
    });
    auto copy_mem = [](Emulator& e) {
        uint64_t dst = e.arg_slot(0), src = e.arg_slot(1), n = e.arg_slot(2);
        if (n) {
            std::vector<uint8_t> tmp(static_cast<size_t>(n));
            e.mem.read(src, tmp.data(), n);
            e.mem.write(dst, tmp.data(), n);
        }
        e.set_result(dst);
    };
    libc("memcpy", copy_mem);
    libc("memmove", copy_mem);  // the temporary buffer already makes it safe
    libc("memcmp", [](Emulator& e) {
        uint64_t a = e.arg_slot(0), b = e.arg_slot(1), n = e.arg_slot(2);
        int result = 0;
        for (uint64_t i = 0; i < n && result == 0; ++i) {
            int x = e.mem.read8(a + i), y = e.mem.read8(b + i);
            result = x - y;
        }
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    // ---- strings -----------------------------------------------------------
    libc("strlen", [](Emulator& e) { e.set_result(e.mem.read_cstring(e.arg_slot(0)).size()); });
    libc("strcpy", [](Emulator& e) {
        uint64_t dst = e.arg_slot(0);
        e.mem.write_cstring(dst, e.mem.read_cstring(e.arg_slot(1)));
        e.set_result(dst);
    });
    libc("strncpy", [](Emulator& e) {
        uint64_t dst = e.arg_slot(0), n = e.arg_slot(2);
        std::string s = e.mem.read_cstring(e.arg_slot(1));
        for (uint64_t i = 0; i < n; ++i)
            e.mem.write8(dst + i, i < s.size() ? static_cast<uint8_t>(s[i]) : 0);
        e.set_result(dst);
    });
    libc("strcat", [](Emulator& e) {
        uint64_t dst = e.arg_slot(0);
        std::string a = e.mem.read_cstring(dst), b = e.mem.read_cstring(e.arg_slot(1));
        e.mem.write_cstring(dst, a + b);
        e.set_result(dst);
    });
    libc("strcmp", [](Emulator& e) {
        std::string a = e.mem.read_cstring(e.arg_slot(0)), b = e.mem.read_cstring(e.arg_slot(1));
        int r = a.compare(b);
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(r < 0 ? -1 : (r > 0 ? 1 : 0))));
    });
    libc("strncmp", [](Emulator& e) {
        uint64_t n = e.arg_slot(2);
        std::string a = e.mem.read_cstring(e.arg_slot(0)), b = e.mem.read_cstring(e.arg_slot(1));
        int r = std::strncmp(a.c_str(), b.c_str(), static_cast<size_t>(n));
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(r < 0 ? -1 : (r > 0 ? 1 : 0))));
    });
    libc("strchr", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        char c = static_cast<char>(e.arg_slot(1));
        std::string s = e.mem.read_cstring(p);
        size_t pos = s.find(c);
        e.set_result(pos == std::string::npos ? 0 : p + pos);
    });
    libc("strstr", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        std::string s = e.mem.read_cstring(p), t = e.mem.read_cstring(e.arg_slot(1));
        size_t pos = s.find(t);
        e.set_result(pos == std::string::npos ? 0 : p + pos);
    });
    libc("atoi", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(
            static_cast<int64_t>(std::atoi(e.mem.read_cstring(e.arg_slot(0)).c_str()))));
    });

    // ---- misc runtime ------------------------------------------------------
    libc("time", [](Emulator& e) {
        auto now = static_cast<uint64_t>(std::time(nullptr));
        uint64_t out = e.arg_slot(0);
        if (out) e.mem.write_sized(out, e.is64() ? 8 : 4, now);
        e.set_result(now);
    });
    libc("clock", [](Emulator& e) { e.set_result(e.cpu().instructions_executed / 1000); });
    libc("rand", [](Emulator& e) {
        // A fixed LCG keeps guest output reproducible across runs.
        static uint32_t state = 1;
        state = state * 1103515245u + 12345u;
        e.set_result((state >> 16) & 0x7FFF);
    });
    libc("srand", [](Emulator& e) { e.set_result(0); });

    // ---- Win32 -------------------------------------------------------------
    win32("ExitProcess", 1, [](Emulator& e) { e.exit_process(static_cast<int>(e.arg_slot(0))); });
    win32("TerminateProcess", 2, [](Emulator& e) { e.exit_process(static_cast<int>(e.arg_slot(1))); });
    win32("GetStdHandle", 1, [](Emulator& e) {
        // STD_INPUT/OUTPUT/ERROR_HANDLE are -10/-11/-12; hand back small
        // synthetic handles that WriteFile understands.
        int32_t which = static_cast<int32_t>(e.arg_slot(0));
        uint64_t h = which == -10 ? 1 : which == -11 ? 2 : which == -12 ? 3 : 0;
        e.set_result(h);
    });
    auto write_file = [](Emulator& e) {
        uint64_t handle = e.arg_slot(0), buf = e.arg_slot(1), len = e.arg_slot(2);
        uint64_t written_ptr = e.arg_slot(3);
        std::string data(static_cast<size_t>(len), '\0');
        if (len) e.mem.read(buf, data.data(), len);
        write_out(e, handle == 3 ? 2 : 1, data);
        if (written_ptr) e.mem.write32(written_ptr, static_cast<uint32_t>(len));
        e.set_result(1);
    };
    win32("WriteFile", 5, write_file);
    win32("WriteConsoleA", 5, write_file);
    win32("WriteConsoleW", 5, write_file);
    win32("OutputDebugStringA", 1, [](Emulator& e) {
        std::fprintf(stderr, "[dbg] %s", e.mem.read_cstring(e.arg_slot(0)).c_str());
        e.set_result(0);
    });
    win32("GetLastError", 0, [](Emulator& e) { e.set_result(e.last_error()); });
    win32("SetLastError", 1, [](Emulator& e) {
        e.set_last_error(e.arg_slot(0));
        e.set_result(0);
    });
    win32("GetCommandLineA", 0, [](Emulator& e) {
        std::string cmd;
        for (const auto& a : e.args()) {
            if (!cmd.empty()) cmd += ' ';
            cmd += a;
        }
        e.set_result(e.alloc_guest_string(cmd));
    });
    win32("GetModuleHandleA", 1, [](Emulator& e) { e.set_result(e.image().image_base); });
    win32("GetModuleFileNameA", 3, [](Emulator& e) {
        std::string name = e.args().empty() ? "program.exe" : e.args()[0];
        uint64_t buf = e.arg_slot(1), size = e.arg_slot(2);
        if (name.size() + 1 > size) name.resize(static_cast<size_t>(size ? size - 1 : 0));
        e.mem.write_cstring(buf, name);
        e.set_result(name.size());
    });
    win32("GetProcessHeap", 0, [](Emulator& e) { e.set_result(0x00420000); });
    win32("GetCurrentProcess", 0, [](Emulator& e) { e.set_result(0xFFFFFFFFull); });
    win32("GetCurrentProcessId", 0, [](Emulator& e) { e.set_result(4242); });
    win32("GetCurrentThreadId", 0, [](Emulator& e) { e.set_result(1234); });
    win32("HeapAlloc", 3, [](Emulator& e) {
        uint64_t flags = e.arg_slot(1), size = e.arg_slot(2);
        uint64_t p = e.heap_alloc(size);
        if (p && (flags & 0x8)) {  // HEAP_ZERO_MEMORY
            std::vector<uint8_t> zeros(static_cast<size_t>(size), 0);
            if (size) e.mem.write(p, zeros.data(), size);
        }
        e.set_result(p);
    });
    win32("HeapFree", 3, [](Emulator& e) {
        e.heap_free(e.arg_slot(2));
        e.set_result(1);
    });
    win32("HeapReAlloc", 4, [](Emulator& e) {
        e.set_result(e.heap_realloc(e.arg_slot(2), e.arg_slot(3)));
    });
    win32("VirtualAlloc", 4, [](Emulator& e) { e.set_result(e.heap_alloc(e.arg_slot(1))); });
    win32("VirtualFree", 3, [](Emulator& e) { e.set_result(1); });
    win32("CloseHandle", 1, [](Emulator& e) { e.set_result(1); });
    win32("Sleep", 1, [](Emulator& e) { e.set_result(0); });
    win32("GetTickCount", 0, [](Emulator& e) {
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
    win32("GetSystemTimeAsFileTime", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        // FILETIME counts 100 ns ticks since 1601; 11644473600 s to the epoch.
        uint64_t ticks = (static_cast<uint64_t>(std::time(nullptr)) + 11644473600ull) * 10000000ull;
        if (p) e.mem.write64(p, ticks);
        e.set_result(0);
    });
    win32("IsDebuggerPresent", 0, [](Emulator& e) { e.set_result(0); });
    win32("InitializeSListHead", 1, [](Emulator& e) { e.set_result(0); });
    win32("SetUnhandledExceptionFilter", 1, [](Emulator& e) { e.set_result(0); });
    win32("GetStartupInfoA", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) e.mem.write32(p, e.is64() ? 104 : 68);  // cb
        e.set_result(0);
    });
}

}  // namespace x86emu
