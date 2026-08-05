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
#include "guest_printf.h"

namespace x86emu {
namespace {

// ---------------------------------------------------------------------------
// printf-family formatting
// ---------------------------------------------------------------------------

void write_out(Emulator& e, int fd, const std::string& s) {
    // The standard streams go through the emulator's output path (and its
    // newline translation); anything else is a real file.
    if (fd >= 0 && fd <= 2)
        e.write_text(fd, s);
    else if (fd > 2)
        e.files.write(fd, s.data(), s.size());
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
    // ---- stdio ------------------------------------------------------------
    libc("printf", [](Emulator& e) {
        Args va(e, 1);
        std::string s = format_guest(e, e.arg_slot(0), va);
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
        std::string s = format_guest(e, e.arg_slot(1), va);
        write_out(e, fd, s);
        e.set_result(s.size());
    });
    libc("vfprintf", [](Emulator& e) {
        int fd = stream_fd(e, e.arg_slot(0));
        Args va = Args::va_list_at(e, e.arg_slot(2));
        std::string s = format_guest(e, e.arg_slot(1), va);
        write_out(e, fd, s);
        e.set_result(s.size());
    });
    libc("vprintf", [](Emulator& e) {
        Args va = Args::va_list_at(e, e.arg_slot(1));
        std::string s = format_guest(e, e.arg_slot(0), va);
        write_out(e, 1, s);
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
        std::string s = format_guest(e, e.arg_slot(1), va);
        e.mem.write_cstring(e.arg_slot(0), s);
        e.set_result(s.size());
    });
    libc("snprintf", [](Emulator& e) {
        uint64_t buf = e.arg_slot(0);
        uint64_t n = e.arg_slot(1);
        Args va(e, 3);
        std::string s = format_guest(e, e.arg_slot(2), va);
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
        std::string s = format_guest(e, e.arg_slot(2), va);
        size_t take = s.size() < n ? s.size() : static_cast<size_t>(n);
        e.mem.write(buf, s.data(), take);
        if (take < n) e.mem.write8(buf + take, 0);
        e.set_result(s.size() < n ? s.size() : 0xFFFFFFFFull);
    });
    // The "_nolock" variants exist because a caller has already taken the
    // stream's lock; with one guest thread at a time the two are the same
    // function, and registering both is what keeps a guest from finding one
    // missing at the worst moment.
    auto do_fwrite = [](Emulator& e) {
        uint64_t ptr = e.arg_slot(0), size = e.arg_slot(1), count = e.arg_slot(2);
        int fd = stream_fd(e, e.arg_slot(3));
        uint64_t total = size * count;
        std::string data(static_cast<size_t>(total), '\0');
        if (total) e.mem.read(ptr, data.data(), total);
        write_out(e, fd, data);
        e.set_result(count);
    };
    libc("fwrite", do_fwrite);
    libc("fflush", [](Emulator& e) {
        // The guest's own buffered stdout has to go out too, not just the host's
        // streams: a guest that flushes before writing to another descriptor is
        // ordering its output deliberately, and holding the bytes back reorders
        // it.  fflush(NULL) means every stream.
        int fd = e.host_fd(e.arg_slot(0));
        if (fd == 1 || e.arg_slot(0) == 0) e.flush_guest_output();
        if (fd > 2) e.files.flush(fd);
        std::fflush(stdout);
        std::fflush(stderr);
        e.set_result(0);
    });
    libc("__acrt_iob_func", [](Emulator& e) { e.set_result(e.guest_file(static_cast<int>(e.arg_slot(0)))); });
    libc("__iob_func", [](Emulator& e) { e.set_result(e.guest_file(0)); });
    libc("_iob", [](Emulator& e) { e.set_result(e.guest_file(0)); });

    // ---- process control ---------------------------------------------------
    // exit() runs the atexit handlers and _exit() does not - that is the whole
    // difference between them, and this registration shadows the one in
    // hooks_win32.cpp (add_hook keeps the first), so it must do the job itself.
    libc("exit", [](Emulator& e) {
        e.run_atexit();
        e.exit_process(static_cast<int>(e.arg_slot(0)));
    });
    libc("_exit", [](Emulator& e) { e.exit_process(static_cast<int>(e.arg_slot(0))); });
    libc("abort", [](Emulator& e) {
        std::fprintf(stderr, "[guest] abort()\n");
        e.exit_process(3);
    });
    // atexit must keep the function, not merely succeed: a /MD C++ program's
    // static *destructors* arrive here (the /MT path goes through _crt_atexit),
    // and a hook that returns 0 while dropping the argument cancels every one of
    // them silently.
    libc("atexit", [](Emulator& e) {
        if (uint64_t fn = e.arg_slot(0)) e.add_atexit(fn);
        e.set_result(0);
    });
    // msvcrt's internal CRT locks: one guest thread runs at a time, so there is
    // nothing to take.
    libc("_lock", [](Emulator& e) { e.set_result(0); });
    libc("_unlock", [](Emulator& e) { e.set_result(0); });
    libc("___lc_codepage_func", [](Emulator& e) { e.set_result(1252); });
    libc("___mb_cur_max_func", [](Emulator& e) { e.set_result(1); });
    // (argc*, argv*, env*, doWildCard, startupInfo*) - mingw's msvcrt startup.
    libc("__getmainargs", [](Emulator& e) {
        int ps = e.pointer_size();
        std::vector<uint64_t> ptrs;
        for (const auto& a : e.args()) ptrs.push_back(e.alloc_guest_string(a));
        std::vector<uint8_t> table((ptrs.size() + 1) * ps, 0);
        uint64_t argv = e.alloc_guest_data(table.data(), table.size());
        for (size_t i = 0; i < ptrs.size(); ++i)
            e.mem.write_sized(argv + i * ps, ps, ptrs[i]);
        if (e.arg_slot(0)) e.mem.write32(e.arg_slot(0), static_cast<uint32_t>(e.args().size()));
        if (e.arg_slot(1)) e.mem.write_sized(e.arg_slot(1), ps, argv);
        if (e.arg_slot(2)) e.mem.write_sized(e.arg_slot(2), ps, e.environment_vector());
        e.set_result(0);
    });
    // _initterm deliberately has no stub here: the real implementation in
    // hooks_win32.cpp walks the table and calls the initialisers, and a no-op
    // registered first would shadow it - mingw's startup sets argv inside one
    // of those initialisers, so the no-op cost every guest its argument list.
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
    // strnlen must not read past `max`, which is the whole reason a caller uses
    // it: the buffer may not be terminated at all.
    auto bounded_strlen = [](Emulator& e) {
        uint64_t p = e.arg_slot(0), max = e.arg_slot(1), n = 0;
        while (n < max && e.mem.read8(p + n) != 0) ++n;
        e.set_result(n);
    };
    libc("strnlen", bounded_strlen);
    libc("strnlen_s", bounded_strlen);
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
        // Searching for the terminator is defined to find it, not to fail: it is
        // how a caller asks "where does this string end?".  Returning NULL here
        // is a real difference in behaviour - CPython's tokeniser uses exactly
        // this idiom to find the end of a line of source.
        if (c == '\0') {
            e.set_result(p + s.size());
            return;
        }
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

    // ---- environment ---------------------------------------------------------
    libc("getenv", [](Emulator& e) {
        const std::string* v = e.getenv(e.mem.read_cstring(e.arg_slot(0)));
        e.set_result(v ? e.alloc_guest_string(*v) : 0);
    });
    libc("_putenv", [](Emulator& e) {
        // The argument is a single "NAME=VALUE" string; no '=' means remove.
        std::string entry = e.mem.read_cstring(e.arg_slot(0));
        size_t eq = entry.find('=');
        if (eq == std::string::npos)
            e.unsetenv(entry);
        else if (eq + 1 == entry.size())
            e.unsetenv(entry.substr(0, eq));
        else
            e.setenv(entry.substr(0, eq), entry.substr(eq + 1));
        e.set_result(0);
    });
    libc("setenv", [](Emulator& e) {
        std::string name = e.mem.read_cstring(e.arg_slot(0));
        std::string value = e.mem.read_cstring(e.arg_slot(1));
        bool overwrite = e.arg_slot(2) != 0;
        if (overwrite || !e.getenv(name)) e.setenv(name, value);
        e.set_result(0);
    });
    libc("unsetenv", [](Emulator& e) {
        e.unsetenv(e.mem.read_cstring(e.arg_slot(0)));
        e.set_result(0);
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

}

}  // namespace x86emu
