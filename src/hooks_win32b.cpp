// More of the Windows surface: synchronisation, directories, handles, and the
// CRT's descriptor/handle bridge.
//
// The synchronisation primitives are all no-ops or immediate successes, which is
// correct rather than lazy while there is exactly one thread: an uncontended
// lock never blocks, and a wait on something already signalled returns at once.
// When threading arrives these become the places that yield.
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "emulator.h"
#include "guest_printf.h"

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace x86emu {
namespace {

std::string current_directory() {
    char buf[4096];
#if defined(_WIN32)
    if (_getcwd(buf, sizeof buf)) return buf;
#else
    if (getcwd(buf, sizeof buf)) return buf;
#endif
    return ".";
}

int make_directory(const std::string& path) {
#if defined(_WIN32)
    return _mkdir(FileTable::host_path(path).c_str());
#else
    return mkdir(FileTable::host_path(path).c_str(), 0777);
#endif
}

int remove_directory(const std::string& path) {
#if defined(_WIN32)
    return _rmdir(FileTable::host_path(path).c_str());
#else
    return rmdir(FileTable::host_path(path).c_str());
#endif
}

}  // namespace

void Emulator::install_win32_extra_hooks() {
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, is64() ? 0 : nargs * 4, std::move(fn));
    };
    auto ret0 = [&](const char* name, int nargs) {
        win32(name, nargs, [](Emulator& e) { e.set_result(0); });
    };
    auto ret1 = [&](const char* name, int nargs) {
        win32(name, nargs, [](Emulator& e) { e.set_result(1); });
    };

    // Synchronisation and thread APIs live in threads.cpp, which owns the
    // scheduler they have to cooperate with.

    // ---- directories and paths --------------------------------------------------
    win32("GetCurrentDirectoryW", 2, [](Emulator& e) {
        std::u16string w = utf8_to_utf16(current_directory());
        uint64_t buf = e.arg_slot(1);
        uint64_t size = e.arg_slot(0);
        if (!buf || w.size() + 1 > size) {
            e.set_result(w.size() + 1);
            return;
        }
        for (size_t i = 0; i <= w.size(); ++i)
            e.mem.write16(buf + i * 2, i < w.size() ? w[i] : 0);
        e.set_result(w.size());
    });
    win32("GetCurrentDirectoryA", 2, [](Emulator& e) {
        std::string s = current_directory();
        uint64_t buf = e.arg_slot(1), size = e.arg_slot(0);
        if (!buf || s.size() + 1 > size) {
            e.set_result(s.size() + 1);
            return;
        }
        e.mem.write_cstring(buf, s);
        e.set_result(s.size());
    });
    win32("SetCurrentDirectoryW", 1, [](Emulator& e) {
        std::string path = FileTable::host_path(utf16_to_utf8(e, e.arg_slot(0), -1));
#if defined(_WIN32)
        e.set_result(_chdir(path.c_str()) == 0 ? 1 : 0);
#else
        e.set_result(chdir(path.c_str()) == 0 ? 1 : 0);
#endif
    });
    win32("CreateDirectoryA", 2, [](Emulator& e) {
        int r = make_directory(e.mem.read_cstring(e.arg_slot(0)));
        if (r != 0) e.set_last_error(183);  // ERROR_ALREADY_EXISTS
        e.set_result(r == 0 ? 1 : 0);
    });
    win32("RemoveDirectoryA", 1, [](Emulator& e) {
        e.set_result(remove_directory(e.mem.read_cstring(e.arg_slot(0))) == 0 ? 1 : 0);
    });
    win32("CreateDirectoryW", 2, [](Emulator& e) {
        int r = make_directory(utf16_to_utf8(e, e.arg_slot(0), -1));
        if (r != 0) e.set_last_error(183);  // ERROR_ALREADY_EXISTS
        e.set_result(r == 0 ? 1 : 0);
    });
    win32("RemoveDirectoryW", 1, [](Emulator& e) {
        e.set_result(remove_directory(utf16_to_utf8(e, e.arg_slot(0), -1)) == 0 ? 1 : 0);
    });
    // (lpFileName, nBufferLength, lpBuffer, lpFilePart)
    win32("GetFullPathNameW", 4, [](Emulator& e) {
        // Without a path canonicaliser, an absolute path passes through and a
        // relative one is joined to the working directory - which is what a guest
        // resolving its own data files needs.
        std::string path = utf16_to_utf8(e, e.arg_slot(0), -1);
        uint64_t length = e.arg_slot(1);
        uint64_t buf = e.arg_slot(2);
        uint64_t part_out = e.arg_slot(3);

        bool absolute = (path.size() > 1 && path[1] == ':') ||
                        (!path.empty() && (path[0] == '\\' || path[0] == '/'));
        std::string full = absolute ? path : current_directory() + "\\" + path;
        std::u16string w = utf8_to_utf16(full);
        if (!buf || w.size() + 1 > length) {
            e.set_result(w.size() + 1);  // the size the caller must provide
            return;
        }
        for (size_t i = 0; i <= w.size(); ++i)
            e.mem.write16(buf + i * 2, i < w.size() ? w[i] : 0);
        if (part_out) {
            size_t slash = full.find_last_of("\\/");
            uint64_t part = slash == std::string::npos ? buf : buf + (slash + 1) * 2;
            e.mem.write_sized(part_out, e.pointer_size(), part);
        }
        e.set_result(w.size());
    });
    // PathCchSkipRoot(path, out): S_OK plus a pointer past the drive or UNC root.
    win32("PathCchSkipRoot", 2, [](Emulator& e) {
        uint64_t path = e.arg_slot(0), out = e.arg_slot(1);
        std::string s = utf16_to_utf8(e, path, -1);
        auto is_sep = [](char c) { return c == '\\' || c == '/'; };
        size_t skip = 0;
        if (s.size() >= 2 && s[1] == ':') {
            skip = 2;
            while (skip < s.size() && is_sep(s[skip])) ++skip;
        } else if (s.size() >= 2 && is_sep(s[0]) && is_sep(s[1])) {
            // A UNC root covers two more components: \server\share.
            skip = 2;
            for (int component = 0; component < 2 && skip < s.size(); ++component) {
                while (skip < s.size() && !is_sep(s[skip])) ++skip;
                while (skip < s.size() && is_sep(s[skip])) ++skip;
            }
        } else {
            e.set_result(0x80070057);  // E_INVALIDARG: the path is not rooted
            return;
        }
        if (out) e.mem.write_sized(out, e.pointer_size(), path + skip * 2);
        e.set_result(0);  // S_OK
    });
    // PathCchCombineEx(out, out_chars, path1, path2, flags)
    win32("PathCchCombineEx", 5, [](Emulator& e) {
        std::string a = e.arg_slot(2) ? utf16_to_utf8(e, e.arg_slot(2), -1) : std::string();
        std::string b = e.arg_slot(3) ? utf16_to_utf8(e, e.arg_slot(3), -1) : std::string();
        bool b_absolute = (b.size() > 1 && b[1] == ':') ||
                          (!b.empty() && (b[0] == '\\' || b[0] == '/'));
        std::string joined;
        if (b.empty())
            joined = a;
        else if (a.empty() || b_absolute)
            joined = b;
        else
            joined = a + ((a.back() == '\\' || a.back() == '/') ? "" : "\\") + b;

        std::u16string w = utf8_to_utf16(joined);
        uint64_t out = e.arg_slot(0), capacity = e.arg_slot(1);
        if (!out || w.size() + 1 > capacity) {
            e.set_result(0x8007007A);  // ERROR_INSUFFICIENT_BUFFER, as an HRESULT
            return;
        }
        for (size_t i = 0; i <= w.size(); ++i)
            e.mem.write16(out + i * 2, i < w.size() ? w[i] : 0);
        e.set_result(0);
    });
    win32("GetFileAttributesExW", 3, [](Emulator& e) {
        FileTable::Stat st;
        if (FileTable::stat_path(utf16_to_utf8(e, e.arg_slot(0), -1), st) != 0) {
            e.set_last_error(2);
            e.set_result(0);
            return;
        }
        // WIN32_FILE_ATTRIBUTE_DATA: attributes, three FILETIMEs, size high/low.
        uint64_t out = e.arg_slot(2);
        if (out) {
            uint64_t ticks =
                (static_cast<uint64_t>(st.mtime) + 11644473600ull) * 10000000ull;
            e.mem.write32(out, st.is_dir ? 0x10u : 0x80u);
            e.mem.write64(out + 4, ticks);
            e.mem.write64(out + 12, ticks);
            e.mem.write64(out + 20, ticks);
            e.mem.write32(out + 28, static_cast<uint32_t>(st.size >> 32));
            e.mem.write32(out + 32, static_cast<uint32_t>(st.size));
        }
        e.set_result(1);
    });
    win32("SetFileAttributesW", 2, [](Emulator& e) { e.set_result(1); });
    win32("MoveFileExW", 3, [](Emulator& e) {
        std::string from = utf16_to_utf8(e, e.arg_slot(0), -1);
        std::string to = utf16_to_utf8(e, e.arg_slot(1), -1);
        e.set_result(FileTable::rename_file(from, to) == 0 ? 1 : 0);
    });
    win32("SetEndOfFile", 1, [](Emulator& e) { e.set_result(1); });
    win32("GetFileSize", 2, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        int64_t size = fd >= 0 ? e.files.size(fd) : -1;
        if (size < 0) {
            e.set_result(0xFFFFFFFFull);
            return;
        }
        if (e.arg_slot(1)) e.mem.write32(e.arg_slot(1), static_cast<uint32_t>(size >> 32));
        e.set_result(static_cast<uint32_t>(size));
    });

    // ---- handles and process information -----------------------------------------
    ret1("DuplicateHandle", 7);
    ret1("SetHandleInformation", 3);
    ret1("GetHandleInformation", 2);
    win32("GetVersion", 0, [](Emulator& e) {
        // Windows 10: major 10, minor 0, build 19045, in the packed legacy form.
        e.set_result(0x0000000A | (0u << 8) | (19045u << 16));
    });
    win32("GetVersionExW", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) {
            e.mem.write32(p + 4, 10);     // dwMajorVersion
            e.mem.write32(p + 8, 0);      // dwMinorVersion
            e.mem.write32(p + 12, 19045); // dwBuildNumber
            e.mem.write32(p + 16, 2);     // dwPlatformId
        }
        e.set_result(1);
    });
    win32("GetErrorMode", 0, [](Emulator& e) { e.set_result(0); });
    win32("SetErrorMode", 1, [](Emulator& e) { e.set_result(0); });
    win32("SetThreadErrorMode", 2, [](Emulator& e) { e.set_result(1); });
    win32("GetActiveProcessorCount", 1, [](Emulator& e) { e.set_result(1); });
    win32("GetCurrentProcessorNumber", 0, [](Emulator& e) { e.set_result(0); });
    win32("GetLargePageMinimum", 0, [](Emulator& e) { e.set_result(0x200000); });
    win32("GetProcessTimes", 5, [](Emulator& e) {
        for (int i = 1; i <= 4; ++i)
            if (e.arg_slot(i)) e.mem.write64(e.arg_slot(i), 0);
        e.set_result(1);
    });
    win32("GetThreadTimes", 5, [](Emulator& e) {
        for (int i = 1; i <= 4; ++i)
            if (e.arg_slot(i)) e.mem.write64(e.arg_slot(i), 0);
        e.set_result(1);
    });
    ret0("AddVectoredExceptionHandler", 2);
    ret1("RemoveVectoredExceptionHandler", 1);
    ret0("AddDllDirectory", 1);
    ret1("RemoveDllDirectory", 1);
    ret1("SetDefaultDllDirectories", 1);
    win32("CompareStringOrdinal", 6, [](Emulator& e) {
        std::string a = utf16_to_utf8(e, e.arg_slot(0),
                                      static_cast<int>(static_cast<int32_t>(e.arg_slot(1))));
        std::string b = utf16_to_utf8(e, e.arg_slot(2),
                                      static_cast<int>(static_cast<int32_t>(e.arg_slot(3))));
        int c = a.compare(b);
        e.set_result(c < 0 ? 1u : c > 0 ? 3u : 2u);
    });
    win32("GetConsoleCP", 0, [](Emulator& e) { e.set_result(65001); });
    win32("GetConsoleScreenBufferInfo", 2, [](Emulator& e) { e.set_result(0); });
    win32("GetNumberOfConsoleInputEvents", 2, [](Emulator& e) { e.set_result(0); });
    win32("ReadConsoleW", 5, [](Emulator& e) { e.set_result(0); });
    win32("GetUserNameW", 2, [](Emulator& e) { e.set_result(0); });
    win32("FormatMessageW", 7, [](Emulator& e) { e.set_result(0); });
    win32("BCryptGenRandom", 4, [](Emulator& e) {
        // Deterministic bytes, for the same reason getrandom() is: reproducible
        // runs are worth more here than unpredictability.
        uint64_t buf = e.arg_slot(1), len = e.arg_slot(2);
        uint32_t state = 0x9E3779B9u;
        for (uint64_t i = 0; i < len; ++i) {
            state = state * 1103515245u + 12345u;
            e.mem.write8(buf + i, static_cast<uint8_t>(state >> 16));
        }
        e.set_result(0);  // STATUS_SUCCESS
    });

    // ---- the CRT's descriptor/handle bridge ----------------------------------------
    // A Windows CRT keeps both a descriptor and a HANDLE for every open file and
    // converts between them; here they are the same number in two costumes.
    auto ucrt = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };
    ucrt("_get_osfhandle", [](Emulator& e) {
        int fd = static_cast<int>(e.arg_slot(0));
        e.set_result(e.files.valid(fd) ? Emulator::handle_from_fd(fd) : ~0ull);
    });
    ucrt("_open_osfhandle", [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(fd)));
    });
    ucrt("_setmode", [](Emulator& e) { e.set_result(0x8000); });  // _O_BINARY
    ucrt("_isatty", [](Emulator& e) {
        auto* entry = e.files.get(static_cast<int>(e.arg_slot(0)));
        e.set_result(entry && entry->is_tty ? 1 : 0);
    });
    ucrt("_commit", [](Emulator& e) { e.set_result(e.files.flush(static_cast<int>(e.arg_slot(0)))); });
    ucrt("_umask", [](Emulator& e) { e.set_result(0); });
    ucrt("_getpid", [](Emulator& e) { e.set_result(4242); });
    ucrt("_heapmin", [](Emulator& e) { e.set_result(0); });
    ucrt("_fdopen", [](Emulator& e) {
        int fd = static_cast<int>(e.arg_slot(0));
        e.set_result(e.files.valid(fd) ? e.guest_file(fd) : 0);
    });
    ucrt("_wfopen", [](Emulator& e) {
        std::string path = utf16_to_utf8(e, e.arg_slot(0), -1);
        std::string mode = utf16_to_utf8(e, e.arg_slot(1), -1);
        FileTable::OpenFlags f;
        f.binary = mode.find('b') != std::string::npos;
        bool plus = mode.find('+') != std::string::npos;
        char base = mode.empty() ? 'r' : mode[0];
        if (base == 'w') {
            f.write = f.create = f.truncate = true;
            f.read = plus;
        } else if (base == 'a') {
            f.write = f.create = f.append = true;
            f.read = plus;
        } else {
            f.read = true;
            f.write = plus;
        }
        int fd = e.files.open(path, f);
        e.log_call("_wfopen(%s, %s) = %d", path.c_str(), mode.c_str(), fd);
        e.report_file_error(fd);
        e.set_result(fd < 0 ? 0 : e.guest_file(fd));
    });
    ucrt("_wopen", [](Emulator& e) {
        std::string path = utf16_to_utf8(e, e.arg_slot(0), -1);
        uint32_t flags = static_cast<uint32_t>(e.arg_slot(1));
        FileTable::OpenFlags f;
        switch (flags & 3) {
            case 1: f.write = true; break;
            case 2: f.read = f.write = true; break;
            default: f.read = true; break;
        }
        f.create = (flags & 0x0100) != 0;
        f.truncate = (flags & 0x0200) != 0;
        f.append = (flags & 0x0008) != 0;
        f.binary = true;
        int fd = e.files.open(path, f);
        e.report_file_error(fd);
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(fd < 0 ? -1 : fd)));
    });
    ucrt("_wgetenv", [](Emulator& e) {
        const std::string* v = e.getenv(utf16_to_utf8(e, e.arg_slot(0), -1));
        if (!v) {
            e.set_result(0);
            return;
        }
        std::u16string w = utf8_to_utf16(*v);
        std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
        std::memcpy(raw.data(), w.data(), w.size() * 2);
        e.set_result(e.alloc_guest_data(raw.data(), raw.size()));
    });
    ucrt("_wputenv", [](Emulator& e) {
        std::string entry = utf16_to_utf8(e, e.arg_slot(0), -1);
        size_t eq = entry.find('=');
        if (eq == std::string::npos || eq + 1 == entry.size())
            e.unsetenv(eq == std::string::npos ? entry : entry.substr(0, eq));
        else
            e.setenv(entry.substr(0, eq), entry.substr(eq + 1));
        e.set_result(0);
    });
    // The _s variants take (name, value) separately and return an errno code.
    ucrt("_wputenv_s", [](Emulator& e) {
        std::string name = utf16_to_utf8(e, e.arg_slot(0), -1);
        std::string value = utf16_to_utf8(e, e.arg_slot(1), -1);
        if (value.empty())
            e.unsetenv(name);
        else
            e.setenv(name, value);
        e.set_result(0);
    });
    ucrt("_putenv_s", [](Emulator& e) {
        std::string name = e.mem.read_cstring(e.arg_slot(0));
        std::string value = e.mem.read_cstring(e.arg_slot(1));
        if (value.empty())
            e.unsetenv(name);
        else
            e.setenv(name, value);
        e.set_result(0);
    });
    // (out_size, buffer, buffer_size, name) -> errno; a null buffer just asks for
    // the size.
    ucrt("getenv_s", [](Emulator& e) {
        uint64_t out_size = e.arg_slot(0), buf = e.arg_slot(1), size = e.arg_slot(2);
        const std::string* v = e.getenv(e.mem.read_cstring(e.arg_slot(3)));
        uint64_t needed = v ? v->size() + 1 : 0;
        if (out_size) e.mem.write_sized(out_size, e.pointer_size(), needed);
        if (!v) {
            e.set_result(0);
            return;
        }
        if (!buf || needed > size) {
            e.set_result(34);  // ERANGE
            return;
        }
        e.mem.write_cstring(buf, *v);
        e.set_result(0);
    });
    ucrt("_wdupenv_s", [](Emulator& e) {
        // (wchar_t** out, size_t* len, const wchar_t* name)
        uint64_t out = e.arg_slot(0), len_out = e.arg_slot(1);
        const std::string* v = e.getenv(utf16_to_utf8(e, e.arg_slot(2), -1));
        int ps = e.pointer_size();
        if (!v) {
            if (out) e.mem.write_sized(out, ps, 0);
            if (len_out) e.mem.write_sized(len_out, ps, 0);
            e.set_result(0);
            return;
        }
        std::u16string w = utf8_to_utf16(*v);
        uint64_t buf = e.heap_alloc((w.size() + 1) * 2);
        for (size_t i = 0; i <= w.size(); ++i)
            e.mem.write16(buf + i * 2, i < w.size() ? w[i] : 0);
        if (out) e.mem.write_sized(out, ps, buf);
        if (len_out) e.mem.write_sized(len_out, ps, w.size() + 1);
        e.set_result(0);
    });
    ucrt("_dupenv_s", [](Emulator& e) {
        uint64_t out = e.arg_slot(0), len_out = e.arg_slot(1);
        const std::string* v = e.getenv(e.mem.read_cstring(e.arg_slot(2)));
        int ps = e.pointer_size();
        if (!v) {
            if (out) e.mem.write_sized(out, ps, 0);
            if (len_out) e.mem.write_sized(len_out, ps, 0);
            e.set_result(0);
            return;
        }
        uint64_t buf = e.heap_alloc(v->size() + 1);
        e.mem.write_cstring(buf, *v);
        if (out) e.mem.write_sized(out, ps, buf);
        if (len_out) e.mem.write_sized(len_out, ps, v->size() + 1);
        e.set_result(0);
    });

    ucrt("_wgetcwd", [](Emulator& e) {
        std::u16string w = utf8_to_utf16(current_directory());
        uint64_t buf = e.arg_slot(0);
        if (!buf) {
            std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
            std::memcpy(raw.data(), w.data(), w.size() * 2);
            e.set_result(e.alloc_guest_data(raw.data(), raw.size()));
            return;
        }
        for (size_t i = 0; i <= w.size(); ++i)
            e.mem.write16(buf + i * 2, i < w.size() ? w[i] : 0);
        e.set_result(buf);
    });

    // ---- time zone and miscellaneous CRT --------------------------------------------
    // The UCRT exports these as functions returning the address of the variable.
    auto int_variable = [this](const char* name, int32_t value) {
        add_hook(name, 0, [value](Emulator& e) {
            uint32_t v = static_cast<uint32_t>(value);
            e.set_result(e.alloc_guest_data(&v, sizeof v));
        });
    };
    int_variable("__daylight", 0);
    int_variable("__timezone", 0);
    int_variable("__sys_nerr", 0);
    int_variable("__fpe_flt_rounds", 1);
    ucrt("__sys_errlist", [](Emulator& e) {
        int ps = e.pointer_size();
        std::vector<uint8_t> table(static_cast<size_t>(ps), 0);
        e.set_result(e.alloc_guest_data(table.data(), table.size()));
    });
    ucrt("_tzset", [](Emulator& e) { e.set_result(0); });
    ucrt("_mktime64", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        std::tm tm{};
        if (p) {
            tm.tm_sec = static_cast<int>(e.mem.read32(p));
            tm.tm_min = static_cast<int>(e.mem.read32(p + 4));
            tm.tm_hour = static_cast<int>(e.mem.read32(p + 8));
            tm.tm_mday = static_cast<int>(e.mem.read32(p + 12));
            tm.tm_mon = static_cast<int>(e.mem.read32(p + 16));
            tm.tm_year = static_cast<int>(e.mem.read32(p + 20));
            tm.tm_isdst = static_cast<int>(e.mem.read32(p + 32));
        }
        e.set_result(static_cast<uint64_t>(std::mktime(&tm)));
    });
    ucrt("_set_abort_behavior", [](Emulator& e) { e.set_result(0); });
    ucrt("_register_thread_local_exe_atexit_callback", [](Emulator& e) { e.set_result(0); });
    ucrt("_seh_filter_dll", [](Emulator& e) { e.set_result(1); });
    ucrt("__std_type_info_destroy_list", [](Emulator& e) { e.set_result(0); });
    ucrt("raise", [](Emulator& e) { e.set_result(0); });
    ucrt("wcsnlen", [](Emulator& e) {
        uint64_t p = e.arg_slot(0), max = e.arg_slot(1);
        uint64_t n = 0;
        while (n < max && e.mem.read16(p + n * 2) != 0) ++n;
        e.set_result(n);
    });
    ucrt("wcstol", [](Emulator& e) {
        std::string s = utf16_to_utf8(e, e.arg_slot(0), -1);
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(
            std::strtol(s.c_str(), nullptr, static_cast<int>(e.arg_slot(2))))));
    });
    ucrt("wcscoll", [](Emulator& e) {
        std::string a = utf16_to_utf8(e, e.arg_slot(0), -1);
        std::string b = utf16_to_utf8(e, e.arg_slot(1), -1);
        int c = a.compare(b);
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(c < 0 ? -1 : (c > 0 ? 1 : 0))));
    });
}

}  // namespace x86emu
