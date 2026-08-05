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
#if defined(_WIN32)
    // Wide, then UTF-8: the narrow _getcwd answers in the ANSI code page, and
    // a working directory with a Japanese username in it came out as bytes no
    // later conversion could rescue.
    wchar_t wbuf[4096];
    if (_wgetcwd(wbuf, 4096))
        return utf16_string_to_utf8(std::u16string(wbuf, wbuf + wcslen(wbuf)));
#else
    char buf[4096];
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
        } else if (!s.empty() && is_sep(s[0])) {
            // A single leading separator is a drive-relative root ("\foo"), which
            // is rooted even though it names no drive.
            skip = 1;
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
    // SetEndOfFile cuts the file at the current position.  Returning success
    // without doing it leaves a guest that over-allocated its output - a linker
    // building an image in a mapped view does - with a file full of slack.
    win32("SetEndOfFile", 1, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        int64_t at = fd >= 0 ? e.files.tell(fd) : -1;
        if (at < 0 || e.files.truncate(fd, at) != 0) {
            e.set_last_error(6);  // ERROR_INVALID_HANDLE
            e.set_result(0);
            return;
        }
        e.set_result(1);
    });
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
    // DuplicateHandle and SetHandleInformation are real implementations in
    // hooks_process.cpp; stubs here would shadow them.
    ret1("GetHandleInformation", 2);
    // A DLL that has no per-thread work asks not to be told about threads.  With
    // one guest thread per module initialisation there is nothing to disable,
    // but the call must succeed - a DLL that gets a failure here may bail out.
    ret1("DisableThreadLibraryCalls", 1);
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
        static uint32_t state = 0x9E3779B9u;  // a stream, not a constant: see CryptGenRandom
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
    ucrt("_getpid", [](Emulator& e) { e.set_result(e.pid()); });
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
    // wcstol and the rest of the wide strto* family live in hooks_win32c.cpp,
    // where they share an implementation that reports the end pointer.
    ucrt("wcscoll", [](Emulator& e) {
        std::string a = utf16_to_utf8(e, e.arg_slot(0), -1);
        std::string b = utf16_to_utf8(e, e.arg_slot(1), -1);
        int c = a.compare(b);
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(c < 0 ? -1 : (c > 0 ? 1 : 0))));
    });

    // ---- what a compiler driver needs --------------------------------------------
    // gcc.exe (mingw) brought each of these in; they are ordinary CRT and
    // kernel32 surface, just corners no earlier guest had touched.

    // Console decoration: no console is being decorated here.
    ret1("SetConsoleTextAttribute", 2);
    ret1("SetConsoleCursorPosition", 2);
    ret1("FillConsoleOutputAttribute", 5);
    ret1("FillConsoleOutputCharacterW", 5);
    ret0("GetThreadPriority", 1);
    ret1("SetThreadPriority", 2);
    ret0("GetThreadContext", 2);
    ret0("SetThreadContext", 2);
    win32("OpenProcess", 3, [](Emulator& e) {
        e.set_last_error(5);  // ERROR_ACCESS_DENIED
        e.set_result(0);
    });
    win32("GetProcessAffinityMask", 3, [](Emulator& e) {
        if (e.arg_slot(1)) e.mem.write_sized(e.arg_slot(1), e.pointer_size(), 1);
        if (e.arg_slot(2)) e.mem.write_sized(e.arg_slot(2), e.pointer_size(), 1);
        e.set_result(1);
    });
    ret1("SetProcessAffinityMask", 2);
    win32("GetVersionExA", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) {
            e.mem.write32(p + 4, 10);      // dwMajorVersion
            e.mem.write32(p + 8, 0);       // dwMinorVersion
            e.mem.write32(p + 12, 19045);  // dwBuildNumber
            e.mem.write32(p + 16, 2);      // dwPlatformId = VER_PLATFORM_WIN32_NT
        }
        e.set_result(1);
    });
    // (flags, source, message_id, language, buffer, size, arguments)
    win32("FormatMessageA", 7, [](Emulator& e) {
        char text[64];
        std::snprintf(text, sizeof text, "error %u",
                      static_cast<unsigned>(e.arg_slot(2)));
        std::string msg = text;
        uint64_t buf = e.arg_slot(4);
        constexpr uint64_t kAllocateBuffer = 0x100;
        if (e.arg_slot(0) & kAllocateBuffer) {
            uint64_t mem = e.alloc_guest_string(msg);
            if (buf) e.mem.write_sized(buf, e.pointer_size(), mem);
        } else {
            if (!buf || e.arg_slot(5) < msg.size() + 1) {
                e.set_result(0);
                return;
            }
            e.mem.write_cstring(buf, msg);
        }
        e.set_result(msg.size());
    });
    win32("GetTempPathA", 2, [](Emulator& e) {
        std::string dir = "C:\\Temp";
        if (const std::string* v = e.getenv("TMP"))
            dir = *v;
        else if (const std::string* v2 = e.getenv("TEMP"))
            dir = *v2;
        if (dir.empty() || (dir.back() != '\\' && dir.back() != '/')) dir += '\\';
        uint64_t buf = e.arg_slot(1), size = e.arg_slot(0);
        if (!buf || dir.size() + 1 > size) {
            e.set_result(dir.size() + 1);
            return;
        }
        e.mem.write_cstring(buf, dir);
        e.set_result(dir.size());
    });
    auto absolutize = [](const std::string& in) {
        bool absolute = (in.size() > 1 && in[1] == ':') ||
                        (!in.empty() && (in[0] == '\\' || in[0] == '/'));
        std::string full = absolute ? in : current_directory() + "\\" + in;
        for (char& c : full)
            if (c == '/') c = '\\';
        return full;
    };
    win32("GetFullPathNameA", 4, [absolutize](Emulator& e) {
        std::string full = absolutize(e.mem.read_cstring(e.arg_slot(0)));
        uint64_t length = e.arg_slot(1), buf = e.arg_slot(2), part_out = e.arg_slot(3);
        if (!buf || full.size() + 1 > length) {
            e.set_result(full.size() + 1);
            return;
        }
        e.mem.write_cstring(buf, full);
        if (part_out) {
            size_t slash = full.find_last_of('\\');
            e.mem.write_sized(part_out, e.pointer_size(),
                              slash == std::string::npos ? buf : buf + slash + 1);
        }
        e.set_result(full.size());
    });
    win32("GetFinalPathNameByHandleA", 4, [absolutize](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        auto* entry = fd >= 0 ? e.files.get(fd) : nullptr;
        if (!entry) {
            e.set_last_error(6);  // ERROR_INVALID_HANDLE
            e.set_result(0);
            return;
        }
        std::string full = absolutize(entry->path);
        uint64_t buf = e.arg_slot(1), size = e.arg_slot(2);
        if (!buf || full.size() + 1 > size) {
            e.set_result(full.size() + 1);
            return;
        }
        e.mem.write_cstring(buf, full);
        e.set_result(full.size());
    });

    // ---- msvcrt corners ------------------------------------------------------------
    ucrt("_getcwd", [](Emulator& e) {
        std::string cwd = current_directory();
        for (char& c : cwd)
            if (c == '/') c = '\\';
        uint64_t buf = e.arg_slot(0), size = e.arg_slot(1);
        if (!buf) {
            buf = e.heap_alloc(cwd.size() + 1);  // getcwd(NULL, 0) mallocs
        } else if (cwd.size() + 1 > size) {
            e.set_result(0);
            return;
        }
        e.mem.write_cstring(buf, cwd);
        e.set_result(buf);
    });
    ucrt("_fullpath", [absolutize](Emulator& e) {
        // (buffer, relative, size); NULL buffer means "malloc one".
        std::string full = absolutize(e.mem.read_cstring(e.arg_slot(1)));
        uint64_t buf = e.arg_slot(0);
        if (!buf)
            buf = e.heap_alloc(full.size() + 1);
        else if (full.size() + 1 > e.arg_slot(2)) {
            e.set_result(0);
            return;
        }
        e.mem.write_cstring(buf, full);
        e.set_result(buf);
    });
    ucrt("_pipe", [](Emulator& e) {
        int fds[2];
        if (e.files.make_pipe(fds) != 0) {
            e.set_result(~0ull);
            return;
        }
        e.mem.write32(e.arg_slot(0), static_cast<uint32_t>(fds[0]));
        e.mem.write32(e.arg_slot(0) + 4, static_cast<uint32_t>(fds[1]));
        e.set_result(0);
    });

    // setjmp/longjmp: the buffer belongs to the guest, so the emulator keeps its
    // own register snapshot in it (nothing in the CRT reads a jmp_buf's fields).
    // Layout, in pointer-sized slots: magic, return address, RSP after return,
    // the general registers, RFLAGS.  That fits both CRTs' buffers (64 bytes on
    // x86, 256 on x64).  XMM registers are not saved - noted in resume.md.
    constexpr uint64_t kJmpMagic = 0x504D4A55; // "UJMP"
    auto do_setjmp = [kJmpMagic](Emulator& e) {
        uint64_t buf = e.arg_slot(0);
        Cpu& c = e.cpu();
        int ps = e.pointer_size();
        int nregs = e.is64() ? 16 : 8;
        uint64_t ret = e.mem.read_sized(c.regs[RSP], ps);
        e.mem.write_sized(buf, ps, kJmpMagic);
        e.mem.write_sized(buf + ps, ps, ret);
        e.mem.write_sized(buf + 2 * ps, ps, c.regs[RSP] + ps);
        for (int i = 0; i < nregs; ++i)
            e.mem.write_sized(buf + (3 + i) * ps, ps, c.regs[i]);
        e.mem.write_sized(buf + (3 + nregs) * ps, ps, c.rflags);
        e.set_result(0);
    };
    ucrt("_setjmp", do_setjmp);
    ucrt("_setjmpex", do_setjmp);
    ucrt("setjmp", do_setjmp);
    ucrt("longjmp", [kJmpMagic](Emulator& e) {
        uint64_t buf = e.arg_slot(0);
        uint64_t val = e.arg_slot(1);
        Cpu& c = e.cpu();
        int ps = e.pointer_size();
        int nregs = e.is64() ? 16 : 8;
        if (e.mem.read_sized(buf, ps) != kJmpMagic)
            throw CpuError(c.rip, "longjmp on a buffer _setjmp never filled");
        uint64_t ret = e.mem.read_sized(buf + ps, ps);
        uint64_t rsp = e.mem.read_sized(buf + 2 * ps, ps);
        for (int i = 0; i < nregs; ++i)
            c.regs[i] = e.mem.read_sized(buf + (3 + i) * ps, ps);
        c.rflags = e.mem.read_sized(buf + (3 + nregs) * ps, ps);
        // The hook's epilogue pops a return address off RSP; point both at the
        // setjmp caller's frame so control lands exactly where _setjmp returned.
        c.regs[RSP] = rsp - ps;
        e.mem.write_sized(c.regs[RSP], ps, ret);
        e.set_result(val ? val : 1);
    });

    ucrt("_vscprintf", [](Emulator& e) {
        Args va = Args::va_list_at(e, e.arg_slot(1));
        e.set_result(format_guest(e, e.arg_slot(0), va).size());
    });
    ucrt("_vsnprintf", [](Emulator& e) {
        uint64_t buf = e.arg_slot(0), count = e.arg_slot(1);
        Args va = Args::va_list_at(e, e.arg_slot(3));
        std::string s = format_guest(e, e.arg_slot(2), va);
        size_t take = s.size() < count ? s.size() : static_cast<size_t>(count);
        if (buf && take) e.mem.write(buf, s.data(), take);
        if (take < count) e.mem.write8(buf + take, 0);
        e.set_result(s.size() <= count ? s.size() : 0xFFFFFFFFull);  // -1 on truncation
    });
    ucrt("_vsnwprintf", [](Emulator& e) {
        uint64_t buf = e.arg_slot(0), count = e.arg_slot(1);
        Args va = Args::va_list_at(e, e.arg_slot(3));
        std::u16string w = utf8_to_utf16(format_guest(e, e.arg_slot(2), va, true));
        size_t take = w.size() < count ? w.size() : static_cast<size_t>(count);
        for (size_t i = 0; i < take; ++i)
            e.mem.write16(buf + i * 2, w[i]);
        if (take < count) e.mem.write16(buf + take * 2, 0);
        e.set_result(w.size() <= count ? w.size() : 0xFFFFFFFFull);
    });
    ucrt("asctime", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        std::tm tm{};
        tm.tm_sec = static_cast<int>(e.mem.read32(p));
        tm.tm_min = static_cast<int>(e.mem.read32(p + 4));
        tm.tm_hour = static_cast<int>(e.mem.read32(p + 8));
        tm.tm_mday = static_cast<int>(e.mem.read32(p + 12));
        tm.tm_mon = static_cast<int>(e.mem.read32(p + 16));
        tm.tm_year = static_cast<int>(e.mem.read32(p + 20));
        tm.tm_wday = static_cast<int>(e.mem.read32(p + 24));
        tm.tm_yday = static_cast<int>(e.mem.read32(p + 28));
        static const char* days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
        static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        char text[64];
        std::snprintf(text, sizeof text, "%s %s%3d %.2d:%.2d:%.2d %d\n",
                      days[tm.tm_wday >= 0 && tm.tm_wday < 7 ? tm.tm_wday : 0],
                      months[tm.tm_mon >= 0 && tm.tm_mon < 12 ? tm.tm_mon : 0],
                      tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_year + 1900);
        e.set_result(e.alloc_guest_string(text));
    });
    ucrt("fgetwc", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        uint8_t b = 0;
        int64_t got = fd >= 0 ? e.files.read(fd, &b, 1) : 0;
        e.set_result(got == 1 ? b : 0xFFFFull);  // WEOF
    });
    // strtok's hidden cursor lives per-emulator, which is also per-process -
    // exactly the scope the real one has (per-thread would be more faithful;
    // no guest so far tokenises on two threads at once).
    {
        auto state = std::make_shared<uint64_t>(0);
        ucrt("strtok", [state](Emulator& e) {
            uint64_t s = e.arg_slot(0);
            std::string delims = e.mem.read_cstring(e.arg_slot(1));
            uint64_t p = s ? s : *state;
            if (!p) {
                e.set_result(0);
                return;
            }
            auto is_delim = [&](uint8_t c) { return delims.find(static_cast<char>(c)) != std::string::npos; };
            while (true) {
                uint8_t c = e.mem.read8(p);
                if (c == 0) {
                    *state = p;
                    e.set_result(0);
                    return;
                }
                if (!is_delim(c)) break;
                ++p;
            }
            uint64_t token = p;
            while (true) {
                uint8_t c = e.mem.read8(p);
                if (c == 0) {
                    *state = p;
                    break;
                }
                if (is_delim(c)) {
                    e.mem.write8(p, 0);
                    *state = p + 1;
                    break;
                }
                ++p;
            }
            e.set_result(token);
        });
    }

    // _findfirst64 and friends: the CRT's directory walk, over the same listing
    // machinery FindFirstFile uses.  struct _finddata64_t is layout-identical on
    // both architectures (the 64-bit times force 8-byte alignment everywhere).
    auto write_finddata = [](Emulator& e, uint64_t out, const Emulator::DirectoryEntry& de) {
        e.mem.write32(out, de.is_dir ? 0x10u : 0x00u);          // attrib
        e.mem.write64(out + 8, static_cast<uint64_t>(de.mtime));   // time_create
        e.mem.write64(out + 16, static_cast<uint64_t>(de.mtime));  // time_access
        e.mem.write64(out + 24, static_cast<uint64_t>(de.mtime));  // time_write
        e.mem.write64(out + 32, de.size);
        std::string name = de.name.substr(0, 259);
        e.mem.write_cstring(out + 40, name);
    };
    ucrt("_findfirst64", [write_finddata](Emulator& e) {
        std::string spec = e.mem.read_cstring(e.arg_slot(0));
        auto entries = e.list_directory(spec);
        if (entries.empty()) {
            e.set_guest_errno(2);  // ENOENT
            e.set_result(~0ull);
            return;
        }
        uint64_t handle = e.open_find_handle(std::move(entries));
        write_finddata(e, e.arg_slot(1), *e.find_current(handle));
        e.set_result(handle);
    });
    ucrt("_findnext64", [write_finddata](Emulator& e) {
        uint64_t handle = e.arg_slot(0);
        if (!e.find_advance(handle)) {
            e.set_result(~0ull);
            return;
        }
        write_finddata(e, e.arg_slot(1), *e.find_current(handle));
        e.set_result(0);
    });
    ucrt("_findclose", [](Emulator& e) {
        e.close_find_handle(e.arg_slot(0));
        e.set_result(0);
    });

    // ---- binutils' additions (as.exe, ld.exe) -------------------------------------
    ucrt("_assert", [](Emulator& e) {
        std::string msg = e.mem.read_cstring(e.arg_slot(0));
        std::string file = e.mem.read_cstring(e.arg_slot(1));
        char text[512];
        std::snprintf(text, sizeof text, "Assertion failed: %s, file %s, line %u\n",
                      msg.c_str(), file.c_str(), static_cast<unsigned>(e.arg_slot(2)));
        e.write_text(2, text);
        e.exit_process(3);  // what abort() reports on Windows
    });
    ucrt("_chmod", [](Emulator& e) { e.set_result(0); });
    ucrt("_locking", [](Emulator& e) { e.set_result(0); });
    ucrt("_ctime64", [](Emulator& e) {
        auto t = static_cast<time_t>(e.mem.read64(e.arg_slot(0)));
        const char* s = std::ctime(&t);
        e.set_result(e.alloc_guest_string(s ? s : "Thu Jan  1 00:00:00 1970\n"));
    });
    ucrt("_filelengthi64", [](Emulator& e) {
        int64_t size = e.files.size(static_cast<int>(e.arg_slot(0)));
        e.set_result(static_cast<uint64_t>(size < 0 ? -1 : size));
    });
    ucrt("_wcsnicmp", [](Emulator& e) {
        uint64_t a = e.arg_slot(0), b = e.arg_slot(1), n = e.arg_slot(2);
        int r = 0;
        for (uint64_t i = 0; i < n; ++i) {
            uint16_t ca = e.mem.read16(a + i * 2), cb = e.mem.read16(b + i * 2);
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) {
                r = ca < cb ? -1 : 1;
                break;
            }
            if (!ca) break;
        }
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(r)));
    });
    // fpos_t is a 64-bit offset in every Windows CRT.
    ucrt("fgetpos", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        int64_t pos = fd >= 0 ? e.files.tell(fd) : -1;
        if (pos < 0) {
            e.set_result(static_cast<uint64_t>(-1));
            return;
        }
        e.mem.write64(e.arg_slot(1), static_cast<uint64_t>(pos));
        e.set_result(0);
    });
    ucrt("fsetpos", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        int64_t pos = static_cast<int64_t>(e.mem.read64(e.arg_slot(1)));
        e.set_result(fd >= 0 && e.files.seek(fd, pos, 0) >= 0 ? 0 : static_cast<uint64_t>(-1));
    });
    ucrt("strftime", [](Emulator& e) {
        uint64_t buf = e.arg_slot(0), max = e.arg_slot(1);
        std::string fmt = e.mem.read_cstring(e.arg_slot(2));
        uint64_t p = e.arg_slot(3);
        std::tm tm{};
        tm.tm_sec = static_cast<int>(e.mem.read32(p));
        tm.tm_min = static_cast<int>(e.mem.read32(p + 4));
        tm.tm_hour = static_cast<int>(e.mem.read32(p + 8));
        tm.tm_mday = static_cast<int>(e.mem.read32(p + 12));
        tm.tm_mon = static_cast<int>(e.mem.read32(p + 16));
        tm.tm_year = static_cast<int>(e.mem.read32(p + 20));
        tm.tm_wday = static_cast<int>(e.mem.read32(p + 24));
        tm.tm_yday = static_cast<int>(e.mem.read32(p + 28));
        std::vector<char> out(static_cast<size_t>(max) + 1);
        size_t n = std::strftime(out.data(), out.size(), fmt.c_str(), &tm);
        if (buf && n) e.mem.write(buf, out.data(), n + 1);
        e.set_result(n);
    });
    ucrt("tmpfile", [](Emulator& e) {
        // A temp file that unlinks itself is more than FileTable models; a
        // uniquely named file in the temp directory is close enough for a
        // linker's scratch space.
        std::string dir = ".";
        if (const std::string* v = e.getenv("TMP")) dir = *v;
        for (int i = 0; i < 100; ++i) {
            char name[64];
            std::snprintf(name, sizeof name, "/x86emu_tmp_%d_%d", e.pid(), i);
            FileTable::OpenFlags f;
            f.read = f.write = f.create = f.exclusive = true;
            int fd = e.files.open(dir + name, f);
            if (fd >= 0) {
                e.set_result(e.guest_file(fd));
                return;
            }
        }
        e.set_result(0);
    });
    ucrt("_popen", [](Emulator& e) {
        e.log_call("_popen(%s) unsupported, failing", e.mem.read_cstring(e.arg_slot(0)).c_str());
        e.set_result(0);
    });
    ucrt("_pclose", [](Emulator& e) { e.set_result(static_cast<uint64_t>(-1)); });
    // MEMORYSTATUSEX: a 4-byte length the caller fills in, 4 bytes of padding,
    // then eight 64-bit counters.  A compiler sizes its caches from these, so
    // "plenty, half of it free" is the answer that keeps it out of a low-memory
    // path it would otherwise take.
    win32("GlobalMemoryStatusEx", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (!p) {
            e.set_result(0);
            return;
        }
        constexpr uint64_t kTotal = 8ull << 30;
        e.mem.write32(p, 64);              // dwLength
        e.mem.write32(p + 4, 25);          // dwMemoryLoad
        e.mem.write64(p + 8, kTotal);      // ullTotalPhys
        e.mem.write64(p + 16, kTotal / 2); // ullAvailPhys
        e.mem.write64(p + 24, kTotal);     // ullTotalPageFile
        e.mem.write64(p + 32, kTotal / 2); // ullAvailPageFile
        e.mem.write64(p + 40, 0x00007FFFFFFEFFFFull);  // ullTotalVirtual
        e.mem.write64(p + 48, 0x00007FFF00000000ull);  // ullAvailVirtual
        e.mem.write64(p + 56, 0);          // ullAvailExtendedVirtual
        e.set_result(1);
    });
    win32("GlobalMemoryStatus", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) {
            e.mem.write32(p, 32);          // dwLength
            e.mem.write32(p + 4, 25);      // dwMemoryLoad
            e.mem.write32(p + 8, 0x80000000u);   // dwTotalPhys: 2 GiB
            e.mem.write32(p + 12, 0x60000000u);  // dwAvailPhys
            e.mem.write32(p + 16, 0x80000000u);
            e.mem.write32(p + 20, 0x60000000u);
            e.mem.write32(p + 24, 0x80000000u);
            e.mem.write32(p + 28, 0x60000000u);
        }
        e.set_result(1);
    });
}

}  // namespace x86emu
