// The Visual C++ toolchain's surface: what cl.exe, its compiler DLLs
// (c1.dll, c1xx.dll, c2.dll) and link.exe need beyond the API the earlier
// guests already exercised.  Almost all of it is the UCRT's wide-character
// dialect plus a few kernel32 corners (thread pools, file mappings).
#include <cctype>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_map>
#include <vector>

#include "emulator.h"
#include "guest_printf.h"
#include "processes.h"

namespace x86emu {
namespace {

// Writes a UTF-16 string with NUL, returning units written including the NUL.
int put_wide(Emulator& e, uint64_t dst, const std::string& s, uint64_t capacity_units) {
    std::u16string w = utf8_to_utf16(s);
    if (!dst || w.size() + 1 > capacity_units) return -static_cast<int>(w.size() + 1);
    for (size_t i = 0; i <= w.size(); ++i)
        e.mem.write16(dst + i * 2, i < w.size() ? w[i] : 0);
    return static_cast<int>(w.size() + 1);
}

std::string wide_arg(Emulator& e, uint64_t ptr) {
    return ptr ? utf16_to_utf8(e, ptr, -1) : std::string();
}

}  // namespace

void Emulator::install_cl_hooks() {
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, is64() ? 0 : nargs * 4, std::move(fn));
    };
    auto ucrt = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };
    auto ret0 = [&](const char* name, int nargs) {
        win32(name, nargs, [](Emulator& e) { e.set_result(0); });
    };
    auto ret1 = [&](const char* name, int nargs) {
        win32(name, nargs, [](Emulator& e) { e.set_result(1); });
    };

    // ---- advapi32: crypto and event tracing ---------------------------------------
    ret1("CryptAcquireContextW", 5);
    ret1("CryptReleaseContext", 2);
    win32("CryptGenRandom", 3, [](Emulator& e) {
        uint64_t len = e.arg_slot(1), buf = e.arg_slot(2);
        uint32_t state = 0xC0FFEE42u;
        for (uint64_t i = 0; i < len; ++i) {
            state = state * 1103515245u + 12345u;
            e.mem.write8(buf + i, static_cast<uint8_t>(state >> 16));
        }
        e.set_result(1);
    });
    ret0("EventRegister", 4);
    ret0("EventUnregister", 1);
    ret0("EventWriteTransfer", 7);
    ret0("EventSetInformation", 4);
    win32("RegOpenKeyExW", 5, [](Emulator& e) { e.set_result(2); });   // FILE_NOT_FOUND
    win32("RegGetValueW", 7, [](Emulator& e) { e.set_result(2); });
    win32("RegQueryValueExW", 6, [](Emulator& e) { e.set_result(2); });
    ret0("RegCloseKey", 1);

    // ---- kernel32 ------------------------------------------------------------------
    ret1("AreFileApisANSI", 0);
    win32("CompareStringEx", 9, [](Emulator& e) {
        // (locale, flags, s1, len1, s2, len2, ...); -1 lengths mean NUL-terminated.
        auto read = [&](uint64_t p, int64_t len) {
            return utf16_to_utf8(e, p, static_cast<int>(len));
        };
        std::string a = read(e.arg_slot(2), static_cast<int64_t>(e.arg_slot(3)));
        std::string b = read(e.arg_slot(4), static_cast<int64_t>(e.arg_slot(5)));
        constexpr uint64_t kIgnoreCase = 1;  // NORM_IGNORECASE / LINGUISTIC_IGNORECASE share bit 0
        if (e.arg_slot(1) & kIgnoreCase) {
            for (char& c : a) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char& c : b) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        int c = a.compare(b);
        e.set_result(c < 0 ? 1u : c > 0 ? 3u : 2u);  // CSTR_LESS_THAN/EQUAL/GREATER
    });
    win32("CopyFileW", 3, [](Emulator& e) {
        std::string from = FileTable::host_path(wide_arg(e, e.arg_slot(0)));
        std::string to = FileTable::host_path(wide_arg(e, e.arg_slot(1)));
        std::FILE* in = std::fopen(from.c_str(), "rb");
        if (!in) {
            e.set_last_error(2);
            e.set_result(0);
            return;
        }
        if (e.arg_slot(2)) {  // bFailIfExists
            if (std::FILE* probe = std::fopen(to.c_str(), "rb")) {
                std::fclose(probe);
                std::fclose(in);
                e.set_last_error(80);  // ERROR_FILE_EXISTS
                e.set_result(0);
                return;
            }
        }
        std::FILE* out = std::fopen(to.c_str(), "wb");
        if (!out) {
            std::fclose(in);
            e.set_last_error(5);
            e.set_result(0);
            return;
        }
        char buf[65536];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof buf, in)) > 0) std::fwrite(buf, 1, n, out);
        std::fclose(in);
        std::fclose(out);
        e.set_result(1);
    });
    ret0("CreateHardLinkW", 3);
    ret0("CreateSymbolicLinkW", 3);
    win32("CreateToolhelp32Snapshot", 2, [](Emulator& e) { e.set_result(~0ull); });
    ret0("Process32FirstW", 2);
    ret0("Process32NextW", 2);
    ret0("FindResourceW", 3);
    ret0("FindResourceExW", 4);
    ret0("LoadResource", 2);
    ret0("LockResource", 1);
    ret0("SizeofResource", 2);
    ret0("FlushProcessWriteBuffers", 0);
    ret0("FreeLibraryWhenCallbackReturns", 2);
    win32("GetDiskFreeSpaceExW", 4, [](Emulator& e) {
        for (int i = 1; i <= 3; ++i)
            if (e.arg_slot(i)) e.mem.write64(e.arg_slot(i), 64ull << 30);  // plenty
        e.set_result(1);
    });
    ret0("GetLocaleInfoEx", 4);
    win32("GetNativeSystemInfo", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) {
            std::vector<uint8_t> zeros(e.is64() ? 48 : 36, 0);
            e.mem.write(p, zeros.data(), zeros.size());
            e.mem.write16(p, 9);  // PROCESSOR_ARCHITECTURE_AMD64
            e.mem.write32(p + 4, 0x1000);
            e.mem.write32(p + (e.is64() ? 32 : 20), 1);
        }
        e.set_result(0);
    });
    ret0("GetThreadPreferredUILanguages", 4);
    ret1("SetThreadPreferredUILanguages", 3);
    win32("RtlCaptureStackBackTrace", 4, [](Emulator& e) { e.set_result(0); });
    win32("SearchPathW", 6, [](Emulator& e) {
        // (path, file, extension, buflen, buf, filepart)
        std::string file = wide_arg(e, e.arg_slot(1));
        std::string ext = wide_arg(e, e.arg_slot(2));
        auto exists = [](const std::string& p) {
            FileTable::Stat st;
            return FileTable::stat_path(p, st) == 0 && !st.is_dir;
        };
        auto try_dir = [&](std::string dir) -> std::string {
            if (!dir.empty() && dir.back() != '\\' && dir.back() != '/') dir += '\\';
            std::string full = dir + file;
            if (exists(full)) return full;
            if (!ext.empty() && exists(full + ext)) return full + ext;
            return {};
        };
        std::string found;
        if (e.arg_slot(0)) {
            found = try_dir(wide_arg(e, e.arg_slot(0)));
        } else {
            found = try_dir(".");
            if (found.empty()) {
                if (const std::string* pathv = e.getenv("PATH")) {
                    size_t start = 0;
                    while (found.empty() && start <= pathv->size()) {
                        size_t sep = pathv->find(';', start);
                        std::string dir = pathv->substr(
                            start, sep == std::string::npos ? std::string::npos : sep - start);
                        if (!dir.empty()) found = try_dir(dir);
                        if (sep == std::string::npos) break;
                        start = sep + 1;
                    }
                }
            }
        }
        if (found.empty()) {
            e.set_result(0);
            return;
        }
        int n = put_wide(e, e.arg_slot(4), found, e.arg_slot(3));
        e.set_result(n < 0 ? static_cast<uint64_t>(-n) : static_cast<uint64_t>(n - 1));
    });

    // Thread pools, driven synchronously: submitting a work item runs it on the
    // spot, so by the time anything waits for the pool it is already drained.
    {
        struct Work {
            uint64_t callback = 0, context = 0;
        };
        auto works = std::make_shared<std::unordered_map<uint64_t, Work>>();
        auto next = std::make_shared<uint64_t>(0xD0000000ull);
        win32("CreateThreadpoolWork", 3, [works, next](Emulator& e) {
            uint64_t h = (*next += 16);
            (*works)[h] = Work{e.arg_slot(0), e.arg_slot(1)};
            e.set_result(h);
        });
        win32("SubmitThreadpoolWork", 1, [works](Emulator& e) {
            auto it = works->find(e.arg_slot(0));
            if (it != works->end())
                e.call_guest(it->second.callback, {0, it->second.context, it->first});
            e.set_result(0);
        });
        ret0("WaitForThreadpoolWorkCallbacks", 2);
        win32("CloseThreadpoolWork", 1, [works](Emulator& e) {
            works->erase(e.arg_slot(0));
            e.set_result(0);
        });
        win32("CreateThreadpoolTimer", 3, [next](Emulator& e) { e.set_result(*next += 16); });
        ret0("SetThreadpoolTimer", 4);
        ret0("WaitForThreadpoolTimerCallbacks", 2);
        ret0("CloseThreadpoolTimer", 1);
        win32("CreateThreadpoolWait", 3, [next](Emulator& e) { e.set_result(*next += 16); });
        ret0("SetThreadpoolWait", 3);
        ret0("CloseThreadpoolWait", 1);
    }

    // One-time initialisation: the INIT_ONCE word itself records "has run".
    win32("InitOnceExecuteOnce", 4, [](Emulator& e) {
        uint64_t once = e.arg_slot(0);
        int ps = e.pointer_size();
        if (e.mem.read_sized(once, ps) == 0) {
            e.mem.write_sized(once, ps, 1);
            e.call_guest(e.arg_slot(1), {once, e.arg_slot(2), e.arg_slot(3)});
        }
        e.set_result(1);
    });

    // File mappings: a view is the file's bytes read into fresh guest pages.
    {
        struct Mapping {
            int fd = -1;
        };
        auto maps = std::make_shared<std::unordered_map<uint64_t, Mapping>>();
        auto next = std::make_shared<uint64_t>(0xE0000000ull);
        auto create_mapping = [maps, next](Emulator& e) {
            int fd = Emulator::fd_from_handle(e.arg_slot(0));
            if (fd < 0 || !e.files.valid(fd)) {
                e.set_result(0);
                return;
            }
            uint64_t h = (*next += 16);
            (*maps)[h] = Mapping{fd};
            e.set_result(h);
        };
        win32("CreateFileMappingA", 6, create_mapping);
        win32("CreateFileMappingW", 6, create_mapping);
        auto map_view = [maps](Emulator& e, uint64_t base) {
            auto it = maps->find(e.arg_slot(0));
            if (it == maps->end()) {
                e.set_result(0);
                return;
            }
            int fd = it->second.fd;
            uint64_t offset = (e.arg_slot(2) << 32) | (e.arg_slot(3) & 0xFFFFFFFFull);
            uint64_t size = e.arg_slot(4);
            if (!size) {
                int64_t file_size = e.files.size(fd);
                if (file_size < 0 || static_cast<uint64_t>(file_size) < offset) {
                    e.set_result(0);
                    return;
                }
                size = static_cast<uint64_t>(file_size) - offset;
            }
            uint64_t target;
            if (base) {
                e.mem.map(base, size, "file view");
                target = base;
            } else {
                target = e.alloc_pages(size);
            }
            int64_t saved = e.files.tell(fd);
            if (e.files.seek(fd, static_cast<int64_t>(offset), 0) >= 0) {
                std::vector<uint8_t> buf(static_cast<size_t>(size));
                int64_t got = e.files.read(fd, buf.data(), size);
                if (got > 0) e.mem.write(target, buf.data(), static_cast<uint64_t>(got));
            }
            if (saved >= 0) e.files.seek(fd, saved, 0);
            e.set_result(target);
        };
        win32("MapViewOfFile", 5, [map_view](Emulator& e) { map_view(e, 0); });
        win32("MapViewOfFileEx", 6, [map_view](Emulator& e) { map_view(e, e.arg_slot(5)); });
        ret1("UnmapViewOfFile", 1);
        ret1("FlushViewOfFile", 2);
    }

    // ---- vcruntime -----------------------------------------------------------------
    win32("__AdjustPointer", 2, [](Emulator& e) { e.set_result(e.arg_slot(0)); });
    ucrt("__std_exception_copy", [](Emulator& e) {
        // (const from*, to*): struct { char* what; bool do_free; }
        uint64_t from = e.arg_slot(0), to = e.arg_slot(1);
        int ps = e.pointer_size();
        uint64_t what = e.mem.read_sized(from, ps);
        if (what) what = e.alloc_guest_string(e.mem.read_cstring(what));
        e.mem.write_sized(to, ps, what);
        e.mem.write8(to + ps, what ? 1 : 0);
        e.set_result(0);
    });
    ucrt("__std_exception_destroy", [](Emulator& e) {
        int ps = e.pointer_size();
        e.mem.write_sized(e.arg_slot(0), ps, 0);
        e.set_result(0);
    });
    ucrt("__std_terminate", [](Emulator& e) {
        e.write_text(2, "terminate() called\n");
        e.exit_process(3);
    });
    ucrt("__uncaught_exception", [](Emulator& e) { e.set_result(0); });
    ucrt("__uncaught_exceptions", [](Emulator& e) { e.set_result(0); });

    // ---- UCRT: conversion ------------------------------------------------------------
    ucrt("_itow_s", [](Emulator& e) {
        char text[32];
        long long v = static_cast<int32_t>(e.arg_slot(0));
        int radix = static_cast<int>(e.arg_slot(3));
        std::snprintf(text, sizeof text, radix == 16 ? "%llx" : radix == 8 ? "%llo" : "%lld", v);
        put_wide(e, e.arg_slot(1), text, e.arg_slot(2));
        e.set_result(0);
    });
    ucrt("_wtoi", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(
            std::strtol(wide_arg(e, e.arg_slot(0)).c_str(), nullptr, 10))));
    });
    ucrt("_wtoi64", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(
            std::strtoll(wide_arg(e, e.arg_slot(0)).c_str(), nullptr, 10)));
    });
    ucrt("btowc", [](Emulator& e) {
        uint64_t c = e.arg_slot(0);
        e.set_result(c <= 0x7F ? c : 0xFFFFFFFFull);  // WEOF outside ASCII
    });
    ucrt("strtof", [](Emulator& e) {
        std::string s = e.mem.read_cstring(e.arg_slot(0));
        char* end = nullptr;
        float v = std::strtof(s.c_str(), &end);
        if (e.arg_slot(1)) e.mem.write_sized(e.arg_slot(1), e.pointer_size(),
                                             e.arg_slot(0) + (end - s.c_str()));
        e.set_result_float(v);
    });
    ucrt("wcstoul", [](Emulator& e) {
        std::string s = wide_arg(e, e.arg_slot(0));
        char* end = nullptr;
        unsigned long v = std::strtoul(s.c_str(), &end, static_cast<int>(e.arg_slot(2)));
        if (e.arg_slot(1)) e.mem.write_sized(e.arg_slot(1), e.pointer_size(),
                                             e.arg_slot(0) + 2 * (end - s.c_str()));
        e.set_result(v);
    });

    // ---- UCRT: environment and filesystem, wide ---------------------------------------
    ucrt("_wgetenv_s", [](Emulator& e) {
        // (size_t* len, buf, bufsize, name)
        const std::string* v = e.getenv(wide_arg(e, e.arg_slot(3)));
        uint64_t len_out = e.arg_slot(0);
        if (!v) {
            if (len_out) e.mem.write_sized(len_out, e.pointer_size(), 0);
            e.set_result(0);
            return;
        }
        std::u16string w = utf8_to_utf16(*v);
        if (len_out) e.mem.write_sized(len_out, e.pointer_size(), w.size() + 1);
        if (e.arg_slot(1) && e.arg_slot(2) > w.size()) put_wide(e, e.arg_slot(1), *v, e.arg_slot(2));
        e.set_result(0);
    });
    ucrt("_lock_file", [](Emulator& e) { e.set_result(0); });
    ucrt("_unlock_file", [](Emulator& e) { e.set_result(0); });
    ucrt("_waccess_s", [](Emulator& e) {
        FileTable::Stat st;
        e.set_result(FileTable::stat_path(wide_arg(e, e.arg_slot(0)), st) == 0 ? 0 : 2);
    });
    ucrt("_waccess", [](Emulator& e) {
        FileTable::Stat st;
        int ok = FileTable::stat_path(wide_arg(e, e.arg_slot(0)), st) == 0 ? 0 : -1;
        if (ok != 0) e.set_guest_errno(2);
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(ok)));
    });
    ucrt("_wremove", [](Emulator& e) {
        e.set_result(FileTable::remove_file(wide_arg(e, e.arg_slot(0))) == 0 ? 0
                                                                             : static_cast<uint64_t>(-1));
    });
    ucrt("_wunlink", [](Emulator& e) {
        e.set_result(FileTable::remove_file(wide_arg(e, e.arg_slot(0))) == 0 ? 0
                                                                             : static_cast<uint64_t>(-1));
    });
    ucrt("_wrename", [](Emulator& e) {
        e.set_result(FileTable::rename_file(wide_arg(e, e.arg_slot(0)),
                                            wide_arg(e, e.arg_slot(1))) == 0
                         ? 0
                         : static_cast<uint64_t>(-1));
    });
    ucrt("_wsplitpath_s", [](Emulator& e) {
        // (path, drive, dsz, dir, dirsz, fname, fsz, ext, esz)
        std::string path = wide_arg(e, e.arg_slot(0));
        std::string drive, dir, fname, ext;
        size_t start = 0;
        if (path.size() >= 2 && path[1] == ':') {
            drive = path.substr(0, 2);
            start = 2;
        }
        size_t slash = path.find_last_of("/\\");
        size_t name_at = slash == std::string::npos ? start : slash + 1;
        if (slash != std::string::npos && slash >= start) dir = path.substr(start, slash + 1 - start);
        std::string base = path.substr(name_at);
        size_t dot = base.find_last_of('.');
        if (dot != std::string::npos) {
            ext = base.substr(dot);
            base = base.substr(0, dot);
        }
        fname = base;
        put_wide(e, e.arg_slot(1), drive, e.arg_slot(2));
        put_wide(e, e.arg_slot(3), dir, e.arg_slot(4));
        put_wide(e, e.arg_slot(5), fname, e.arg_slot(6));
        put_wide(e, e.arg_slot(7), ext, e.arg_slot(8));
        e.set_result(0);
    });
    ucrt("_wmakepath_s", [](Emulator& e) {
        // (buf, size, drive, dir, fname, ext)
        std::string drive = wide_arg(e, e.arg_slot(2));
        std::string dir = wide_arg(e, e.arg_slot(3));
        std::string fname = wide_arg(e, e.arg_slot(4));
        std::string ext = wide_arg(e, e.arg_slot(5));
        std::string path = drive;
        path += dir;
        if (!dir.empty() && dir.back() != '\\' && dir.back() != '/') path += '\\';
        path += fname;
        if (!ext.empty() && ext[0] != '.') path += '.';
        path += ext;
        put_wide(e, e.arg_slot(0), path, e.arg_slot(1));
        e.set_result(0);
    });
    ucrt("_callnewh", [](Emulator& e) { e.set_result(1); });

    // ---- UCRT: locale tables -----------------------------------------------------------
    ucrt("_lock_locales", [](Emulator& e) { e.set_result(0); });
    ucrt("_unlock_locales", [](Emulator& e) { e.set_result(0); });
    ucrt("___lc_collate_cp_func", [](Emulator& e) { e.set_result(1252); });
    ucrt("___lc_locale_name_func", [](Emulator& e) {
        // wchar_t** indexed by LC_* category; all C locale, all NULL.
        static const uint64_t zeros[8] = {};
        e.set_result(e.alloc_guest_data(zeros, sizeof zeros));
    });
    ucrt("__pctype_func", [](Emulator& e) {
        // The 256-entry classification table isalpha() and friends index.
        uint16_t table[256] = {};
        for (int c = 0; c < 256; ++c) {
            uint16_t f = 0;
            if (c >= 'A' && c <= 'Z') f |= 0x0001;             // _UPPER
            if (c >= 'a' && c <= 'z') f |= 0x0002;             // _LOWER
            if (c >= '0' && c <= '9') f |= 0x0004;             // _DIGIT
            if (c == ' ' || (c >= 9 && c <= 13)) f |= 0x0008;  // _SPACE
            if (c < 32 || c == 127) f |= 0x0020;               // _CONTROL
            if (c == ' ' || c == '\t') f |= 0x0040;            // _BLANK
            if ((c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'))
                f |= 0x0080;                                   // _HEX
            if (c >= 33 && c <= 126 && !std::isalnum(c)) f |= 0x0010;  // _PUNCT
            if (f & 0x0003) f |= 0x0100;                       // _ALPHA
            table[c] = f;
        }
        e.set_result(e.alloc_guest_data(table, sizeof table));
    });

    // ---- UCRT: process -----------------------------------------------------------------
    ucrt("_wspawnv", [](Emulator& e) {
        // (mode, path, argv).  cl uses _P_WAIT (0) to run link.exe; the whole
        // child runs to completion inside this hook, driven by the System.
        int mode = static_cast<int>(e.arg_slot(0));
        std::string path = wide_arg(e, e.arg_slot(1));
        std::vector<std::string> argv;
        uint64_t vec = e.arg_slot(2);
        int ps = e.pointer_size();
        for (int i = 0; i < 1024; ++i) {
            uint64_t p = e.mem.read_sized(vec + static_cast<uint64_t>(i) * ps, ps);
            if (!p) break;
            argv.push_back(wide_arg(e, p));
        }
        if (argv.empty()) argv.push_back(path);
        System::SpawnRequest req;
        req.path = FileTable::host_path(path);
        req.argv = argv;
        req.env = e.environment();
        req.ppid = e.pid();
        for (int fd = 0; fd < 3; ++fd)
            if (FileTable::Entry* entry = e.files.get(fd)) req.handles.emplace_back(fd, *entry);
        int pid = e.system()->spawn(req);
        e.log_call("_wspawnv(%s) -> pid %d", path.c_str(), pid);
        if (pid < 0) {
            e.set_guest_errno(2);
            e.set_result(static_cast<uint64_t>(-1));
            return;
        }
        if (mode == 0 /* _P_WAIT */) {
            int code = e.system()->run_until_exit(pid, e.pid());
            e.set_result(static_cast<uint64_t>(static_cast<int64_t>(code)));
        } else {
            e.set_result(static_cast<uint64_t>(pid));
        }
    });
    ucrt("_wsystem", [](Emulator& e) {
        if (!e.arg_slot(0)) {
            e.set_result(1);  // "a shell exists"
            return;
        }
        e.log_call("_wsystem(%s) unsupported", wide_arg(e, e.arg_slot(0)).c_str());
        e.set_result(static_cast<uint64_t>(-1));
    });

    // ---- UCRT: runtime -------------------------------------------------------------------
    ucrt("__p__wpgmptr", [](Emulator& e) {
        std::string path = e.args().empty() ? "program.exe" : e.args()[0];
        for (char& c : path)
            if (c == '/') c = '\\';
        std::u16string w = utf8_to_utf16(path);
        std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
        std::memcpy(raw.data(), w.data(), w.size() * 2);
        uint64_t str = e.alloc_guest_data(raw.data(), raw.size());
        uint64_t var = e.alloc_guest_data(nullptr, 0);
        e.mem.write_sized(var, e.pointer_size(), str);
        e.set_result(var);
    });
    ucrt("_get_wpgmptr", [](Emulator& e) {
        std::string path = e.args().empty() ? "program.exe" : e.args()[0];
        for (char& c : path)
            if (c == '/') c = '\\';
        std::u16string w = utf8_to_utf16(path);
        std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
        std::memcpy(raw.data(), w.data(), w.size() * 2);
        uint64_t str = e.alloc_guest_data(raw.data(), raw.size());
        if (e.arg_slot(0)) e.mem.write_sized(e.arg_slot(0), e.pointer_size(), str);
        e.set_result(0);
    });
    ucrt("_invalid_parameter_noinfo", [](Emulator& e) { e.set_result(0); });
    ucrt("_invalid_parameter_noinfo_noreturn", [](Emulator& e) {
        e.write_text(2, "invalid parameter\n");
        e.exit_process(3);
    });
    ucrt("_set_new_handler", [](Emulator& e) { e.set_result(0); });

    // ---- UCRT: stdio, wide ------------------------------------------------------------------
    ucrt("__stdio_common_vsnwprintf_s", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);                      // options
        uint64_t buf = a.next_ptr();
        uint64_t bufsize = a.next_ptr();    // in wide characters
        uint64_t count = a.next_ptr();
        uint64_t fmt = a.next_ptr();
        a.next_ptr();                       // locale
        uint64_t va = a.next_ptr();
        Args tail = Args::va_list_at(e, va);
        std::u16string s = utf8_to_utf16(format_guest(e, fmt, tail, true));
        uint64_t limit = count < bufsize ? count : (bufsize ? bufsize - 1 : 0);
        size_t n = s.size() < limit ? s.size() : static_cast<size_t>(limit);
        if (buf) {
            for (size_t i = 0; i < n; ++i) e.mem.write16(buf + i * 2, s[i]);
            e.mem.write16(buf + n * 2, 0);
        }
        e.set_result(s.size());
    });
    ucrt("__stdio_common_vsprintf_s", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);
        uint64_t buf = a.next_ptr();
        uint64_t bufsize = a.next_ptr();
        uint64_t fmt = a.next_ptr();
        a.next_ptr();
        uint64_t va = a.next_ptr();
        Args tail = Args::va_list_at(e, va);
        std::string s = format_guest(e, fmt, tail);
        if (buf && bufsize) {
            size_t n = s.size() < bufsize ? s.size() : static_cast<size_t>(bufsize - 1);
            e.mem.write(buf, s.data(), n);
            e.mem.write8(buf + n, 0);
        }
        e.set_result(s.size());
    });
    ucrt("__stdio_common_vswprintf_s", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);
        uint64_t buf = a.next_ptr();
        uint64_t bufsize = a.next_ptr();
        uint64_t fmt = a.next_ptr();
        a.next_ptr();
        uint64_t va = a.next_ptr();
        Args tail = Args::va_list_at(e, va);
        std::u16string s = utf8_to_utf16(format_guest(e, fmt, tail, true));
        if (buf && bufsize) {
            size_t n = s.size() < bufsize ? s.size() : static_cast<size_t>(bufsize - 1);
            for (size_t i = 0; i < n; ++i) e.mem.write16(buf + i * 2, s[i]);
            e.mem.write16(buf + n * 2, 0);
        }
        e.set_result(s.size());
    });
    ucrt("_flushall", [](Emulator& e) {
        e.flush_guest_output();
        e.set_result(0);
    });
    auto fsopen = [](Emulator& e, bool wide) {
        std::string path = wide ? wide_arg(e, e.arg_slot(0)) : e.mem.read_cstring(e.arg_slot(0));
        std::string mode = wide ? wide_arg(e, e.arg_slot(1)) : e.mem.read_cstring(e.arg_slot(1));
        FileTable::OpenFlags f;
        f.binary = mode.find('b') != std::string::npos;
        if (mode.find('r') != std::string::npos) {
            f.read = true;
            if (mode.find('+') != std::string::npos) f.write = true;
        } else if (mode.find('w') != std::string::npos) {
            f.write = f.create = f.truncate = true;
            if (mode.find('+') != std::string::npos) f.read = true;
        } else {
            f.append = f.create = true;
        }
        int fd = e.files.open(path, f);
        if (fd < 0) {
            e.report_file_error(fd);
            e.set_result(0);
            return;
        }
        e.set_result(e.guest_file(fd));
    };
    ucrt("_fsopen", [fsopen](Emulator& e) { fsopen(e, false); });
    ucrt("_wfsopen", [fsopen](Emulator& e) { fsopen(e, true); });
    ucrt("_wfopen_s", [fsopen](Emulator& e) {
        // (FILE** out, path, mode) - shift the arguments over and reuse.
        uint64_t out = e.arg_slot(0);
        std::string path = wide_arg(e, e.arg_slot(1));
        std::string mode = wide_arg(e, e.arg_slot(2));
        FileTable::OpenFlags f;
        f.binary = mode.find('b') != std::string::npos;
        if (mode.find('r') != std::string::npos) {
            f.read = true;
            if (mode.find('+') != std::string::npos) f.write = true;
        } else if (mode.find('w') != std::string::npos) {
            f.write = f.create = f.truncate = true;
            if (mode.find('+') != std::string::npos) f.read = true;
        } else {
            f.append = f.create = true;
        }
        int fd = e.files.open(path, f);
        if (out) e.mem.write_sized(out, e.pointer_size(), fd < 0 ? 0 : e.guest_file(fd));
        e.set_result(fd < 0 ? 2 : 0);
    });
    ucrt("_get_stream_buffer_pointers", [](Emulator& e) {
        for (int i = 1; i <= 3; ++i)
            if (e.arg_slot(i)) e.mem.write_sized(e.arg_slot(i), e.pointer_size(), 0);
        e.set_result(0);
    });
    ucrt("fputwc", [](Emulator& e) {
        uint32_t c = static_cast<uint16_t>(e.arg_slot(0));
        std::string out;
        if (c < 0x80) {
            out += static_cast<char>(c);
        } else if (c < 0x800) {
            out += static_cast<char>(0xC0 | (c >> 6));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            out += static_cast<char>(0xE0 | (c >> 12));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        }
        int fd = e.host_fd(e.arg_slot(1));
        e.write_text(fd == 2 ? 2 : 1, out);
        e.set_result(c);
    });
    ucrt("fputws", [](Emulator& e) {
        std::string s = wide_arg(e, e.arg_slot(0));
        int fd = e.host_fd(e.arg_slot(1));
        e.write_text(fd == 2 ? 2 : 1, s);
        e.set_result(0);
    });
    ucrt("fgetws", [](Emulator& e) {
        // (buf, n, stream): read a line, widen it.
        uint64_t buf = e.arg_slot(0);
        int64_t n = static_cast<int64_t>(e.arg_slot(1));
        int fd = e.host_fd(e.arg_slot(2));
        std::string line;
        while (static_cast<int64_t>(line.size()) < n - 1) {
            uint8_t b = 0;
            if (e.files.read(fd, &b, 1) != 1) break;
            line += static_cast<char>(b);
            if (b == '\n') break;
        }
        if (line.empty()) {
            e.set_result(0);
            return;
        }
        put_wide(e, buf, line, static_cast<uint64_t>(n));
        e.set_result(buf);
    });
    ucrt("getwchar", [](Emulator& e) {
        uint8_t b = 0;
        e.set_result(e.files.read(0, &b, 1) == 1 ? b : 0xFFFFull);
    });
    ucrt("ungetwc", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(1));
        if (fd >= 0) e.files.seek(fd, -1, 1);
        e.set_result(e.arg_slot(0));
    });
    ucrt("_cputws", [](Emulator& e) {
        e.write_text(1, wide_arg(e, e.arg_slot(0)));
        e.set_result(0);
    });

    // ---- UCRT: string, wide ---------------------------------------------------------------
    ucrt("__strncnt", [](Emulator& e) {
        uint64_t p = e.arg_slot(0), max = e.arg_slot(1), n = 0;
        while (n < max && e.mem.read8(p + n) != 0) ++n;
        e.set_result(n);
    });
    auto wcs_case = [](Emulator& e, bool upper) {
        uint64_t p = e.arg_slot(0);
        for (uint64_t i = 0;; ++i) {
            uint16_t c = e.mem.read16(p + i * 2);
            if (!c) break;
            if (upper && c >= 'a' && c <= 'z') e.mem.write16(p + i * 2, c - 32);
            if (!upper && c >= 'A' && c <= 'Z') e.mem.write16(p + i * 2, c + 32);
        }
        e.set_result(0);
    };
    ucrt("_wcslwr_s", [wcs_case](Emulator& e) { wcs_case(e, false); });
    ucrt("_wcsupr_s", [wcs_case](Emulator& e) { wcs_case(e, true); });
    auto isw_class = [](Emulator& e, int kind) {
        uint32_t c = static_cast<uint32_t>(e.arg_slot(0));
        bool r = false;
        switch (kind) {
            case 0: r = (c < 128) && std::isalnum(static_cast<int>(c)); break;
            case 1: r = (c < 128) && std::isdigit(static_cast<int>(c)); break;
            case 2: r = (c < 128) && std::isspace(static_cast<int>(c)); break;
            case 3: r = (c < 128) && std::isxdigit(static_cast<int>(c)); break;
            case 4: r = (c < 128) && std::isalpha(static_cast<int>(c)); break;
            case 5: r = (c < 128) && std::isprint(static_cast<int>(c)); break;
            default: break;
        }
        e.set_result(r ? 1 : 0);
    };
    ucrt("iswalnum", [isw_class](Emulator& e) { isw_class(e, 0); });
    ucrt("iswdigit", [isw_class](Emulator& e) { isw_class(e, 1); });
    ucrt("iswspace", [isw_class](Emulator& e) { isw_class(e, 2); });
    ucrt("iswxdigit", [isw_class](Emulator& e) { isw_class(e, 3); });
    ucrt("iswalpha", [isw_class](Emulator& e) { isw_class(e, 4); });
    ucrt("iswprint", [isw_class](Emulator& e) { isw_class(e, 5); });
    ucrt("towlower", [](Emulator& e) {
        uint64_t c = e.arg_slot(0);
        e.set_result(c >= 'A' && c <= 'Z' ? c + 32 : c);
    });
    ucrt("towupper", [](Emulator& e) {
        uint64_t c = e.arg_slot(0);
        e.set_result(c >= 'a' && c <= 'z' ? c - 32 : c);
    });
    auto wcs_copy = [](Emulator& e, bool cat, bool bounded) {
        // wcscpy_s(dst, size, src) / wcsncpy_s(dst, size, src, count)
        uint64_t dst = e.arg_slot(0);
        uint64_t src = e.arg_slot(2);
        uint64_t count = bounded ? e.arg_slot(3) : ~0ull;
        uint64_t at = 0;
        if (cat)
            while (e.mem.read16(dst + at * 2) != 0) ++at;
        for (uint64_t i = 0; i < count; ++i) {
            uint16_t c = e.mem.read16(src + i * 2);
            e.mem.write16(dst + (at + i) * 2, c);
            if (!c) {
                e.set_result(0);
                return;
            }
        }
        e.mem.write16(dst + (at + count) * 2, 0);
        e.set_result(0);
    };
    ucrt("wcscpy_s", [wcs_copy](Emulator& e) { wcs_copy(e, false, false); });
    ucrt("wcscat_s", [wcs_copy](Emulator& e) { wcs_copy(e, true, false); });
    ucrt("wcsncpy_s", [wcs_copy](Emulator& e) { wcs_copy(e, false, true); });
    ucrt("wcsncat_s", [wcs_copy](Emulator& e) { wcs_copy(e, true, true); });
    ucrt("wcspbrk", [](Emulator& e) {
        std::string set = wide_arg(e, e.arg_slot(1));
        uint64_t p = e.arg_slot(0);
        for (uint64_t i = 0;; ++i) {
            uint16_t c = e.mem.read16(p + i * 2);
            if (!c) break;
            if (c < 128 && set.find(static_cast<char>(c)) != std::string::npos) {
                e.set_result(p + i * 2);
                return;
            }
        }
        e.set_result(0);
    });
    ucrt("wcsspn", [](Emulator& e) {
        std::string set = wide_arg(e, e.arg_slot(1));
        uint64_t p = e.arg_slot(0), n = 0;
        while (true) {
            uint16_t c = e.mem.read16(p + n * 2);
            if (!c || c >= 128 || set.find(static_cast<char>(c)) == std::string::npos) break;
            ++n;
        }
        e.set_result(n);
    });

    // ---- UCRT: time -----------------------------------------------------------------------
    ucrt("_Getdays", [](Emulator& e) {
        e.set_result(e.alloc_guest_string(
            ":Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday"));
    });
    ucrt("_Getmonths", [](Emulator& e) {
        e.set_result(e.alloc_guest_string(
            ":Jan:January:Feb:February:Mar:March:Apr:April:May:May:Jun:June:Jul:July:Aug:August"
            ":Sep:September:Oct:October:Nov:November:Dec:December"));
    });
    ucrt("_Gettnames", [](Emulator& e) { e.set_result(0); });
    ucrt("_W_Getdays", [](Emulator& e) { e.set_result(0); });
    ucrt("_W_Getmonths", [](Emulator& e) { e.set_result(0); });
    ucrt("_W_Gettnames", [](Emulator& e) { e.set_result(0); });
    ucrt("_ftime64_s", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) {
            e.mem.write64(p, static_cast<uint64_t>(std::time(nullptr)));  // time
            e.mem.write16(p + 8, 0);   // millitm
            e.mem.write16(p + 10, 0);  // timezone
            e.mem.write16(p + 12, 0);  // dstflag
        }
        e.set_result(0);
    });
    ucrt("rand_s", [](Emulator& e) {
        if (e.arg_slot(0)) e.mem.write32(e.arg_slot(0), 0x2A2A2A2Au);
        e.set_result(0);
    });

    // ---- ole32 -------------------------------------------------------------------------
    win32("CoCreateGuid", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        static uint32_t counter = 0;
        ++counter;
        if (p) {
            e.mem.write32(p, 0xE586A9E0u + counter);
            e.mem.write32(p + 4, 0x4D4D0000u);
            e.mem.write32(p + 8, 0x11EE0000u);
            e.mem.write32(p + 12, counter);
        }
        e.set_result(0);  // S_OK
    });
    win32("StringFromGUID2", 3, [](Emulator& e) {
        uint64_t g = e.arg_slot(0);
        char text[64];
        std::snprintf(text, sizeof text,
                      "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                      e.mem.read32(g), e.mem.read16(g + 4), e.mem.read16(g + 6),
                      e.mem.read8(g + 8), e.mem.read8(g + 9), e.mem.read8(g + 10),
                      e.mem.read8(g + 11), e.mem.read8(g + 12), e.mem.read8(g + 13),
                      e.mem.read8(g + 14), e.mem.read8(g + 15));
        int n = put_wide(e, e.arg_slot(1), text, e.arg_slot(2));
        e.set_result(n < 0 ? 0 : static_cast<uint64_t>(n));
    });
}

}  // namespace x86emu
