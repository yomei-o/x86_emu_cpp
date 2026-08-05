// The surface link.exe needs on top of cl.exe's.
//
// This file exists because of what `x86emu --imports link.exe` prints: binding
// the imports of a new guest and reading the unresolved list is a complete,
// finite specification of what is missing, and it beats discovering the same
// names one crash at a time.  Everything here came off that list.
//
// The theme is that a linker is a *file* program: it wants times, volumes, file
// lengths, and the console.  Where an answer has to be invented, the honest
// invention is the one a plain fixed disk with one volume would give, because
// that is what the linker is being asked to write to.
#include <algorithm>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#if defined(_WIN32)
#include <direct.h>
#else
#include <unistd.h>
#endif

#include "emulator.h"
#include "guest_printf.h"

namespace x86emu {

namespace {

// 100-nanosecond ticks since 1601, which is what every Windows time API speaks.
constexpr uint64_t kUnixEpochInTicks = 116444736000000000ull;

uint64_t unix_to_filetime(int64_t t) {
    return kUnixEpochInTicks + static_cast<uint64_t>(t) * 10000000ull;
}

// SYSTEMTIME: year, month, day-of-week, day, hour, minute, second, milliseconds,
// all 16-bit.
void write_system_time(Emulator& e, uint64_t p, const std::tm& tm, int ms) {
    if (!p) return;
    const uint16_t f[8] = {static_cast<uint16_t>(tm.tm_year + 1900),
                           static_cast<uint16_t>(tm.tm_mon + 1),
                           static_cast<uint16_t>(tm.tm_wday),
                           static_cast<uint16_t>(tm.tm_mday),
                           static_cast<uint16_t>(tm.tm_hour),
                           static_cast<uint16_t>(tm.tm_min),
                           static_cast<uint16_t>(tm.tm_sec),
                           static_cast<uint16_t>(ms)};
    for (int i = 0; i < 8; ++i) e.mem.write16(p + i * 2, f[i]);
}

std::tm read_system_time(Emulator& e, uint64_t p) {
    std::tm tm{};
    tm.tm_year = e.mem.read16(p) - 1900;
    tm.tm_mon = e.mem.read16(p + 2) - 1;
    tm.tm_mday = e.mem.read16(p + 6);
    tm.tm_hour = e.mem.read16(p + 8);
    tm.tm_min = e.mem.read16(p + 10);
    tm.tm_sec = e.mem.read16(p + 12);
    tm.tm_isdst = 0;
    return tm;
}

// Reads a guest `struct tm`, whose first eight ints are the standard fields in
// the standard order in every CRT this emulator deals with.
std::tm read_guest_tm(Emulator& e, uint64_t p) {
    std::tm tm{};
    if (!p) return tm;
    tm.tm_sec = static_cast<int>(e.mem.read32(p));
    tm.tm_min = static_cast<int>(e.mem.read32(p + 4));
    tm.tm_hour = static_cast<int>(e.mem.read32(p + 8));
    tm.tm_mday = static_cast<int>(e.mem.read32(p + 12));
    tm.tm_mon = static_cast<int>(e.mem.read32(p + 16));
    tm.tm_year = static_cast<int>(e.mem.read32(p + 20));
    tm.tm_wday = static_cast<int>(e.mem.read32(p + 24));
    tm.tm_yday = static_cast<int>(e.mem.read32(p + 28));
    return tm;
}

bool chdir_host(const std::string& path) {
#if defined(_WIN32)
    return _chdir(path.c_str()) == 0;
#else
    return chdir(path.c_str()) == 0;
#endif
}

bool rmdir_host(const std::string& path) {
#if defined(_WIN32)
    return _rmdir(path.c_str()) == 0;
#else
    return rmdir(path.c_str()) == 0;
#endif
}

void write_utf16(Emulator& e, uint64_t dst, const std::string& s) {
    std::u16string w = utf8_to_utf16(s);
    for (size_t i = 0; i < w.size(); ++i) e.mem.write16(dst + i * 2, w[i]);
    e.mem.write16(dst + w.size() * 2, 0);
}

}  // namespace

void Emulator::install_link_hooks() {
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, is64() ? 0 : nargs * 4, std::move(fn));
    };
    auto ucrt = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };

    // ---- kernel32: time -----------------------------------------------------
    win32("GetSystemTime", 1, [](Emulator& e) {
        std::time_t now = std::time(nullptr);
        std::tm tm{};
#if defined(_WIN32)
        gmtime_s(&tm, &now);
#else
        gmtime_r(&now, &tm);
#endif
        write_system_time(e, e.arg_slot(0), tm, 0);
        e.set_result(0);
    });
    win32("SystemTimeToFileTime", 2, [](Emulator& e) {
        std::tm tm = read_system_time(e, e.arg_slot(0));
        // timegm is the inverse of gmtime, which is the direction a SYSTEMTIME in
        // UTC needs; mktime would apply the host's zone twice.
#if defined(_WIN32)
        std::time_t t = _mkgmtime(&tm);
#else
        std::time_t t = timegm(&tm);
#endif
        if (e.arg_slot(1)) e.mem.write64(e.arg_slot(1), unix_to_filetime(t));
        e.set_result(1);
    });
    // (handle, *creation, *access, *write).  A linker uses these to decide
    // whether an input is newer than its output, so the write time has to be the
    // file's real one; the other two are the same answer rather than a lie about
    // metadata this emulator does not track.
    win32("GetFileTime", 4, [](Emulator& e) {
        FileTable::Stat st;
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        if (fd < 0 || e.files.stat_fd(fd, st) != 0) {
            e.set_last_error(6);  // ERROR_INVALID_HANDLE
            e.set_result(0);
            return;
        }
        uint64_t ft = unix_to_filetime(st.mtime);
        for (int i = 1; i <= 3; ++i)
            if (e.arg_slot(i)) e.mem.write64(e.arg_slot(i), ft);
        e.set_result(1);
    });

    // ---- kernel32: volumes --------------------------------------------------
    // One fixed disk is the whole story here: the guest asks so it can decide
    // whether to trust file times and whether renames are atomic, and both
    // answers are the ones a local NTFS volume gives.
    auto drive_fixed = [](Emulator& e) { e.set_result(3); };  // DRIVE_FIXED
    win32("GetDriveTypeA", 1, drive_fixed);
    win32("GetDriveTypeW", 1, drive_fixed);
    // (path, buffer, buffer length in characters)
    win32("GetVolumePathNameW", 3, [](Emulator& e) {
        std::string path = utf16_to_utf8(e, e.arg_slot(0), -1);
        std::string root = path.size() >= 2 && path[1] == ':' ? path.substr(0, 2) + "\\" : "C:\\";
        if (e.arg_slot(1) && e.arg_slot(2) > root.size()) {
            write_utf16(e, e.arg_slot(1), root);
            e.set_result(1);
            return;
        }
        e.set_last_error(122);  // ERROR_INSUFFICIENT_BUFFER
        e.set_result(0);
    });
    // A linker asks DeviceIoControl about sparse files and volume geometry.
    // Failing is the answer that makes it use the portable path instead; claiming
    // success without filling the output buffer would not.
    win32("DeviceIoControl", 8, [](Emulator& e) {
        if (e.arg_slot(6)) e.mem.write32(e.arg_slot(6), 0);
        e.set_last_error(1);  // ERROR_INVALID_FUNCTION
        e.set_result(0);
    });

    // ---- kernel32: files ----------------------------------------------------
    // The 32-bit SetFilePointer: the low half of the offset is a value, the high
    // half is an in/out pointer, and the result is the new low half - with
    // INVALID_SET_FILE_POINTER indistinguishable from a legitimate 0xFFFFFFFF
    // unless the caller also clears the last error, which is why the Ex form
    // exists and why this one has to set it explicitly.
    win32("SetFilePointer", 4, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        int64_t offset = static_cast<int32_t>(e.arg_slot(1));
        uint64_t high_ptr = e.arg_slot(2);
        if (high_ptr) {
            int64_t high = static_cast<int32_t>(e.mem.read32(high_ptr));
            offset = static_cast<int64_t>((static_cast<uint64_t>(high) << 32) |
                                          (e.arg_slot(1) & 0xFFFFFFFFull));
        }
        int64_t pos = e.files.seek(fd, offset, static_cast<int>(e.arg_slot(3)));
        if (pos < 0) {
            e.set_last_error(25);  // ERROR_SEEK
            e.set_result(0xFFFFFFFFull);
            return;
        }
        if (high_ptr) e.mem.write32(high_ptr, static_cast<uint32_t>(pos >> 32));
        e.set_last_error(0);
        e.set_result(static_cast<uint32_t>(pos));
    });

    // ---- kernel32: process and diagnostics ----------------------------------
    // GetThreadId(handle).  A caller almost always passes its own handle - it is
    // asking "which thread am I" through the only API that takes a handle - and
    // the emulator has no reverse map from handle to thread, so answering for the
    // current thread is both the common case and the only one it can answer.
    win32("GetThreadId", 1, [](Emulator& e) { e.set_result(e.current_thread_id()); });
    win32("SetProcessWorkingSetSize", 3, [](Emulator& e) { e.set_result(1); });
    // (buffer, in/out size in characters).  cl's C++ front end asks for the
    // machine name while building its PCH/IFC identity; any stable name will do.
    auto computer_name = [](Emulator& e, bool wide) {
        const std::string name = "X86EMU";
        uint64_t buf = e.arg_slot(0), size_ptr = e.arg_slot(1);
        uint32_t capacity = size_ptr ? e.mem.read32(size_ptr) : 0;
        if (!buf || capacity <= name.size()) {
            if (size_ptr) e.mem.write32(size_ptr, static_cast<uint32_t>(name.size() + 1));
            e.set_last_error(111);  // ERROR_BUFFER_OVERFLOW
            e.set_result(0);
            return;
        }
        if (wide)
            write_utf16(e, buf, name);
        else
            e.mem.write_cstring(buf, name);
        if (size_ptr) e.mem.write32(size_ptr, static_cast<uint32_t>(name.size()));
        e.set_result(1);
    };
    win32("GetComputerNameA", 2, [computer_name](Emulator& e) { computer_name(e, false); });
    win32("GetComputerNameW", 2, [computer_name](Emulator& e) { computer_name(e, true); });
    // The Ex form takes a format enum first; every format may answer the same.
    win32("GetComputerNameExW", 3, [](Emulator& e) {
        const std::string name = "X86EMU";
        uint64_t buf = e.arg_slot(1), size_ptr = e.arg_slot(2);
        uint32_t capacity = size_ptr ? e.mem.read32(size_ptr) : 0;
        if (!buf || capacity <= name.size()) {
            if (size_ptr) e.mem.write32(size_ptr, static_cast<uint32_t>(name.size() + 1));
            e.set_last_error(234);  // ERROR_MORE_DATA
            e.set_result(0);
            return;
        }
        write_utf16(e, buf, name);
        if (size_ptr) e.mem.write32(size_ptr, static_cast<uint32_t>(name.size()));
        e.set_result(1);
    });
    win32("DebugBreak", 0, [](Emulator& e) { e.set_result(0); });
    // Windows Error Reporting: a crashing linker would attach these files to its
    // report.  Registering them successfully and never reporting anything is
    // exactly what happens on a machine with WER disabled.
    win32("WerRegisterFile", 3, [](Emulator& e) { e.set_result(0); });
    win32("WerRegisterMemoryBlock", 2, [](Emulator& e) { e.set_result(0); });
    win32("WerUnregisterMemoryBlock", 1, [](Emulator& e) { e.set_result(0); });
    // RaiseFailFastException is the one that must *not* return: it is how the CRT
    // reports a corrupted invariant, and continuing past it would turn a clear
    // abort into unexplained wrong behaviour further on.
    win32("RaiseFailFastException", 3, [](Emulator& e) {
        e.flush_guest_output();
        std::fprintf(stderr, "x86emu: the guest called RaiseFailFastException\n");
        std::fprintf(stderr, "%s", e.stack_trace(12).c_str());
        e.exit_process(0xC0000409);  // STATUS_STACK_BUFFER_OVERRUN, what WER logs
    });

    // Interlocked singly-linked lists.  The header is a guest-owned structure
    // whose first pointer-sized word is the head of the chain, and each entry's
    // first word is its next pointer; nothing else in it matters to a
    // single-threaded interpreter, and the guest allocates and aligns the memory.
    win32("InterlockedPushEntrySList", 2, [](Emulator& e) {
        uint64_t head = e.arg_slot(0), entry = e.arg_slot(1);
        int ps = e.pointer_size();
        uint64_t first = e.mem.read_sized(head, ps);
        e.mem.write_sized(entry, ps, first);
        e.mem.write_sized(head, ps, entry);
        e.set_result(first);
    });
    win32("InterlockedPopEntrySList", 1, [](Emulator& e) {
        uint64_t head = e.arg_slot(0);
        int ps = e.pointer_size();
        uint64_t first = e.mem.read_sized(head, ps);
        if (first) e.mem.write_sized(head, ps, e.mem.read_sized(first, ps));
        e.set_result(first);
    });

    // ---- oleaut32: BSTR and VARIANT -----------------------------------------
    // A BSTR is a wide string with its byte length in the 4 bytes *before* the
    // pointer, NUL-terminated after; SysFreeString must accept what
    // SysAllocString made, so both sides live here and agree on that layout.
    // c1xx reaches these by delay-loaded ordinal at shutdown.
    auto alloc_bstr = [](Emulator& e, const uint8_t* data, uint32_t bytes) {
        uint64_t block = e.heap_alloc(4 + bytes + 2);
        e.mem.write32(block, bytes);
        if (bytes) e.mem.write(block + 4, data, bytes);
        e.mem.write16(block + 4 + bytes, 0);
        return block + 4;
    };
    win32("SysAllocString", 1, [alloc_bstr](Emulator& e) {
        uint64_t src = e.arg_slot(0);
        if (!src) {
            e.set_result(0);
            return;
        }
        uint64_t units = 0;
        while (e.mem.read16(src + units * 2) != 0) ++units;
        std::vector<uint8_t> raw(static_cast<size_t>(units) * 2);
        if (units) e.mem.read(src, raw.data(), raw.size());
        e.set_result(alloc_bstr(e, raw.data(), static_cast<uint32_t>(raw.size())));
    });
    // (source, length in characters): the source may be null - that allocates
    // uninitialised room - and may contain embedded NULs, which is the point of
    // carrying an explicit length.
    win32("SysAllocStringLen", 2, [alloc_bstr](Emulator& e) {
        uint64_t src = e.arg_slot(0);
        uint32_t units = static_cast<uint32_t>(e.arg_slot(1));
        std::vector<uint8_t> raw(static_cast<size_t>(units) * 2, 0);
        if (src && units) e.mem.read(src, raw.data(), raw.size());
        e.set_result(alloc_bstr(e, raw.data(), units * 2));
    });
    win32("SysAllocStringByteLen", 2, [alloc_bstr](Emulator& e) {
        uint64_t src = e.arg_slot(0);
        uint32_t bytes = static_cast<uint32_t>(e.arg_slot(1));
        std::vector<uint8_t> raw(bytes, 0);
        if (src && bytes) e.mem.read(src, raw.data(), bytes);
        e.set_result(alloc_bstr(e, raw.data(), bytes));
    });
    win32("SysFreeString", 1, [](Emulator& e) {
        if (uint64_t b = e.arg_slot(0)) e.heap_free(b - 4);
        e.set_result(0);
    });
    win32("SysStringLen", 1, [](Emulator& e) {
        uint64_t b = e.arg_slot(0);
        e.set_result(b ? e.mem.read32(b - 4) / 2 : 0);
    });
    win32("SysStringByteLen", 1, [](Emulator& e) {
        uint64_t b = e.arg_slot(0);
        e.set_result(b ? e.mem.read32(b - 4) : 0);
    });
    // A VARIANT is 24 bytes v-type first; Init zeroes it (VT_EMPTY), and Clear
    // frees what the type says it owns.  Only the BSTR case owns anything a
    // compiler produces.
    win32("VariantInit", 1, [](Emulator& e) {
        uint64_t v = e.arg_slot(0);
        if (v)
            for (int i = 0; i < 24; i += 8) e.mem.write64(v + i, 0);
        e.set_result(0);
    });
    win32("VariantClear", 1, [](Emulator& e) {
        uint64_t v = e.arg_slot(0);
        if (!v) {
            e.set_result(0x80070057);  // E_INVALIDARG
            return;
        }
        constexpr uint16_t kVtBstr = 8;
        if (e.mem.read16(v) == kVtBstr) {
            if (uint64_t b = e.mem.read_sized(v + 8, e.pointer_size())) e.heap_free(b - 4);
        }
        for (int i = 0; i < 24; i += 8) e.mem.write64(v + i, 0);
        e.set_result(0);
    });

    // ---- psapi --------------------------------------------------------------
    // PROCESS_MEMORY_COUNTERS, used for the "peak memory" line a linker can
    // print.  cb comes in already set by the caller; the counters we can answer
    // truthfully are the ones the emulator knows.
    win32("GetProcessMemoryInfo", 3, [](Emulator& e) {
        uint64_t p = e.arg_slot(1), cb = e.arg_slot(2);
        for (uint64_t i = 0; i < cb; i += 4) e.mem.write32(p + i, 0);
        if (cb >= 4) e.mem.write32(p, static_cast<uint32_t>(cb));
        e.set_result(1);
    });

    // ---- user32 -------------------------------------------------------------
    // wsprintfW(buffer, format, ...) is sprintf with a wide format and no length
    // limit, so the variadic tail starts at the third slot.
    win32("wsprintfW", 2, [](Emulator& e) {
        Args a(e, 2);
        std::string s = format_guest(e, e.arg_slot(1), a, true);
        write_utf16(e, e.arg_slot(0), s);
        e.set_result(utf8_to_utf16(s).size());
    });

    // ---- CRT: the console ---------------------------------------------------
    // _cprintf and friends write to the console rather than to stdout.  With no
    // console of its own, the emulator's stdout *is* the console, which is also
    // what a redirected build expects to capture.
    ucrt("__conio_common_vcprintf", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);                    // options
        uint64_t fmt = a.next_ptr();
        a.next_ptr();                     // locale
        Args tail = Args::va_list_at(e, a.next_ptr());
        std::string s = format_guest(e, fmt, tail);
        e.write_text(1, s);
        e.set_result(s.size());
    });
    ucrt("__conio_common_vcwprintf", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);
        uint64_t fmt = a.next_ptr();
        a.next_ptr();
        Args tail = Args::va_list_at(e, a.next_ptr());
        std::string s = format_guest(e, fmt, tail, true);
        e.write_text(1, s);
        e.set_result(s.size());
    });
    ucrt("_cputs", [](Emulator& e) {
        e.write_text(1, e.mem.read_cstring(e.arg_slot(0)));
        e.set_result(0);
    });
    ucrt("_putwch", [](Emulator& e) {
        uint16_t c = static_cast<uint16_t>(e.arg_slot(0));
        std::u16string w(1, static_cast<char16_t>(c));
        std::string s;
        // One code unit at a time, so a surrogate pair arrives as two calls and
        // has to survive being encoded separately; the BMP case is all a linker
        // produces.
        if (c < 0x80) {
            s.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            s.push_back(static_cast<char>(0xC0 | (c >> 6)));
            s.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            s.push_back(static_cast<char>(0xE0 | (c >> 12)));
            s.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            s.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
        e.write_text(1, s);
        e.set_result(c);
    });

    // ---- CRT: files and directories ----------------------------------------
    ucrt("_wchdir", [](Emulator& e) {
        std::string host = FileTable::host_path(utf16_to_utf8(e, e.arg_slot(0), -1));
        e.set_result(chdir_host(host) ? 0 : static_cast<uint64_t>(-1));
    });
    ucrt("_wrmdir", [](Emulator& e) {
        std::string host = FileTable::host_path(utf16_to_utf8(e, e.arg_slot(0), -1));
        e.set_result(rmdir_host(host) ? 0 : static_cast<uint64_t>(-1));
    });
    ucrt("_filelength", [](Emulator& e) {
        int64_t size = e.files.size(static_cast<int>(e.arg_slot(0)));
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(
            size < 0 ? -1 : static_cast<int32_t>(size))));
    });
    ucrt("_wfdopen", [](Emulator& e) {
        int fd = static_cast<int>(e.arg_slot(0));
        e.set_result(e.files.valid(fd) ? e.guest_file(fd) : 0);
    });
    // (file, env var name, buffer, buffer size): looks for `file` in each
    // directory listed in the named environment variable, writing the first hit.
    // An empty result is the documented "not found" - not an error return.
    ucrt("_wsearchenv_s", [](Emulator& e) {
        std::string file = utf16_to_utf8(e, e.arg_slot(0), -1);
        std::string var = utf16_to_utf8(e, e.arg_slot(1), -1);
        uint64_t buf = e.arg_slot(2), size = e.arg_slot(3);
        auto fits = [&](const std::string& s) { return buf && s.size() + 1 <= size; };
        FileTable::Stat st;
        if (FileTable::stat_path(FileTable::host_path(file), st) == 0 && fits(file)) {
            write_utf16(e, buf, file);
            e.set_result(0);
            return;
        }
        const std::string* dirs = e.getenv(var);
        if (dirs) {
            size_t at = 0;
            while (at <= dirs->size()) {
                size_t end = dirs->find(';', at);
                if (end == std::string::npos) end = dirs->size();
                std::string dir = dirs->substr(at, end - at);
                at = end + 1;
                if (dir.empty()) continue;
                if (dir.back() != '\\' && dir.back() != '/') dir += '\\';
                std::string full = dir + file;
                if (FileTable::stat_path(FileTable::host_path(full), st) == 0 && fits(full)) {
                    write_utf16(e, buf, full);
                    e.set_result(0);
                    return;
                }
            }
        }
        if (buf && size) e.mem.write16(buf, 0);
        e.set_result(0);
    });

    // ---- CRT: strings -------------------------------------------------------
    ucrt("iswascii", [](Emulator& e) { e.set_result(e.arg_slot(0) < 0x80 ? 1 : 0); });
    ucrt("wcscspn", [](Emulator& e) {
        uint64_t s = e.arg_slot(0), reject = e.arg_slot(1), n = 0;
        for (;; ++n) {
            uint16_t c = e.mem.read16(s + n * 2);
            if (!c) break;
            bool found = false;
            for (uint64_t i = 0;; ++i) {
                uint16_t r = e.mem.read16(reject + i * 2);
                if (!r) break;
                if (r == c) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        }
        e.set_result(n);
    });
    // (string, delimiters, *context).  The caller owns the cursor, which is what
    // makes this the reentrant form: on the first call `string` is the subject and
    // afterwards it is null and the cursor says where to carry on.  Tokens are
    // returned by terminating them in place, in the caller's own buffer.
    ucrt("wcstok_s", [](Emulator& e) {
        uint64_t str = e.arg_slot(0), delim = e.arg_slot(1), ctx = e.arg_slot(2);
        int ps = e.pointer_size();
        uint64_t p = str ? str : (ctx ? e.mem.read_sized(ctx, ps) : 0);
        if (!p) {
            e.set_result(0);
            return;
        }
        auto is_delim = [&](uint16_t c) {
            for (uint64_t i = 0;; ++i) {
                uint16_t d = e.mem.read16(delim + i * 2);
                if (!d) return false;
                if (d == c) return true;
            }
        };
        while (e.mem.read16(p) && is_delim(e.mem.read16(p))) p += 2;
        if (!e.mem.read16(p)) {
            if (ctx) e.mem.write_sized(ctx, ps, p);
            e.set_result(0);
            return;
        }
        uint64_t start = p;
        while (e.mem.read16(p) && !is_delim(e.mem.read16(p))) p += 2;
        if (e.mem.read16(p)) {
            e.mem.write16(p, 0);
            p += 2;
        }
        if (ctx) e.mem.write_sized(ctx, ps, p);
        e.set_result(start);
    });

    // ---- CRT: time formatting ----------------------------------------------
    // _Strftime and _Wcsftime are the UCRT's internal entry points behind
    // strftime and wcsftime: the same arguments plus a trailing locale, which
    // nothing here varies by.
    ucrt("_Strftime", [](Emulator& e) {
        uint64_t buf = e.arg_slot(0), max = e.arg_slot(1);
        std::string fmt = e.mem.read_cstring(e.arg_slot(2));
        std::tm tm = read_guest_tm(e, e.arg_slot(3));
        std::vector<char> out(static_cast<size_t>(max) + 1, 0);
        size_t n = std::strftime(out.data(), out.size(), fmt.c_str(), &tm);
        if (buf && max) e.mem.write(buf, out.data(), n + 1);
        e.set_result(n);
    });
    ucrt("_Wcsftime", [](Emulator& e) {
        uint64_t buf = e.arg_slot(0), max = e.arg_slot(1);
        std::string fmt = utf16_to_utf8(e, e.arg_slot(2), -1);
        std::tm tm = read_guest_tm(e, e.arg_slot(3));
        std::vector<char> out(static_cast<size_t>(max) * 4 + 1, 0);
        size_t n = std::strftime(out.data(), out.size(), fmt.c_str(), &tm);
        std::string s(out.data(), n);
        if (buf && max) write_utf16(e, buf, s);
        e.set_result(utf8_to_utf16(s).size());
    });
    ucrt("_wctime64", [](Emulator& e) {
        auto t = static_cast<std::time_t>(e.mem.read64(e.arg_slot(0)));
        const char* s = std::ctime(&t);
        std::string text = s ? s : "Thu Jan  1 00:00:00 1970\n";
        std::u16string w = utf8_to_utf16(text);
        std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
        std::memcpy(raw.data(), w.data(), w.size() * 2);
        e.set_result(e.alloc_guest_data(raw.data(), raw.size()));
    });

    // ---- CRT: qsort_s -------------------------------------------------------
    // The same as qsort with a context pointer threaded through to the
    // comparison, which is also why the argument order differs: (base, count,
    // size, compare, context), and compare takes (context, a, b).
    ucrt("qsort_s", [](Emulator& e) {
        uint64_t base = e.arg_slot(0), count = e.arg_slot(1), size = e.arg_slot(2);
        uint64_t compare = e.arg_slot(3), context = e.arg_slot(4);
        if (!count || !size || !compare) {
            e.set_result(0);
            return;
        }
        std::vector<std::vector<uint8_t>> items;
        items.reserve(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) {
            std::vector<uint8_t> item(static_cast<size_t>(size));
            e.mem.read(base + i * size, item.data(), size);
            items.push_back(std::move(item));
        }
        uint64_t a_buf = e.heap_alloc(size), b_buf = e.heap_alloc(size);
        std::stable_sort(items.begin(), items.end(),
                         [&](const std::vector<uint8_t>& x, const std::vector<uint8_t>& y) {
                             e.mem.write(a_buf, x.data(), size);
                             e.mem.write(b_buf, y.data(), size);
                             int64_t r = static_cast<int32_t>(
                                 e.call_guest(compare, {context, a_buf, b_buf}));
                             return r < 0;
                         });
        for (uint64_t i = 0; i < count; ++i) e.mem.write(base + i * size, items[i].data(), size);
        e.heap_free(a_buf);
        e.heap_free(b_buf);
        e.set_result(0);
    });
    // ---- CRT: the scanf family ---------------------------------------------
    // (options, input, input size, format, locale, va_list) - the UCRT entry
    // point behind sscanf, and the *_s forms differ only in taking buffer sizes
    // this scanner does not need, since it bounds writes by the field width.
    auto common_vsscanf = [](Emulator& e, bool wide) {
        Args a(e, 0);
        a.next_int(8);                     // options
        uint64_t buffer = a.next_ptr();
        a.next_ptr();                      // input size in characters
        uint64_t fmt = a.next_ptr();
        a.next_ptr();                      // locale
        Args tail = Args::va_list_at(e, a.next_ptr());
        std::string input = wide ? utf16_to_utf8(e, buffer, -1) : e.mem.read_cstring(buffer);
        int n = scan_guest(e, input, fmt, tail, wide);
        if (e.options().trace_calls) {
            std::string f = wide ? utf16_to_utf8(e, fmt, -1) : e.mem.read_cstring(fmt);
            e.log_call("vsscanf(\"%.40s\", \"%.24s\") = %d", input.c_str(), f.c_str(), n);
        }
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(n)));
    };
    ucrt("__stdio_common_vsscanf", [common_vsscanf](Emulator& e) { common_vsscanf(e, false); });
    ucrt("__stdio_common_vswscanf", [common_vsscanf](Emulator& e) { common_vsscanf(e, true); });
    // The classic entry points, for a guest that links them statically.
    auto plain_sscanf = [](Emulator& e, bool wide) {
        Args a(e, 2);
        std::string input = wide ? utf16_to_utf8(e, e.arg_slot(0), -1)
                                 : e.mem.read_cstring(e.arg_slot(0));
        int n = scan_guest(e, input, e.arg_slot(1), a, wide);
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(n)));
    };
    ucrt("sscanf", [plain_sscanf](Emulator& e) { plain_sscanf(e, false); });
    ucrt("swscanf", [plain_sscanf](Emulator& e) { plain_sscanf(e, true); });

    // (options, buffer, buffer size, max count, format, locale, va_list).  The
    // _s form truncates at max_count and, unlike snprintf, reports the truncated
    // length rather than the length it wanted.
    ucrt("__stdio_common_vsnprintf_s", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);                     // options
        uint64_t buf = a.next_ptr();
        uint64_t size = a.next_ptr();
        uint64_t max_count = a.next_ptr();
        uint64_t fmt = a.next_ptr();
        a.next_ptr();                      // locale
        Args tail = Args::va_list_at(e, a.next_ptr());
        std::string s = format_guest(e, fmt, tail);
        uint64_t room = size ? size - 1 : 0;
        if (max_count != ~0ull && max_count < room) room = max_count;
        size_t n = s.size() > room ? static_cast<size_t>(room) : s.size();
        if (buf && size) {
            e.mem.write(buf, s.data(), n);
            e.mem.write8(buf + n, 0);
        }
        e.set_result(n);
    });
}

}  // namespace x86emu
