// Directory enumeration, file metadata, and the registry.
//
// A language runtime spends its startup answering "where are my files?", and it
// asks that question through these: walking directories, stat-ing candidate
// paths, and consulting the registry for an install location.  The registry has
// no equivalent here, so it answers "not present" - which is a real answer that
// every such runtime already handles, because a user install has no registry
// entries either.
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "emulator.h"
#include "guest_printf.h"

namespace x86emu {
namespace {

// File type bits, as the C runtime's struct stat reports them.
constexpr uint32_t kIfDir = 0x4000;
constexpr uint32_t kIfReg = 0x8000;
constexpr uint32_t kIfChr = 0x2000;

uint64_t to_filetime(int64_t unix_seconds) {
    // FILETIME counts 100 ns ticks since 1601.
    return (static_cast<uint64_t>(unix_seconds) + 11644473600ull) * 10000000ull;
}

// Splits "dir\pattern" into its two halves, with "*" and "*.*" meaning everything.
void split_pattern(const std::string& spec, std::string& directory, std::string& pattern) {
    std::string normalised = FileTable::host_path(spec);
    size_t slash = normalised.find_last_of('/');
    if (slash == std::string::npos) {
        directory = ".";
        pattern = normalised;
    } else {
        directory = normalised.substr(0, slash);
        pattern = normalised.substr(slash + 1);
        if (directory.empty()) directory = "/";
    }
    if (pattern.empty()) pattern = "*";
}

// Windows wildcard matching, limited to '*' and '?', which is all a path
// pattern ever uses.
bool matches(const std::string& name, const std::string& pattern) {
    if (pattern == "*" || pattern == "*.*") return true;
    size_t n = 0, p = 0, star = std::string::npos, star_n = 0;
    auto fold = [](char c) { return static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c); };
    while (n < name.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || fold(pattern[p]) == fold(name[n]))) {
            ++n;
            ++p;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            star_n = n;
        } else if (star != std::string::npos) {
            p = star + 1;
            n = ++star_n;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

// Writes a WIN32_FIND_DATA.  The fixed part has no pointers, so it is identical
// in both bitnesses - but the A and W forms differ in the size of the two name
// arrays, and therefore in the size of the whole structure.  Writing the wide
// form into a narrow caller's buffer overruns it by 274 bytes, which on a stack
// buffer means overwriting return addresses.
void write_find_data(Emulator& e, uint64_t out, const Emulator::DirectoryEntry& entry,
                     bool wide) {
    constexpr size_t kFixed = 44;   // attributes, three FILETIMEs, size, reserved
    constexpr size_t kNameChars = 260;
    constexpr size_t kAltChars = 14;
    size_t total = kFixed + (kNameChars + kAltChars) * (wide ? 2 : 1);

    std::vector<uint8_t> zeros(total, 0);
    e.mem.write(out, zeros.data(), zeros.size());
    e.mem.write32(out + 0, entry.is_dir ? 0x10u : 0x80u);
    uint64_t ticks = to_filetime(entry.mtime);
    e.mem.write64(out + 4, ticks);
    e.mem.write64(out + 12, ticks);
    e.mem.write64(out + 20, ticks);
    e.mem.write32(out + 28, static_cast<uint32_t>(entry.size >> 32));
    e.mem.write32(out + 32, static_cast<uint32_t>(entry.size));

    if (wide) {
        std::u16string w = utf8_to_utf16(entry.name);
        if (w.size() >= kNameChars) w.resize(kNameChars - 1);
        for (size_t i = 0; i <= w.size(); ++i)
            e.mem.write16(out + kFixed + i * 2, i < w.size() ? w[i] : 0);
    } else {
        std::string n = entry.name;
        if (n.size() >= kNameChars) n.resize(kNameChars - 1);
        e.mem.write_cstring(out + kFixed, n);
    }
}

}  // namespace

std::vector<Emulator::DirectoryEntry> Emulator::list_directory(const std::string& spec) {
    std::string directory, pattern;
    split_pattern(spec, directory, pattern);

    std::vector<DirectoryEntry> found;
    std::error_code ec;
    // Paths are UTF-8 strings here; going through u8path/u8string keeps the
    // host's ANSI code page out of it.  path::string() is worse than lossy on
    // MSVC - a filename it cannot represent *throws*, and an uncaught throw
    // inside a hook takes the whole emulator down with no message.
    std::filesystem::directory_iterator it(std::filesystem::u8path(directory), ec);
    if (ec) return found;
    for (const auto& item : it) {
        std::string name = item.path().filename().u8string();
        if (!matches(name, pattern)) continue;
        DirectoryEntry entry;
        entry.name = name;
        entry.is_dir = item.is_directory(ec);
        entry.size = entry.is_dir ? 0 : static_cast<uint64_t>(item.file_size(ec));
        if (ec) {
            entry.size = 0;
            ec.clear();
        }
        FileTable::Stat st;
        entry.mtime = FileTable::stat_path(item.path().u8string(), st) == 0 ? st.mtime : 0;
        found.push_back(std::move(entry));
    }
    // A stable order keeps a guest's output reproducible, which the host's
    // directory order does not guarantee.
    std::sort(found.begin(), found.end(),
              [](const DirectoryEntry& a, const DirectoryEntry& b) { return a.name < b.name; });
    return found;
}

void Emulator::install_win32_fs_hooks() {
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, is64() ? 0 : nargs * 4, std::move(fn));
    };
    auto ucrt = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };

    // ---- directory enumeration ------------------------------------------------
    auto find_first = [](Emulator& e, bool wide) {
        std::string spec = wide ? utf16_to_utf8(e, e.arg_slot(0), -1)
                                : e.mem.read_cstring(e.arg_slot(0));
        auto entries = e.list_directory(spec);
        e.log_call("FindFirstFile(%s) = %zu entries", spec.c_str(), entries.size());
        if (entries.empty()) {
            e.set_last_error(2);  // ERROR_FILE_NOT_FOUND
            e.set_result(~0ull);  // INVALID_HANDLE_VALUE
            return;
        }
        uint64_t handle = e.open_find_handle(std::move(entries));
        write_find_data(e, e.arg_slot(1), *e.find_current(handle), wide);
        e.set_result(handle);
    };
    win32("FindFirstFileW", 2, [find_first](Emulator& e) { find_first(e, true); });
    win32("FindFirstFileA", 2, [find_first](Emulator& e) { find_first(e, false); });
    win32("FindFirstFileExW", 6, [](Emulator& e) {
        // (name, info level, out, search op, filter, flags) - the extra arguments
        // only select detail levels this does not distinguish.
        std::string spec = utf16_to_utf8(e, e.arg_slot(0), -1);
        auto entries = e.list_directory(spec);
        if (entries.empty()) {
            e.set_last_error(2);
            e.set_result(~0ull);
            return;
        }
        uint64_t handle = e.open_find_handle(std::move(entries));
        write_find_data(e, e.arg_slot(2), *e.find_current(handle), true);
        e.set_result(handle);
    });
    win32("FindNextFileW", 2, [](Emulator& e) {
        if (!e.find_advance(e.arg_slot(0))) {
            e.set_last_error(18);  // ERROR_NO_MORE_FILES
            e.set_result(0);
            return;
        }
        const auto* entry = e.find_current(e.arg_slot(0));
        e.log_call("FindNextFileW -> %s", entry->name.c_str());
        write_find_data(e, e.arg_slot(1), *entry, true);
        e.set_result(1);
    });
    win32("FindNextFileA", 2, [](Emulator& e) {
        if (!e.find_advance(e.arg_slot(0))) {
            e.set_last_error(18);
            e.set_result(0);
            return;
        }
        write_find_data(e, e.arg_slot(1), *e.find_current(e.arg_slot(0)), false);
        e.set_result(1);
    });
    win32("FindClose", 1, [](Emulator& e) {
        e.close_find_handle(e.arg_slot(0));
        e.set_result(1);
    });

    // ---- stat, in the CRT's several shapes -------------------------------------
    // struct _stat64 and _stat64i32 differ only in the width of st_size, and the
    // fields before it are laid out the same way in both.
    auto write_stat_struct = [](Emulator& e, uint64_t out, const FileTable::Stat& st,
                                bool size_is_64) {
        std::vector<uint8_t> zeros(size_is_64 ? 56 : 48, 0);
        e.mem.write(out, zeros.data(), zeros.size());
        uint32_t mode = (st.is_dir ? kIfDir : st.is_char_device ? kIfChr : kIfReg) | 0666u;
        e.mem.write32(out + 0, 0);                                  // st_dev
        e.mem.write16(out + 4, 0);                                  // st_ino
        e.mem.write16(out + 6, static_cast<uint16_t>(mode));        // st_mode
        e.mem.write16(out + 8, 1);                                  // st_nlink
        if (size_is_64) {
            e.mem.write64(out + 24, st.size);
            e.mem.write64(out + 32, to_filetime(st.mtime) / 10000000ull - 11644473600ull);
            e.mem.write64(out + 40, static_cast<uint64_t>(st.mtime));
            e.mem.write64(out + 48, static_cast<uint64_t>(st.mtime));
        } else {
            e.mem.write32(out + 20, static_cast<uint32_t>(st.size));
            e.mem.write64(out + 24, static_cast<uint64_t>(st.mtime));
            e.mem.write64(out + 32, static_cast<uint64_t>(st.mtime));
            e.mem.write64(out + 40, static_cast<uint64_t>(st.mtime));
        }
    };
    auto stat_by_path = [write_stat_struct](Emulator& e, bool wide, bool size_is_64) {
        std::string path = wide ? utf16_to_utf8(e, e.arg_slot(0), -1)
                                : e.mem.read_cstring(e.arg_slot(0));
        FileTable::Stat st;
        int r = FileTable::stat_path(path, st);
        // Logging the path is what makes "why can it not find its files?" a
        // question with an answer.
        e.log_call("stat(%s) = %d", path.c_str(), r);
        e.report_file_error(r);
        if (r != 0) {
            e.set_result(static_cast<uint64_t>(static_cast<int64_t>(-1)));
            return;
        }
        write_stat_struct(e, e.arg_slot(1), st, size_is_64);
        e.set_result(0);
    };
    ucrt("_wstat64i32", [stat_by_path](Emulator& e) { stat_by_path(e, true, false); });
    ucrt("_wstat32", [stat_by_path](Emulator& e) { stat_by_path(e, true, false); });
    ucrt("_wstat64", [stat_by_path](Emulator& e) { stat_by_path(e, true, true); });
    ucrt("_stat64i32", [stat_by_path](Emulator& e) { stat_by_path(e, false, false); });
    ucrt("_stat64", [stat_by_path](Emulator& e) { stat_by_path(e, false, true); });
    ucrt("_stat32", [stat_by_path](Emulator& e) { stat_by_path(e, false, false); });
    auto fstat_by_fd = [write_stat_struct](Emulator& e, bool size_is_64) {
        FileTable::Stat st;
        if (e.files.stat_fd(static_cast<int>(e.arg_slot(0)), st) != 0) {
            e.set_result(static_cast<uint64_t>(static_cast<int64_t>(-1)));
            return;
        }
        write_stat_struct(e, e.arg_slot(1), st, size_is_64);
        e.set_result(0);
    };
    ucrt("_fstat64i32", [fstat_by_fd](Emulator& e) { fstat_by_fd(e, false); });
    ucrt("_fstat32", [fstat_by_fd](Emulator& e) { fstat_by_fd(e, false); });
    ucrt("_fstat64", [fstat_by_fd](Emulator& e) { fstat_by_fd(e, true); });

    // ---- file information by handle -------------------------------------------
    win32("GetFileInformationByHandle", 2, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        FileTable::Stat st;
        if (fd < 0 || e.files.stat_fd(fd, st) != 0) {
            e.set_result(0);
            return;
        }
        // BY_HANDLE_FILE_INFORMATION: attributes, three FILETIMEs, volume serial,
        // size high/low, link count, then the file index.
        uint64_t out = e.arg_slot(1);
        std::vector<uint8_t> zeros(52, 0);
        e.mem.write(out, zeros.data(), zeros.size());
        uint64_t ticks = to_filetime(st.mtime);
        e.mem.write32(out + 0, st.is_dir ? 0x10u : 0x80u);
        e.mem.write64(out + 4, ticks);
        e.mem.write64(out + 12, ticks);
        e.mem.write64(out + 20, ticks);
        e.mem.write32(out + 28, 0x1234);  // volume serial number
        e.mem.write32(out + 32, static_cast<uint32_t>(st.size >> 32));
        e.mem.write32(out + 36, static_cast<uint32_t>(st.size));
        e.mem.write32(out + 40, 1);       // number of links
        e.set_result(1);
    });
    // (handle, volume name buf+size, serial*, max component*, fs flags*, fs
    // name buf+size).  cl 14.31's c1 asks about the volume its source file
    // lives on; the serial matches GetFileInformationByHandle's, because a
    // caller may correlate the two.
    win32("GetVolumeInformationByHandleW", 8, [](Emulator& e) {
        uint64_t vol_name = e.arg_slot(1), vol_len = e.arg_slot(2);
        uint64_t serial = e.arg_slot(3), max_comp = e.arg_slot(4);
        uint64_t flags = e.arg_slot(5), fs_name = e.arg_slot(6), fs_len = e.arg_slot(7);
        if (vol_name && vol_len) e.mem.write16(vol_name, 0);
        if (serial) e.mem.write32(serial, 0x1234);
        if (max_comp) e.mem.write32(max_comp, 255);
        if (flags) e.mem.write32(flags, 0x03E700FF);  // what NTFS reports
        if (fs_name && fs_len >= 5)
            for (int i = 0; i < 5; ++i) e.mem.write16(fs_name + i * 2, "NTFS"[i]);
        e.set_result(1);
    });
    // The by-path sibling: (root path, volume name buf+size, serial*, max
    // component*, fs flags*, fs name buf+size).
    win32("GetVolumeInformationW", 8, [](Emulator& e) {
        uint64_t vol_name = e.arg_slot(1), vol_len = e.arg_slot(2);
        uint64_t serial = e.arg_slot(3), max_comp = e.arg_slot(4);
        uint64_t flags = e.arg_slot(5), fs_name = e.arg_slot(6), fs_len = e.arg_slot(7);
        if (vol_name && vol_len) e.mem.write16(vol_name, 0);
        if (serial) e.mem.write32(serial, 0x1234);
        if (max_comp) e.mem.write32(max_comp, 255);
        if (flags) e.mem.write32(flags, 0x03E700FF);
        if (fs_name && fs_len >= 5)
            for (int i = 0; i < 5; ++i) e.mem.write16(fs_name + i * 2, "NTFS"[i]);
        e.set_result(1);
    });
    // (handle, information class, buffer, size).  CPython's os.stat needs the
    // attribute-tag class in particular: it opens the path, asks for the basic
    // information, and then asks whether it is a reparse point.
    win32("GetFileInformationByHandleEx", 4, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        uint32_t info_class = static_cast<uint32_t>(e.arg_slot(1));
        uint64_t out = e.arg_slot(2);
        FileTable::Stat st;
        if (fd < 0 || !out || e.files.stat_fd(fd, st) != 0) {
            e.set_last_error(6);  // ERROR_INVALID_HANDLE
            e.set_result(0);
            return;
        }
        uint64_t ticks = to_filetime(st.mtime);
        uint32_t attributes = st.is_dir ? 0x10u : 0x80u;
        switch (info_class) {
            case 0: {  // FileBasicInfo: four times then the attributes
                std::vector<uint8_t> zeros(40, 0);
                e.mem.write(out, zeros.data(), zeros.size());
                e.mem.write64(out + 0, ticks);
                e.mem.write64(out + 8, ticks);
                e.mem.write64(out + 16, ticks);
                e.mem.write64(out + 24, ticks);
                e.mem.write32(out + 32, attributes);
                break;
            }
            case 1: {  // FileStandardInfo
                std::vector<uint8_t> zeros(24, 0);
                e.mem.write(out, zeros.data(), zeros.size());
                e.mem.write64(out + 0, (st.size + 4095) & ~4095ull);  // allocation size
                e.mem.write64(out + 8, st.size);                      // end of file
                e.mem.write32(out + 16, 1);                           // link count
                e.mem.write8(out + 20, 0);                            // delete pending
                e.mem.write8(out + 21, st.is_dir ? 1 : 0);
                break;
            }
            case 9: {  // FileAttributeTagInfo: attributes and the reparse tag
                e.mem.write32(out + 0, attributes);
                e.mem.write32(out + 4, 0);  // not a reparse point
                break;
            }
            case 18: {  // FileIdInfo: a volume serial and a 128-bit file id
                // The id must be *distinct per file*: cl 14.31's include cache
                // keys directories by it, and an all-zero id made every include
                // directory the same directory - reported as "cannot open
                // stdio.h" with the path plainly correct.  st.ino is the same
                // stable per-path hash the Linux side hands musl's ld.so.
                std::vector<uint8_t> zeros(24, 0);
                e.mem.write(out, zeros.data(), zeros.size());
                e.mem.write64(out + 0, 0x1234);
                e.mem.write64(out + 8, st.ino);
                break;
            }
            default:
                e.set_last_error(87);  // ERROR_INVALID_PARAMETER
                e.set_result(0);
                return;
        }
        e.set_result(1);
    });
    win32("SetFileInformationByHandle", 4, [](Emulator& e) { e.set_result(1); });
    win32("SetFileTime", 4, [](Emulator& e) { e.set_result(1); });
    win32("GetFinalPathNameByHandleW", 4, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        auto* entry = fd >= 0 ? e.files.get(fd) : nullptr;
        if (!entry) {
            e.set_result(0);
            return;
        }
        std::u16string w = utf8_to_utf16(entry->path);
        uint64_t buf = e.arg_slot(1), size = e.arg_slot(2);
        if (!buf || w.size() + 1 > size) {
            e.set_result(w.size() + 1);
            return;
        }
        for (size_t i = 0; i <= w.size(); ++i)
            e.mem.write16(buf + i * 2, i < w.size() ? w[i] : 0);
        e.set_result(w.size());
    });
    win32("GetLongPathNameW", 3, [](Emulator& e) {
        // No short names exist here, so the input is already the long form.
        std::u16string w = utf8_to_utf16(utf16_to_utf8(e, e.arg_slot(0), -1));
        uint64_t buf = e.arg_slot(1), size = e.arg_slot(2);
        if (!buf || w.size() + 1 > size) {
            e.set_result(w.size() + 1);
            return;
        }
        for (size_t i = 0; i <= w.size(); ++i)
            e.mem.write16(buf + i * 2, i < w.size() ? w[i] : 0);
        e.set_result(w.size());
    });
    win32("GetShortPathNameW", 3, [](Emulator& e) { e.set_result(0); });
    win32("GetTempPathW", 2, [](Emulator& e) {
        const std::string* tmp = e.getenv("TEMP");
        std::string path = tmp ? *tmp : std::string(".");
        if (!path.empty() && path.back() != '\\' && path.back() != '/') path += '\\';
        std::u16string w = utf8_to_utf16(path);
        uint64_t size = e.arg_slot(0), buf = e.arg_slot(1);
        if (!buf || w.size() + 1 > size) {
            e.set_result(w.size() + 1);
            return;
        }
        for (size_t i = 0; i <= w.size(); ++i)
            e.mem.write16(buf + i * 2, i < w.size() ? w[i] : 0);
        e.set_result(w.size());
    });

    // ---- the registry ----------------------------------------------------------
    // There is no registry, and saying so is a real answer: a runtime installed
    // without one has to cope, and every one of them does.
    constexpr uint64_t kFileNotFound = 2;
    for (const char* name : {"RegOpenKeyExW", "RegOpenKeyExA", "RegCreateKeyW",
                             "RegCreateKeyExW", "RegQueryValueExW", "RegQueryValueExA",
                             "RegQueryInfoKeyW", "RegEnumKeyExW", "RegEnumValueW",
                             "RegSetValueExW", "RegDeleteKeyW", "RegDeleteKeyExW",
                             "RegDeleteValueW", "RegConnectRegistryW", "RegLoadKeyW",
                             "RegSaveKeyW"}) {
        // The number of arguments differs, but the 32-bit stdcall cleanup only
        // matters for a function that returns; six covers the widest of these and
        // the guest's own thunk fixes the stack either way.
        add_hook(name, 0, [kFileNotFound](Emulator& e) { e.set_result(kFileNotFound); });
    }
    add_hook("RegCloseKey", 0, [](Emulator& e) { e.set_result(0); });
    add_hook("RegFlushKey", 0, [](Emulator& e) { e.set_result(0); });
    add_hook("LsaNtStatusToWinError", 0, [](Emulator& e) { e.set_result(0); });
}

}  // namespace x86emu
