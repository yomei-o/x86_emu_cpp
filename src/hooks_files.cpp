// File I/O, in all three spellings a guest might use.
//
// The C stdio layer (fopen/fread), the POSIX layer (open/read, which msvcrt
// exports with underscores) and the Win32 layer (CreateFile/ReadFile) are three
// interfaces onto the same operations, so all of them are thin translations over
// FileTable.  The Linux syscalls in syscalls.cpp are the fourth.
#include <cstring>
#include <string>
#include <vector>

#include "emulator.h"
#include "guest_printf.h"

namespace x86emu {
namespace {

// Turns a C stdio mode string into the emulator's flags.
FileTable::OpenFlags parse_mode(const std::string& mode) {
    FileTable::OpenFlags f;
    f.binary = mode.find('b') != std::string::npos;
    bool plus = mode.find('+') != std::string::npos;
    char base = mode.empty() ? 'r' : mode[0];
    switch (base) {
        case 'w':
            f.write = true;
            f.create = true;
            f.truncate = true;
            f.read = plus;
            break;
        case 'a':
            f.write = true;
            f.create = true;
            f.append = true;
            f.read = plus;
            break;
        default:  // 'r'
            f.read = true;
            f.write = plus;
            break;
    }
    return f;
}

// Reads a guest buffer into a std::string.
std::string read_bytes(Emulator& e, uint64_t addr, uint64_t len) {
    std::string data(static_cast<size_t>(len), '\0');
    if (len) e.mem.read(addr, data.data(), len);
    return data;
}

// A negative FileTable result is an errno-style code; Win32 wants a boolean plus
// GetLastError, so translate as we go.
uint64_t win32_error_for(int64_t code) {
    switch (code) {
        case -2: return 2;    // ERROR_FILE_NOT_FOUND
        case -13: return 5;   // ERROR_ACCESS_DENIED
        case -17: return 80;  // ERROR_FILE_EXISTS
        case -9: return 6;    // ERROR_INVALID_HANDLE
        default: return 87;   // ERROR_INVALID_PARAMETER
    }
}

}  // namespace

void Emulator::install_file_hooks() {
    auto libc = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };
    // The same implementation under both the plain and the msvcrt underscore name.
    auto libc2 = [&](const char* name, std::function<void(Emulator&)> fn) {
        libc(name, fn);
        libc(("_" + std::string(name)).c_str(), fn);
    };
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, is64() ? 0 : nargs * 4, std::move(fn));
    };

    // ---- C stdio -------------------------------------------------------------
    libc("fopen", [](Emulator& e) {
        std::string path = e.mem.read_cstring(e.arg_slot(0));
        std::string mode = e.mem.read_cstring(e.arg_slot(1));
        int fd = e.files.open(path, parse_mode(mode));
        e.log_call("fopen(%s, %s) = %d", path.c_str(), mode.c_str(), fd);
        e.report_file_error(fd);
        e.set_result(fd < 0 ? 0 : e.guest_file(fd));
    });
    libc("fopen_s", [](Emulator& e) {
        // (FILE** out, path, mode) -> 0 on success
        uint64_t out = e.arg_slot(0);
        std::string path = e.mem.read_cstring(e.arg_slot(1));
        std::string mode = e.mem.read_cstring(e.arg_slot(2));
        int fd = e.files.open(path, parse_mode(mode));
        e.report_file_error(fd);
        if (out) e.mem.write_sized(out, e.pointer_size(), fd < 0 ? 0 : e.guest_file(fd));
        e.set_result(fd < 0 ? 22 : 0);
    });
    libc("freopen", [](Emulator& e) {
        std::string path = e.mem.read_cstring(e.arg_slot(0));
        std::string mode = e.mem.read_cstring(e.arg_slot(1));
        int old = e.host_fd(e.arg_slot(2));
        if (old >= 3) e.files.close(old);
        int fd = e.files.open(path, parse_mode(mode));
        e.report_file_error(fd);
        e.set_result(fd < 0 ? 0 : e.guest_file(fd));
    });
    libc("fclose", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        e.set_result(fd < 0 ? 0xFFFFFFFFull : static_cast<uint64_t>(e.files.close(fd) == 0 ? 0 : -1));
    });
    // fread, and the "_nolock" form a caller uses when it already holds the
    // stream's lock: the same function while one guest thread runs at a time.
    auto do_fread = [](Emulator& e) {
        uint64_t buf = e.arg_slot(0), size = e.arg_slot(1), count = e.arg_slot(2);
        int fd = e.host_fd(e.arg_slot(3));
        uint64_t total = size * count;
        if (fd < 0 || total == 0) {
            e.set_result(0);
            return;
        }
        std::vector<uint8_t> tmp(static_cast<size_t>(total));
        int64_t got = e.files.read(fd, tmp.data(), total);
        if (got > 0) e.mem.write(buf, tmp.data(), static_cast<uint64_t>(got));
        // fread reports whole items, not bytes.
        e.set_result(got <= 0 || size == 0 ? 0 : static_cast<uint64_t>(got) / size);
    };
    libc("fread", do_fread);
    libc("_fread_nolock", do_fread);
    // fread_s takes the destination's size as its second argument and shifts the
    // rest along; the bound is what it adds, and reading less is always safe.
    libc("fread_s", [do_fread](Emulator& e) {
        uint64_t buf = e.arg_slot(0), capacity = e.arg_slot(1);
        uint64_t size = e.arg_slot(2), count = e.arg_slot(3);
        int fd = e.host_fd(e.arg_slot(4));
        uint64_t total = size * count;
        if (total > capacity) total = capacity;
        if (fd < 0 || total == 0) {
            e.set_result(0);
            return;
        }
        std::vector<uint8_t> tmp(static_cast<size_t>(total));
        int64_t got = e.files.read(fd, tmp.data(), total);
        if (got > 0) e.mem.write(buf, tmp.data(), static_cast<uint64_t>(got));
        e.set_result(got <= 0 || size == 0 ? 0 : static_cast<uint64_t>(got) / size);
    });
    libc("fgetc", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        uint8_t c = 0;
        int64_t got = fd < 0 ? -1 : e.files.read(fd, &c, 1);
        e.set_result(got == 1 ? c : 0xFFFFFFFFull);  // EOF
    });
    libc("getc", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        uint8_t c = 0;
        int64_t got = fd < 0 ? -1 : e.files.read(fd, &c, 1);
        e.set_result(got == 1 ? c : 0xFFFFFFFFull);
    });
    libc("getchar", [](Emulator& e) {
        uint8_t c = 0;
        e.set_result(e.files.read(0, &c, 1) == 1 ? c : 0xFFFFFFFFull);
    });
    libc("fgets", [](Emulator& e) {
        uint64_t buf = e.arg_slot(0);
        int64_t n = static_cast<int32_t>(e.arg_slot(1));
        int fd = e.host_fd(e.arg_slot(2));
        if (fd < 0 || n <= 1) {
            e.set_result(0);
            return;
        }
        // One byte at a time: stopping after the newline is the whole contract,
        // and a buffered read would consume past it.
        std::string line;
        while (static_cast<int64_t>(line.size()) < n - 1) {
            uint8_t c;
            if (e.files.read(fd, &c, 1) != 1) break;
            line += static_cast<char>(c);
            if (c == '\n') break;
        }
        if (line.empty()) {
            e.set_result(0);
            return;
        }
        e.mem.write_cstring(buf, line);
        e.set_result(buf);
    });
    libc("ungetc", [](Emulator& e) {
        // Pushing a byte back is a one-character seek backwards, which is enough
        // for the usual "peek then put it back" pattern.
        int fd = e.host_fd(e.arg_slot(1));
        if (fd >= 0) e.files.seek(fd, -1, 1);
        e.set_result(e.arg_slot(0));
    });
    libc("fseek", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        int64_t off = static_cast<int32_t>(e.arg_slot(1));
        int whence = static_cast<int>(e.arg_slot(2));
        int64_t r = fd < 0 ? -1 : e.files.seek(fd, off, whence);
        e.set_result(r < 0 ? 0xFFFFFFFFull : 0);
    });
    libc("_fseeki64", [](Emulator& e) {
        Args a(e);
        int fd = e.host_fd(a.next_ptr());
        int64_t off = static_cast<int64_t>(a.next_int(8));
        int whence = static_cast<int>(a.next_int(4));
        int64_t r = fd < 0 ? -1 : e.files.seek(fd, off, whence);
        e.set_result(r < 0 ? 0xFFFFFFFFull : 0);
    });
    libc("ftell", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        int64_t r = fd < 0 ? -1 : e.files.tell(fd);
        e.set_result(static_cast<uint64_t>(r));
    });
    libc("_ftelli64", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        int64_t r = fd < 0 ? -1 : e.files.tell(fd);
        e.set_result(static_cast<uint64_t>(r));
    });
    libc("rewind", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        if (fd >= 0) e.files.seek(fd, 0, 0);
        e.set_result(0);
    });
    libc("feof", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(0));
        e.set_result(fd >= 0 && e.files.eof(fd) ? 1 : 0);
    });
    libc("ferror", [](Emulator& e) { e.set_result(0); });
    libc("clearerr", [](Emulator& e) { e.set_result(0); });
    libc("setvbuf", [](Emulator& e) { e.set_result(0); });
    libc("setbuf", [](Emulator& e) { e.set_result(0); });
    libc("remove", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(
            FileTable::remove_file(e.mem.read_cstring(e.arg_slot(0))) == 0 ? 0 : -1));
    });
    libc("rename", [](Emulator& e) {
        std::string from = e.mem.read_cstring(e.arg_slot(0));
        std::string to = e.mem.read_cstring(e.arg_slot(1));
        e.set_result(static_cast<uint64_t>(FileTable::rename_file(from, to) == 0 ? 0 : -1));
    });

    // ---- POSIX-style descriptors (msvcrt spells these with an underscore) -----
    libc2("open", [](Emulator& e) {
        std::string path = e.mem.read_cstring(e.arg_slot(0));
        uint32_t flags = static_cast<uint32_t>(e.arg_slot(1));
        // msvcrt uses its own O_ constants: 0x0100 O_CREAT, 0x0200 O_TRUNC,
        // 0x0008 O_APPEND, 0x0400 O_EXCL, 0x8000 O_BINARY.
        FileTable::OpenFlags f;
        switch (flags & 3) {
            case 1: f.write = true; break;
            case 2: f.read = f.write = true; break;
            default: f.read = true; break;
        }
        f.create = (flags & 0x0100) != 0;
        f.truncate = (flags & 0x0200) != 0;
        f.append = (flags & 0x0008) != 0;
        f.exclusive = (flags & 0x0400) != 0;
        f.binary = true;
        int fd = e.files.open(path, f);
        e.report_file_error(fd);
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(fd < 0 ? -1 : fd)));
    });
    libc2("close", [](Emulator& e) {
        int fd = static_cast<int>(e.arg_slot(0));
        e.set_result(static_cast<uint64_t>(e.files.close(fd) == 0 ? 0 : -1));
    });
    libc2("read", [](Emulator& e) {
        int fd = static_cast<int>(e.arg_slot(0));
        uint64_t buf = e.arg_slot(1), len = e.arg_slot(2);
        std::vector<uint8_t> tmp(static_cast<size_t>(len));
        int64_t got = len ? e.files.read(fd, tmp.data(), len) : 0;
        if (got > 0) e.mem.write(buf, tmp.data(), static_cast<uint64_t>(got));
        e.set_result(static_cast<uint64_t>(got < 0 ? -1 : got));
    });
    libc2("write", [](Emulator& e) {
        int fd = static_cast<int>(e.arg_slot(0));
        std::string data = read_bytes(e, e.arg_slot(1), e.arg_slot(2));
        int64_t put;
        if (fd == 1 || fd == 2) {
            // The standard streams go through the emulator's own output path so
            // that a front end can capture them.
            e.write_raw(fd, data.data(), data.size());
            put = static_cast<int64_t>(data.size());
        } else {
            put = e.files.write(fd, data.data(), data.size());
        }
        e.set_result(static_cast<uint64_t>(put < 0 ? -1 : put));
    });
    libc2("lseek", [](Emulator& e) {
        int fd = static_cast<int>(e.arg_slot(0));
        int64_t off = static_cast<int32_t>(e.arg_slot(1));
        int64_t r = e.files.seek(fd, off, static_cast<int>(e.arg_slot(2)));
        e.set_result(static_cast<uint64_t>(r));
    });
    libc("_lseeki64", [](Emulator& e) {
        Args a(e);
        int fd = static_cast<int>(a.next_int(4));
        int64_t off = static_cast<int64_t>(a.next_int(8));
        int64_t r = e.files.seek(fd, off, static_cast<int>(a.next_int(4)));
        e.set_result(static_cast<uint64_t>(r));
    });
    libc2("dup", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(e.files.dup(static_cast<int>(e.arg_slot(0)))));
    });
    libc2("dup2", [](Emulator& e) {
        int r = e.files.dup(static_cast<int>(e.arg_slot(0)), static_cast<int>(e.arg_slot(1)));
        e.set_result(static_cast<uint64_t>(r));
    });
    libc2("isatty", [](Emulator& e) {
        auto* entry = e.files.get(static_cast<int>(e.arg_slot(0)));
        e.set_result(entry && entry->is_tty ? 1 : 0);
    });
    libc2("unlink", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(
            FileTable::remove_file(e.mem.read_cstring(e.arg_slot(0))) == 0 ? 0 : -1));
    });
    libc2("fileno", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(e.host_fd(e.arg_slot(0))));
    });
    libc2("access", [](Emulator& e) {
        FileTable::Stat st;
        int r = FileTable::stat_path(e.mem.read_cstring(e.arg_slot(0)), st);
        e.set_result(static_cast<uint64_t>(r == 0 ? 0 : -1));
    });

    // ---- Win32 ---------------------------------------------------------------
    auto create_file = [](Emulator& e, bool wide) {
        std::string path = wide ? utf16_to_utf8(e, e.arg_slot(0), -1)
                                : e.mem.read_cstring(e.arg_slot(0));
        uint32_t access = static_cast<uint32_t>(e.arg_slot(1));
        uint32_t disposition = static_cast<uint32_t>(e.arg_slot(4));

        // Windows lets a program open a *directory* to ask about its attributes,
        // which is how os.stat works there.  No C library can do that, so such a
        // handle names the path without holding a stream.
        //
        // What decides this is whether the path *is* a directory, not whether the
        // caller passed FILE_FLAG_BACKUP_SEMANTICS: a stat implementation passes
        // that flag for every path it looks at, files included, precisely so the
        // one code path covers both.
        FileTable::Stat probe;
        bool is_directory = FileTable::stat_path(path, probe) == 0 && probe.is_dir;
        if (is_directory) {
            int dir_fd = e.files.open_directory(path);
            if (dir_fd < 0) {
                e.report_file_error(dir_fd);
                e.set_last_error(win32_error_for(dir_fd));
                e.set_result(~0ull);
            } else {
                e.set_result(Emulator::handle_from_fd(dir_fd));
            }
            return;
        }

        FileTable::OpenFlags f;
        // CreateFile has no text mode: the CRT's "t" translation happens a layer
        // above, in _open_osfhandle and the FILE* it wraps.  Leaving this unset
        // meant every binary file a Windows guest opened through the Win32 API
        // lost a byte per CRLF, silently and only in the middle of large ones -
        // link.exe reported LIBCMT.lib as a corrupt library, which is exactly
        // what a static library with bytes missing from the middle is.
        f.binary = true;
        f.read = (access & 0x80000000u) != 0;   // GENERIC_READ
        f.write = (access & 0x40000000u) != 0;  // GENERIC_WRITE
        // FILE_READ_ATTRIBUTES on its own is how a metadata-only open looks.
        if (!f.read && !f.write) f.read = true;
        switch (disposition) {
            case 1: f.create = true; f.exclusive = true; break;  // CREATE_NEW
            case 2: f.create = true; f.truncate = true; break;    // CREATE_ALWAYS
            case 3: break;                                        // OPEN_EXISTING
            case 4: f.create = true; break;                       // OPEN_ALWAYS
            case 5: f.truncate = true; break;                     // TRUNCATE_EXISTING
            default: break;
        }
        int fd = e.files.open(path, f);
        if (fd < 0) {
            e.report_file_error(fd);
            e.set_last_error(win32_error_for(fd));
            e.set_result(~0ull);  // INVALID_HANDLE_VALUE
        } else {
            e.set_result(Emulator::handle_from_fd(fd));
        }
    };
    win32("CreateFileA", 7, [create_file](Emulator& e) { create_file(e, false); });
    win32("CreateFileW", 7, [create_file](Emulator& e) { create_file(e, true); });
    win32("CloseHandle", 1, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        if (fd >= 3) e.files.close(fd);
        e.set_result(1);
    });
    win32("ReadFile", 5, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        uint64_t buf = e.arg_slot(1), len = e.arg_slot(2), read_ptr = e.arg_slot(3);
        std::vector<uint8_t> tmp(static_cast<size_t>(len));
        int64_t got = (fd >= 0 && len) ? e.files.read(fd, tmp.data(), len) : 0;
        if (got == kEAGAINPipe) {
            // An empty pipe with a live writer: block this thread and run the
            // whole call again once bytes (or end-of-file) arrive.
            auto end = e.files.get(fd)->pipe_end;
            e.block_hook_retry([end] {
                return !end->pipe->buffer.empty() || end->pipe->writers <= 0;
            });
            return;
        }
        if (got > 0) e.mem.write(buf, tmp.data(), static_cast<uint64_t>(got));
        if (read_ptr) e.mem.write32(read_ptr, static_cast<uint32_t>(got > 0 ? got : 0));
        if (got == 0 && e.files.get(fd) && e.files.get(fd)->is_pipe())
            e.set_last_error(109);  // ERROR_BROKEN_PIPE: how Windows spells pipe EOF
        e.set_result(got < 0 ? 0 : (got == 0 && e.files.get(fd) && e.files.get(fd)->is_pipe()) ? 0 : 1);
    });
    win32("WriteFile", 5, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        uint64_t buf = e.arg_slot(1), len = e.arg_slot(2), written_ptr = e.arg_slot(3);
        std::string data = read_bytes(e, buf, len);
        int64_t put;
        if (fd == 1 || fd == 2) {
            // WriteFile is a raw byte channel even on Windows: no text translation.
            e.write_raw(fd, data.data(), data.size());
            put = static_cast<int64_t>(data.size());
        } else {
            put = fd >= 0 ? e.files.write(fd, data.data(), data.size()) : -1;
        }
        if (written_ptr) e.mem.write32(written_ptr, static_cast<uint32_t>(put > 0 ? put : 0));
        e.set_result(put < 0 ? 0 : 1);
    });
    win32("SetFilePointerEx", 5, [](Emulator& e) {
        Args a(e);
        int fd = Emulator::fd_from_handle(a.next_ptr());
        int64_t distance = static_cast<int64_t>(a.next_int(8));
        uint64_t new_ptr = a.next_ptr();
        int method = static_cast<int>(a.next_int(4));
        int64_t r = fd >= 0 ? e.files.seek(fd, distance, method) : -1;
        if (r >= 0 && new_ptr) e.mem.write64(new_ptr, static_cast<uint64_t>(r));
        e.set_result(r < 0 ? 0 : 1);
    });
    win32("GetFileSizeEx", 2, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        int64_t size = fd >= 0 ? e.files.size(fd) : -1;
        if (size >= 0 && e.arg_slot(1)) e.mem.write64(e.arg_slot(1), static_cast<uint64_t>(size));
        e.set_result(size < 0 ? 0 : 1);
    });
    win32("FlushFileBuffers", 1, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        if (fd >= 0) e.files.flush(fd);
        e.set_result(1);
    });
    win32("GetStdHandle", 1, [](Emulator& e) {
        // STD_INPUT/OUTPUT/ERROR_HANDLE are -10/-11/-12.
        int32_t which = static_cast<int32_t>(e.arg_slot(0));
        int fd = which == -10 ? 0 : which == -11 ? 1 : which == -12 ? 2 : -1;
        e.set_result(fd < 0 ? ~0ull : Emulator::handle_from_fd(fd));
    });
    win32("GetFileType", 1, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        auto* entry = fd >= 0 ? e.files.get(fd) : nullptr;
        if (!entry) {
            e.set_result(0);  // FILE_TYPE_UNKNOWN
            return;
        }
        // A redirected standard stream really is a disk file, which is what a
        // guest choosing its buffering strategy needs to know.
        e.set_result(entry->is_pipe() ? 3u /* FILE_TYPE_PIPE */
                     : entry->is_tty ? 2u /* FILE_TYPE_CHAR */
                                     : 1u /* FILE_TYPE_DISK */);
    });
    auto delete_file = [](Emulator& e, bool wide) {
        std::string path = wide ? utf16_to_utf8(e, e.arg_slot(0), -1)
                                : e.mem.read_cstring(e.arg_slot(0));
        int r = FileTable::remove_file(path);
        if (r != 0) e.set_last_error(win32_error_for(r));
        e.set_result(r == 0 ? 1 : 0);
    };
    win32("DeleteFileA", 1, [delete_file](Emulator& e) { delete_file(e, false); });
    win32("DeleteFileW", 1, [delete_file](Emulator& e) { delete_file(e, true); });
    auto file_attributes = [](Emulator& e, bool wide) {
        std::string path = wide ? utf16_to_utf8(e, e.arg_slot(0), -1)
                                : e.mem.read_cstring(e.arg_slot(0));
        FileTable::Stat st;
        if (FileTable::stat_path(path, st) != 0) {
            e.set_last_error(2);
            e.set_result(0xFFFFFFFFull);  // INVALID_FILE_ATTRIBUTES
            return;
        }
        e.set_result(st.is_dir ? 0x10u /* DIRECTORY */ : 0x80u /* NORMAL */);
    };
    win32("GetFileAttributesA", 1, [file_attributes](Emulator& e) { file_attributes(e, false); });
    win32("GetFileAttributesW", 1, [file_attributes](Emulator& e) { file_attributes(e, true); });

    // Every stdio function the CRT also ships in a "_nolock" form, which a
    // caller uses when it already holds the stream's lock.  With one guest
    // thread running at a time the lock is the only difference, so the two are
    // the same implementation under two names - said once here rather than
    // duplicated at each definition.
    for (const char* name : {"fread", "fwrite", "fflush", "fclose", "fgetc", "fputc",
                             "fgets", "fputs", "fseek", "ftell", "ungetc", "getc",
                             "putc", "fgetwc", "fputwc", "rewind", "_fseeki64",
                             "_ftelli64", "fsetpos", "fgetpos"}) {
        alias_hook(name, "_" + std::string(name) + "_nolock");
        if (name[0] == '_') alias_hook(name, std::string(name) + "_nolock");
    }
}

}  // namespace x86emu
