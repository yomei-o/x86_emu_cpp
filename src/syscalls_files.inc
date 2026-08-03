// File-related Linux syscalls, included by syscalls.cpp.
//
// Kept separate because the set is large and mechanical: each one is a spelling
// of an operation FileTable already performs, and the only real work is the two
// struct layouts (stat differs between i386 and x86-64) and the fact that the
// kernel's error convention is a negative return value, which is exactly what
// FileTable produces.

// Translates the kernel's open flags.  The values are the Linux ones on both
// architectures.
inline FileTable::OpenFlags open_flags_from_linux(uint32_t flags) {
    FileTable::OpenFlags f;
    switch (flags & 3) {
        case 1: f.write = true; break;
        case 2: f.read = f.write = true; break;
        default: f.read = true; break;
    }
    f.create = (flags & 0100) != 0;     // O_CREAT
    f.exclusive = (flags & 0200) != 0;  // O_EXCL
    f.truncate = (flags & 01000) != 0;  // O_TRUNC
    f.append = (flags & 02000) != 0;    // O_APPEND
    f.binary = true;                    // there is no text mode on Linux
    return f;
}

// Fills a struct stat for a real file.  The layouts are entirely different
// between the two architectures, which is why this is not one memcpy.
inline void write_stat(Emulator& e, uint64_t buf, const FileTable::Stat& st, bool is64) {
    uint32_t mode = (st.is_dir ? 0040000u : st.is_char_device ? 0020000u : 0100000u) | 0666u;
    if (is64) {
        std::vector<uint8_t> zeros(144, 0);
        e.mem.write(buf, zeros.data(), zeros.size());
        e.mem.write64(buf + 0, 1);                 // st_dev
        e.mem.write64(buf + 8, 1);                 // st_ino
        e.mem.write64(buf + 16, 1);                // st_nlink
        e.mem.write32(buf + 24, mode);             // st_mode
        e.mem.write64(buf + 48, st.size);          // st_size
        e.mem.write64(buf + 56, 4096);             // st_blksize
        e.mem.write64(buf + 64, (st.size + 511) / 512);  // st_blocks
        e.mem.write64(buf + 72, static_cast<uint64_t>(st.mtime));   // st_atime
        e.mem.write64(buf + 88, static_cast<uint64_t>(st.mtime));   // st_mtime
        e.mem.write64(buf + 104, static_cast<uint64_t>(st.mtime));  // st_ctime
    } else {
        // struct stat64, the layout the i386 fstat64/stat64 syscalls use.
        std::vector<uint8_t> zeros(96, 0);
        e.mem.write(buf, zeros.data(), zeros.size());
        e.mem.write64(buf + 0, 1);                 // st_dev
        e.mem.write32(buf + 12, 1);                // __st_ino
        e.mem.write32(buf + 16, mode);             // st_mode
        e.mem.write32(buf + 20, 1);                // st_nlink
        e.mem.write64(buf + 44, st.size);          // st_size
        e.mem.write32(buf + 52, 4096);             // st_blksize
        e.mem.write64(buf + 56, (st.size + 511) / 512);  // st_blocks
        e.mem.write32(buf + 64, static_cast<uint32_t>(st.mtime));  // st_atime
        e.mem.write32(buf + 72, static_cast<uint32_t>(st.mtime));  // st_mtime
        e.mem.write32(buf + 80, static_cast<uint32_t>(st.mtime));  // st_ctime
    }
}

inline int64_t do_file_syscall(Emulator& e, Sys sys, const uint64_t a[6]) {
    switch (sys) {
        case Sys::Open:
        case Sys::Openat: {
            // openat's first argument is a directory descriptor; only AT_FDCWD
            // (-100) is meaningful without a directory table, and everything the
            // emulator sees uses that.
            bool at = sys == Sys::Openat;
            uint64_t path_ptr = at ? a[1] : a[0];
            uint32_t flags = static_cast<uint32_t>(at ? a[2] : a[1]);
            std::string path = e.mem.read_cstring(path_ptr);
            int fd = e.files.open(path, open_flags_from_linux(flags));
            if (e.options().trace_calls)
                std::fprintf(stderr, "[sys] open(%s, 0%o) = %d\n", path.c_str(), flags, fd);
            return fd;
        }
        case Sys::Lseek:
            return e.files.seek(static_cast<int>(a[0]), static_cast<int64_t>(a[1]),
                                static_cast<int>(a[2]));
        case Sys::Stat:
        case Sys::Lstat: {
            FileTable::Stat st;
            int r = FileTable::stat_path(e.mem.read_cstring(a[0]), st);
            if (r != 0) return r;
            write_stat(e, a[1], st, e.is64());
            return 0;
        }
        case Sys::Newfstatat: {
            // (dirfd, path, statbuf, flags); an empty path means "the descriptor".
            std::string path = e.mem.read_cstring(a[1]);
            FileTable::Stat st;
            int r = path.empty() ? e.files.stat_fd(static_cast<int>(a[0]), st)
                                 : FileTable::stat_path(path, st);
            if (r != 0) return r;
            write_stat(e, a[2], st, e.is64());
            return 0;
        }
        case Sys::Unlink:
            return FileTable::remove_file(e.mem.read_cstring(a[0]));
        case Sys::Unlinkat:
            return FileTable::remove_file(e.mem.read_cstring(a[1]));
        case Sys::Rename:
            return FileTable::rename_file(e.mem.read_cstring(a[0]), e.mem.read_cstring(a[1]));
        case Sys::Access: {
            FileTable::Stat st;
            return FileTable::stat_path(e.mem.read_cstring(a[0]), st);
        }
        case Sys::Faccessat: {
            FileTable::Stat st;
            return FileTable::stat_path(e.mem.read_cstring(a[1]), st);
        }
        case Sys::Getcwd: {
            // There is one working directory and it is the host's.
            const char* cwd = ".";
            std::string s = cwd;
            if (a[1] < s.size() + 1) return -34;  // ERANGE
            e.mem.write_cstring(a[0], s);
            return static_cast<int64_t>(s.size() + 1);
        }
        case Sys::Dup:
            return e.files.dup(static_cast<int>(a[0]));
        case Sys::Dup2:
        case Sys::Dup3:
            return e.files.dup(static_cast<int>(a[0]), static_cast<int>(a[1]));
        case Sys::Pread: {
            int fd = static_cast<int>(a[0]);
            int64_t saved = e.files.tell(fd);
            if (e.files.seek(fd, static_cast<int64_t>(a[3]), 0) < 0) return -22;
            std::vector<uint8_t> tmp(static_cast<size_t>(a[2]));
            int64_t got = a[2] ? e.files.read(fd, tmp.data(), a[2]) : 0;
            if (got > 0) e.mem.write(a[1], tmp.data(), static_cast<uint64_t>(got));
            if (saved >= 0) e.files.seek(fd, saved, 0);
            return got;
        }
        case Sys::Pwrite: {
            int fd = static_cast<int>(a[0]);
            int64_t saved = e.files.tell(fd);
            if (e.files.seek(fd, static_cast<int64_t>(a[3]), 0) < 0) return -22;
            std::string data(static_cast<size_t>(a[2]), '\0');
            if (a[2]) e.mem.read(a[1], data.data(), a[2]);
            int64_t put = e.files.write(fd, data.data(), data.size());
            if (saved >= 0) e.files.seek(fd, saved, 0);
            return put;
        }
        case Sys::Readv: {
            int fd = static_cast<int>(a[0]);
            int ps = e.pointer_size();
            int64_t total = 0;
            for (uint64_t i = 0; i < a[2]; ++i) {
                uint64_t entry = a[1] + i * (static_cast<uint64_t>(ps) * 2);
                uint64_t base = e.mem.read_sized(entry, ps);
                uint64_t len = e.mem.read_sized(entry + ps, ps);
                if (!len) continue;
                std::vector<uint8_t> tmp(static_cast<size_t>(len));
                int64_t got = e.files.read(fd, tmp.data(), len);
                if (got <= 0) break;
                e.mem.write(base, tmp.data(), static_cast<uint64_t>(got));
                total += got;
                if (static_cast<uint64_t>(got) < len) break;
            }
            return total;
        }
        case Sys::Ftruncate:
            // Nothing here needs to shorten a file, and silently succeeding would
            // corrupt one; report that the operation is unsupported.
            return -22;
        default:
            return kENOSYS;
    }
}
