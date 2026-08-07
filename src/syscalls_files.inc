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
        e.mem.write64(buf + 0, st.dev);            // st_dev
        e.mem.write64(buf + 8, st.ino);            // st_ino
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
        e.mem.write64(buf + 0, st.dev);            // st_dev
        e.mem.write32(buf + 12, static_cast<uint32_t>(st.ino));  // __st_ino
        e.mem.write32(buf + 16, mode);             // st_mode
        e.mem.write32(buf + 20, 1);                // st_nlink
        e.mem.write64(buf + 88, st.ino);           // st_ino (the 64-bit one)
        e.mem.write64(buf + 44, st.size);          // st_size
        e.mem.write32(buf + 52, 4096);             // st_blksize
        e.mem.write64(buf + 56, (st.size + 511) / 512);  // st_blocks
        e.mem.write32(buf + 64, static_cast<uint32_t>(st.mtime));  // st_atime
        e.mem.write32(buf + 72, static_cast<uint32_t>(st.mtime));  // st_mtime
        e.mem.write32(buf + 80, static_cast<uint32_t>(st.mtime));  // st_ctime
    }
}

// Fills a struct statx (256 bytes, the same on both architectures).  glibc 2.28
// and later reach for statx first and only fall back to fstatat if the kernel
// answers ENOSYS - and that fallback is what a missing statx costs: glibc's
// generic path calls fstatat with a NULL pathname to probe, which is a read of
// address zero rather than an error the caller can see.
inline void write_statx(Emulator& e, uint64_t buf, const FileTable::Stat& st) {
    std::vector<uint8_t> zeros(256, 0);
    e.mem.write(buf, zeros.data(), zeros.size());
    uint32_t mode = (st.is_dir ? 0040000u : st.is_char_device ? 0020000u : 0100000u) | 0666u;
    // STATX_BASIC_STATS, minus the fields there is nothing behind: what a caller
    // may believe is exactly what stx_mask says was filled in.
    constexpr uint32_t kType = 0x001, kMode = 0x002, kNlink = 0x004, kUid = 0x008,
                       kGid = 0x010, kAtime = 0x020, kMtime = 0x040, kCtime = 0x080,
                       kIno = 0x100, kSize = 0x200, kBlocks = 0x400;
    e.mem.write32(buf + 0, kType | kMode | kNlink | kUid | kGid | kAtime | kMtime | kCtime |
                               kIno | kSize | kBlocks);  // stx_mask
    e.mem.write32(buf + 4, 4096);                        // stx_blksize
    e.mem.write32(buf + 16, 1);                          // stx_nlink
    e.mem.write16(buf + 28, static_cast<uint16_t>(mode));  // stx_mode
    e.mem.write64(buf + 32, st.ino);                     // stx_ino
    e.mem.write64(buf + 40, st.size);                    // stx_size
    e.mem.write64(buf + 48, (st.size + 511) / 512);      // stx_blocks
    for (uint64_t off : {64ull, 96ull, 112ull})          // atime, ctime, mtime
        e.mem.write64(buf + off, static_cast<uint64_t>(st.mtime));  // .tv_sec
    e.mem.write32(buf + 136, static_cast<uint32_t>(st.dev >> 8));   // stx_dev_major
    e.mem.write32(buf + 140, static_cast<uint32_t>(st.dev & 0xFF));  // stx_dev_minor
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
            // O_DIRECTORY (0200000): the caller wants a directory descriptor to
            // enumerate with getdents64, which fopen cannot give. opendir(".") is
            // how a Unix runtime lists a directory, so route it accordingly.
            int fd = (flags & 0200000)
                         ? e.files.open_directory(path)
                         : e.files.open(path, open_flags_from_linux(flags));
            if (fd >= 0 && (flags & 02000000))  // O_CLOEXEC
                e.files.get(fd)->cloexec = true;
            if (e.options().trace_calls)
                std::fprintf(stderr, "[sys] open(%s, 0%o) = %d\n", path.c_str(), flags, fd);
            return fd;
        }
        case Sys::Fcntl: {
            // fcntl(fd, cmd, arg). Close-on-exec is real now that execve exists.
            int fd = static_cast<int>(a[0]);
            int cmd = static_cast<int>(a[1]);
            if (!e.files.valid(fd) && fd > 2) return -9;  // EBADF
            switch (cmd) {
                case 0:      // F_DUPFD
                    return e.files.dup(fd, -1);
                case 1030: {  // F_DUPFD_CLOEXEC
                    int copy = e.files.dup(fd, -1);
                    if (copy >= 0) e.files.get(copy)->cloexec = true;
                    return copy;
                }
                case 1: {  // F_GETFD
                    FileTable::Entry* entry = e.files.get(fd);
                    return entry && entry->cloexec ? 1 : 0;  // FD_CLOEXEC
                }
                case 2: {  // F_SETFD
                    if (FileTable::Entry* entry = e.files.get(fd))
                        entry->cloexec = (a[2] & 1) != 0;
                    return 0;
                }
                case 3: return 2;   // F_GETFL -> O_RDWR, no O_NONBLOCK
                case 4: return 0;   // F_SETFL (accept)
                default: return 0;  // permissive: startup only sets flags
            }
        }
        case Sys::Getdents64: {
            // struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen; u8 d_type;
            // char d_name[]; } - records padded to 8 bytes, return value the number
            // of bytes written (0 = end). The cursor lives on the descriptor.
            int fd = static_cast<int>(a[0]);
            uint64_t buf = a[1];
            size_t cap = static_cast<size_t>(a[2]);
            FileTable::Entry* ent = e.files.get(fd);
            if (!ent || !ent->is_directory) return -20;  // ENOTDIR
            if (!ent->dir_loaded) {
                ent->dir_loaded = true;
                ent->dir_names = {".", ".."};
                ent->dir_types = {4, 4};  // DT_DIR
                for (const auto& de : e.list_directory(ent->path + "/*")) {
                    ent->dir_names.push_back(de.name);
                    ent->dir_types.push_back(de.is_dir ? 4 : 8);  // DT_DIR / DT_REG
                }
            }
            size_t written = 0;
            while (ent->dir_pos < ent->dir_names.size()) {
                const std::string& name = ent->dir_names[ent->dir_pos];
                size_t reclen = (19 + name.size() + 1 + 7) & ~static_cast<size_t>(7);
                if (written + reclen > cap) break;      // caller will read again
                uint64_t rec = buf + written;
                e.mem.write64(rec + 0, ent->dir_pos + 1);                      // d_ino (nonzero)
                e.mem.write64(rec + 8, static_cast<uint64_t>(ent->dir_pos + 1));  // d_off (opaque)
                e.mem.write16(rec + 16, static_cast<uint16_t>(reclen));        // d_reclen
                e.mem.write8(rec + 18, ent->dir_types[ent->dir_pos]);          // d_type
                for (size_t i = 0; i < name.size(); ++i)
                    e.mem.write8(rec + 19 + i, static_cast<uint8_t>(name[i]));
                for (size_t i = 19 + name.size(); i < reclen; ++i)
                    e.mem.write8(rec + i, 0);           // NUL + alignment padding
                written += reclen;
                ++ent->dir_pos;
            }
            if (written == 0 && ent->dir_pos < ent->dir_names.size())
                return -22;  // EINVAL: a single entry did not fit the buffer
            return static_cast<int64_t>(written);
        }
        case Sys::Lseek:
            return e.files.seek(static_cast<int>(a[0]), static_cast<int64_t>(a[1]),
                                static_cast<int>(a[2]));
        case Sys::Llseek: {
            // _llseek(fd, off_high, off_low, loff_t* result, whence): the 64-bit
            // offset arrives split, the new position leaves through the pointer,
            // and the return value is 0 - not the position.  Treating it like
            // lseek made glibc read a stale errno and report EPERM for every
            // seek, which `as` passed on as "can't write to section".
            const int64_t off = static_cast<int64_t>((a[1] << 32) | (a[2] & 0xFFFFFFFFull));
            const int64_t pos = e.files.seek(static_cast<int>(a[0]), off,
                                             static_cast<int>(a[4]));
            if (pos < 0) return pos;
            if (a[3]) e.mem.write64(a[3], static_cast<uint64_t>(pos));
            return 0;
        }
        case Sys::Stat:
        case Sys::Lstat: {
            FileTable::Stat st;
            int r = FileTable::stat_path(e.mem.read_cstring(a[0]), st);
            if (r != 0) return r;
            write_stat(e, a[1], st, e.is64());
            return 0;
        }
        case Sys::Statx: {
            // (dirfd, path, flags, mask, statxbuf).  Rust's standard library
            // decides whether statx exists at all by calling it with NULL
            // pointers and reading errno back: ENOSYS or EPERM means "fall back
            // to fstat", anything else - EFAULT here, as on a real kernel -
            // means the syscall is present.  Answering the probe with a fault
            // instead of an error is what killed the guest.
            if (a[1] == 0 || a[4] == 0) return -14;  // EFAULT
            constexpr uint32_t kAtEmptyPath = 0x1000;
            std::string path = e.mem.read_cstring(a[1]);
            FileTable::Stat st;
            int r = (path.empty() && (a[2] & kAtEmptyPath))
                        ? e.files.stat_fd(static_cast<int>(static_cast<int32_t>(a[0])), st)
                        : FileTable::stat_path(path, st);
            if (r != 0) return r;
            write_statx(e, a[4], st);
            return 0;
        }
        case Sys::Newfstatat: {
            // (dirfd, path, statbuf, flags); an empty path means "the descriptor".
            if (a[1] == 0 || a[2] == 0) return -14;  // EFAULT, not a read of zero
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
            // A Unix runtime needs an absolute cwd (CPython's getpath calls abspath,
            // which fails on a relative "."). On a Unix-shaped host pass the real
            // directory through; on a Windows host, spell the drive path as
            // "/C:/dir", which host_path() knows how to turn back into C:/dir.
            std::string s = "/";
            char buf[4096];
#if defined(_WIN32)
            if (_getcwd(buf, sizeof buf)) {
                s = buf;
                for (char& c : s)
                    if (c == '\\') c = '/';
                s = "/" + s;
            }
#else
            if (::getcwd(buf, sizeof buf)) s = buf;
#endif
            if (a[1] < s.size() + 1) return -34;  // ERANGE
            e.mem.write_cstring(a[0], s);
            return static_cast<int64_t>(s.size() + 1);
        }
        case Sys::Dup:
            return e.files.dup(static_cast<int>(a[0]));
        case Sys::Dup2:
        case Sys::Dup3: {
            int r = e.files.dup(static_cast<int>(a[0]), static_cast<int>(a[1]));
            if (sys == Sys::Dup3 && r >= 0 && (a[2] & 02000000))  // O_CLOEXEC
                e.files.get(r)->cloexec = true;
            return r;
        }
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
