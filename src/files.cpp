#include "files.h"

#include <cerrno>
#include <cstring>
#include <ctime>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>

#if defined(_WIN32)
#include <io.h>
#define x86emu_stat _stat64
#define x86emu_stat_struct struct _stat64
#else
#include <unistd.h>
#define x86emu_stat stat
#define x86emu_stat_struct struct stat
#endif

namespace x86emu {
namespace {

// errno-style negatives, using the Linux numbers.  The Win32 hooks translate
// them into their own error codes, and the Linux syscalls pass them straight
// through, which is why the table speaks in these terms.
constexpr int kENOENT = -2;
constexpr int kEBADF = -9;
constexpr int kEACCES = -13;
constexpr int kEEXIST = -17;
constexpr int kEINVAL = -22;
constexpr int kEMFILE = -24;

int from_errno(int e) {
    switch (e) {
        case ENOENT: return kENOENT;
        case EACCES: return kEACCES;
        case EEXIST: return kEEXIST;
        case EINVAL: return kEINVAL;
        default: return kEACCES;
    }
}

}  // namespace

FileTable::FileTable() {
    // The three standard streams are always present and always the host's.  Their
    // terminal-ness is whatever the host's really is, so that a guest asking
    // GetFileType or isatty gets the truth about where its output is going.
    auto standard = [](std::FILE* fp, const char* name, bool readable, bool writable) {
        Entry e;
        e.fp = fp;
        e.path = name;
        e.readable = readable;
        e.writable = writable;
        e.standard_stream = true;
#if defined(_WIN32)
        e.is_tty = _isatty(_fileno(fp)) != 0;
#else
        e.is_tty = isatty(fileno(fp)) != 0;
#endif
        return e;
    };
    files_[0] = standard(stdin, "<stdin>", true, false);
    files_[1] = standard(stdout, "<stdout>", false, true);
    files_[2] = standard(stderr, "<stderr>", false, true);
}

std::string FileTable::host_path(const std::string& guest_path) {
    // Guests write paths in their own OS's convention and the host may be the
    // other one; backslashes work as separators on Windows and would be a
    // literal character on Unix, so normalise to forward slashes, which both
    // accept.
    std::string out;
    out.reserve(guest_path.size());
    for (char c : guest_path) out += (c == '\\') ? '/' : c;
    return out;
}

int FileTable::alloc_slot() {
    // Guests, and especially libcs, expect the lowest free descriptor.
    for (int fd = 3; fd < 4096; ++fd)
        if (files_.find(fd) == files_.end()) return fd;
    return -1;
}

int FileTable::open(const std::string& path, const OpenFlags& flags) {
    std::string mode;
    if (flags.append)
        mode = flags.read ? "a+" : "a";
    else if (flags.write && flags.read)
        mode = flags.truncate ? "w+" : (flags.create ? "w+" : "r+");
    else if (flags.write)
        mode = "w";
    else
        mode = "r";
    if (flags.binary) mode += "b";

    std::string host = host_path(path);

    // O_EXCL means "fail if it already exists", which fopen has no mode for.
    if (flags.exclusive && flags.create) {
        Stat probe;
        if (stat_path(path, probe) == 0) return kEEXIST;
    }
    // Opening for update without O_CREAT must not create the file, and "r+"
    // already behaves that way; the reverse case needs no special handling.
    std::FILE* fp = std::fopen(host.c_str(), mode.c_str());
    if (!fp && flags.write && flags.read && flags.create && !flags.truncate) {
        // "r+" failed because the file does not exist yet and we may create it.
        fp = std::fopen(host.c_str(), flags.binary ? "w+b" : "w+");
    }
    if (!fp) return from_errno(errno);

    int fd = alloc_slot();
    if (fd < 0) {
        std::fclose(fp);
        return kEMFILE;
    }
    Entry e;
    e.fp = fp;
    e.path = path;
    e.readable = flags.read || (flags.write && flags.read);
    e.writable = flags.write || flags.append;
    e.append = flags.append;
    e.text_mode = translate_newlines_ && !flags.binary;
    files_[fd] = e;
    return fd;
}

bool FileTable::valid(int fd) const {
    auto it = files_.find(fd);
    return it != files_.end() && !it->second.closed && it->second.fp != nullptr;
}

FileTable::Entry* FileTable::get(int fd) {
    auto it = files_.find(fd);
    if (it == files_.end() || it->second.closed) return nullptr;
    return &it->second;
}

int FileTable::close(int fd) {
    Entry* e = get(fd);
    if (!e) return kEBADF;
    if (e->standard_stream) {
        // Closing a standard stream must not close the host's copy; the guest
        // just loses its descriptor.
        files_.erase(fd);
        return 0;
    }
    std::fclose(e->fp);
    files_.erase(fd);
    return 0;
}

int64_t FileTable::read(int fd, void* dst, uint64_t len) {
    Entry* e = get(fd);
    if (!e) return kEBADF;
    if (!e->readable) return kEBADF;
    if (len == 0) return 0;
    if (e->last_was_write) {
        std::fflush(e->fp);
        e->last_was_write = false;
    }
    size_t got = std::fread(dst, 1, static_cast<size_t>(len), e->fp);
    if (e->text_mode && got) {
        // Text mode collapses CRLF to LF, so the guest sees fewer bytes than
        // were on disk - which is exactly what a real CRT reports.
        auto* p = static_cast<uint8_t*>(dst);
        size_t out = 0;
        for (size_t i = 0; i < got; ++i) {
            if (p[i] == '\r' && i + 1 < got && p[i + 1] == '\n') continue;
            p[out++] = p[i];
        }
        got = out;
    }
    return static_cast<int64_t>(got);
}

int64_t FileTable::write(int fd, const void* src, uint64_t len) {
    Entry* e = get(fd);
    if (!e) return kEBADF;
    if (!e->writable) return kEBADF;
    if (len == 0) return 0;
    if (!e->last_was_write && !e->standard_stream) {
        // Seeking to the current position is the standard way to switch a stream
        // from reading to writing.
        std::fseek(e->fp, 0, SEEK_CUR);
    }
    e->last_was_write = true;
    if (e->text_mode) {
        const auto* p = static_cast<const uint8_t*>(src);
        std::vector<uint8_t> expanded;
        expanded.reserve(static_cast<size_t>(len) + 16);
        for (uint64_t i = 0; i < len; ++i) {
            if (p[i] == '\n') expanded.push_back('\r');
            expanded.push_back(p[i]);
        }
        if (std::fwrite(expanded.data(), 1, expanded.size(), e->fp) != expanded.size())
            return 0;
        // Report the count the guest asked about, not the expanded one.
        return static_cast<int64_t>(len);
    }
    size_t put = std::fwrite(src, 1, static_cast<size_t>(len), e->fp);
    return static_cast<int64_t>(put);
}

int64_t FileTable::seek(int fd, int64_t offset, int whence) {
    Entry* e = get(fd);
    if (!e) return kEBADF;
    if (e->standard_stream) return kEINVAL;
    e->last_was_write = false;
    int origin = whence == 1 ? SEEK_CUR : whence == 2 ? SEEK_END : SEEK_SET;
#if defined(_WIN32)
    if (_fseeki64(e->fp, offset, origin) != 0) return kEINVAL;
    return _ftelli64(e->fp);
#else
    if (fseeko(e->fp, static_cast<off_t>(offset), origin) != 0) return kEINVAL;
    return static_cast<int64_t>(ftello(e->fp));
#endif
}

int64_t FileTable::tell(int fd) {
    Entry* e = get(fd);
    if (!e) return kEBADF;
#if defined(_WIN32)
    return _ftelli64(e->fp);
#else
    return static_cast<int64_t>(ftello(e->fp));
#endif
}

int64_t FileTable::size(int fd) {
    Stat s;
    int r = stat_fd(fd, s);
    return r < 0 ? r : static_cast<int64_t>(s.size);
}

int FileTable::flush(int fd) {
    Entry* e = get(fd);
    if (!e) return kEBADF;
    return std::fflush(e->fp) == 0 ? 0 : kEINVAL;
}

bool FileTable::eof(int fd) {
    Entry* e = get(fd);
    return e ? std::feof(e->fp) != 0 : true;
}

int FileTable::dup(int fd, int to) {
    Entry* e = get(fd);
    if (!e) return kEBADF;
    int target = to;
    if (target < 0) {
        target = alloc_slot();
        if (target < 0) return kEMFILE;
    } else if (target != fd && files_.find(target) != files_.end()) {
        close(target);
    }
    // The two descriptors share one host FILE*, so only the standard streams and
    // the original owner may close it; mark the copy as a shared view.
    Entry copy = *e;
    // Both descriptors share one host stream, so neither may close it.
    copy.standard_stream = true;
    files_[target] = copy;
    return target;
}

int FileTable::remove_file(const std::string& path) {
    if (std::remove(host_path(path).c_str()) != 0) return from_errno(errno);
    return 0;
}

int FileTable::rename_file(const std::string& from, const std::string& to) {
    if (std::rename(host_path(from).c_str(), host_path(to).c_str()) != 0)
        return from_errno(errno);
    return 0;
}

int FileTable::stat_path(const std::string& path, Stat& out) {
    x86emu_stat_struct st;
    if (x86emu_stat(host_path(path).c_str(), &st) != 0) return from_errno(errno);
    out.size = static_cast<uint64_t>(st.st_size);
    out.is_dir = (st.st_mode & S_IFMT) == S_IFDIR;
    out.is_char_device = (st.st_mode & S_IFMT) == S_IFCHR;
    out.mtime = static_cast<int64_t>(st.st_mtime);
    return 0;
}

int FileTable::stat_fd(int fd, Stat& out) {
    Entry* e = get(fd);
    if (!e) return kEBADF;
    if (e->standard_stream) {
        out.is_char_device = true;
        out.size = 0;
        return 0;
    }
    // Start from the path so mode and timestamps are right, then take the size
    // from the stream itself: Windows does not update a file's directory entry
    // until the handle is closed, so stat() on an open file can report a stale
    // size where the guest expects the value its own write() just produced.
    int r = stat_path(e->path, out);
    if (r != 0) return r;
    if (e->last_was_write) {
        std::fflush(e->fp);
        e->last_was_write = false;
    }
#if defined(_WIN32)
    long long here = _ftelli64(e->fp);
    if (here >= 0 && _fseeki64(e->fp, 0, SEEK_END) == 0) {
        long long end = _ftelli64(e->fp);
        if (end >= 0) out.size = static_cast<uint64_t>(end);
        _fseeki64(e->fp, here, SEEK_SET);
    }
#else
    off_t here = ftello(e->fp);
    if (here >= 0 && fseeko(e->fp, 0, SEEK_END) == 0) {
        off_t end = ftello(e->fp);
        if (end >= 0) out.size = static_cast<uint64_t>(end);
        fseeko(e->fp, here, SEEK_SET);
    }
#endif
    return 0;
}

}  // namespace x86emu
