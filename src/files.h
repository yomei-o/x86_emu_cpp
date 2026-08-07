// The guest's view of files.
//
// A guest gets small integer descriptors that mean nothing to the host; this
// table maps them onto real host files.  Everything above it - the Linux
// syscalls, the Win32 file API and the C stdio layer - is a different spelling of
// the same operations, so they all go through here.
//
// A descriptor can also name a pipe: an in-memory byte queue shared between
// guest processes.  The buffer is unbounded, so a writer never blocks; a reader
// with an empty buffer gets kEAGAINPipe while a writer still exists, and the
// caller is expected to block its guest thread and retry.
#pragma once

#include <cstdint>
#include <cstdio>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace x86emu {

// What FileTable::read returns when a pipe is empty but not at end-of-file.
// The value is Linux's -EAGAIN, so the syscall layer can also pass it through.
constexpr int64_t kEAGAINPipe = -11;

// One pipe, shared by every descriptor that references either of its ends -
// including descriptors in *other processes'* tables, which is what makes
// `gcc | as` style plumbing work.
struct Pipe {
    std::deque<uint8_t> buffer;
    int readers = 0;  // open read ends, counted across all processes
    int writers = 0;  // open write ends
};

// One *end* of a pipe.  Duplicated descriptors share a single end object; the
// pipe's reader/writer count drops only when the last duplicate closes, which
// is exactly the rule that makes "close your copy of the child's write end"
// produce EOF at the right moment.
struct PipeEnd {
    std::shared_ptr<Pipe> pipe;
    bool writer = false;
    PipeEnd(std::shared_ptr<Pipe> p, bool w) : pipe(std::move(p)), writer(w) {
        (writer ? pipe->writers : pipe->readers)++;
    }
    ~PipeEnd() { (writer ? pipe->writers : pipe->readers)--; }
    PipeEnd(const PipeEnd&) = delete;
    PipeEnd& operator=(const PipeEnd&) = delete;
};

class FileTable {
public:
    // Open flags, in the emulator's own terms so that neither the Linux nor the
    // Windows spelling leaks into the table.
    // How wide-character stdio turns wchar_t into bytes on a stream.  The CRT
    // takes this from the open mode, and it is not a detail: cl.exe writes the
    // linker's response file with fputws on a *binary* stream, where MSVC emits
    // the wide characters unchanged, and link.exe reads it back with
    // `ccs=unicode`.  The two only agree if both halves are UTF-16, and when they
    // do not the linker sees one garbled argument and reports it as a missing
    // input file.
    enum class WideIo {
        Multibyte,  // a text stream with no ccs: convert through the locale
        Utf16,      // ccs=UNICODE / ccs=UTF-16LE, and any binary stream
        Utf8,       // ccs=UTF-8
    };

    struct OpenFlags {
        bool read = false;
        bool write = false;
        bool append = false;
        bool create = false;
        bool truncate = false;
        bool exclusive = false;
        bool binary = true;
        WideIo wide_io = WideIo::Multibyte;
    };

    struct Entry {
        // Shared, because dup() and child processes reference the same host
        // stream - and with it the same file offset, as POSIX specifies.  The
        // deleter closes the stream when the last reference goes, and is a no-op
        // for the host's own standard streams.
        std::shared_ptr<std::FILE> fp;
        std::shared_ptr<PipeEnd> pipe_end;
        std::string path;
        bool readable = false;
        bool writable = false;
        bool append = false;
        // Two different questions: whether this is one of the three streams the
        // emulator must never close, and whether it is actually a terminal.  A
        // redirected stdout is the first without being the second, and a guest
        // asking GetFileType deserves the real answer.
        bool standard_stream = false;
        bool is_tty = false;
        // A directory handle has no stream behind it: Windows lets a program open
        // a directory to ask about its attributes, which no C library can do.
        bool is_directory = false;
        bool text_mode = false;  // a Windows guest opened it without "b"
        WideIo wide_io = WideIo::Multibyte;
        bool cloexec = false;    // closed by execve(), as FD_CLOEXEC asks
        bool closed = false;
        // getdents64 iteration state for a directory descriptor: the listing is
        // snapshotted on the first read and a cursor walks it across calls.
        std::vector<std::string> dir_names;
        std::vector<uint8_t> dir_types;   // DT_DIR=4, DT_REG=8
        size_t dir_pos = 0;
        bool dir_loaded = false;
        // The wildcard the listing was taken with; a caller that changes it, as
        // the native directory query may, needs a fresh snapshot.
        std::string dir_filter;
        // C forbids reading straight after writing on the same stream without an
        // intervening flush or seek.  A guest calling the kernel's read() and
        // write() has no such rule, so the table tracks the direction and
        // resynchronises for it.
        bool last_was_write = false;

        bool is_pipe() const { return pipe_end != nullptr; }
    };

    FileTable();

    // A Windows guest that opens a file without "b" expects the CRT's newline
    // translation.  The emulator turns this on for Windows guests so the bytes on
    // disk match what the real runtime would have written.
    void set_text_translation(bool enabled) { translate_newlines_ = enabled; }

    // Returns a descriptor, or a negative errno-style code.
    int open(const std::string& path, const OpenFlags& flags);
    // A descriptor that names a directory rather than a stream.  Only the
    // metadata operations work on it, which is all Windows allows either.
    int open_directory(const std::string& path);
    int close(int fd);
    // Negative return values are errno-style; otherwise a byte count.  A pipe
    // with nothing buffered returns kEAGAINPipe while a writer exists and 0
    // (end of file) once the last write end has closed.
    int64_t read(int fd, void* dst, uint64_t len);
    int64_t write(int fd, const void* src, uint64_t len);
    // whence: 0 = set, 1 = current, 2 = end.
    int64_t seek(int fd, int64_t offset, int whence);
    int64_t tell(int fd);
    int64_t size(int fd);
    int flush(int fd);
    // Cuts the file off at `length` (SetEndOfFile, ftruncate).  A guest that
    // builds its output in a memory-mapped view over-allocates and then trims,
    // so without this the file keeps whatever slack the view had.
    int truncate(int fd, int64_t length);
    bool eof(int fd);

    // Duplicates a descriptor onto the lowest free slot, or onto `to`.
    int dup(int fd, int to = -1);

    // Creates a pipe; fds[0] is the read end, fds[1] the write end.
    // Returns 0 or a negative errno-style code.
    int make_pipe(int fds[2]);
    // Installs a copy of another table's descriptor at `fd` here.  This is how a
    // child process inherits its standard handles: both tables then reference
    // the same host stream or pipe end.
    void install(int fd, const Entry& entry);
    // A copy of the whole table, for fork(): every descriptor shared, offsets
    // and all.
    FileTable clone() const;
    // Closes every descriptor marked close-on-exec, for execve().
    void close_cloexec();

    Entry* get(int fd);
    bool valid(int fd) const;

    // What the guest opened this descriptor with.  The memory map is far more
    // use when a file mapping says which library it is than when every one of
    // them says "mmap": the guest's own ld.so does the mapping, so this is the
    // only place the name is still known.
    std::string path_of(int fd) const;

    // Filesystem operations that do not involve a descriptor.
    static int remove_file(const std::string& path);
    static int rename_file(const std::string& from, const std::string& to);
    // Fills in size/mode; returns 0 or a negative errno-style code.
    struct Stat {
        uint64_t size = 0;
        bool is_dir = false;
        bool is_char_device = false;
        bool is_fifo = false;
        int64_t mtime = 0;
        // A distinct inode per path.  This is not decoration: musl's dynamic
        // linker decides whether a shared library is already loaded by
        // comparing st_dev/st_ino, so one shared inode number makes the second
        // library it opens look like the first, and every symbol in it goes
        // missing.
        uint64_t ino = 1;
        uint64_t dev = 1;
    };
    static int stat_path(const std::string& path, Stat& out);
    int stat_fd(int fd, Stat& out);

    // A host path for a guest path.  Windows and Linux guests write paths in
    // their own conventions, and the host may be either.
    static std::string host_path(const std::string& guest_path);

    // A directory standing in for a Linux guest's "/": absolute paths like
    // /usr/bin/cc1 resolve inside it.  This is what lets an unmodified distro
    // toolchain, which has /usr baked into every search path, run from a
    // directory of unpacked packages.  Empty (the default) means no remapping.
    static void set_sysroot(std::string dir);

private:
    int alloc_slot();
    // A stable inode number for a host path (see Stat::ino).
    static uint64_t inode_for(const std::string& host_path);

    std::unordered_map<int, Entry> files_;
    bool translate_newlines_ = false;
};

}  // namespace x86emu
