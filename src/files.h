// The guest's view of files.
//
// A guest gets small integer descriptors that mean nothing to the host; this
// table maps them onto real host files.  Everything above it - the Linux
// syscalls, the Win32 file API and the C stdio layer - is a different spelling of
// the same operations, so they all go through here.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

namespace x86emu {

class FileTable {
public:
    // Open flags, in the emulator's own terms so that neither the Linux nor the
    // Windows spelling leaks into the table.
    struct OpenFlags {
        bool read = false;
        bool write = false;
        bool append = false;
        bool create = false;
        bool truncate = false;
        bool exclusive = false;
        bool binary = true;
    };

    struct Entry {
        std::FILE* fp = nullptr;
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
        bool closed = false;
        // getdents64 iteration state for a directory descriptor: the listing is
        // snapshotted on the first read and a cursor walks it across calls.
        std::vector<std::string> dir_names;
        std::vector<uint8_t> dir_types;   // DT_DIR=4, DT_REG=8
        size_t dir_pos = 0;
        bool dir_loaded = false;
        // C forbids reading straight after writing on the same stream without an
        // intervening flush or seek.  A guest calling the kernel's read() and
        // write() has no such rule, so the table tracks the direction and
        // resynchronises for it.
        bool last_was_write = false;
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
    // Negative return values are errno-style; otherwise a byte count.
    int64_t read(int fd, void* dst, uint64_t len);
    int64_t write(int fd, const void* src, uint64_t len);
    // whence: 0 = set, 1 = current, 2 = end.
    int64_t seek(int fd, int64_t offset, int whence);
    int64_t tell(int fd);
    int64_t size(int fd);
    int flush(int fd);
    bool eof(int fd);

    // Duplicates a descriptor onto the lowest free slot, or onto `to`.
    int dup(int fd, int to = -1);

    Entry* get(int fd);
    bool valid(int fd) const;

    // Filesystem operations that do not involve a descriptor.
    static int remove_file(const std::string& path);
    static int rename_file(const std::string& from, const std::string& to);
    // Fills in size/mode; returns 0 or a negative errno-style code.
    struct Stat {
        uint64_t size = 0;
        bool is_dir = false;
        bool is_char_device = false;
        int64_t mtime = 0;
    };
    static int stat_path(const std::string& path, Stat& out);
    int stat_fd(int fd, Stat& out);

    // A host path for a guest path.  Windows and Linux guests write paths in
    // their own conventions, and the host may be either.
    static std::string host_path(const std::string& guest_path);

private:
    int alloc_slot();

    std::unordered_map<int, Entry> files_;
    int next_fd_ = 3;
    bool translate_newlines_ = false;
};

}  // namespace x86emu
