// Linux kernel interface.
//
// A statically linked ELF talks to the kernel directly, so there is nothing to
// hook by name: the emulator instead implements the syscalls themselves.  The
// two entry points are `syscall` (x86-64) and `int 0x80` (i386), which differ in
// both their register conventions and their syscall numbers.
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#if !defined(_WIN32)
#include <unistd.h>  // getcwd, for the Linux/emscripten host
#endif

#include "emulator.h"

namespace x86emu {
namespace {

// The syscalls the emulator understands, named rather than numbered so the two
// architectures can share one implementation.
enum class Sys {
    Unknown,
    Read, Write, Writev, Readv, Close, Fstat, Ioctl,
    Open, Lseek, Stat, Lstat, Newfstatat, Unlink, Unlinkat, Rename,
    Access, Faccessat, Getcwd, Getdents64, Fcntl, Dup, Dup2, Dup3, Pread, Pwrite, Ftruncate,
    Mmap, Munmap, Brk,
    Exit, ExitGroup,
    Getpid, Gettid, Uname, ClockGettime, Time,
    ArchPrctl, SetTidAddress, RtSigaction, RtSigprocmask, SetThreadArea,
    Mprotect, Madvise, Futex, GetRandom, Readlink, Openat, SetRobustList,
    Prlimit64, GetIds, SchedGetaffinity, Ignored, NotImplemented,
};

Sys map_x86_64(uint64_t nr) {
    switch (nr) {
        case 0: return Sys::Read;
        case 1: return Sys::Write;
        case 3: return Sys::Close;
        case 5: return Sys::Fstat;
        case 9: return Sys::Mmap;
        case 11: return Sys::Munmap;
        case 12: return Sys::Brk;
        case 13: return Sys::RtSigaction;
        case 14: return Sys::RtSigprocmask;
        case 16: return Sys::Ioctl;
        case 20: return Sys::Writev;
        case 2: return Sys::Open;
        case 4: return Sys::Stat;
        case 6: return Sys::Lstat;
        case 8: return Sys::Lseek;
        case 10: return Sys::Mprotect;
        case 17: return Sys::Pread;
        case 18: return Sys::Pwrite;
        case 19: return Sys::Readv;
        case 21: return Sys::Access;
        case 32: return Sys::Dup;
        case 33: return Sys::Dup2;
        case 77: return Sys::Ftruncate;
        case 79: return Sys::Getcwd;
        case 82: return Sys::Rename;
        case 87: return Sys::Unlink;
        case 28: return Sys::Madvise;
        case 39: return Sys::Getpid;
        case 60: return Sys::Exit;
        case 63: return Sys::Uname;
        case 96: return Sys::Time;
        case 89: return Sys::Readlink;
        case 97: return Sys::Prlimit64;   // getrlimit, close enough
        case 102: case 104: case 107: case 108: return Sys::GetIds;
        case 158: return Sys::ArchPrctl;
        case 186: return Sys::Gettid;
        case 202: return Sys::Futex;
        case 204: return Sys::SchedGetaffinity;
        case 218: return Sys::SetTidAddress;
        case 228: return Sys::ClockGettime;
        case 231: return Sys::ExitGroup;
        case 72: return Sys::Fcntl;
        case 217: return Sys::Getdents64;
        case 257: return Sys::Openat;
        case 262: return Sys::Newfstatat;
        case 263: return Sys::Unlinkat;
        case 269: return Sys::Faccessat;
        case 292: return Sys::Dup3;
        case 273: return Sys::SetRobustList;
        case 302: return Sys::Prlimit64;
        case 318: return Sys::GetRandom;
        case 334: return Sys::Ignored;    // rseq
        default: return Sys::Unknown;
    }
}

Sys map_i386(uint64_t nr) {
    switch (nr) {
        case 1: return Sys::Exit;
        case 3: return Sys::Read;
        case 4: return Sys::Write;
        case 6: return Sys::Close;
        case 13: return Sys::Time;
        case 20: return Sys::Getpid;
        case 45: return Sys::Brk;
        case 54: return Sys::Ioctl;
        case 122: return Sys::Uname;
        case 146: return Sys::Writev;
        case 174: return Sys::RtSigaction;
        case 175: return Sys::RtSigprocmask;
        case 192: return Sys::Mmap;   // mmap2, offset in pages
        case 91: return Sys::Munmap;
        case 197: return Sys::Fstat;  // fstat64
        case 243: return Sys::SetThreadArea;
        case 252: return Sys::ExitGroup;
        case 258: return Sys::SetTidAddress;
        case 265: return Sys::ClockGettime;
        case 5: return Sys::Open;
        case 19: return Sys::Lseek;
        case 10: return Sys::Unlink;
        case 33: return Sys::Access;
        case 38: return Sys::Rename;
        case 41: return Sys::Dup;
        case 63: return Sys::Dup2;
        case 93: return Sys::Ftruncate;
        case 106: return Sys::Stat;
        case 107: return Sys::Lstat;
        case 125: return Sys::Mprotect;
        case 140: return Sys::Lseek;   // llseek
        case 145: return Sys::Readv;
        case 183: return Sys::Getcwd;
        case 195: return Sys::Stat;    // stat64
        case 196: return Sys::Lstat;   // lstat64
        case 180: return Sys::Pread;
        case 181: return Sys::Pwrite;
        case 300: return Sys::Newfstatat;  // fstatat64
        case 301: return Sys::Unlinkat;
        case 307: return Sys::Faccessat;
        case 330: return Sys::Dup3;
        case 219: return Sys::Madvise;
        case 240: return Sys::Futex;
        case 224: return Sys::Gettid;
        case 85: return Sys::Readlink;
        case 295: return Sys::Openat;
        case 311: return Sys::SetRobustList;
        case 340: return Sys::Prlimit64;
        case 355: return Sys::GetRandom;
        case 199: case 200: case 201: case 202: return Sys::GetIds;
        default: return Sys::Unknown;
    }
}

constexpr int64_t kENOSYS = -38;
constexpr int64_t kENOTTY = -25;
constexpr int64_t kEBADF = -9;

void host_write(Emulator& e, int fd, const std::string& data) {
    e.write_raw(fd, data.data(), data.size());
}

#include "syscalls_files.inc"

int64_t do_syscall(Emulator& e, Sys sys, const uint64_t a[6]) {
    switch (sys) {
        case Sys::Write: {
            int fd = static_cast<int>(a[0]);
            std::string data(static_cast<size_t>(a[2]), '\0');
            if (a[2]) e.mem.read(a[1], data.data(), a[2]);
            // The standard streams go through the emulator's output path so a
            // front end can capture them; anything else is a real file.
            if (fd == 1 || fd == 2) {
                host_write(e, fd, data);
                return static_cast<int64_t>(a[2]);
            }
            return e.files.write(fd, data.data(), data.size());
        }
        case Sys::Writev: {
            uint64_t fd = a[0], iov = a[1], cnt = a[2];
            int ps = e.pointer_size();
            uint64_t total = 0;
            for (uint64_t i = 0; i < cnt; ++i) {
                uint64_t entry = iov + i * (ps * 2);
                uint64_t base = e.mem.read_sized(entry, ps);
                uint64_t len = e.mem.read_sized(entry + ps, ps);
                std::string data(static_cast<size_t>(len), '\0');
                if (len) e.mem.read(base, data.data(), len);
                host_write(e, static_cast<int>(fd), data);
                total += len;
            }
            return static_cast<int64_t>(total);
        }
        case Sys::Read: {
            std::vector<uint8_t> tmp(static_cast<size_t>(a[2]));
            int64_t got = a[2] ? e.files.read(static_cast<int>(a[0]), tmp.data(), a[2]) : 0;
            if (got > 0) e.mem.write(a[1], tmp.data(), static_cast<uint64_t>(got));
            return got;
        }
        case Sys::Close:
            return e.files.close(static_cast<int>(a[0]));
        case Sys::Fstat: {
            FileTable::Stat st;
            int r = e.files.stat_fd(static_cast<int>(a[0]), st);
            if (r != 0) return r;
            write_stat(e, a[1], st, e.is64());
            return 0;
        }
        case Sys::Ioctl:
            return kENOTTY;  // "not a terminal" is a valid answer libc handles
        case Sys::Mmap: {
            // mmap(addr, len, prot, flags, fd, offset). The host's mmap is never
            // used: an anonymous mapping is just guest pages, and a file mapping is
            // the file's bytes read (fopen/fread) into those pages - which is all a
            // dynamic loader needs to bring a .so into memory.
            uint64_t addr = a[0], len = a[1];
            uint32_t flags = static_cast<uint32_t>(a[3]);
            int fd = static_cast<int>(static_cast<int32_t>(a[4]));
            uint64_t offset = a[5];
            constexpr uint32_t kMapFixed = 0x10, kMapAnon = 0x20;
            if (len == 0) return -22;  // EINVAL

            uint64_t target;
            if (flags & kMapFixed) {           // ld.so reserves a span, then drops
                target = addr;                 // each segment at a fixed sub-address
                e.mem.map(target, len, "mmap");
            } else {
                target = e.alloc_pages(len);   // a fresh region (hint addr ignored)
                if (!target) return -12;       // ENOMEM
            }

            if (!(flags & kMapAnon) && fd >= 0 && e.files.valid(fd)) {
                int64_t saved = e.files.tell(fd);   // mmap must not disturb the fd
                if (e.files.seek(fd, static_cast<int64_t>(offset), 0) >= 0) {
                    std::vector<uint8_t> buf(static_cast<size_t>(len));
                    int64_t got = e.files.read(fd, buf.data(), len);   // short at EOF -> rest stays zero
                    if (got > 0) e.mem.write(target, buf.data(), static_cast<uint64_t>(got));
                }
                if (saved >= 0) e.files.seek(fd, saved, 0);
            }
            return static_cast<int64_t>(target);
        }
        case Sys::Munmap:
            return 0;
        case Sys::Brk:
            return static_cast<int64_t>(e.set_brk(a[0]));
        case Sys::Exit:
        case Sys::ExitGroup:
            e.exit_process(static_cast<int>(static_cast<int32_t>(a[0])));
            return 0;
        case Sys::Getpid:
            return 4242;
        case Sys::Time: {
            auto now = static_cast<int64_t>(std::time(nullptr));
            if (a[0]) e.mem.write_sized(a[0], e.pointer_size(), static_cast<uint64_t>(now));
            return now;
        }
        case Sys::ClockGettime: {
            uint64_t ts = a[1];
            int ps = e.pointer_size();
            if (ts) {
                e.mem.write_sized(ts, ps, static_cast<uint64_t>(std::time(nullptr)));
                e.mem.write_sized(ts + ps, ps, 0);
            }
            return 0;
        }
        case Sys::Uname: {
            // struct utsname is 6 fixed 65-byte fields.
            const char* fields[6] = {"Linux", "x86emu", "5.15.0-emu", "#1 SMP x86emu",
                                     e.is64() ? "x86_64" : "i686", "(none)"};
            for (int i = 0; i < 6; ++i) {
                std::vector<uint8_t> field(65, 0);
                std::memcpy(field.data(), fields[i], std::strlen(fields[i]));
                e.mem.write(a[0] + static_cast<uint64_t>(i) * 65, field.data(), field.size());
            }
            return 0;
        }
        case Sys::ArchPrctl: {
            // glibc puts its thread-local storage behind fs: on x86-64, so this
            // one cannot be a stub - ignoring it leaves every TLS access
            // dereferencing a null segment base.
            constexpr uint64_t kSetGs = 0x1001, kSetFs = 0x1002;
            constexpr uint64_t kGetFs = 0x1003, kGetGs = 0x1004;
            switch (a[0]) {
                case kSetFs: e.cpu().fs_base = a[1]; return 0;
                case kSetGs: e.cpu().gs_base = a[1]; return 0;
                case kGetFs: e.mem.write64(a[1], e.cpu().fs_base); return 0;
                case kGetGs: e.mem.write64(a[1], e.cpu().gs_base); return 0;
                default: return -22;  // EINVAL
            }
        }
        case Sys::SetThreadArea: {
            // The 32-bit equivalent: a struct user_desc whose base_addr becomes
            // what gs: resolves to.  entry_number -1 means "pick one for me".
            uint64_t desc = a[0];
            uint32_t entry = e.mem.read32(desc);
            if (entry == 0xFFFFFFFFu) e.mem.write32(desc, 12);  // any free slot
            e.cpu().gs_base = e.mem.read32(desc + 4);           // base_addr
            return 0;
        }
        case Sys::GetRandom: {
            // Deterministic bytes: reproducible runs beat unpredictability here,
            // and nothing in the emulator is trying to be cryptographically sound.
            uint64_t buf = a[0], len = a[1];
            uint32_t state = 0x12345678u;
            for (uint64_t i = 0; i < len; ++i) {
                state = state * 1103515245u + 12345u;
                e.mem.write8(buf + i, static_cast<uint8_t>(state >> 16));
            }
            return static_cast<int64_t>(len);
        }
        case Sys::Prlimit64: {
            // Report a generous, fixed stack and file-descriptor limit.
            uint64_t out = a[3] ? a[3] : a[1];
            if (out) {
                e.mem.write64(out, 8ull << 20);       // rlim_cur
                e.mem.write64(out + 8, ~0ull);        // rlim_max
            }
            return 0;
        }
        case Sys::SchedGetaffinity: {
            uint64_t mask = a[2];
            if (mask) e.mem.write64(mask, 1);  // one CPU
            return 8;
        }
        case Sys::Gettid:
            return 4242;
        case Sys::GetIds:
            return 0;  // running as root, which nothing here checks
        case Sys::Readlink: {
            // A Unix runtime finds its own executable through /proc/self/exe -
            // CPython's getpath depends on it. There is no real procfs, so answer
            // it (and /proc/self/cwd) from what the emulator already knows.
            std::string path = e.mem.read_cstring(a[0]);
            std::string target;
            if (path == "/proc/self/exe")
                target = e.args().empty() ? std::string() : e.args()[0];
            if (target.empty()) return -22;  // EINVAL: nothing we resolve
            uint64_t buf = a[1];
            size_t n = std::min<size_t>(target.size(), static_cast<size_t>(a[2]));
            for (size_t i = 0; i < n; ++i) e.mem.write8(buf + i, static_cast<uint8_t>(target[i]));
            return static_cast<int64_t>(n);  // readlink does not NUL-terminate
        }
        // Signal handling, futexes and memory advice: a static libc sets these up
        // at startup, and since nothing is ever delivered and there is only one
        // thread, reporting success is accurate.
        case Sys::SetTidAddress:
        case Sys::RtSigaction:
        case Sys::RtSigprocmask:
        case Sys::Mprotect:
        case Sys::Madvise:
        case Sys::Futex:
        case Sys::SetRobustList:
        case Sys::Ignored:
            return 0;
        default:
            // The file-related calls live in their own translation unit's worth of
            // code, included below.
            return do_file_syscall(e, sys, a);
    }
}

}  // namespace

void Emulator::install_syscall_handlers() {
    if (os() != Os::Linux) {
        // A Windows guest has no business issuing syscalls; report clearly.
        cpu_->on_interrupt = [this](uint8_t vec) {
            throw CpuError(cpu_->rip, "unexpected int 0x" + std::to_string(vec) +
                                          " from a Windows guest");
        };
        cpu_->on_syscall = [this]() {
            throw CpuError(cpu_->rip, "unexpected syscall from a Windows guest");
        };
        return;
    }

    // x86-64: number in RAX, arguments in RDI, RSI, RDX, R10, R8, R9.
    cpu_->on_syscall = [this]() {
        uint64_t nr = cpu_->regs[RAX];
        const uint64_t a[6] = {cpu_->regs[RDI], cpu_->regs[RSI], cpu_->regs[RDX],
                               cpu_->regs[R10], cpu_->regs[R8],  cpu_->regs[R9]};
        Sys sys = map_x86_64(nr);
        if (sys == Sys::Unknown && opt_.trace_calls)
            std::fprintf(stderr, "[sys] unimplemented syscall %llu\n",
                         (unsigned long long)nr);
        else if (opt_.trace_calls)
            std::fprintf(stderr, "[sys] %llu\n", (unsigned long long)nr);
        int64_t r = do_syscall(*this, sys, a);
        if (!cpu_->halted) cpu_->regs[RAX] = static_cast<uint64_t>(r);
    };

    // i386: number in EAX, arguments in EBX, ECX, EDX, ESI, EDI, EBP.
    cpu_->on_interrupt = [this](uint8_t vec) {
        if (vec != 0x80)
            throw CpuError(cpu_->rip, "unhandled int 0x" + std::to_string(vec));
        uint64_t nr = cpu_->regs[RAX] & 0xFFFFFFFFull;
        const uint64_t a[6] = {cpu_->regs[RBX] & 0xFFFFFFFFull, cpu_->regs[RCX] & 0xFFFFFFFFull,
                               cpu_->regs[RDX] & 0xFFFFFFFFull, cpu_->regs[RSI] & 0xFFFFFFFFull,
                               cpu_->regs[RDI] & 0xFFFFFFFFull, cpu_->regs[RBP] & 0xFFFFFFFFull};
        Sys sys = map_i386(nr);
        if (opt_.trace_calls)
            std::fprintf(stderr, "[sys] int80 %llu%s\n", (unsigned long long)nr,
                         sys == Sys::Unknown ? " (unimplemented)" : "");
        int64_t r = do_syscall(*this, sys, a);
        if (!cpu_->halted) cpu_->regs[RAX] = static_cast<uint64_t>(r) & 0xFFFFFFFFull;
    };
}

}  // namespace x86emu
