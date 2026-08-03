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

#include "emulator.h"

namespace x86emu {
namespace {

// The syscalls the emulator understands, named rather than numbered so the two
// architectures can share one implementation.
enum class Sys {
    Unknown,
    Read, Write, Writev, Close, Fstat, Ioctl,
    Mmap, Munmap, Brk,
    Exit, ExitGroup,
    Getpid, Uname, ClockGettime, Time,
    ArchPrctl, SetTidAddress, RtSigaction, RtSigprocmask, SetThreadArea,
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
        case 39: return Sys::Getpid;
        case 60: return Sys::Exit;
        case 63: return Sys::Uname;
        case 96: return Sys::Time;
        case 158: return Sys::ArchPrctl;
        case 218: return Sys::SetTidAddress;
        case 228: return Sys::ClockGettime;
        case 231: return Sys::ExitGroup;
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
        default: return Sys::Unknown;
    }
}

constexpr int64_t kENOSYS = -38;
constexpr int64_t kENOTTY = -25;
constexpr int64_t kEBADF = -9;

void host_write(int fd, const std::string& data) {
    if (data.empty()) return;
    std::fwrite(data.data(), 1, data.size(), fd == 2 ? stderr : stdout);
}

// Fills in just the fields a libc actually looks at after fstat: the file type
// (so it can pick line vs. block buffering) and the block size.
void fake_stat(Emulator& e, uint64_t buf, bool is64, bool tty) {
    uint32_t mode = (tty ? 0020000u : 0100000u) | 0666u;  // S_IFCHR / S_IFREG
    if (is64) {
        std::vector<uint8_t> zeros(144, 0);
        e.mem.write(buf, zeros.data(), zeros.size());
        e.mem.write32(buf + 24, mode);      // st_mode
        e.mem.write64(buf + 56, 4096);      // st_blksize
    } else {
        std::vector<uint8_t> zeros(96, 0);
        e.mem.write(buf, zeros.data(), zeros.size());
        e.mem.write32(buf + 16, mode);      // st_mode
        e.mem.write32(buf + 52, 4096);      // st_blksize
    }
}

int64_t do_syscall(Emulator& e, Sys sys, const uint64_t a[6]) {
    switch (sys) {
        case Sys::Write: {
            uint64_t fd = a[0], buf = a[1], len = a[2];
            std::string data(static_cast<size_t>(len), '\0');
            if (len) e.mem.read(buf, data.data(), len);
            host_write(static_cast<int>(fd), data);
            return static_cast<int64_t>(len);
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
                host_write(static_cast<int>(fd), data);
                total += len;
            }
            return static_cast<int64_t>(total);
        }
        case Sys::Read: {
            uint64_t fd = a[0], buf = a[1], len = a[2];
            if (fd != 0) return kEBADF;
            std::vector<char> tmp(static_cast<size_t>(len));
            size_t got = len ? std::fread(tmp.data(), 1, static_cast<size_t>(len), stdin) : 0;
            if (got) e.mem.write(buf, tmp.data(), got);
            return static_cast<int64_t>(got);
        }
        case Sys::Close:
            return 0;
        case Sys::Fstat:
            fake_stat(e, a[1], e.is64(), a[0] <= 2);
            return 0;
        case Sys::Ioctl:
            return kENOTTY;  // "not a terminal" is a valid answer libc handles
        case Sys::Mmap: {
            uint64_t len = a[1];
            uint64_t p = e.alloc_pages(len);
            return p ? static_cast<int64_t>(p) : -12 /* ENOMEM */;
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
        // Thread/signal setup a static libc performs at startup; pretending it
        // succeeded is enough because nothing here is ever delivered.
        case Sys::ArchPrctl:
        case Sys::SetTidAddress:
        case Sys::RtSigaction:
        case Sys::RtSigprocmask:
        case Sys::SetThreadArea:
            return 0;
        default:
            return kENOSYS;
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
