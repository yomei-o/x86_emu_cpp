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
#if defined(_WIN32)
#include <direct.h>  // _chdir, _getcwd
#else
#include <unistd.h>  // getcwd/chdir, for the Linux/emscripten host
#endif

#include "emulator.h"
#include "processes.h"

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
    Fork, Vfork, Execve, Wait4, Kill, Pipe, Pipe2, Clone, Getppid, SchedYield,
    Chdir, Fchdir,
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
        case 22: return Sys::Pipe;
        case 293: return Sys::Pipe2;
        case 24: return Sys::SchedYield;
        case 56: return Sys::Clone;
        case 57: return Sys::Fork;
        case 58: return Sys::Vfork;
        case 59: return Sys::Execve;
        case 61: return Sys::Wait4;
        case 62: return Sys::Kill;
        case 80: return Sys::Chdir;
        case 81: return Sys::Fchdir;
        case 110: return Sys::Getppid;
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
        case 2: return Sys::Fork;
        case 190: return Sys::Vfork;
        case 11: return Sys::Execve;
        case 7: return Sys::Wait4;    // waitpid: same shape, no rusage
        case 114: return Sys::Wait4;
        case 37: return Sys::Kill;
        case 42: return Sys::Pipe;
        case 331: return Sys::Pipe2;
        case 120: return Sys::Clone;
        case 64: return Sys::Getppid;
        case 12: return Sys::Chdir;
        case 133: return Sys::Fchdir;
        case 158: return Sys::SchedYield;
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
constexpr int64_t kEAGAIN = -11;

void host_write(Emulator& e, int fd, const std::string& data) {
    e.write_raw(fd, data.data(), data.size());
}

int64_t host_chdir(const std::string& path) {
#if defined(_WIN32)
    return _chdir(path.c_str()) == 0 ? 0 : -2;  // ENOENT
#else
    return ::chdir(path.c_str()) == 0 ? 0 : -2;
#endif
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
            if (got == kEAGAINPipe) {
                // An empty pipe with a live writer: block this thread and run
                // the syscall again when bytes or end-of-file arrive.
                auto end = e.files.get(static_cast<int>(a[0]))->pipe_end;
                e.block_syscall_retry([end] {
                    return !end->pipe->buffer.empty() || end->pipe->writers <= 0;
                });
                return kEAGAINPipe;  // never written back; the retry answers
            }
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
        case Sys::Exit: {
            // exit() ends the calling *thread*; exit_group ends the process.
            // With one thread they are the same thing.
            Emulator::GuestThread* t = e.current_thread();
            if (t && e.threads().size() > 1) {
                if (t->clear_child_tid) {
                    // CLONE_CHILD_CLEARTID: pthread_join waits on this word.
                    e.mem.write32(t->clear_child_tid, 0);
                }
                e.exit_thread(static_cast<uint32_t>(a[0]));
                return 0;
            }
            e.exit_process(static_cast<int>(static_cast<int32_t>(a[0])));
            return 0;
        }
        case Sys::ExitGroup:
            e.exit_process(static_cast<int>(static_cast<int32_t>(a[0])));
            return 0;
        case Sys::Getpid:
            return e.pid();
        case Sys::Getppid: {
            if (!e.system()) return 1;
            System::Process* p = e.system()->find(e.pid());
            return p ? p->ppid : 1;
        }
        case Sys::SchedYield:
            e.yield_now();
            return 0;
        case Sys::Fork:
        case Sys::Vfork: {
            if (!e.system()) return kENOSYS;
            std::unique_ptr<Emulator> child = e.fork_clone();
            int pid = e.system()->adopt(std::move(child), e.pid());
            if (sys == Sys::Vfork) {
                // vfork suspends the parent until the child execs or exits.
                System* s = e.system();
                Emulator::GuestThread* t = e.current_thread();
                if (t) {
                    t->state = Emulator::GuestThread::State::Blocked;
                    t->wait_predicate = [s, pid] { return s->exec_done_or_zombie(pid); };
                    e.yield_now();
                }
            }
            if (e.options().trace_calls)
                std::fprintf(stderr, "[sys] %s -> pid %d\n",
                             sys == Sys::Vfork ? "vfork" : "fork", pid);
            return pid;
        }
        case Sys::Clone: {
            // clone(flags, stack, parent_tid, child_tid, tls) on x86-64; the
            // last two arguments trade places on i386.
            uint64_t flags = a[0], stack = a[1], parent_tid = a[2];
            uint64_t child_tid = e.is64() ? a[3] : a[4];
            uint64_t tls = e.is64() ? a[4] : a[3];
            constexpr uint64_t kVm = 0x100, kVfork = 0x4000, kThread = 0x10000;
            constexpr uint64_t kSettls = 0x80000, kParentSettid = 0x100000;
            constexpr uint64_t kChildCleartid = 0x200000, kChildSettid = 0x1000000;

            if ((flags & kVm) && (flags & kThread)) {
                // A thread: same address space, new stack, new TLS.  Raw clone
                // semantics - the child resumes right here with RAX = 0.
                uint32_t tid = e.clone_thread(stack, (flags & kSettls) ? tls : 0,
                                              (flags & kChildCleartid) ? child_tid : 0);
                if (flags & kParentSettid) e.mem.write32(parent_tid, tid);
                if (flags & kChildSettid) e.mem.write32(child_tid, tid);
                if (e.options().trace_calls)
                    std::fprintf(stderr, "[sys] clone(thread) -> tid %u\n", tid);
                return tid;
            }
            // A process.  CLONE_VM without CLONE_VFORK cannot be honoured with
            // a copied address space, but CLONE_VFORK's suspend-until-exec means
            // the parent never looks at the (unshared) memory in between - which
            // is exactly posix_spawn's pattern.
            if (!e.system()) return kENOSYS;
            std::unique_ptr<Emulator> child = e.fork_clone();
            if (stack) child->cpu().regs[RSP] = stack;
            int pid = e.system()->adopt(std::move(child), e.pid());
            if (flags & kVfork) {
                System* s = e.system();
                Emulator::GuestThread* t = e.current_thread();
                if (t) {
                    t->state = Emulator::GuestThread::State::Blocked;
                    t->wait_predicate = [s, pid] { return s->exec_done_or_zombie(pid); };
                    e.yield_now();
                }
            }
            if (e.options().trace_calls)
                std::fprintf(stderr, "[sys] clone(process, flags 0x%llx) -> pid %d\n",
                             (unsigned long long)flags, pid);
            return pid;
        }
        case Sys::Execve: {
            std::string path = e.mem.read_cstring(a[0]);
            int ps = e.pointer_size();
            std::vector<std::string> argv;
            for (uint64_t p = a[1]; p; p += ps) {
                uint64_t s = e.mem.read_sized(p, ps);
                if (!s) break;
                argv.push_back(e.mem.read_cstring(s));
            }
            std::vector<std::pair<std::string, std::string>> env;
            for (uint64_t p = a[2]; p; p += ps) {
                uint64_t s = e.mem.read_sized(p, ps);
                if (!s) break;
                std::string entry = e.mem.read_cstring(s);
                size_t eq = entry.find('=');
                if (eq != std::string::npos && eq > 0)
                    env.emplace_back(entry.substr(0, eq), entry.substr(eq + 1));
            }
            if (argv.empty()) argv.push_back(path);
            if (e.options().trace_calls)
                std::fprintf(stderr, "[sys] execve(%s)\n", path.c_str());
            Emulator::ExecRequest req;
            req.path = FileTable::host_path(path);
            req.argv = std::move(argv);
            req.env = std::move(env);
            e.request_exec(std::move(req));
            return 0;  // on success this thread never sees the return value
        }
        case Sys::Wait4: {
            // (pid, status*, options, rusage)
            if (!e.system()) return kENOSYS;
            System* s = e.system();
            int want = static_cast<int>(static_cast<int32_t>(a[0]));
            int self = e.pid();
            System::Process* z = s->zombie_child(self, want <= 0 ? -1 : want);
            if (!z) {
                if (!s->has_children(self)) return -10;  // ECHILD
                if (a[2] & 1) return 0;                  // WNOHANG
                e.block_syscall_retry([s, self, want] {
                    return s->zombie_child(self, want <= 0 ? -1 : want) != nullptr ||
                           !s->has_children(self);
                });
                return 0;  // retried; never written back
            }
            z->reaped = true;
            if (a[1]) e.mem.write32(a[1], static_cast<uint32_t>(z->exit_code & 0xFF) << 8);
            return z->pid;
        }
        case Sys::Kill: {
            int target = static_cast<int>(static_cast<int32_t>(a[0]));
            int sig = static_cast<int>(a[1]);
            if (target == e.pid()) {
                if (sig) e.exit_process(128 + sig);
                return 0;
            }
            if (!e.system() || !e.system()->find(target)) return -3;  // ESRCH
            if (sig) e.system()->terminate(target, 128 + sig);
            return 0;
        }
        case Sys::Pipe:
        case Sys::Pipe2: {
            int fds[2];
            int r = e.files.make_pipe(fds);
            if (r != 0) return r;
            constexpr uint32_t kCloexec = 02000000;
            if (sys == Sys::Pipe2 && (a[1] & kCloexec)) {
                e.files.get(fds[0])->cloexec = true;
                e.files.get(fds[1])->cloexec = true;
            }
            e.mem.write32(a[0], static_cast<uint32_t>(fds[0]));
            e.mem.write32(a[0] + 4, static_cast<uint32_t>(fds[1]));
            return 0;
        }
        case Sys::Chdir: {
            std::string path = FileTable::host_path(e.mem.read_cstring(a[0]));
            return host_chdir(path);
        }
        case Sys::Fchdir: {
            FileTable::Entry* entry = e.files.get(static_cast<int>(a[0]));
            if (!entry || !entry->is_directory) return -20;  // ENOTDIR
            return host_chdir(FileTable::host_path(entry->path));
        }
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
        case Sys::Gettid: {
            // The main thread's tid is the pid, as Linux has it.
            Emulator::GuestThread* t = e.current_thread();
            if (!t || e.threads().empty() || t == e.threads()[0].get())
                return e.pid();
            return t->id;
        }
        case Sys::GetIds:
            return 0;  // running as root, which nothing here checks
        case Sys::Readlink: {
            // A Unix runtime finds its own executable through /proc/self/exe -
            // CPython's getpath depends on it. There is no real procfs, so answer
            // it (and /proc/self/cwd) from what the emulator already knows.  The
            // answer must be absolute and start with '/' (glibc's ld.so asserts
            // exactly that); a Windows host path is spelled "/C:/dir/prog".
            std::string path = e.mem.read_cstring(a[0]);
            std::string target;
            if (path == "/proc/self/exe")
                target = e.args().empty() ? std::string() : e.args()[0];
            if (target.empty()) return -22;  // EINVAL: nothing we resolve
            for (char& c : target)
                if (c == '\\') c = '/';
            if (target[0] != '/') {
                if (target.size() > 1 && target[1] == ':') {
                    target = "/" + target;  // absolute Windows path
                } else {
                    char buf[4096];
#if defined(_WIN32)
                    if (_getcwd(buf, sizeof buf)) {
                        std::string cwd = buf;
                        for (char& c : cwd)
                            if (c == '\\') c = '/';
                        target = "/" + cwd + "/" + target;
                    }
#else
                    if (::getcwd(buf, sizeof buf)) target = std::string(buf) + "/" + target;
#endif
                }
            }
            uint64_t buf = a[1];
            size_t n = std::min<size_t>(target.size(), static_cast<size_t>(a[2]));
            for (size_t i = 0; i < n; ++i) e.mem.write8(buf + i, static_cast<uint8_t>(target[i]));
            return static_cast<int64_t>(n);  // readlink does not NUL-terminate
        }
        case Sys::SetTidAddress: {
            // Records where to write 0 (and wake) when this thread exits;
            // pthread_join on the main thread depends on it.
            Emulator::GuestThread* t = e.current_thread();
            if (t) t->clear_child_tid = a[0];
            return (!t || e.threads().empty() || t == e.threads()[0].get()) ? e.pid()
                                                                            : t->id;
        }
        case Sys::Futex: {
            // (addr, op, val, timeout/val2, addr2, val3)
            uint64_t addr = a[0];
            int op = static_cast<int>(a[1]) & 0x7F;  // strip FUTEX_PRIVATE_FLAG
            uint32_t val = static_cast<uint32_t>(a[2]);
            switch (op) {
                case 0:    // FUTEX_WAIT
                case 9: {  // FUTEX_WAIT_BITSET
                    if (e.mem.read32(addr) != val) return kEAGAIN;
                    // Waking "when the word changes" allows spurious wakeups,
                    // which the futex contract explicitly permits; the waiter
                    // re-checks and calls back in if it must.
                    Memory* m = &e.mem;
                    e.block_syscall_retry([m, addr, val] { return m->read32(addr) != val; });
                    return 0;
                }
                case 1:    // FUTEX_WAKE
                case 10:   // FUTEX_WAKE_BITSET
                    // Waiters watch the word itself; there is no queue to pop.
                    return static_cast<int64_t>(val);
                default:
                    return 0;  // requeue and friends: claim success
            }
        }
        // Signal handling and memory advice: a static libc sets these up at
        // startup, and since nothing is ever delivered, reporting success is
        // accurate.
        case Sys::RtSigaction:
        case Sys::RtSigprocmask:
        case Sys::Mprotect:
        case Sys::Madvise:
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
        // A blocked syscall rewound RIP to run again; RAX still holds the
        // syscall number and must survive until the retry.
        if (!cpu_->halted && !take_syscall_block()) cpu_->regs[RAX] = static_cast<uint64_t>(r);
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
        if (!cpu_->halted && !take_syscall_block())
            cpu_->regs[RAX] = static_cast<uint64_t>(r) & 0xFFFFFFFFull;
    };
}

}  // namespace x86emu
