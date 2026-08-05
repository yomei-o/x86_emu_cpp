// Win32 process creation: CreateProcess, pipes, process handles.
//
// A compiler driver is mostly this file: gcc.exe runs cc1.exe, as.exe and
// ld.exe with CreateProcess, hands them temp files or pipes, and waits.  The
// child is a fresh Emulator built by the System; the handle the parent gets
// back is an ordinary waitable object whose signalled state is "the System says
// that pid is finished", so WaitForSingleObject needs nothing new.
#include <cstring>
#include <string>
#include <vector>

#include "emulator.h"
#include "guest_printf.h"
#include "processes.h"

namespace x86emu {
namespace {

// Splits a Windows command line into argv, by the rules CommandLineToArgvW and
// the CRT use: backslashes are literal except before a quote, where n
// backslashes plus a quote become n/2 backslashes and (if n is odd) a literal
// quote; a quote toggles whitespace-splitting; "" inside quotes is a quote.
std::vector<std::string> split_command_line(const std::string& cmd) {
    std::vector<std::string> argv;
    size_t i = 0;
    while (i < cmd.size() && (cmd[i] == ' ' || cmd[i] == '\t')) ++i;
    if (i >= cmd.size()) return argv;

    // The program name follows simpler rules: no backslash games, just an
    // optional pair of quotes around the whole token.
    std::string arg0;
    if (cmd[i] == '"') {
        ++i;
        while (i < cmd.size() && cmd[i] != '"') arg0 += cmd[i++];
        if (i < cmd.size()) ++i;
    } else {
        while (i < cmd.size() && cmd[i] != ' ' && cmd[i] != '\t') arg0 += cmd[i++];
    }
    argv.push_back(arg0);

    while (true) {
        while (i < cmd.size() && (cmd[i] == ' ' || cmd[i] == '\t')) ++i;
        if (i >= cmd.size()) break;
        std::string arg;
        bool in_quotes = false;
        while (i < cmd.size()) {
            char c = cmd[i];
            if (c == '\\') {
                size_t n = 0;
                while (i < cmd.size() && cmd[i] == '\\') {
                    ++n;
                    ++i;
                }
                if (i < cmd.size() && cmd[i] == '"') {
                    arg.append(n / 2, '\\');
                    if (n % 2) {
                        arg += '"';
                        ++i;
                    }
                } else {
                    arg.append(n, '\\');
                }
                continue;
            }
            if (c == '"') {
                if (in_quotes && i + 1 < cmd.size() && cmd[i + 1] == '"') {
                    arg += '"';
                    i += 2;
                    continue;
                }
                in_quotes = !in_quotes;
                ++i;
                continue;
            }
            if (!in_quotes && (c == ' ' || c == '\t')) break;
            arg += c;
            ++i;
        }
        argv.push_back(arg);
    }
    return argv;
}

bool file_exists(const std::string& path) {
    FileTable::Stat st;
    return FileTable::stat_path(path, st) == 0 && !st.is_dir;
}

// Resolves the program a spawn names, the way CreateProcess does: an explicit
// path is tried as-is and with ".exe"; a bare name is additionally searched in
// the current directory and along PATH.
std::string resolve_program(Emulator& e, const std::string& name) {
    if (name.empty()) return {};
    auto try_one = [](const std::string& p) -> std::string {
        if (file_exists(p)) return p;
        // Look for an extension in the last component only.
        size_t slash = p.find_last_of("/\\");
        std::string base = slash == std::string::npos ? p : p.substr(slash + 1);
        if (base.find('.') == std::string::npos && file_exists(p + ".exe")) return p + ".exe";
        return {};
    };
    bool has_dir = name.find('/') != std::string::npos || name.find('\\') != std::string::npos;
    if (std::string r = try_one(name); !r.empty()) return r;
    if (has_dir) return {};
    // Bare name: the program's own directory, then PATH.
    if (!e.args().empty()) {
        std::string self = e.args()[0];
        size_t slash = self.find_last_of("/\\");
        if (slash != std::string::npos) {
            if (std::string r = try_one(self.substr(0, slash + 1) + name); !r.empty()) return r;
        }
    }
    if (const std::string* path = e.getenv("PATH")) {
        size_t start = 0;
        while (start <= path->size()) {
            size_t sep = path->find(';', start);
            std::string dir = path->substr(start, sep == std::string::npos ? std::string::npos
                                                                           : sep - start);
            if (!dir.empty()) {
                char last = dir.back();
                if (last != '/' && last != '\\') dir += '\\';
                if (std::string r = try_one(dir + name); !r.empty()) return r;
            }
            if (sep == std::string::npos) break;
            start = sep + 1;
        }
    }
    return {};
}

// Reads an environment block ("NAME=VALUE\0...\0\0"), narrow or wide, into the
// pair list a child Emulator wants.
std::vector<std::pair<std::string, std::string>> read_environment_block(Emulator& e,
                                                                        uint64_t block,
                                                                        bool wide) {
    std::vector<std::pair<std::string, std::string>> env;
    uint64_t p = block;
    while (true) {
        std::string entry;
        if (wide) {
            entry = utf16_to_utf8(e, p, -1);
            p += (entry.size() + 1) * 2;  // close enough for ASCII env vars
        } else {
            entry = e.mem.read_cstring(p);
            p += entry.size() + 1;
        }
        if (entry.empty()) break;
        size_t eq = entry.find('=');
        if (eq != std::string::npos && eq > 0)
            env.emplace_back(entry.substr(0, eq), entry.substr(eq + 1));
    }
    return env;
}

void create_process(Emulator& e, bool wide) {
    Emulator::Args a(e);
    uint64_t app_ptr = a.next_ptr();
    uint64_t cmd_ptr = a.next_ptr();
    a.next_ptr();  // process attributes
    a.next_ptr();  // thread attributes
    a.next_int(4); // bInheritHandles: descriptors named in STARTUPINFO are enough
    uint64_t creation_flags = a.next_int(4);
    uint64_t env_ptr = a.next_ptr();
    uint64_t cwd_ptr = a.next_ptr();
    uint64_t startup_ptr = a.next_ptr();
    uint64_t procinfo_ptr = a.next_ptr();

    auto read_str = [&](uint64_t p) -> std::string {
        if (!p) return {};
        return wide ? utf16_to_utf8(e, p, -1) : e.mem.read_cstring(p);
    };
    std::string app = read_str(app_ptr);
    std::string cmd = read_str(cmd_ptr);
    std::vector<std::string> argv = split_command_line(cmd.empty() ? app : cmd);
    if (argv.empty()) argv.push_back(app);

    std::string program = resolve_program(e, app.empty() ? argv[0] : app);
    e.log_call("CreateProcess(%s) -> %s", (app.empty() ? argv[0] : app).c_str(),
               program.empty() ? "not found" : program.c_str());
    e.log_call("  command line: %s", cmd.c_str());
    if (program.empty()) {
        e.set_last_error(2);  // ERROR_FILE_NOT_FOUND
        e.set_result(0);
        return;
    }
    if (cwd_ptr) {
        // Per-process working directories are not modelled; a child asked to
        // start elsewhere would quietly misbehave, so say so loudly.
        std::fprintf(stderr, "x86emu: CreateProcess(%s): lpCurrentDirectory ignored\n",
                     program.c_str());
    }

    System::SpawnRequest req;
    req.path = FileTable::host_path(program);
    req.argv = std::move(argv);
    req.raw_command_line = cmd.empty() ? app : cmd;
    req.ppid = e.pid();
    constexpr uint64_t kCreateUnicodeEnvironment = 0x400;
    req.env = env_ptr ? read_environment_block(e, env_ptr,
                                               wide || (creation_flags & kCreateUnicodeEnvironment))
                      : e.environment();

    // The child starts from the parent's standard descriptors, overridden by
    // whatever STARTUPINFO names.
    for (int fd = 0; fd < 3; ++fd)
        if (FileTable::Entry* entry = e.files.get(fd)) req.handles.emplace_back(fd, *entry);
    if (startup_ptr) {
        bool w64 = e.is64();
        uint32_t flags = e.mem.read32(startup_ptr + (w64 ? 60 : 44));
        constexpr uint32_t kStartfUseStdHandles = 0x100;
        if (flags & kStartfUseStdHandles) {
            uint64_t h_in = e.mem.read_sized(startup_ptr + (w64 ? 80 : 56), e.pointer_size());
            uint64_t h_out = e.mem.read_sized(startup_ptr + (w64 ? 88 : 60), e.pointer_size());
            uint64_t h_err = e.mem.read_sized(startup_ptr + (w64 ? 96 : 64), e.pointer_size());
            const uint64_t hs[3] = {h_in, h_out, h_err};
            for (int i = 0; i < 3; ++i) {
                int fd = Emulator::fd_from_handle(hs[i]);
                if (fd < 0) continue;
                if (FileTable::Entry* entry = e.files.get(fd))
                    req.handles.emplace_back(i, *entry);
            }
        }
    }

    int pid = e.system()->spawn(req);
    if (pid < 0) {
        e.set_last_error(pid == -2 ? 2 /* FILE_NOT_FOUND */ : 193 /* BAD_EXE_FORMAT */);
        e.set_result(0);
        return;
    }

    uint64_t h_process =
        e.create_sync_object(Emulator::SyncObject::Kind::Process, true, false, 0);
    e.sync_object(h_process)->owner = static_cast<uint32_t>(pid);
    // The primary-thread handle: waiting on it means waiting for the process,
    // which is also what it means on real Windows once the thread is the last.
    uint64_t h_thread =
        e.create_sync_object(Emulator::SyncObject::Kind::Process, true, false, 0);
    e.sync_object(h_thread)->owner = static_cast<uint32_t>(pid);

    if (procinfo_ptr) {
        int ps = e.pointer_size();
        e.mem.write_sized(procinfo_ptr, ps, h_process);
        e.mem.write_sized(procinfo_ptr + ps, ps, h_thread);
        e.mem.write32(procinfo_ptr + 2 * ps, static_cast<uint32_t>(pid));
        e.mem.write32(procinfo_ptr + 2 * ps + 4, static_cast<uint32_t>(pid) | 0x10000);
    }
    e.set_result(1);
}

}  // namespace

void Emulator::install_process_hooks() {
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, is64() ? 0 : nargs * 4, std::move(fn));
    };

    win32("CreateProcessA", 10, [](Emulator& e) { create_process(e, false); });
    win32("CreateProcessW", 10, [](Emulator& e) { create_process(e, true); });

    // (read_out, write_out, security_attributes, suggested_size)
    win32("CreatePipe", 4, [](Emulator& e) {
        int fds[2];
        if (e.files.make_pipe(fds) != 0) {
            e.set_result(0);
            return;
        }
        if (e.arg_slot(0)) e.mem.write_sized(e.arg_slot(0), e.pointer_size(),
                                             Emulator::handle_from_fd(fds[0]));
        if (e.arg_slot(1)) e.mem.write_sized(e.arg_slot(1), e.pointer_size(),
                                             Emulator::handle_from_fd(fds[1]));
        e.set_result(1);
    });
    // Handle inheritance flags: descriptors named in STARTUPINFO reach the
    // child regardless, so the flag itself has nothing to record.
    win32("SetHandleInformation", 3, [](Emulator& e) { e.set_result(1); });

    // (pipe, buffer, size, bytes_read, bytes_avail, bytes_left_this_message)
    win32("PeekNamedPipe", 6, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        FileTable::Entry* entry = fd >= 0 ? e.files.get(fd) : nullptr;
        if (!entry || !entry->is_pipe()) {
            e.set_last_error(6);  // ERROR_INVALID_HANDLE
            e.set_result(0);
            return;
        }
        const auto& buf = entry->pipe_end->pipe->buffer;
        uint64_t want = std::min<uint64_t>(e.arg_slot(2), buf.size());
        if (e.arg_slot(1) && want) {
            std::vector<uint8_t> tmp(buf.begin(), buf.begin() + static_cast<long>(want));
            e.mem.write(e.arg_slot(1), tmp.data(), want);
        }
        if (e.arg_slot(3)) e.mem.write32(e.arg_slot(3), static_cast<uint32_t>(want));
        if (e.arg_slot(4)) e.mem.write32(e.arg_slot(4), static_cast<uint32_t>(buf.size()));
        if (e.arg_slot(5)) e.mem.write32(e.arg_slot(5), 0);
        e.set_result(1);
    });

    win32("GetExitCodeProcess", 2, [](Emulator& e) {
        auto* o = e.sync_object(e.arg_slot(0));
        if (!o || o->kind != SyncObject::Kind::Process || !e.system()) {
            e.set_last_error(6);  // ERROR_INVALID_HANDLE
            e.set_result(0);
            return;
        }
        int pid = static_cast<int>(o->owner);
        uint32_t code = e.system()->is_zombie(pid)
                            ? static_cast<uint32_t>(e.system()->exit_code_of(pid))
                            : 259;  // STILL_ACTIVE
        if (e.arg_slot(1)) e.mem.write32(e.arg_slot(1), code);
        e.set_result(1);
    });

    win32("GetProcessId", 1, [](Emulator& e) {
        auto* o = e.sync_object(e.arg_slot(0));
        e.set_result(o && o->kind == SyncObject::Kind::Process ? o->owner : 0);
    });

    win32("TerminateProcess", 2, [](Emulator& e) {
        uint64_t handle = e.arg_slot(0);
        int code = static_cast<int>(e.arg_slot(1));
        if (handle == ~0ull) {  // GetCurrentProcess()
            e.exit_process(code);
            return;
        }
        auto* o = e.sync_object(handle);
        if (o && o->kind == SyncObject::Kind::Process && e.system()) {
            e.system()->terminate(static_cast<int>(o->owner), code);
            e.set_result(1);
            return;
        }
        // The old behaviour, for a guest terminating itself through a handle
        // the emulator never issued.
        e.exit_process(code);
    });

    // (src_process, src_handle, dst_process, out_handle, access, inherit, options)
    win32("DuplicateHandle", 7, [](Emulator& e) {
        uint64_t src = e.arg_slot(1);
        uint64_t out = e.arg_slot(3);
        uint64_t result = src;
        int fd = Emulator::fd_from_handle(src);
        if (fd >= 0 && e.files.get(fd)) {
            int copy = e.files.dup(fd);
            if (copy < 0) {
                e.set_result(0);
                return;
            }
            result = Emulator::handle_from_fd(copy);
        } else if (auto* o = e.sync_object(src)) {
            uint64_t copy = e.create_sync_object(o->kind, o->manual_reset, o->signalled,
                                                 o->count);
            *e.sync_object(copy) = *o;
            result = copy;
        }
        // Pseudo-handles (~0 = this process) pass through unchanged.
        if (out) e.mem.write_sized(out, e.pointer_size(), result);
        e.set_result(1);
    });
}

}  // namespace x86emu
