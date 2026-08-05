#include "processes.h"

#include <cstdio>
#include <string>

#include "loader.h"

namespace x86emu {

namespace {
// The same slice the thread scheduler uses; processes and threads interleave at
// the same grain.
constexpr uint64_t kQuantum = 20000;
}  // namespace

System::System(Emulator* root) {
    auto p = std::make_unique<Process>();
    // The pid getpid() answered back when there was only ever one process, kept
    // so that single-process runs stay byte-identical.
    p->pid = 4242;
    p->ppid = 1;
    p->emu = root;
    root_pid_ = p->pid;
    next_pid_ = p->pid + 1;
    root->set_system(this, p->pid);
    procs_.push_back(std::move(p));
}

System::Process* System::find(int pid) {
    for (auto& p : procs_)
        if (p->pid == pid && !p->reaped) return p.get();
    return nullptr;
}

bool System::is_zombie(int pid) {
    Process* p = find(pid);
    return p && p->zombie;
}

int System::exit_code_of(int pid) {
    Process* p = find(pid);
    return p ? p->exit_code : -1;
}

bool System::exec_done_or_zombie(int pid) {
    Process* p = find(pid);
    return !p || p->zombie || p->exec_done;
}

System::Process* System::zombie_child(int ppid, int pid) {
    for (auto& p : procs_)
        if (p->ppid == ppid && p->zombie && !p->reaped && (pid < 0 || p->pid == pid))
            return p.get();
    return nullptr;
}

bool System::has_children(int ppid) {
    for (auto& p : procs_)
        if (p->ppid == ppid && !p->reaped) return true;
    return false;
}

void System::make_zombie(Process& p, int exit_code) {
    p.zombie = true;
    p.exit_code = exit_code;
    if (p.emu) p.emu->flush_guest_output();
    // Release the process's resources now rather than at reap time: a zombie
    // holding the write end of a pipe would keep its parent from ever seeing
    // end-of-file.
    if (p.owned) {
        p.owned.reset();
        p.emu = nullptr;
    }
}

void System::terminate(int pid, int exit_code) {
    Process* p = find(pid);
    if (p && !p->zombie) make_zombie(*p, exit_code);
}

int System::spawn(const SpawnRequest& req) {
    Process* parent = find(req.ppid);
    auto child = std::make_unique<Emulator>(parent && parent->emu
                                                ? parent->emu->options()
                                                : Emulator::Options{});
    child->set_environment(req.env);
    if (!req.raw_command_line.empty()) child->set_raw_command_line(req.raw_command_line);
    if (parent && parent->emu) child->output_sink = parent->emu->output_sink;
    for (const auto& [fd, entry] : req.handles) child->files.install(fd, entry);

    // Loading runs guest code (DllMain and TLS callbacks on Windows), so any
    // failure - including a fault in the child's own initialisers - has to
    // surface as "the spawn failed", not escape into the parent's hook.
    try {
        child->load(req.path, req.argv);
    } catch (const LoadError&) {
        return -2;  // ENOENT: not a loadable image
    } catch (const std::exception& err) {
        std::fprintf(stderr, "x86emu: child %s failed to start: %s\n", req.path.c_str(),
                     err.what());
        return -8;  // ENOEXEC
    }

    auto p = std::make_unique<Process>();
    p->pid = next_pid_++;
    p->ppid = req.ppid;
    p->owned = std::move(child);
    p->emu = p->owned.get();
    p->emu->set_system(this, p->pid);
    procs_.push_back(std::move(p));
    return procs_.back()->pid;
}

int System::adopt(std::unique_ptr<Emulator> child, int ppid) {
    auto p = std::make_unique<Process>();
    p->pid = next_pid_++;
    p->ppid = ppid;
    p->owned = std::move(child);
    p->emu = p->owned.get();
    p->emu->set_system(this, p->pid);
    procs_.push_back(std::move(p));
    return procs_.back()->pid;
}

void System::do_exec(Process& p, Emulator::ExecRequest req) {
    Emulator* old = p.emu;
    auto fresh = std::make_unique<Emulator>(old->options());
    fresh->set_environment(req.env);
    fresh->files = old->files.clone();
    fresh->files.close_cloexec();
    fresh->output_sink = old->output_sink;
    try {
        fresh->load(req.path, req.argv);
    } catch (const LoadError&) {
        old->fail_exec(-2);  // ENOENT
        return;
    } catch (const std::exception& err) {
        std::fprintf(stderr, "x86emu: execve %s failed: %s\n", req.path.c_str(), err.what());
        old->fail_exec(-8);  // ENOEXEC
        return;
    }
    fresh->set_system(this, p.pid);
    p.owned = std::move(fresh);   // destroys the old image; the pid lives on
    p.emu = p.owned.get();
    p.exec_done = true;
}

int System::run_until_exit(int pid, int except_pid) {
    while (true) {
        Process* target = find(pid);
        if (!target) return -1;
        if (target->zombie) return target->exit_code;

        bool progress = false;
        for (size_t i = 0; i < procs_.size(); ++i) {
            Process& p = *procs_[i];
            if (p.zombie || !p.emu || p.pid == except_pid) continue;
            if (p.emu->has_exec_request()) {
                do_exec(p, std::move(*p.emu->take_exec_request()));
                progress = true;
                continue;
            }
            Emulator::SliceStatus st;
            try {
                st = p.emu->run_slice(kQuantum);
            } catch (...) {
                if (p.pid == root_pid_) throw;
                try {
                    throw;
                } catch (const std::exception& err) {
                    std::fflush(stdout);
                    std::fprintf(stderr, "x86emu: child pid %d (%s) crashed: %s\n", p.pid,
                                 p.emu->args().empty() ? "?" : p.emu->args()[0].c_str(),
                                 err.what());
                }
                make_zombie(p, 127);
                progress = true;
                continue;
            }
            if (st == Emulator::SliceStatus::Exited) {
                make_zombie(p, p.emu->cpu().exit_code);
                progress = true;
            } else if (st == Emulator::SliceStatus::Ran) {
                progress = true;
            }
        }
        if (!progress) {
            bool advanced = false;
            for (auto& p : procs_) {
                if (p->zombie || !p->emu || p->pid == except_pid) continue;
                uint64_t wake = p->emu->next_timer_wake();
                if (wake) {
                    p->emu->advance_time_to(wake);
                    advanced = true;
                }
            }
            if (!advanced) return -1;  // the child cannot finish; report failure
        }
    }
}

int System::run() {
    while (true) {
        bool progress = false;
        // procs_ may grow while iterating (a hook spawns a child); index-based
        // iteration keeps that safe, and the newcomer simply runs this round.
        for (size_t i = 0; i < procs_.size(); ++i) {
            Process& p = *procs_[i];
            if (p.zombie || !p.emu) continue;
            if (p.emu->has_exec_request()) {
                do_exec(p, std::move(*p.emu->take_exec_request()));
                progress = true;
                continue;
            }
            Emulator::SliceStatus st;
            try {
                st = p.emu->run_slice(kQuantum);
            } catch (...) {
                if (p.pid == root_pid_) throw;  // main() prints the diagnosis
                // A crashed child is a failed tool, not a failed emulator: report
                // it the way a shell would and let the parent see a bad exit.
                try {
                    throw;
                } catch (const std::exception& err) {
                    std::fflush(stdout);
                    std::fprintf(stderr, "x86emu: child pid %d (%s) crashed: %s\n", p.pid,
                                 p.emu->args().empty() ? "?" : p.emu->args()[0].c_str(),
                                 err.what());
                }
                // Becoming a zombie *is* progress: a parent blocked in wait4
                // wakes on it, and without saying so the very next check
                // declares deadlock before that parent ever runs again.
                make_zombie(p, 127);
                progress = true;
                continue;
            }
            switch (st) {
                case Emulator::SliceStatus::Exited:
                    make_zombie(p, p.emu->cpu().exit_code);
                    progress = true;
                    break;
                case Emulator::SliceStatus::Ran:
                    progress = true;
                    break;
                case Emulator::SliceStatus::Idle:
                    // Let an idle process's clock keep pace, so its timeouts
                    // expire while the others do the work.
                    p.emu->advance_time_to(p.emu->cpu().instructions_executed + kQuantum);
                    break;
            }
        }

        Process* root = find(root_pid_);
        if (!root || root->zombie) {
            int code = root ? root->exit_code : 0;
            return code;
        }

        if (!progress) {
            // Everyone is blocked.  Time here is instruction counts, so with the
            // whole system idle the clocks can jump to the earliest deadline.
            bool advanced = false;
            for (auto& p : procs_) {
                if (p->zombie || !p->emu) continue;
                uint64_t wake = p->emu->next_timer_wake();
                if (wake) {
                    p->emu->advance_time_to(wake);
                    advanced = true;
                }
            }
            if (!advanced) {
                // Naming who is stuck on what is the difference between a
                // one-line diagnosis and an afternoon: the usual cause is a
                // parent waiting for a child that died, or a pipe whose writer
                // no longer exists.
                std::string detail;
                for (const auto& p : procs_) {
                    if (p->reaped) continue;
                    char line[256];
                    std::snprintf(line, sizeof line, "    pid %d (%s): %s\n", p->pid,
                                  p->emu && !p->emu->args().empty()
                                      ? p->emu->args()[0].c_str()
                                      : "?",
                                  p->zombie ? "exited" : "blocked");
                    detail += line;
                }
                throw CpuError(root->emu->cpu().rip,
                               "all processes are blocked: deadlock\n" + detail);
            }
        }
    }
}

}  // namespace x86emu
