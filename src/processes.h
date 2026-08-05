// Guest processes.
//
// One Emulator is one guest process: its own address space, CPU, descriptor
// table and threads.  The System owns the process table and runs the emulators
// round-robin, a quantum at a time, the same way each emulator already runs its
// own threads.  Everything shared between processes - pipes, host files - is
// reference counted and lives in FileTable entries, so the System itself only
// has to know who is alive, who has exited, and who is waiting for whom.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "emulator.h"

namespace x86emu {

class System {
public:
    struct Process {
        int pid = 0;
        int ppid = 0;
        Emulator* emu = nullptr;          // the root is caller-owned; children are owned_
        std::unique_ptr<Emulator> owned;
        bool zombie = false;              // finished, exit_code valid, not yet reaped
        bool reaped = false;              // a wait() collected it; forget it entirely
        bool exec_done = false;           // an execve replaced the image (vfork wakes on this)
        int exit_code = 0;
    };

    // What a spawn request needs, regardless of which OS API asked for it.
    struct SpawnRequest {
        std::string path;                              // host-resolvable program path
        std::vector<std::string> argv;
        std::vector<std::pair<std::string, std::string>> env;
        std::string raw_command_line;                  // Windows: the exact string
        // Descriptors for the child's fds 0/1/2, given as entries from the
        // parent's table; empty entries mean "inherit the host's".
        std::vector<std::pair<int, FileTable::Entry>> handles;
        int ppid = 0;
    };

    explicit System(Emulator* root);

    // Runs every process until the root exits; returns the root's exit code.
    int run();

    // Creates a process from an executable image.  Returns the pid, or a
    // negative errno-style code (-2 if the image cannot be loaded).
    int spawn(const SpawnRequest& req);
    // Adopts an already-built emulator (fork_clone's result) as a child of
    // `ppid`; returns its pid.
    int adopt(std::unique_ptr<Emulator> child, int ppid);

    Process* find(int pid);
    bool is_zombie(int pid);
    int exit_code_of(int pid);
    bool exec_done_or_zombie(int pid);
    // A zombie child of `ppid` (matching `pid` if >= 0), or nullptr.  The
    // caller reaps it by setting `reaped`.
    Process* zombie_child(int ppid, int pid = -1);
    bool has_children(int ppid);

    // Terminates a process from outside (TerminateProcess, kill).
    void terminate(int pid, int exit_code);

    // Runs the machine until `pid` finishes, never scheduling `except_pid` -
    // for a hook (_wspawnv with _P_WAIT) that must wait for a child while its
    // own process is paused inside the hook.  Returns the child's exit code.
    int run_until_exit(int pid, int except_pid);

private:
    void make_zombie(Process& p, int exit_code);
    void do_exec(Process& p, Emulator::ExecRequest req);

    std::vector<std::unique_ptr<Process>> procs_;
    int root_pid_ = 0;
    int next_pid_ = 0;
};

}  // namespace x86emu
