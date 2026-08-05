// Command line front end.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "emulator.h"

namespace {

void usage() {
    std::fprintf(stderr,
                 "x86emu - a small x86-32/x86-64 user-mode emulator\n"
                 "\n"
                 "usage: x86emu [options] <program> [guest args...]\n"
                 "\n"
                 "  Runs a PE (Windows) or ELF (Linux) executable by interpreting its\n"
                 "  machine code.  Library calls such as printf are intercepted and run\n"
                 "  natively on the host; Linux syscalls are implemented directly.\n"
                 "\n"
                 "options:\n"
                 "  -t, --trace          dump CPU state before every instruction\n"
                 "  -c, --trace-calls    log intercepted library calls and syscalls\n"
                 "  -m, --map            print the guest memory map after loading\n"
                 "  -n, --max-insns N    stop after N instructions (0 = unlimited)\n"
                 "  -d, --dump ADDR[:N]  hex dump N bytes of guest memory after loading\n"
                 "  -L, --libpath DIR    also look here for DLLs the guest imports\n"
                 "  -r, --sysroot DIR    treat DIR as a Linux guest's filesystem root\n"
                 "      --history N      on a fault, print the last N instruction addresses\n"
                 "      --imports        list imports with no implementation, then exit\n"
                 "  -h, --help           this text\n");
}

// The tail of --history, printed after a fault.  Runs of consecutive addresses
// are collapsed: what matters is the branches and calls, not the straight-line
// code between them.
void print_history(x86emu::Emulator& emu) {
    std::vector<uint64_t> h = emu.cpu().history();
    if (h.empty()) return;
    std::fprintf(stderr, "  last %zu instructions (--history):\n", h.size());
    for (size_t i = 0; i < h.size(); ++i) {
        // Only print an address when control did not simply fall through from
        // the previous one, plus the last few unconditionally.
        bool interesting = i == 0 || i + 4 >= h.size() || h[i] < h[i - 1] || h[i] > h[i - 1] + 16;
        if (!interesting) continue;
        std::fprintf(stderr, "    %012llX\n", (unsigned long long)h[i]);
    }
}

}  // namespace

int main(int argc, char** argv) {
    x86emu::Emulator::Options opt;
    std::string program;
    std::vector<std::string> guest_args;
    std::vector<std::pair<uint64_t, uint64_t>> dumps;
    size_t history = 0;

    int i = 1;
    for (; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-t" || a == "--trace") {
            opt.trace = true;
        } else if (a == "-c" || a == "--trace-calls") {
            opt.trace_calls = true;
        } else if (a == "-m" || a == "--map") {
            opt.dump_map = true;
        } else if (a == "-n" || a == "--max-insns") {
            if (i + 1 >= argc) {
                usage();
                return 2;
            }
            opt.max_instructions = std::strtoull(argv[++i], nullptr, 0);
        } else if (a == "--imports") {
            opt.imports_only = true;
        } else if (a == "-L" || a == "--libpath") {
            if (i + 1 >= argc) {
                usage();
                return 2;
            }
            opt.library_paths.push_back(argv[++i]);
        } else if (a == "--history") {
            if (i + 1 >= argc) {
                usage();
                return 2;
            }
            history = static_cast<size_t>(std::strtoull(argv[++i], nullptr, 0));
        } else if (a == "-r" || a == "--sysroot") {
            if (i + 1 >= argc) {
                usage();
                return 2;
            }
            x86emu::FileTable::set_sysroot(argv[++i]);
        } else if (a == "-d" || a == "--dump") {
            if (i + 1 >= argc) {
                usage();
                return 2;
            }
            std::string spec = argv[++i];
            size_t colon = spec.find(':');
            uint64_t addr = std::strtoull(spec.substr(0, colon).c_str(), nullptr, 0);
            uint64_t len = colon == std::string::npos
                               ? 64
                               : std::strtoull(spec.substr(colon + 1).c_str(), nullptr, 0);
            dumps.emplace_back(addr, len);
        } else if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else if (!a.empty() && a[0] == '-' && a != "-") {
            std::fprintf(stderr, "x86emu: unknown option %s\n", a.c_str());
            return 2;
        } else {
            program = a;
            ++i;
            break;
        }
    }
    if (program.empty()) {
        usage();
        return 2;
    }
    // Everything after the program name belongs to the guest; argv[0] is the
    // program itself, as a real process would see it.
    guest_args.push_back(program);
    for (; i < argc; ++i) guest_args.push_back(argv[i]);

    x86emu::Emulator emu(opt);
    try {
        emu.load(program, guest_args);
    } catch (const x86emu::LoadError& err) {
        std::fprintf(stderr, "x86emu: cannot load %s: %s\n", program.c_str(), err.what());
        return 1;
    } catch (const std::exception& err) {
        // Loading now runs guest code (DllMain, TLS callbacks), so a fault here is
        // possible and belongs in a message rather than escaping as a crash.
        std::fflush(stdout);
        std::fprintf(stderr, "x86emu: while loading %s: %s\n", program.c_str(), err.what());
        if (const auto* fault = dynamic_cast<const x86emu::MemoryFault*>(&err)) {
            std::string what = emu.describe_address(fault->addr);
            if (!what.empty()) std::fprintf(stderr, "  %s\n", what.c_str());
        }
        std::fprintf(stderr, "  %s\n", emu.cpu().state_line().c_str());
        return 1;
    }

    if (opt.imports_only) {
        for (const auto& name : emu.unimplemented_imports()) std::printf("%s\n", name.c_str());
        return 0;
    }

    if (history) emu.cpu().enable_history(history);

    // Dumps happen after loading and before the first instruction, which is
    // where you want them when checking that an image was mapped correctly.
    for (const auto& [addr, len] : dumps) {
        std::fprintf(stderr, "dump 0x%llX:\n", (unsigned long long)addr);
        for (uint64_t off = 0; off < len; off += 16) {
            std::fprintf(stderr, "  %012llX ", (unsigned long long)(addr + off));
            char text[17] = {};
            for (uint64_t k = 0; k < 16 && off + k < len; ++k) {
                uint8_t b = 0;
                try {
                    b = emu.mem.read8(addr + off + k);
                } catch (const x86emu::MemoryFault&) {
                    std::fprintf(stderr, "-- ");
                    text[k] = '.';
                    continue;
                }
                std::fprintf(stderr, "%02X ", b);
                text[k] = (b >= 32 && b < 127) ? static_cast<char>(b) : '.';
            }
            std::fprintf(stderr, " %s\n", text);
        }
    }

    try {
        int code = emu.run();
        if (opt.trace_calls || opt.dump_map)
            std::fprintf(stderr, "[exit] code %d after %llu instructions\n", code,
                         (unsigned long long)emu.cpu().instructions_executed);
        return code;
    } catch (const x86emu::CpuError& err) {
        std::fflush(stdout);
        std::fprintf(stderr, "\nx86emu: %s\n", err.what());
        std::fprintf(stderr, "  %s\n", emu.cpu().state_line().c_str());
        std::fprintf(stderr, "  after %llu instructions\n",
                     (unsigned long long)emu.cpu().instructions_executed);
        print_history(emu);
        return 1;
    } catch (const x86emu::MemoryFault& err) {
        std::fflush(stdout);
        std::fprintf(stderr, "\nx86emu: %s\n", err.what());
        // Saying what the address is turns "unmapped read" into an explanation.
        std::string what = emu.describe_address(err.addr);
        if (!what.empty()) std::fprintf(stderr, "  %s\n", what.c_str());
        std::fprintf(stderr, "  %s\n", emu.cpu().state_line().c_str());
        std::string trace = emu.stack_trace();
        if (!trace.empty()) std::fprintf(stderr, "  possible callers:\n%s", trace.c_str());
        print_history(emu);
        return 1;
    }
}
