// The emulator: guest memory layout, the hook mechanism, and the ABI glue that
// lets host C++ functions stand in for guest library calls.
//
// Hooks work by giving every intercepted function a unique fake guest address
// in an otherwise unused region.  Loaders write those addresses into the import
// table, so when the guest calls printf it jumps into the hook region; the CPU
// notices before fetching, runs the host implementation, and performs the
// return itself.  No guest code for the library ever has to exist.
#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "cpu.h"
#include "loader.h"
#include "memory.h"

namespace x86emu {

// How arguments reach a called function.
enum class Abi {
    Cdecl32,  // 32-bit: everything on the stack
    MsX64,    // RCX, RDX, R8, R9, then the stack above the shadow area
    SysV64,   // RDI, RSI, RDX, RCX, R8, R9, then the stack
};

class Emulator {
public:
    struct Options {
        bool trace = false;         // dump CPU state per instruction
        bool trace_calls = false;   // log intercepted library calls
        bool dump_map = false;      // print the guest memory map after loading
        uint64_t max_instructions = 500000000ull;
    };

    // No default argument: a nested type's default member initializers are not
    // usable from the enclosing class's own declaration.
    explicit Emulator(Options opt);
    ~Emulator();

    // Loads the executable and prepares the initial guest state.
    void load(const std::string& path, const std::vector<std::string>& args);
    // Runs until the guest exits.  Returns its exit code.
    int run();

    Memory mem;

    Cpu& cpu() { return *cpu_; }
    const LoadedImage& image() const { return image_; }
    bool is64() const { return image_.mode == Mode::X86_64; }
    Os os() const { return image_.os; }
    Abi abi() const;
    const Options& options() const { return opt_; }
    int pointer_size() const { return is64() ? 8 : 4; }

    // ---- hooks -------------------------------------------------------------
    // Registers a host implementation and returns the guest address that calls
    // it.  stdcall_bytes is how many argument bytes the callee pops, which only
    // matters for 32-bit stdcall functions (the Win32 API); pass 0 for cdecl.
    uint64_t add_hook(std::string name, int stdcall_bytes, std::function<void(Emulator&)> fn);
    // Looks up a hook for an imported symbol, creating a "not implemented"
    // stub if there is none, so that an unknown import only fails if it is
    // actually called.
    uint64_t resolve_import(const std::string& dll, const std::string& symbol);

    // ---- argument access for hook bodies ----------------------------------
    // One pointer-sized argument slot, 0-based, per the active ABI.
    uint64_t arg_slot(int index) const;

    // Cursor over an argument list that knows how wide a slot is; also used for
    // walking printf's variadic tail.
    class Args {
    public:
        Args(const Emulator& e, int start = 0) : e_(e), i_(start) {}
        uint64_t next_int(int bytes);  // a 4- or 8-byte C integer
        uint64_t next_ptr() { return e_.arg_slot(i_++); }
        double next_double();
        int index() const { return i_; }

    private:
        const Emulator& e_;
        int i_;
    };

    void set_result(uint64_t v);
    void exit_process(int code);

    // ---- guest services ----------------------------------------------------
    uint64_t heap_alloc(uint64_t size);
    // Page-aligned allocation, for mmap().
    uint64_t alloc_pages(uint64_t size);
    // The Linux program break; set_brk returns the value after the request.
    uint64_t brk_value() const { return brk_; }
    uint64_t set_brk(uint64_t addr);
    void heap_free(uint64_t addr);
    uint64_t heap_realloc(uint64_t addr, uint64_t size);
    uint64_t heap_block_size(uint64_t addr) const;
    uint64_t alloc_guest_data(const void* data, uint64_t size);
    uint64_t alloc_guest_string(const std::string& s);

    // stdio: guest FILE* values are synthetic objects the emulator owns.
    uint64_t guest_file(int fd);
    std::FILE* host_stream(uint64_t guest_file_ptr) const;
    int host_fd(uint64_t guest_file_ptr) const;

    void log_call(const char* fmt, ...);
    const std::vector<std::string>& args() const { return args_; }
    uint64_t last_error() const { return last_error_; }
    void set_last_error(uint64_t e) { last_error_ = e; }

    // Installed by hooks.cpp / syscalls.cpp.
    void install_library_hooks();
    void install_syscall_handlers();

private:
    struct Hook {
        std::string name;
        int stdcall_bytes = 0;
        std::function<void(Emulator&)> fn;
    };
    struct HeapBlock {
        uint64_t size;
        bool free;
    };

    static constexpr uint64_t kHookStride = 16;

    void choose_layout();
    bool dispatch_hook(uint64_t addr);
    void setup_windows_env(const std::vector<std::string>& args);
    void setup_linux_stack(const std::vector<std::string>& args);
    void dump_memory_map() const;

    Options opt_;
    LoadedImage image_;
    std::unique_ptr<Cpu> cpu_;
    std::vector<std::string> args_;

    std::vector<Hook> hooks_;
    std::unordered_map<std::string, uint64_t> hook_by_name_;

    // Guest layout, chosen from the image's bitness in choose_layout().
    uint64_t hook_base_ = 0;
    uint64_t stack_base_ = 0, stack_size_ = 0, stack_top_ = 0;
    uint64_t heap_base_ = 0, heap_next_ = 0, heap_limit_ = 0;
    uint64_t misc_base_ = 0, misc_next_ = 0;
    uint64_t teb_base_ = 0;

    uint64_t brk_ = 0;
    std::unordered_map<uint64_t, HeapBlock> heap_blocks_;
    uint64_t guest_files_[3] = {};
    uint64_t last_error_ = 0;
    uint64_t exit_thunk_ = 0;
};

}  // namespace x86emu
