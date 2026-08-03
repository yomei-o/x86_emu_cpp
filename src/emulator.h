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
#include "files.h"
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
    // Same, for an image already in memory (used by the WebAssembly front end,
    // which has no filesystem to read from).
    void load_bytes(const std::vector<uint8_t>& file, const std::vector<std::string>& args);

    // Where guest stdout/stderr bytes go.  Unset means the host's own streams;
    // a front end that is not a terminal (the browser demo) installs its own.
    std::function<void(int /*fd*/, const char* /*data*/, size_t /*len*/)> output_sink;
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
        Args(const Emulator& e, int start = 0) : e_(&e), i_(start) {}

        // A va_list the guest handed us: the arguments live in memory rather
        // than in registers.  This is how the UCRT's __stdio_common_* entry
        // points receive printf's variadic tail.
        static Args va_list_at(const Emulator& e, uint64_t ptr);

        uint64_t next_int(int bytes);  // a 4- or 8-byte C integer
        uint64_t next_ptr() { return next_slot(); }

        // A variadic floating-point argument, i.e. part of printf's tail.
        double next_double();
        // A *declared* double or float parameter.  This is a different question
        // from the one above: Microsoft's ABI passes these in XMM registers
        // only, and duplicates them into the integer registers just for
        // variadic calls, which is why printf can read them either way.
        double next_double_param();
        float next_float_param();

    private:
        uint64_t next_slot();

        const Emulator* e_;
        int i_ = 0;          // register/stack slot index
        int fp_ = 0;         // SysV keeps float arguments in their own registers
        uint64_t va_ = 0;    // cursor when reading from a va_list
        bool from_memory_ = false;
    };

    void set_result(uint64_t v);
    // Returns a floating-point value the way the ABI expects: XMM0 in 64-bit
    // code, the top of the x87 stack in 32-bit code.
    void set_result_double(double v);
    void set_result_float(float v);
    void exit_process(int code);

    // Calls a function *in the guest* from inside a hook and returns its result.
    // The C runtime's _initterm walks a table of initialisers and calls each
    // one, so a hook for it has to be able to re-enter guest code; without this
    // a C++ program's static constructors would silently never run.
    uint64_t call_guest(uint64_t func, const std::vector<uint64_t>& args);

    // Thread-local storage slots for the Tls*/Fls* APIs (single-threaded, so one
    // set of slots is the whole story).
    uint32_t tls_alloc();
    uint64_t tls_get(uint32_t index) const;
    void tls_set(uint32_t index, uint64_t value);

    // atexit / static destructors: the C runtime registers them with us, and we
    // run them, newest first, when the guest exits.
    void add_atexit(uint64_t func) { atexit_funcs_.push_back(func); }
    void run_atexit();

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

    // ---- guest output ------------------------------------------------------
    // Writes to a guest stdio stream (fd 1 or 2).  `write_text` goes through the
    // newline translation a Windows CRT would apply; `write_raw` is a byte
    // channel, which is what WriteFile and the Linux write() syscall are.
    void write_text(int fd, const std::string& data);
    void write_raw(int fd, const void* data, size_t len);

    // ---- files ---------------------------------------------------------------
    FileTable files;

    // A guest FILE* is a small synthetic object the emulator owns, holding the
    // descriptor it stands for; guest_file() creates one on demand.
    uint64_t guest_file(int fd);
    int host_fd(uint64_t guest_file_ptr) const;

    // Win32 HANDLEs for files are descriptors in disguise.  The offset keeps them
    // clear of 0 (NULL) and of the small integers a guest might treat specially.
    static constexpr uint64_t kHandleBase = 0x1000;
    static uint64_t handle_from_fd(int fd) {
        return kHandleBase + static_cast<uint64_t>(fd);
    }
    static int fd_from_handle(uint64_t handle) {
        return handle >= kHandleBase && handle < kHandleBase + 4096
                   ? static_cast<int>(handle - kHandleBase)
                   : -1;
    }

    // Explains what lives at an address, for fault reporting.  Returns an empty
    // string if there is nothing useful to say.
    std::string describe_address(uint64_t addr) const;

    void log_call(const char* fmt, ...);
    const std::vector<std::string>& args() const { return args_; }
    uint64_t last_error() const { return last_error_; }
    void set_last_error(uint64_t e) { last_error_ = e; }

    // The old msvcrt.dll prints %e/%g exponents with three digits (1e+010);
    // the UCRT and every other libc use the C99 minimum of two (1e+10).  The
    // loader notices which runtime the guest imports so that emulated output
    // matches the real thing byte for byte.
    bool three_digit_exponents() const { return three_digit_exponents_; }
    void set_three_digit_exponents(bool v) { three_digit_exponents_ = v; }

    // Installed by hooks.cpp, hooks_win32.cpp and syscalls.cpp.
    void install_library_hooks();
    void install_math_hooks();
    void install_file_hooks();
    void install_win32_hooks();
    void install_ucrt_hooks();
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
    // Big enough that a guest poking at "FILE internals" stays inside it.
    static constexpr uint64_t kFileObjectSize = 64;

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
    // mmap gets its own region: it must not hand out addresses that a later
    // brk() would also claim.
    uint64_t mmap_next_ = 0, mmap_limit_ = 0;
    uint64_t misc_base_ = 0, misc_next_ = 0;
    uint64_t teb_base_ = 0;

    uint64_t brk_ = 0;
    std::unordered_map<uint64_t, HeapBlock> heap_blocks_;
    std::unordered_map<int, uint64_t> guest_files_;   // fd -> guest FILE*
    std::unordered_map<uint64_t, int> guest_file_fds_; // guest FILE* -> fd
    uint64_t last_error_ = 0;
    bool three_digit_exponents_ = false;
    uint64_t exit_thunk_ = 0;
    uint64_t nested_return_ = 0;  // sentinel address call_guest() returns to
    std::vector<uint64_t> tls_slots_;
    std::vector<uint64_t> atexit_funcs_;
};

}  // namespace x86emu
