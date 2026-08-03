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
#include "pe.h"
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
        // Where to look for DLLs the guest imports, beyond the program's own
        // directory and the working directory.
        std::vector<std::string> library_paths;
        // Stop after binding imports, so they can be reported without running
        // anything.  Bringing up a new guest is mostly a matter of reading this
        // list and implementing what is on it.
        bool imports_only = false;
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

    // ---- threads ---------------------------------------------------------------
    // Guest threads are cooperative: the emulator runs one at a time and switches
    // at a quantum boundary or when a thread blocks.  That is enough to be
    // correct - a guest may not assume anything about interleaving - and it means
    // the whole emulator stays single-threaded on the host.
    struct GuestThread {
        uint32_t id = 0;
        uint64_t handle = 0;

        // The saved context, valid whenever this thread is not the running one.
        uint64_t regs[16] = {};
        Cpu::Xmm xmm[16] = {};
        double st[8] = {};
        bool st_used[8] = {};
        int st_top = 0;
        uint16_t fpu_control = 0x037F, fpu_status = 0;
        uint32_t mxcsr = 0x1F80;
        uint64_t rip = 0, rflags = 0x202;
        uint64_t fs_base = 0, gs_base = 0;

        uint64_t stack_base = 0, stack_size = 0;
        uint64_t teb = 0;
        uint64_t tls_array = 0;
        std::vector<uint64_t> tls_slots;  // the Tls*/Fls* API's per-thread values

        enum class State { Runnable, Blocked, Finished };
        State state = State::Runnable;
        uint32_t exit_code = 0;

        // What this thread is blocked on, if anything.
        uint64_t wait_handle = 0;
        uint64_t wake_at = 0;  // an instruction count, for Sleep
    };

    // A Win32 waitable object.  Threads are objects too, which is what makes
    // joining one the same operation as waiting on an event.
    struct SyncObject {
        enum class Kind { Event, Mutex, Semaphore, Thread };
        Kind kind = Kind::Event;
        bool manual_reset = false;
        bool signalled = false;
        int64_t count = 0;       // a semaphore's remaining permits
        uint32_t owner = 0;      // a mutex's holder, or a thread's id
        int64_t recursion = 0;   // a mutex may be taken repeatedly by its owner
    };

    uint32_t current_thread_id() const;
    GuestThread* current_thread();
    // Creates a thread that will call `start` with `argument`; returns its handle.
    uint64_t create_thread(uint64_t start, uint64_t argument, uint64_t stack_size);
    void exit_thread(uint32_t exit_code);
    // Gives up the rest of this thread's slice.  Hooks that block call this after
    // recording what they are waiting for.
    void yield_now() { reschedule_ = true; }
    // Blocks the current thread until `handle` is signalled, or forever if it
    // never is.  Returns false if the wait could not be set up.
    bool begin_wait(uint64_t handle, uint64_t timeout_ms);
    SyncObject* sync_object(uint64_t handle);
    uint64_t create_sync_object(SyncObject::Kind kind, bool manual_reset, bool signalled,
                                int64_t count);
    void signal_object(uint64_t handle);
    bool try_acquire(uint64_t handle);

    void install_thread_hooks();
    const std::vector<std::unique_ptr<GuestThread>>& threads() const { return threads_; }
    // Leaves the current hook without returning to the guest, so that the same
    // call happens again the next time this thread runs.  That is how a blocking
    // lock retries: the guest re-enters the hook and finds the lock free.
    void retry_current_call() { retry_hook_ = true; }

    // ---- modules -------------------------------------------------------------
    // A DLL actually loaded into guest memory, as opposed to one whose functions
    // the emulator provides itself.
    struct Module {
        std::string name;      // as the guest spelled it, lowercased
        std::string path;      // where it was found
        PeImage image;
        bool initialised = false;
    };

    // Loads a DLL if one can be found and is not better served by hooks.  Returns
    // its base address, or 0 if the emulator will hook its functions instead.
    uint64_t load_library(const std::string& name);
    // Resolves a symbol in a loaded module, following forwarders; 0 if absent.
    uint64_t find_export(uint64_t module_base, const std::string& symbol);
    uint64_t find_export_ordinal(uint64_t module_base, uint32_t ordinal);
    Module* module_for(uint64_t base);
    Module* module_by_name(const std::string& name);
    const std::vector<std::unique_ptr<Module>>& modules() const { return modules_; }

    // ---- hooks -------------------------------------------------------------
    // Registers a host implementation and returns the guest address that calls
    // it.  stdcall_bytes is how many argument bytes the callee pops, which only
    // matters for 32-bit stdcall functions (the Win32 API); pass 0 for cdecl.
    uint64_t add_hook(std::string name, int stdcall_bytes, std::function<void(Emulator&)> fn);
    // Looks up a hook for an imported symbol, creating a "not implemented"
    // stub if there is none, so that an unknown import only fails if it is
    // actually called.
    uint64_t resolve_import(const std::string& dll, const std::string& symbol);
    // The address of an already-registered hook, or 0.  Unlike resolve_import
    // this never creates a stub, so a guest probing for an optional API gets the
    // NULL it is looking for.
    uint64_t existing_hook(const std::string& symbol) const;
    // A stand-in HMODULE for a library the emulator implements rather than loads.
    uint64_t hooked_module_handle(const std::string& name);

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
    // Pushes any buffered guest output out.  A Windows CRT block-buffers stdout
    // when it is not a terminal, so the emulator does too - otherwise a guest
    // that mixes printf with WriteFile would see its output interleaved
    // differently here than on Windows.
    void flush_guest_output();

    // ---- files ---------------------------------------------------------------
    FileTable files;

    // One entry from a directory listing, as FindFirstFile reports them.
    struct DirectoryEntry {
        std::string name;
        bool is_dir = false;
        uint64_t size = 0;
        int64_t mtime = 0;
    };
    // Lists a directory, filtered by the wildcard in `spec` ("dir/*.py").
    std::vector<DirectoryEntry> list_directory(const std::string& spec);
    // The FindFirstFile/FindNextFile cursor, kept behind a handle.
    uint64_t open_find_handle(std::vector<DirectoryEntry> entries);
    const DirectoryEntry* find_current(uint64_t handle);
    bool find_advance(uint64_t handle);
    void close_find_handle(uint64_t handle);

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

    // Imports that resolved to a "not implemented" stub rather than to a real
    // hook or a loaded DLL.  Calling one of these is what fails.
    std::vector<std::string> unimplemented_imports() const;

    // A crude backtrace: the return addresses sitting near the top of the stack,
    // each with whatever can be said about it.  Enough to answer "which call
    // faulted?" without a full unwinder.
    std::string stack_trace(int depth = 8);

    // Explains what lives at an address, for fault reporting.  Returns an empty
    // string if there is nothing useful to say.
    std::string describe_address(uint64_t addr) const;

    // The guest's errno.  A libc distinguishes "not found" from "permission
    // denied" by this and nothing else, and control flow depends on the answer:
    // CPython's path search catches FileNotFoundError specifically, so a failed
    // open that leaves errno at 0 raises the wrong exception and escapes.
    uint64_t errno_address();
    void set_guest_errno(int value);
    // Translates a FileTable result (a negative errno-style code) and records it.
    void report_file_error(int64_t code);

    void log_call(const char* fmt, ...);
    const std::vector<std::string>& args() const { return args_; }

    // ---- environment -----------------------------------------------------
    // Seeded from the host's environment, because a guest like a language
    // runtime reads PATH and its own *HOME variables to find its files.
    const std::string* getenv(const std::string& name) const;
    void setenv(const std::string& name, const std::string& value);
    void unsetenv(const std::string& name);
    const std::vector<std::pair<std::string, std::string>>& environment() const {
        return env_;
    }
    // The environment as a guest-memory block: "NAME=VALUE\0...\0\0", narrow or
    // wide.  Rebuilt on demand, since a guest may have changed it.
    uint64_t environment_block(bool wide);
    // A char*[] terminated by NULL, which is what `environ` and main's third
    // argument are.
    uint64_t environment_vector();
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
    void install_libc_hooks();
    void install_win32_hooks();
    void install_win32_extra_hooks();
    void install_win32_fs_hooks();
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
    void seed_environment();
    bool dispatch_hook(uint64_t addr);
    // Fills in one image's import table, loading real DLLs where that is the
    // better answer and falling back to hooks otherwise.
    void bind_imports(PeImage& img);
    void run_module_init(Module& module);
    // DllMain and TLS callbacks are guest code, and guest code needs the TEB and
    // a stack, so initialisation waits until the environment exists - which is
    // also the order the real loader uses.
    void run_pending_module_init();
    // Saves the running thread's context and makes `index` the running one.
    void switch_to_thread(size_t index);
    // The next thread that could run, waking anything whose wait is satisfied.
    size_t pick_runnable();
    uint64_t allocate_thread_tls(uint64_t teb);
    // Gives a module its slot in the thread's TLS array and fills that slot with
    // a copy of the module's TLS template.
    void setup_static_tls(Module& module);
    std::string find_library_file(const std::string& name) const;
    void setup_windows_env(const std::vector<std::string>& args);
    void setup_linux_stack(const std::vector<std::string>& args);
    void dump_memory_map() const;

    Options opt_;
    LoadedImage image_;
    std::unique_ptr<Cpu> cpu_;
    std::vector<std::string> args_;
    std::vector<std::pair<std::string, std::string>> env_;

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
    std::string stdout_buffer_;
    bool buffer_stdout_ = false;
    uint64_t exit_thunk_ = 0;
    uint64_t nested_return_ = 0;  // sentinel address call_guest() returns to
    std::vector<std::unique_ptr<Module>> modules_;
    std::vector<uint64_t> exe_tls_callbacks_;
    bool guest_env_ready_ = false;
    uint64_t errno_address_ = 0;  // the guest's errno variable
    uint64_t lconv_address_ = 0;  // the guest's struct lconv
    uint64_t tls_array_ = 0;      // the main thread's TEB.ThreadLocalStoragePointer
    uint32_t next_tls_slot_ = 0;  // next free index in that array
    // What a new thread needs to reproduce every module's static TLS.
    struct TlsTemplate {
        uint32_t slot;
        uint64_t source;         // the module's template, in its own image
        uint64_t template_size;
        uint64_t total_size;
    };
    std::vector<TlsTemplate> tls_templates_;

    std::vector<std::unique_ptr<GuestThread>> threads_;
    size_t current_thread_ = 0;
    uint32_t next_thread_id_ = 0x1000;
    bool reschedule_ = false;
    bool retry_hook_ = false;
    uint64_t thread_exit_thunk_ = 0;
    std::unordered_map<uint64_t, SyncObject> sync_objects_;
    uint64_t next_sync_handle_ = 0x8000;
    struct FindState {
        std::vector<DirectoryEntry> entries;
        size_t index = 0;
    };
    std::unordered_map<uint64_t, FindState> find_handles_;
    uint64_t next_find_handle_ = 0x30000;
    // Handles for libraries answered by hooks; deliberately far from any real
    // mapping so that a stray dereference faults instead of reading a module.
    static constexpr uint64_t kHookedModuleBase = 0x00000000EE000000ull;
    std::unordered_map<std::string, uint64_t> hooked_modules_;
    uint64_t dll_next_base_ = 0;   // where the next real DLL gets mapped
    // Guards against a cycle in DLL dependencies.
    std::vector<std::string> loading_;
    uint32_t next_dynamic_tls_slot_ = 0;  // TlsAlloc hands these out
    std::vector<uint64_t> atexit_funcs_;
};

}  // namespace x86emu
