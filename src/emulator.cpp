#include "emulator.h"

#include <cinttypes>
#include <cstring>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

namespace x86emu {

Emulator::Emulator(Options opt) : opt_(opt) {}
Emulator::~Emulator() = default;

Abi Emulator::abi() const {
    if (!is64()) return Abi::Cdecl32;
    return os() == Os::Windows ? Abi::MsX64 : Abi::SysV64;
}

// ---------------------------------------------------------------------------
// Guest address space layout
// ---------------------------------------------------------------------------

void Emulator::choose_layout() {
    // The exact addresses are arbitrary; they only have to stay clear of the
    // image, and look plausible enough that a guest printing a pointer shows
    // something recognisable.
    if (!is64()) {
        hook_base_ = 0x7A000000ull;
        misc_base_ = 0x7A800000ull;
        teb_base_ = 0x7EFDD000ull;
        stack_size_ = 4ull << 20;
        stack_base_ = (os() == Os::Windows) ? 0x00140000ull : 0xBFB00000ull;
        heap_base_ = 0x02000000ull;
        heap_limit_ = 0x40000000ull;
    } else {
        hook_base_ = 0x00007FF700000000ull;
        misc_base_ = 0x00007FF700800000ull;
        teb_base_ = 0x00007FF600000000ull;
        stack_size_ = 8ull << 20;
        stack_base_ = (os() == Os::Windows) ? 0x0000000000300000ull
                                            : 0x00007FFFFF700000ull;
        heap_base_ = 0x0000000200000000ull;
        heap_limit_ = heap_base_ + (1ull << 30);
    }
    // A Linux guest grows its heap with brk() starting right after the image.
    if (os() == Os::Linux) {
        heap_base_ = (image_.brk + 0xFFF) & ~0xFFFull;
        heap_limit_ = heap_base_ + (1ull << 28);
    }
    stack_top_ = stack_base_ + stack_size_;
    heap_next_ = heap_base_;
    misc_next_ = misc_base_;
    brk_ = heap_base_;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

uint64_t Emulator::add_hook(std::string name, int stdcall_bytes,
                            std::function<void(Emulator&)> fn) {
    auto it = hook_by_name_.find(name);
    if (it != hook_by_name_.end()) return it->second;
    uint64_t addr = hook_base_ + hooks_.size() * kHookStride;
    hooks_.push_back(Hook{name, stdcall_bytes, std::move(fn)});
    hook_by_name_[hooks_.back().name] = addr;
    return addr;
}

uint64_t Emulator::resolve_import(const std::string& dll, const std::string& symbol) {
    auto it = hook_by_name_.find(symbol);
    if (it != hook_by_name_.end()) return it->second;

    // Some CRTs import the same function under a decorated name; try the
    // undecorated form before giving up.
    std::string alt = symbol;
    while (!alt.empty() && alt[0] == '_') {
        alt.erase(0, 1);
        auto a = hook_by_name_.find(alt);
        if (a != hook_by_name_.end()) return a->second;
    }

    std::string label = dll + "!" + symbol;
    return add_hook(label, 0, [label](Emulator& e) {
        throw CpuError(e.cpu().rip, "call to unimplemented import " + label +
                                       " (add a hook for it in hooks.cpp)");
    });
}

bool Emulator::dispatch_hook(uint64_t addr) {
    if (addr < hook_base_ || addr >= hook_base_ + hooks_.size() * kHookStride) return false;
    size_t idx = static_cast<size_t>((addr - hook_base_) / kHookStride);
    Hook& h = hooks_[idx];
    if (opt_.trace_calls && idx != 0)
        std::fprintf(stderr, "[hook] %s\n", h.name.c_str());

    h.fn(*this);
    if (cpu_->halted) return true;

    // Perform the return the intercepted function would have done.
    uint64_t ret = cpu_->pop();
    if (!is64()) cpu_->regs[RSP] += static_cast<uint64_t>(h.stdcall_bytes);
    cpu_->rip = ret;
    return true;
}

// ---------------------------------------------------------------------------
// Argument access
// ---------------------------------------------------------------------------

uint64_t Emulator::arg_slot(int index) const {
    uint64_t rsp = cpu_->regs[RSP];
    switch (abi()) {
        case Abi::Cdecl32:
            // [esp] is the return address, arguments follow.
            return mem.read32(rsp + 4 + static_cast<uint64_t>(index) * 4);
        case Abi::MsX64: {
            static const int kRegs[4] = {RCX, RDX, R8, R9};
            if (index < 4) return cpu_->regs[kRegs[index]];
            // [rsp] return address, [rsp+8 .. rsp+40) shadow space.
            return mem.read64(rsp + 8 + 32 + static_cast<uint64_t>(index - 4) * 8);
        }
        default: {  // SysV64
            static const int kRegs[6] = {RDI, RSI, RDX, RCX, R8, R9};
            if (index < 6) return cpu_->regs[kRegs[index]];
            return mem.read64(rsp + 8 + static_cast<uint64_t>(index - 6) * 8);
        }
    }
}

uint64_t Emulator::Args::next_int(int bytes) {
    // In 32-bit code a 64-bit value spans two stack slots; in 64-bit code every
    // argument occupies exactly one slot.
    if (!e_.is64() && bytes == 8) {
        uint64_t lo = e_.arg_slot(i_++) & 0xFFFFFFFFull;
        uint64_t hi = e_.arg_slot(i_++) & 0xFFFFFFFFull;
        return (hi << 32) | lo;
    }
    uint64_t v = e_.arg_slot(i_++);
    return bytes == 4 ? (v & 0xFFFFFFFFull) : v;
}

double Emulator::Args::next_double() {
    uint64_t bits = next_int(8);
    double d;
    std::memcpy(&d, &bits, sizeof d);
    return d;
}

void Emulator::set_result(uint64_t v) {
    if (is64())
        cpu_->regs[RAX] = v;
    else
        cpu_->regs[RAX] = v & 0xFFFFFFFFull;
}

void Emulator::exit_process(int code) {
    cpu_->exit_code = code;
    cpu_->halted = true;
}

void Emulator::log_call(const char* fmt, ...) {
    if (!opt_.trace_calls) return;
    std::va_list ap;
    va_start(ap, fmt);
    std::fprintf(stderr, "[hook] ");
    std::vfprintf(stderr, fmt, ap);
    std::fprintf(stderr, "\n");
    va_end(ap);
}

// ---------------------------------------------------------------------------
// Guest heap and scratch allocations
// ---------------------------------------------------------------------------

uint64_t Emulator::heap_alloc(uint64_t size) {
    if (size == 0) size = 1;
    uint64_t need = (size + 15) & ~15ull;

    // Reuse a freed block that is big enough before growing the heap.
    for (auto& [addr, blk] : heap_blocks_) {
        if (blk.free && blk.size >= need) {
            blk.free = false;
            return addr;
        }
    }
    if (heap_next_ + need > heap_limit_) return 0;  // out of memory
    uint64_t addr = heap_next_;
    heap_next_ += need;
    mem.map(addr, need);
    heap_blocks_[addr] = HeapBlock{need, false};
    return addr;
}

uint64_t Emulator::alloc_pages(uint64_t size) {
    uint64_t need = (size + 0xFFF) & ~0xFFFull;
    heap_next_ = (heap_next_ + 0xFFF) & ~0xFFFull;
    if (heap_next_ + need > heap_limit_) return 0;
    uint64_t addr = heap_next_;
    heap_next_ += need;
    mem.map(addr, need);
    return addr;
}

uint64_t Emulator::set_brk(uint64_t addr) {
    // brk(0) queries the current break; anything below it is ignored.
    if (addr > brk_) {
        if (addr > heap_limit_) return brk_;
        mem.map(brk_, addr - brk_);
        brk_ = addr;
        if (heap_next_ < brk_) heap_next_ = brk_;
    }
    return brk_;
}

void Emulator::heap_free(uint64_t addr) {
    auto it = heap_blocks_.find(addr);
    if (it != heap_blocks_.end()) it->second.free = true;
}

uint64_t Emulator::heap_block_size(uint64_t addr) const {
    auto it = heap_blocks_.find(addr);
    return it == heap_blocks_.end() ? 0 : it->second.size;
}

uint64_t Emulator::heap_realloc(uint64_t addr, uint64_t size) {
    if (addr == 0) return heap_alloc(size);
    uint64_t old = heap_block_size(addr);
    if (old >= size) return addr;
    uint64_t fresh = heap_alloc(size);
    if (!fresh) return 0;
    if (old) {
        std::vector<uint8_t> tmp(static_cast<size_t>(old));
        mem.read(addr, tmp.data(), old);
        mem.write(fresh, tmp.data(), old);
    }
    heap_free(addr);
    return fresh;
}

uint64_t Emulator::alloc_guest_data(const void* data, uint64_t size) {
    uint64_t addr = misc_next_;
    misc_next_ = (misc_next_ + size + 15) & ~15ull;
    mem.map(addr, size + 16);
    if (size) mem.write(addr, data, size);
    return addr;
}

uint64_t Emulator::alloc_guest_string(const std::string& s) {
    uint64_t addr = alloc_guest_data(s.data(), s.size() + 1);
    mem.write8(addr + s.size(), 0);
    return addr;
}

// ---------------------------------------------------------------------------
// Guest output
// ---------------------------------------------------------------------------

void Emulator::write_raw(int fd, const void* data, size_t len) {
    if (!len) return;
    if (output_sink)
        output_sink(fd, static_cast<const char*>(data), len);
    else
        std::fwrite(data, 1, len, fd == 2 ? stderr : stdout);
}

void Emulator::write_text(int fd, const std::string& data) {
    if (os() != Os::Windows) {
        write_raw(fd, data.data(), data.size());
        return;
    }
    // A Windows CRT opens the console streams in text mode, so a guest printing
    // "\n" really emits CRLF.  Translating here rather than leaning on the
    // host's C runtime keeps guest output byte-identical on every host OS.
    std::string out;
    out.reserve(data.size() + data.size() / 16 + 8);
    for (char c : data) {
        if (c == '\n') out += '\r';
        out += c;
    }
    write_raw(fd, out.data(), out.size());
}

// ---------------------------------------------------------------------------
// Synthetic stdio streams
// ---------------------------------------------------------------------------

uint64_t Emulator::guest_file(int fd) {
    if (fd < 0 || fd > 2) return 0;
    if (guest_files_[fd] == 0) {
        // A small opaque object; the guest only ever passes the pointer back.
        uint8_t blob[32] = {};
        blob[0] = 'E';
        blob[1] = 'M';
        blob[2] = 'U';
        blob[3] = static_cast<uint8_t>(fd);
        guest_files_[fd] = alloc_guest_data(blob, sizeof blob);
    }
    return guest_files_[fd];
}

int Emulator::host_fd(uint64_t ptr) const {
    for (int fd = 0; fd < 3; ++fd)
        if (guest_files_[fd] && guest_files_[fd] == ptr) return fd;
    return -1;
}

std::FILE* Emulator::host_stream(uint64_t ptr) const {
    switch (host_fd(ptr)) {
        case 0: return stdin;
        case 1: return stdout;
        case 2: return stderr;
        default: return nullptr;
    }
}

// ---------------------------------------------------------------------------
// Initial guest state
// ---------------------------------------------------------------------------

void Emulator::setup_windows_env(const std::vector<std::string>& args) {
    // A minimal TEB/PEB so that fs:/gs: reads do not fault.  Real Windows code
    // reads the stack bounds and the PEB pointer from here.
    mem.map(teb_base_, 0x3000, "TEB/PEB");
    uint64_t peb = teb_base_ + 0x2000;
    if (!is64()) {
        mem.write32(teb_base_ + 0x00, 0xFFFFFFFFu);  // SEH chain: end of list
        mem.write32(teb_base_ + 0x04, static_cast<uint32_t>(stack_top_));
        mem.write32(teb_base_ + 0x08, static_cast<uint32_t>(stack_base_));
        mem.write32(teb_base_ + 0x18, static_cast<uint32_t>(teb_base_));  // Self
        mem.write32(teb_base_ + 0x30, static_cast<uint32_t>(peb));
        cpu_->fs_base = teb_base_;
    } else {
        mem.write64(teb_base_ + 0x08, stack_top_);
        mem.write64(teb_base_ + 0x10, stack_base_);
        mem.write64(teb_base_ + 0x30, teb_base_);  // Self
        mem.write64(teb_base_ + 0x60, peb);
        cpu_->gs_base = teb_base_;
    }
    // PEB.ImageBaseAddress
    if (!is64())
        mem.write32(peb + 0x08, static_cast<uint32_t>(image_.image_base));
    else
        mem.write64(peb + 0x10, image_.image_base);

    // Stack: the entry point returns into the exit thunk.
    cpu_->regs[RSP] = stack_top_ & ~0xFull;
    cpu_->push(exit_thunk_);
    (void)args;
}

void Emulator::setup_linux_stack(const std::vector<std::string>& args) {
    // Build the System V initial process stack:
    //   argc, argv[0..n], NULL, envp NULL, auxv pairs, AT_NULL, then the
    //   strings the pointers refer to.
    const int ps = pointer_size();
    uint64_t sp = stack_top_ - 0x1000;

    auto push_bytes = [&](const std::string& s) {
        sp -= s.size() + 1;
        mem.write_cstring(sp, s);
        return sp;
    };

    std::vector<uint64_t> argv_ptrs;
    for (const auto& a : args) argv_ptrs.push_back(push_bytes(a));
    // 16 random bytes for AT_RANDOM, which libc uses to seed stack guards.
    uint8_t random[16] = {0x5A, 0x17, 0x3C, 0x91, 0x2B, 0x44, 0xE0, 0x77,
                          0x1F, 0x63, 0xB8, 0x0A, 0xD5, 0x29, 0x8E, 0x46};
    sp -= sizeof random;
    uint64_t at_random = sp;
    mem.write(sp, random, sizeof random);

    struct Aux {
        uint64_t key, val;
    };
    const std::vector<Aux> auxv = {
        {6, 0x1000},                        // AT_PAGESZ
        {3, image_.phdr_addr},              // AT_PHDR
        {4, image_.phent_size},             // AT_PHENT
        {5, image_.phnum},                  // AT_PHNUM
        {9, image_.entry},                  // AT_ENTRY
        {11, 0}, {12, 0}, {13, 0}, {14, 0}, // AT_UID/EUID/GID/EGID
        {25, at_random},                    // AT_RANDOM
        {23, 0},                            // AT_SECURE
        {0, 0},                             // AT_NULL
    };

    // Total slots: argc + argv + NULL + envp NULL + auxv pairs.
    uint64_t slots = 1 + argv_ptrs.size() + 1 + 1 + auxv.size() * 2;
    sp -= slots * ps;
    sp &= ~0xFull;  // the ABI requires a 16-byte aligned stack at entry

    uint64_t p = sp;
    auto put = [&](uint64_t v) {
        mem.write_sized(p, ps, v);
        p += ps;
    };
    put(argv_ptrs.size());
    for (uint64_t a : argv_ptrs) put(a);
    put(0);  // end of argv
    put(0);  // empty environment
    for (const auto& a : auxv) {
        put(a.key);
        put(a.val);
    }
    cpu_->regs[RSP] = sp;
}

void Emulator::load(const std::string& path, const std::vector<std::string>& args) {
    load_bytes(read_file(path), args);
}

void Emulator::load_bytes(const std::vector<uint8_t>& file, const std::vector<std::string>& args) {
    args_ = args;

    // The layout and the hook addresses depend on the bitness, and PE import
    // binding needs the hook addresses, so peek at the headers first.
    Mode mode;
    Os os_kind;
    std::string format;
    peek_image(file, mode, os_kind, format);
    image_.mode = mode;
    image_.os = os_kind;
    image_.format = format;

    cpu_ = std::make_unique<Cpu>(mem, mode);
    cpu_->trace = opt_.trace;

    choose_layout();
    mem.map(stack_base_, stack_size_, "stack");

    // Slot 0 is the address the entry point returns to.
    exit_thunk_ = add_hook("__emu_exit__", 0, [](Emulator& e) {
        e.exit_process(static_cast<int>(static_cast<int32_t>(e.cpu().regs[RAX])));
    });
    install_library_hooks();

    if (os_kind == Os::Windows) {
        image_ = load_pe(file, mem, [this](const std::string& dll, const std::string& sym) {
            return resolve_import(dll, sym);
        });
    } else {
        image_ = load_elf(file, mem);
        // The Linux heap sits right after the image, which is only known now.
        choose_layout();
    }

    // Guest bytes must reach the console exactly as the guest wrote them; any
    // newline translation a Windows guest needs is done in write_text().
#if defined(_WIN32)
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
#endif

    cpu_->on_hook_call = [this](uint64_t addr) { return dispatch_hook(addr); };
    install_syscall_handlers();

    if (os_kind == Os::Windows)
        setup_windows_env(args);
    else
        setup_linux_stack(args);

    cpu_->rip = image_.entry;

    if (opt_.dump_map) dump_memory_map();
}

void Emulator::dump_memory_map() const {
    std::fprintf(stderr, "-- %s, entry 0x%llX, base 0x%llX\n", image_.format.c_str(),
                 (unsigned long long)image_.entry, (unsigned long long)image_.image_base);
    for (const auto& r : mem.regions())
        std::fprintf(stderr, "   %016llX - %016llX  %s\n", (unsigned long long)r.base,
                     (unsigned long long)(r.base + r.size), r.name.c_str());
    std::fprintf(stderr, "   %016llX - %016llX  hooks (%zu)\n", (unsigned long long)hook_base_,
                 (unsigned long long)(hook_base_ + hooks_.size() * kHookStride), hooks_.size());
}

int Emulator::run() {
    cpu_->run(opt_.max_instructions);
    std::fflush(stdout);
    return cpu_->exit_code;
}

}  // namespace x86emu
