#include "emulator.h"

#include <algorithm>
#include <cinttypes>
#include <cstring>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <stdlib.h>  // _environ
#else
extern "C" char** environ;
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
    // mmap lives above the brk heap so the two can never collide.
    mmap_next_ = heap_limit_;
    mmap_limit_ = mmap_next_ + (1ull << 28);
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
    // Which C runtime the guest links against changes observable formatting, so
    // note it while the DLL name is in front of us.
    std::string lower;
    for (char c : dll) lower += static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
    if (lower.compare(0, 6, "msvcrt") == 0) three_digit_exponents_ = true;

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

uint64_t Emulator::existing_hook(const std::string& symbol) const {
    auto it = hook_by_name_.find(symbol);
    if (it != hook_by_name_.end()) return it->second;
    // The stub created for an unimplemented import is registered as "DLL!name";
    // that is not an implementation, so it must not be handed out here.
    return 0;
}

uint64_t Emulator::hooked_module_handle(const std::string& name) {
    // Distinct per name so a guest can tell two modules apart, and tagged so that
    // module_for() will not mistake it for a real mapping.
    auto it = hooked_modules_.find(name);
    if (it != hooked_modules_.end()) return it->second;
    uint64_t handle = kHookedModuleBase + hooked_modules_.size() * 0x10000;
    hooked_modules_[name] = handle;
    return handle;
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

Emulator::Args Emulator::Args::va_list_at(const Emulator& e, uint64_t ptr) {
    Args a(e);
    a.va_ = ptr;
    a.from_memory_ = true;
    return a;
}

uint64_t Emulator::Args::next_slot() {
    if (from_memory_) {
        int ps = e_->pointer_size();
        uint64_t v = e_->mem.read_sized(va_, ps);
        va_ += ps;
        return v;
    }
    return e_->arg_slot(i_++);
}

uint64_t Emulator::Args::next_int(int bytes) {
    // In 32-bit code a 64-bit value spans two slots; in 64-bit code every
    // argument occupies exactly one.
    if (!e_->is64() && bytes == 8) {
        uint64_t lo = next_slot() & 0xFFFFFFFFull;
        uint64_t hi = next_slot() & 0xFFFFFFFFull;
        return (hi << 32) | lo;
    }
    uint64_t v = next_slot();
    return bytes == 4 ? (v & 0xFFFFFFFFull) : v;
}

double Emulator::Args::next_double() {
    uint64_t bits;
    // The System V ABI keeps variadic floating-point arguments in XMM0-7, a
    // separate sequence from the integer ones.  Microsoft's ABI instead
    // duplicates them into the integer registers, so the normal slot walk works
    // there, as it does for a va_list already spilled to memory.
    if (!from_memory_ && e_->abi() == Abi::SysV64 && fp_ < 8)
        bits = e_->cpu_->xmm[fp_++].q[0];
    else
        bits = next_int(8);
    double d;
    std::memcpy(&d, &bits, sizeof d);
    return d;
}

double Emulator::Args::next_double_param() {
    if (from_memory_) return next_double();
    switch (e_->abi()) {
        case Abi::Cdecl32:
            return next_double();  // two stack slots, same as the variadic case
        case Abi::MsX64: {
            // Position-based: the Nth argument travels in XMM(N), sharing the
            // counter with the integer registers, and spills to the stack past
            // the fourth.
            uint64_t bits;
            if (i_ < 4)
                bits = e_->cpu_->xmm[i_].q[0];
            else
                bits = e_->mem.read64(e_->cpu_->regs[RSP] + 8 + 32 +
                                      static_cast<uint64_t>(i_ - 4) * 8);
            ++i_;
            double d;
            std::memcpy(&d, &bits, sizeof d);
            return d;
        }
        default: {  // SysV64: floating point has its own register sequence
            uint64_t bits;
            if (fp_ < 8)
                bits = e_->cpu_->xmm[fp_++].q[0];
            else
                bits = next_slot();
            double d;
            std::memcpy(&d, &bits, sizeof d);
            return d;
        }
    }
}

float Emulator::Args::next_float_param() {
    if (!e_->is64()) {
        // A float parameter occupies one 4-byte stack slot in 32-bit code.
        uint32_t bits = static_cast<uint32_t>(next_slot());
        float f;
        std::memcpy(&f, &bits, sizeof f);
        return f;
    }
    uint32_t bits;
    if (e_->abi() == Abi::MsX64)
        bits = i_ < 4 ? e_->cpu_->xmm[i_++].d[0] : static_cast<uint32_t>(next_slot());
    else
        bits = fp_ < 8 ? e_->cpu_->xmm[fp_++].d[0] : static_cast<uint32_t>(next_slot());
    float f;
    std::memcpy(&f, &bits, sizeof f);
    return f;
}

void Emulator::set_result_double(double v) {
    if (is64()) {
        cpu_->xmm[0] = Cpu::Xmm{};
        cpu_->xmm[0].f64[0] = v;
    } else {
        // The 32-bit ABI returns floating point on the x87 stack.
        cpu_->fpu_push(v);
    }
}

void Emulator::set_result_float(float v) {
    if (is64()) {
        cpu_->xmm[0] = Cpu::Xmm{};
        cpu_->xmm[0].f32[0] = v;
    } else {
        cpu_->fpu_push(v);
    }
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

uint64_t Emulator::call_guest(uint64_t func, const std::vector<uint64_t>& args) {
    // Save everything the callee may clobber.  Only the mutable register state
    // needs saving: memory changes are the point of the call.
    struct Saved {
        uint64_t regs[16];
        Cpu::Xmm xmm[16];
        uint64_t rip, rflags;
        bool halted;
    } saved;
    std::memcpy(saved.regs, cpu_->regs, sizeof saved.regs);
    std::memcpy(saved.xmm, cpu_->xmm, sizeof saved.xmm);
    saved.rip = cpu_->rip;
    saved.rflags = cpu_->rflags;
    saved.halted = cpu_->halted;

    // Build a fresh frame well clear of the interrupted one.
    uint64_t rsp = (cpu_->regs[RSP] - 0x200) & ~0xFull;

    switch (abi()) {
        case Abi::Cdecl32:
            // The argument block is reserved *and aligned* before anything is
            // written into it: aligning afterwards would move the stack pointer
            // away from the arguments, which the callee reads at fixed offsets
            // from it.
            rsp = (rsp - 4 * static_cast<uint64_t>(args.size())) & ~0xFull;
            for (size_t i = 0; i < args.size(); ++i)
                mem.write32(rsp + i * 4, static_cast<uint32_t>(args[i]));
            break;
        case Abi::MsX64: {
            static const int kRegs[4] = {RCX, RDX, R8, R9};
            // Stack arguments sit above the shadow space, so reserve both at once
            // and then fill them in relative to the final stack pointer.
            size_t stack_args = args.size() > 4 ? args.size() - 4 : 0;
            rsp = (rsp - 32 - stack_args * 8) & ~0xFull;
            for (size_t i = 4; i < args.size(); ++i)
                mem.write64(rsp + 32 + (i - 4) * 8, args[i]);
            for (size_t i = 0; i < args.size() && i < 4; ++i) cpu_->regs[kRegs[i]] = args[i];
            break;
        }
        default: {  // SysV64
            static const int kRegs[6] = {RDI, RSI, RDX, RCX, R8, R9};
            size_t stack_args = args.size() > 6 ? args.size() - 6 : 0;
            rsp = (rsp - stack_args * 8) & ~0xFull;
            for (size_t i = 6; i < args.size(); ++i)
                mem.write64(rsp + (i - 6) * 8, args[i]);
            for (size_t i = 0; i < args.size() && i < 6; ++i) cpu_->regs[kRegs[i]] = args[i];
            cpu_->regs[RAX] = 0;  // no vector arguments
            break;
        }
    }
    // Pushing the return address onto a 16-byte boundary is what every one of
    // these ABIs expects at a function's first instruction.
    cpu_->regs[RSP] = rsp;
    cpu_->push(nested_return_);
    cpu_->rip = func;
    cpu_->halted = false;

    while (!cpu_->halted && cpu_->rip != nested_return_) cpu_->step();
    uint64_t result = cpu_->regs[RAX];
    bool guest_exited = cpu_->halted;
    int code = cpu_->exit_code;

    std::memcpy(cpu_->regs, saved.regs, sizeof saved.regs);
    std::memcpy(cpu_->xmm, saved.xmm, sizeof saved.xmm);
    cpu_->rip = saved.rip;
    cpu_->rflags = saved.rflags;
    // If the guest called exit() from inside the initialiser, honour it rather
    // than resuming a program that asked to stop.
    cpu_->halted = saved.halted || guest_exited;
    if (guest_exited) cpu_->exit_code = code;
    return result;
}

void Emulator::run_atexit() {
    // Take the list first: a destructor may register more, and it must not see
    // itself run twice.
    std::vector<uint64_t> pending;
    pending.swap(atexit_funcs_);
    for (size_t i = pending.size(); i-- > 0;) {
        if (cpu_->halted) break;
        call_guest(pending[i], {});
    }
}

uint32_t Emulator::tls_alloc() {
    tls_slots_.push_back(0);
    return static_cast<uint32_t>(tls_slots_.size() - 1);
}

uint64_t Emulator::tls_get(uint32_t index) const {
    return index < tls_slots_.size() ? tls_slots_[index] : 0;
}

void Emulator::tls_set(uint32_t index, uint64_t value) {
    if (index >= tls_slots_.size()) tls_slots_.resize(index + 1, 0);
    tls_slots_[index] = value;
}

void Emulator::seed_environment() {
    // A language runtime finds its own installation through the environment, so
    // the guest inherits the host's rather than starting empty.
#if defined(_WIN32)
    char** block = _environ;
#else
    char** block = environ;
#endif
    for (char** p = block; p && *p; ++p) {
        std::string entry = *p;
        size_t eq = entry.find('=');
        // A leading '=' marks Windows's hidden per-drive current directories,
        // which mean nothing here.
        if (eq == std::string::npos || eq == 0) continue;
        env_.emplace_back(entry.substr(0, eq), entry.substr(eq + 1));
    }
}

const std::string* Emulator::getenv(const std::string& name) const {
    for (const auto& [k, v] : env_)
        if (k == name) return &v;
    return nullptr;
}

void Emulator::setenv(const std::string& name, const std::string& value) {
    for (auto& [k, v] : env_) {
        if (k == name) {
            v = value;
            return;
        }
    }
    env_.emplace_back(name, value);
}

void Emulator::unsetenv(const std::string& name) {
    for (size_t i = 0; i < env_.size(); ++i) {
        if (env_[i].first == name) {
            env_.erase(env_.begin() + static_cast<long>(i));
            return;
        }
    }
}

uint64_t Emulator::environment_block(bool wide) {
    std::string flat;
    for (const auto& [k, v] : env_) {
        flat += k;
        flat += '=';
        flat += v;
        flat += '\0';
    }
    flat += '\0';  // the block ends with an empty string

    if (!wide) return alloc_guest_data(flat.data(), flat.size());

    std::vector<uint8_t> raw;
    raw.reserve(flat.size() * 2);
    for (char c : flat) {
        raw.push_back(static_cast<uint8_t>(c));
        raw.push_back(0);
    }
    return alloc_guest_data(raw.data(), raw.size());
}

uint64_t Emulator::environment_vector() {
    int ps = pointer_size();
    std::vector<uint64_t> pointers;
    for (const auto& [k, v] : env_) pointers.push_back(alloc_guest_string(k + "=" + v));
    std::vector<uint8_t> table((pointers.size() + 1) * ps, 0);
    uint64_t base = alloc_guest_data(table.data(), table.size());
    for (size_t i = 0; i < pointers.size(); ++i)
        mem.write_sized(base + i * ps, ps, pointers[i]);
    return base;
}

std::vector<std::string> Emulator::unimplemented_imports() const {
    std::vector<std::string> names;
    // resolve_import() names a stub "DLL!symbol"; a real hook is named after the
    // function alone, so the separator is what tells them apart.
    for (const auto& h : hooks_)
        if (h.name.find('!') != std::string::npos) names.push_back(h.name);
    std::sort(names.begin(), names.end());
    return names;
}

std::string Emulator::describe_address(uint64_t addr) const {
    if (addr >= hook_base_ && addr < hook_base_ + hooks_.size() * kHookStride) {
        size_t idx = static_cast<size_t>((addr - hook_base_) / kHookStride);
        // Reading from a hook address rather than calling it means the guest
        // imported a *variable*, not a function - the loader cannot tell the two
        // apart, so it binds both to a hook.
        return "this is the hook for '" + hooks_[idx].name +
               "'; reading it as data means the guest imports it as a variable, "
               "which needs the real DLL loaded";
    }
    if (addr >= image_.image_base && addr < image_.image_base + image_.image_size)
        return "inside the loaded image";
    if (addr >= stack_base_ && addr < stack_top_) return "inside the stack";
    if (addr >= heap_base_ && addr < heap_limit_) return "inside the heap";
    if (addr < 0x10000) return "a null or near-null pointer";
    return {};
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
    if (mmap_next_ + need > mmap_limit_) return 0;
    uint64_t addr = mmap_next_;
    mmap_next_ += need;
    mem.map(addr, need);
    return addr;
}

uint64_t Emulator::set_brk(uint64_t addr) {
    // brk(0) queries the current break; anything below it is ignored.
    if (addr > brk_) {
        if (addr > heap_limit_) return brk_;
        mem.map(brk_, addr - brk_);
        brk_ = addr;
        if (heap_next_ < brk_) heap_next_ = brk_;  // keep malloc() above the break
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
    auto it = guest_files_.find(fd);
    if (it != guest_files_.end()) return it->second;

    // The first three are allocated as one contiguous block, because a guest may
    // reach them through an imported _iob[] array rather than one at a time.
    if (guest_files_.empty()) {
        std::vector<uint8_t> blob(3 * kFileObjectSize, 0);
        uint64_t base = alloc_guest_data(blob.data(), blob.size());
        for (int i = 0; i < 3; ++i) {
            uint64_t obj = base + static_cast<uint64_t>(i) * kFileObjectSize;
            mem.write32(obj, 0x554D4546);  // 'FEMU', so a stray pointer is obvious
            mem.write32(obj + 4, static_cast<uint32_t>(i));
            guest_files_[i] = obj;
            guest_file_fds_[obj] = i;
        }
        if (fd >= 0 && fd <= 2) return guest_files_[fd];
    }

    std::vector<uint8_t> blob(kFileObjectSize, 0);
    uint64_t obj = alloc_guest_data(blob.data(), blob.size());
    mem.write32(obj, 0x554D4546);
    mem.write32(obj + 4, static_cast<uint32_t>(fd));
    guest_files_[fd] = obj;
    guest_file_fds_[obj] = fd;
    return obj;
}

int Emulator::host_fd(uint64_t ptr) const {
    auto it = guest_file_fds_.find(ptr);
    if (it != guest_file_fds_.end()) return it->second;
    // A guest that got its FILE* from something the emulator does not model (an
    // imported _iob array, say) still deserves an answer; the object carries its
    // descriptor, so read it back if the magic matches.
    if (ptr) {
        try {
            if (mem.read32(ptr) == 0x554D4546) return static_cast<int>(mem.read32(ptr + 4));
        } catch (const MemoryFault&) {
        }
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Initial guest state
// ---------------------------------------------------------------------------

void Emulator::setup_windows_env(const std::vector<std::string>& args) {
    // The TEB, the PEB and the process parameters, laid out the way real Windows
    // does.  A CRT reaches through all three during startup - fs:/gs: to the
    // TEB, TEB to the PEB, PEB to the parameters - so stopping short at any
    // level shows up as a null dereference deep inside the runtime.
    mem.map(teb_base_, 0x10000, "TEB/PEB");
    const uint64_t peb = teb_base_ + 0x2000;
    const uint64_t params = teb_base_ + 0x3000;
    const uint64_t tls_array = teb_base_ + 0x4000;
    tls_array_ = tls_array;
    const int ps = pointer_size();

    // Command line and image path, as UNICODE_STRINGs.
    std::string cmd;
    for (const auto& a : args) {
        if (!cmd.empty()) cmd += ' ';
        cmd += a;
    }
    auto put_unicode_string = [&](uint64_t at, const std::string& text) {
        std::u16string w(text.begin(), text.end());  // ASCII widening is enough here
        std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
        for (size_t i = 0; i < w.size(); ++i) {
            raw[i * 2] = static_cast<uint8_t>(w[i] & 0xFF);
            raw[i * 2 + 1] = static_cast<uint8_t>(w[i] >> 8);
        }
        uint64_t buf = alloc_guest_data(raw.data(), raw.size());
        mem.write16(at, static_cast<uint16_t>(w.size() * 2));        // Length
        mem.write16(at + 2, static_cast<uint16_t>((w.size() + 1) * 2));  // MaximumLength
        mem.write_sized(at + (is64() ? 8 : 4), ps, buf);             // Buffer
    };

    if (!is64()) {
        mem.write32(teb_base_ + 0x00, 0xFFFFFFFFu);  // SEH chain: end of list
        mem.write32(teb_base_ + 0x04, static_cast<uint32_t>(stack_top_));
        mem.write32(teb_base_ + 0x08, static_cast<uint32_t>(stack_base_));
        mem.write32(teb_base_ + 0x18, static_cast<uint32_t>(teb_base_));   // Self
        mem.write32(teb_base_ + 0x2C, static_cast<uint32_t>(tls_array));   // TLS slots
        mem.write32(teb_base_ + 0x30, static_cast<uint32_t>(peb));
        cpu_->fs_base = teb_base_;

        mem.write32(peb + 0x08, static_cast<uint32_t>(image_.image_base));
        mem.write32(peb + 0x10, static_cast<uint32_t>(params));
        mem.write32(peb + 0x18, 0x00420000);  // ProcessHeap
        mem.write32(peb + 0xA4, 10);          // OSMajorVersion
        mem.write32(peb + 0xA8, 0);           // OSMinorVersion
        mem.write32(peb + 0xAC, 19045);       // OSBuildNumber
        mem.write32(peb + 0xB0, 2);           // OSPlatformId = VER_PLATFORM_WIN32_NT

        mem.write32(params + 0x00, 0x1000);   // MaximumLength
        mem.write32(params + 0x04, 0x1000);   // Length
        mem.write32(params + 0x08, 0);        // Flags
        mem.write32(params + 0x10, 1);        // ConsoleHandle
        mem.write32(params + 0x18, 1);        // StandardInput
        mem.write32(params + 0x1C, 2);        // StandardOutput
        mem.write32(params + 0x20, 3);        // StandardError
        put_unicode_string(params + 0x38, args.empty() ? "program.exe" : args[0]);
        put_unicode_string(params + 0x40, cmd);
    } else {
        mem.write64(teb_base_ + 0x08, stack_top_);
        mem.write64(teb_base_ + 0x10, stack_base_);
        mem.write64(teb_base_ + 0x30, teb_base_);    // Self
        mem.write64(teb_base_ + 0x58, tls_array);    // TLS slots
        mem.write64(teb_base_ + 0x60, peb);
        cpu_->gs_base = teb_base_;

        mem.write64(peb + 0x10, image_.image_base);
        mem.write64(peb + 0x20, params);
        mem.write64(peb + 0x30, 0x00420000);  // ProcessHeap
        mem.write32(peb + 0x118, 10);         // OSMajorVersion
        mem.write32(peb + 0x11C, 0);          // OSMinorVersion
        mem.write16(peb + 0x120, 19045);      // OSBuildNumber
        mem.write32(peb + 0x124, 2);          // OSPlatformId

        mem.write32(params + 0x00, 0x1000);   // MaximumLength
        mem.write32(params + 0x04, 0x1000);   // Length
        mem.write32(params + 0x08, 0);        // Flags
        mem.write64(params + 0x10, 1);        // ConsoleHandle
        mem.write64(params + 0x20, 1);        // StandardInput
        mem.write64(params + 0x28, 2);        // StandardOutput
        mem.write64(params + 0x30, 3);        // StandardError
        put_unicode_string(params + 0x60, args.empty() ? "program.exe" : args[0]);
        put_unicode_string(params + 0x70, cmd);
    }

    // Stack: the entry point returns into the exit thunk.  Start a page below
    // the top, because the entry function may write to the argument/shadow area
    // *above* its return address, which is the caller's frame - ours.
    cpu_->regs[RSP] = (stack_top_ - 0x1000) & ~0xFull;
    cpu_->push(exit_thunk_);
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
    seed_environment();

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
    files.set_text_translation(os_kind == Os::Windows);

    choose_layout();
    mem.map(stack_base_, stack_size_, "stack");

    // Slot 0 is the address the entry point returns to.
    exit_thunk_ = add_hook("__emu_exit__", 0, [](Emulator& e) {
        e.exit_process(static_cast<int>(static_cast<int32_t>(e.cpu().regs[RAX])));
    });
    // call_guest() stops when execution reaches this address; the body never
    // runs, because the check happens before hook dispatch.
    nested_return_ = add_hook("__emu_nested_return__", 0, [](Emulator&) {});

    install_library_hooks();
    install_math_hooks();
    install_file_hooks();
    install_libc_hooks();
    if (os_kind == Os::Windows) {
        install_win32_hooks();
        install_win32_extra_hooks();
        install_ucrt_hooks();
    }

    if (os_kind == Os::Windows) {
        PeImage exe = map_pe(file, mem, 0);
        image_.mode = exe.mode;
        image_.os = Os::Windows;
        image_.format = exe.format;
        image_.entry = exe.entry;
        image_.image_base = exe.base;
        image_.image_size = exe.size;
        image_.brk = exe.base + exe.size;
        // Real DLLs are mapped above the executable, well clear of it.
        dll_next_base_ = (exe.base + exe.size + 0xFFFFF) & ~0xFFFFFull;
        // The main image is registered as a module too, so that GetModuleHandle
        // and GetProcAddress can treat it like any other.
        auto self = std::make_unique<Module>();
        self->name = "__main__";
        self->path = args_.empty() ? std::string() : args_[0];
        self->image = exe;
        self->initialised = true;  // its entry point is the program, not DllMain
        Module* self_raw = self.get();
        modules_.push_back(std::move(self));
        bind_imports(self_raw->image);
        exe_tls_callbacks_ = self_raw->image.tls_callbacks;
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

    // Reporting imports needs them bound but nothing run.
    if (opt_.imports_only) return;

    cpu_->on_hook_call = [this](uint64_t addr) { return dispatch_hook(addr); };
    install_syscall_handlers();

    if (os_kind == Os::Windows)
        setup_windows_env(args);
    else
        setup_linux_stack(args);

    cpu_->rip = image_.entry;

    // Now that there is a TEB and a stack, the loaded modules can initialise.
    if (os_kind == Os::Windows) run_pending_module_init();

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
