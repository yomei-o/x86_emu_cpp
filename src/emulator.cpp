#include "emulator.h"

#include "guest_printf.h"

#include <algorithm>
#include <cinttypes>
#include <limits>
#include <cstring>

#include "processes.h"

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
        // Close above a Windows image (which loads at 0x140000000), because a
        // guest may compress pointers into 32 bits relative to something it
        // already has - a compiler's arena does - and anything more than 4 GiB
        // from the image cannot be reached that way.  A Linux guest's heap
        // follows its image instead, chosen below.
        heap_base_ = 0x0000000150000000ull;
        heap_limit_ = heap_base_ + (1ull << 30);
    }
    // A Linux guest grows its heap with brk() starting right after the image.
    if (os() == Os::Linux) {
        heap_base_ = (image_.brk + 0xFFF) & ~0xFFFull;
        heap_limit_ = heap_base_ + (1ull << 28);
    }
    // mmap lives above the brk heap so the two can never collide.  A 64-bit
    // guest gets a large window because addresses cost nothing there and a real
    // toolchain maps a great deal (cc1 alone wants hundreds of megabytes);
    // pages are only created when touched.
    mmap_next_ = heap_limit_;
    mmap_limit_ = mmap_next_ + (is64() ? (16ull << 30) : (1ull << 28));

    // X86EMU_QEMU_LAYOUT makes a 64-bit Linux guest see qemu-x86_64's address
    // layout: the stack below 0x4000800000, mmap climbing from 0x40008A6000,
    // and no address reuse (qemu's mmap_find_vma is a monotonic cursor).  With
    // brk already identical - it follows the image in both - every pointer the
    // guest ever compares or hashes comes out numerically equal to the qemu
    // run's, which is what lets tools/qemu-diff push past address-dependent
    // branches.  Diagnostics only; nothing sets it in normal use.
    if (os() == Os::Linux && is64() && std::getenv("X86EMU_QEMU_LAYOUT")) {
        stack_size_ = 8ull << 20;
        stack_base_ = 0x4000000000ull;
        mmap_next_ = 0x40008A6000ull;
        mmap_limit_ = mmap_next_ + (64ull << 30);
        mmap_no_reuse_ = true;
        stack_top_ = stack_base_ + stack_size_;
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
    // Which C runtime the guest links against changes observable formatting, so
    // note it while the DLL name is in front of us.
    std::string lower;
    for (char c : dll) lower += static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
    if (lower.compare(0, 6, "msvcrt") == 0) three_digit_exponents_ = true;

    // A few CRT imports are variables, not functions; binding those to a hook
    // address plants a bomb that goes off when the guest reads them as data.
    // They get real guest memory instead.
    if (uint64_t var = data_import(symbol)) return var;

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

bool Emulator::alias_hook(const std::string& existing, const std::string& alias) {
    auto it = hook_by_name_.find(existing);
    if (it == hook_by_name_.end()) return false;
    hook_by_name_[alias] = it->second;
    return true;
}

uint64_t Emulator::data_import(const std::string& symbol) {
    auto it = data_imports_.find(symbol);
    if (it != data_imports_.end()) return it->second;

    auto remember = [&](uint64_t addr) {
        data_imports_[symbol] = addr;
        return addr;
    };
    auto pointer_var = [&](uint64_t value) {
        // A pointer-sized variable holding `value` - the shape of _environ,
        // __argv and friends, whose import is the variable's address.
        uint64_t var = alloc_guest_data(nullptr, 0);
        mem.write_sized(var, pointer_size(), value);
        return remember(var);
    };

    if (symbol == "__initenv" || symbol == "_environ")
        return pointer_var(environment_vector());
    if (symbol == "__argc") {
        uint32_t argc = static_cast<uint32_t>(args_.size());
        return remember(alloc_guest_data(&argc, sizeof argc));
    }
    if (symbol == "__argv") {
        int ps = pointer_size();
        std::vector<uint64_t> ptrs;
        for (const auto& a : args_) ptrs.push_back(alloc_guest_string(a));
        std::vector<uint8_t> table((ptrs.size() + 1) * ps, 0);
        uint64_t base = alloc_guest_data(table.data(), table.size());
        for (size_t i = 0; i < ptrs.size(); ++i) mem.write_sized(base + i * ps, ps, ptrs[i]);
        return pointer_var(base);
    }
    if (symbol == "_fmode" || symbol == "_commode" || symbol == "__mb_cur_max") {
        uint32_t v = symbol == "__mb_cur_max" ? 1 : 0;
        return remember(alloc_guest_data(&v, sizeof v));
    }
    if (symbol == "_HUGE") {
        double inf = std::numeric_limits<double>::infinity();
        return remember(alloc_guest_data(&inf, sizeof inf));
    }
    if (symbol == "_iob") return remember(guest_file(0));  // the 3-entry FILE array
    if (symbol == "_pgmptr" || symbol == "__progname") {
        std::string path = args_.empty() ? "program.exe" : args_[0];
        if (os() == Os::Windows)
            for (char& c : path)
                if (c == '/') c = '\\';
        return pointer_var(alloc_guest_string(path));
    }
    return 0;
}

uint64_t Emulator::existing_hook(const std::string& symbol) const {
    auto it = hook_by_name_.find(symbol);
    if (it != hook_by_name_.end()) return it->second;
    // The stub created for an unimplemented import is registered as "DLL!name";
    // that is not an implementation, so it must not be handed out here.
    return 0;
}

uint64_t Emulator::hooked_module_handle(const std::string& name) {
    auto it = hooked_modules_.find(name);
    if (it != hooked_modules_.end()) return it->second;

    // Distinct per name so a guest can tell two modules apart.  An HMODULE is
    // also a base address, and code does read the PE header behind one - to look
    // for a version resource, say - so the page is real and carries a minimal
    // header describing a module with nothing in it.  A guest then finds no
    // exports and no resources, which it can handle; a fault it cannot.
    uint64_t handle = kHookedModuleBase + hooked_modules_.size() * 0x10000;
    mem.map(handle, 0x1000, "hooked module " + name);
    std::vector<uint8_t> zeros(0x1000, 0);
    mem.write(handle, zeros.data(), zeros.size());

    constexpr uint32_t kPeOffset = 0x40;
    mem.write8(handle + 0, 'M');
    mem.write8(handle + 1, 'Z');
    mem.write32(handle + 0x3C, kPeOffset);          // e_lfanew
    mem.write32(handle + kPeOffset, 0x00004550);    // "PE\0\0"
    mem.write16(handle + kPeOffset + 4, is64() ? 0x8664 : 0x014C);  // Machine
    mem.write16(handle + kPeOffset + 6, 0);         // NumberOfSections
    uint16_t optional_size = is64() ? 240 : 224;
    mem.write16(handle + kPeOffset + 20, optional_size);
    mem.write16(handle + kPeOffset + 22, 0x2000 | 0x0002);  // DLL, executable image

    uint64_t opt = handle + kPeOffset + 24;
    mem.write16(opt, is64() ? 0x020B : 0x010B);     // Magic
    if (is64())
        mem.write64(opt + 24, handle);              // ImageBase
    else
        mem.write32(opt + 28, static_cast<uint32_t>(handle));
    mem.write32(opt + 56, 0x1000);                  // SizeOfImage
    mem.write32(opt + 60, 0x1000);                  // SizeOfHeaders
    mem.write32(opt + (is64() ? 108 : 92), 16);     // NumberOfRvaAndSizes

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
    if (retry_hook_) {
        // The hook wants to be called again rather than return; leaving RIP where
        // it is means the next fetch dispatches it afresh.
        retry_hook_ = false;
        return true;
    }

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

void Emulator::add_atexit(uint64_t func, uint64_t table) {
    if (!table) {
        atexit_funcs_.push_back(func);
        return;
    }
    for (auto& [key, funcs] : onexit_tables_) {
        if (key == table) {
            funcs.push_back(func);
            return;
        }
    }
    onexit_tables_.push_back({table, {func}});
}

void Emulator::run_onexit_table(uint64_t table) {
    if (!table) {
        // Take the list first: a destructor may register more, and it must not
        // see itself run twice.
        std::vector<uint64_t> pending;
        pending.swap(atexit_funcs_);
        for (size_t i = pending.size(); i-- > 0;) {
            if (cpu_->halted) break;
            call_guest(pending[i], {});
        }
        return;
    }
    for (auto& [key, funcs] : onexit_tables_) {
        if (key != table) continue;
        std::vector<uint64_t> pending;
        pending.swap(funcs);
        for (size_t i = pending.size(); i-- > 0;) {
            if (cpu_->halted) break;
            call_guest(pending[i], {});
        }
        return;
    }
}

void Emulator::run_atexit() {
    // The process-wide list first, then each table in the order it appeared:
    // a module's own teardown should not run before the program's destructors.
    run_onexit_table(0);
    for (size_t i = 0; i < onexit_tables_.size() && !cpu_->halted; ++i)
        run_onexit_table(onexit_tables_[i].first);
}

uint32_t Emulator::tls_alloc() {
    // An index is process-wide; the value behind it is per-thread, which is the
    // whole point of the API.
    return next_dynamic_tls_slot_++;
}

uint64_t Emulator::tls_get(uint32_t index) const {
    if (threads_.empty()) return 0;
    const auto& slots = threads_[current_thread_]->tls_slots;
    return index < slots.size() ? slots[index] : 0;
}

void Emulator::tls_set(uint32_t index, uint64_t value) {
    if (threads_.empty()) return;
    auto& slots = threads_[current_thread_]->tls_slots;
    if (index >= slots.size()) slots.resize(index + 1, 0);
    slots[index] = value;
}

void Emulator::seed_environment() {
    // A language runtime finds its own installation through the environment, so
    // the guest inherits the host's rather than starting empty.
#if defined(_WIN32)
    // The wide environment, converted to UTF-8: the narrow one is in the host's
    // ANSI code page, and passing those bytes on turned a Japanese username in
    // %TMP% into mojibake the guest then failed to open.
    if (!_wenviron) (void)_wgetenv(L"PATH");  // force the wide environment into being
    for (wchar_t** p = _wenviron; p && *p; ++p) {
        std::u16string entry(reinterpret_cast<const char16_t*>(*p));
        std::string utf8;
        utf8.reserve(entry.size());
        for (size_t i = 0; i < entry.size();) {
            uint32_t cp = entry[i++];
            if (cp >= 0xD800 && cp < 0xDC00 && i < entry.size() &&
                entry[i] >= 0xDC00 && entry[i] < 0xE000)
                cp = 0x10000 + ((cp - 0xD800) << 10) + (entry[i++] - 0xDC00);
            if (cp < 0x80) {
                utf8 += static_cast<char>(cp);
            } else if (cp < 0x800) {
                utf8 += static_cast<char>(0xC0 | (cp >> 6));
                utf8 += static_cast<char>(0x80 | (cp & 0x3F));
            } else if (cp < 0x10000) {
                utf8 += static_cast<char>(0xE0 | (cp >> 12));
                utf8 += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                utf8 += static_cast<char>(0x80 | (cp & 0x3F));
            } else {
                utf8 += static_cast<char>(0xF0 | (cp >> 18));
                utf8 += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                utf8 += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                utf8 += static_cast<char>(0x80 | (cp & 0x3F));
            }
        }
        size_t eq = utf8.find('=');
        // A leading '=' marks Windows's hidden per-drive current directories,
        // which mean nothing here.
        if (eq == std::string::npos || eq == 0) continue;
        env_.emplace_back(utf8.substr(0, eq), utf8.substr(eq + 1));
    }
#else
    for (char** p = environ; p && *p; ++p) {
        std::string entry = *p;
        size_t eq = entry.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        env_.emplace_back(entry.substr(0, eq), entry.substr(eq + 1));
    }
#endif
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

    // env_ is UTF-8 now (see seed_environment); the wide block has to be real
    // UTF-16, not zero-extended bytes.
    std::u16string w = utf8_to_utf16(flat);
    return alloc_guest_data(w.data(), (w.size() + 0) * 2);
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

uint64_t Emulator::open_find_handle(std::vector<DirectoryEntry> entries) {
    uint64_t handle = next_find_handle_;
    next_find_handle_ += 8;
    find_handles_[handle] = FindState{std::move(entries), 0};
    return handle;
}

const Emulator::DirectoryEntry* Emulator::find_current(uint64_t handle) {
    auto it = find_handles_.find(handle);
    if (it == find_handles_.end() || it->second.index >= it->second.entries.size())
        return nullptr;
    return &it->second.entries[it->second.index];
}

bool Emulator::find_advance(uint64_t handle) {
    auto it = find_handles_.find(handle);
    if (it == find_handles_.end()) return false;
    ++it->second.index;
    return it->second.index < it->second.entries.size();
}

void Emulator::close_find_handle(uint64_t handle) { find_handles_.erase(handle); }

std::vector<std::string> Emulator::unimplemented_imports() const {
    std::vector<std::string> names;
    // resolve_import() names a stub "DLL!symbol"; a real hook is named after the
    // function alone, so the separator is what tells them apart.
    for (const auto& h : hooks_)
        if (h.name.find('!') != std::string::npos) names.push_back(h.name);
    std::sort(names.begin(), names.end());
    return names;
}

uint64_t Emulator::errno_address() {
    if (!errno_address_) {
        const uint32_t zero = 0;
        errno_address_ = alloc_guest_data(&zero, sizeof zero);
    }
    return errno_address_;
}

void Emulator::set_guest_errno(int value) {
    mem.write32(errno_address(), static_cast<uint32_t>(value));
}

void Emulator::report_file_error(int64_t code) {
    if (code >= 0) return;
    // FileTable speaks in negative Linux errno numbers, and the ones that matter
    // here happen to have the same values in a Windows CRT.
    set_guest_errno(static_cast<int>(-code));
}

std::string Emulator::stack_trace(int depth) {
    // Without unwind information the honest thing is to report every stack slot
    // that *could* be a return address, rather than pretend to know the frames.
    std::string out;
    int ps = pointer_size();
    uint64_t rsp = cpu_->regs[RSP];
    int found = 0;
    for (int i = 0; i < 64 && found < depth; ++i) {
        uint64_t slot = rsp + static_cast<uint64_t>(i) * ps;
        uint64_t value;
        try {
            value = mem.read_sized(slot, ps);
        } catch (const MemoryFault&) {
            break;
        }
        // A return address points into a mapped module.  Anything else is data,
        // but it is still worth showing: a stack slot that looks like nothing is
        // itself a clue.
        Module* m = module_for(value);
        if (!m && value < 0x10000) continue;
        char line[192];
        if (!m) {
            std::snprintf(line, sizeof line, "    [rsp+%-4d] 0x%llX\n", i * ps,
                          (unsigned long long)value);
            out += line;
            ++found;
            continue;
        }
        std::snprintf(line, sizeof line, "    [rsp+%-4d] 0x%llX  %s+0x%llX\n", i * ps,
                      (unsigned long long)value, m->name.c_str(),
                      (unsigned long long)(value - m->image.base));
        out += line;
        ++found;
    }
    return out;
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

uint64_t Emulator::alloc_pages(uint64_t size, uint64_t alignment) {
    uint64_t need = (size + 0xFFF) & ~0xFFFull;
    if (alignment > 0x1000) {
        // Round the frontier up instead of searching the free list: an
        // over-aligned request is rare (VirtualAlloc) and mixing the two
        // policies would fragment the window for no gain.
        mmap_next_ = (mmap_next_ + alignment - 1) & ~(alignment - 1);
        if (mmap_next_ + need > mmap_limit_) return 0;
        uint64_t addr = mmap_next_;
        mmap_next_ += need;
        mem.map(addr, need);
        mmap_live_[addr] = need;
        return addr;
    }

    // Best fit among the ranges munmap() returned, so that a long run of
    // equal-sized allocate/free cycles reuses one range forever.  (Under
    // X86EMU_QEMU_LAYOUT the free list is never consulted - qemu's cursor is
    // monotonic and matching its addresses is the whole point.)
    size_t best = mmap_free_.size();
    for (size_t i = 0; !mmap_no_reuse_ && i < mmap_free_.size(); ++i) {
        if (mmap_free_[i].second < need) continue;
        if (best == mmap_free_.size() || mmap_free_[i].second < mmap_free_[best].second) best = i;
    }
    if (best < mmap_free_.size()) {
        uint64_t addr = mmap_free_[best].first;
        uint64_t have = mmap_free_[best].second;
        if (have > need)
            mmap_free_[best] = {addr + need, have - need};  // keep the remainder
        else
            mmap_free_.erase(mmap_free_.begin() + static_cast<long>(best));
        mem.map(addr, need);
        mmap_live_[addr] = need;
        return addr;
    }

    if (mmap_next_ + need > mmap_limit_) return 0;
    uint64_t addr = mmap_next_;
    mmap_next_ += need;
    mem.map(addr, need);
    mmap_live_[addr] = need;
    return addr;
}

uint64_t Emulator::reserve_pages(uint64_t size, uint64_t alignment) {
    uint64_t need = (size + 0xFFF) & ~0xFFFull;
    if (alignment < 0x1000) alignment = 0x1000;
    mmap_next_ = (mmap_next_ + alignment - 1) & ~(alignment - 1);
    if (mmap_next_ + need > mmap_limit_) return 0;
    uint64_t addr = mmap_next_;
    mmap_next_ += need;
    // Deliberately no mem.map(): the pages appear when the guest commits them.
    return addr;
}

void Emulator::free_pages(uint64_t addr, uint64_t size) {
    uint64_t page_addr = addr & ~0xFFFull;
    uint64_t need = (size + (addr - page_addr) + 0xFFF) & ~0xFFFull;
    if (!need) return;
    // Only ranges inside the mmap window are ours to recycle; a guest may also
    // munmap part of its own image or a range ld.so mapped at a fixed address,
    // which just drops the pages.
    mem.unmap(page_addr, need);
    if (page_addr >= mmap_limit_) return;
    auto it = mmap_live_.find(page_addr);
    if (it != mmap_live_.end() && it->second <= need) {
        mmap_free_.emplace_back(page_addr, it->second);
        mmap_live_.erase(it);
        return;
    }
    // A partial unmap: give back exactly what was asked for.  Coalescing is not
    // attempted; best-fit reuse is enough for the allocation patterns seen here.
    if (page_addr >= mmap_next_) return;   // never handed out
    mmap_free_.emplace_back(page_addr, need);
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

void Emulator::write_wide_stream(uint64_t guest_file, const std::string& text) {
    int fd = host_fd(guest_file);
    if (fd < 0) fd = 1;
    FileTable::Entry* entry = files.get(fd);
    FileTable::WideIo enc = entry ? entry->wide_io : FileTable::WideIo::Multibyte;
    if (enc != FileTable::WideIo::Utf16) {
        // Multibyte and UTF-8 are the same thing here: this emulator's narrow
        // encoding is UTF-8 throughout, and GetACP says so.
        write_stream(guest_file, text);
        return;
    }
    std::u16string w = utf8_to_utf16(text);
    std::string bytes;
    bytes.reserve(w.size() * 2);
    for (char16_t u : w) {
        bytes.push_back(static_cast<char>(u & 0xFF));
        bytes.push_back(static_cast<char>((u >> 8) & 0xFF));
    }
    if (fd <= 2) {
        write_raw(fd, bytes.data(), bytes.size());
        return;
    }
    files.write(fd, bytes.data(), bytes.size());
}

std::string Emulator::read_wide_line(uint64_t guest_file, bool& found) {
    found = false;
    int fd = host_fd(guest_file);
    if (fd < 0) return {};
    FileTable::Entry* entry = files.get(fd);
    FileTable::WideIo enc = entry ? entry->wide_io : FileTable::WideIo::Multibyte;
    if (enc != FileTable::WideIo::Utf16) {
        std::string line;
        char c;
        while (files.read(fd, &c, 1) == 1) {
            found = true;
            line += c;
            if (c == 0x0A) break;
        }
        return line;
    }
    // A UTF-16 stream: one code unit at a time, so the newline is recognised in
    // the same encoding the file is written in.  A byte-oriented reader would
    // find a newline byte in the low half of any character whose code point is
    // 0x0A00-something, and stop in the middle of one.
    std::u16string w;
    uint8_t pair[2];
    while (files.read(fd, pair, 2) == 2) {
        found = true;
        char16_t u = static_cast<char16_t>(pair[0] | (pair[1] << 8));
        // The byte-order mark a writer puts at the start is not part of the text.
        if (u == 0xFEFF) continue;
        w.push_back(u);
        if (u == 0x0A) break;
    }
    std::string out;
    for (char16_t u : w) {
        if (u < 0x80) {
            out.push_back(static_cast<char>(u));
        } else if (u < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (u >> 6)));
            out.push_back(static_cast<char>(0x80 | (u & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (u >> 12)));
            out.push_back(static_cast<char>(0x80 | ((u >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (u & 0x3F)));
        }
    }
    return out;
}

void Emulator::write_stream(uint64_t guest_file, const std::string& data) {
    int fd = host_fd(guest_file);
    // A stream the emulator does not model - one taken from an imported _iob
    // array, say - is most likely the console, and that is the harmless guess.
    if (fd < 0) fd = 1;
    if (fd <= 2) {
        write_text(fd, data);
        return;
    }
    // FileTable owns whether this descriptor translates newlines, so the data
    // goes through unchanged; translating here as well would double every
    // carriage return.
    files.write(fd, data.data(), data.size());
}

void Emulator::write_raw(int fd, const void* data, size_t len) {
    if (!len) return;
    // A child process whose stdout is a pipe or a redirected file has a
    // non-standard entry at descriptor 1; those bytes belong in the descriptor,
    // not on the host's console.
    if (FileTable::Entry* e = files.get(fd); e && !e->standard_stream) {
        files.write(fd, data, len);
        return;
    }
    // Deliberately does *not* flush the stdio buffer first.  WriteFile knows
    // nothing about the C runtime's buffer on real Windows either, so a guest
    // that mixes the two sees its raw writes overtake its buffered ones - and
    // matching that is the whole point of buffering here.
    if (output_sink)
        output_sink(fd, static_cast<const char*>(data), len);
    else
        std::fwrite(data, 1, len, fd == 2 ? stderr : stdout);
}

void Emulator::flush_guest_output() {
    if (stdout_buffer_.empty()) return;
    std::string out;
    out.swap(stdout_buffer_);
    if (FileTable::Entry* e = files.get(1); e && !e->standard_stream) {
        files.write(1, out.data(), out.size());
        return;
    }
    if (output_sink)
        output_sink(1, out.data(), out.size());
    else
        std::fwrite(out.data(), 1, out.size(), stdout);
}

void Emulator::write_text(int fd, const std::string& data) {
    if (os() != Os::Windows) {
        write_raw(fd, data.data(), data.size());
        return;
    }
    // stderr is never buffered, matching every C runtime.
    if (fd == 1 && buffer_stdout_) {
        for (char c : data) {
            if (c == '\n') stdout_buffer_ += '\r';
            stdout_buffer_ += c;
        }
        // 4 KiB is the usual block size, and holding more than that would only
        // delay output a guest expects to have written.
        if (stdout_buffer_.size() >= 4096) flush_guest_output();
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

// Fills in a synthetic FILE using the layout a Windows CRT really has, so that
// code which reads *inside* the structure - and real DLLs do, `_fileno` being a
// macro over `_file` - finds what it expects rather than a private encoding.
// The UCRT's `__crt_stdio_stream_data` is:
//     0x00 _ptr, 0x08 _base, 0x10 _cnt, 0x14 _flags, 0x18 _file,
//     0x1C _charbuf, 0x20 _bufsiz, 0x28 _tmpfname, 0x30 CRITICAL_SECTION
// which is 88 bytes on x64; msvcrt's older form is the same fields at half the
// pointer width.  `_flags` says the stream is open and in which direction,
// because a stream with no direction bits reads as closed.
void Emulator::write_guest_file_object(uint64_t obj, int fd) {
    constexpr uint32_t kIoRead = 0x0001, kIoWrite = 0x0002, kIoUpdate = 0x0004;
    uint32_t flags = fd == 0 ? kIoRead : (fd <= 2 ? kIoWrite : (kIoRead | kIoWrite | kIoUpdate));
    if (is64()) {
        mem.write32(obj + 0x14, flags);
        mem.write32(obj + 0x18, static_cast<uint32_t>(fd));
        mem.write32(obj + 0x1C, 0);
        mem.write32(obj + 0x20, 4096);   // _bufsiz
    } else {
        // 32-bit: _ptr(0) _base(4) _cnt(8) _flags(0xC) _file(0x10) ...
        mem.write32(obj + 0x0C, flags);
        mem.write32(obj + 0x10, static_cast<uint32_t>(fd));
        mem.write32(obj + 0x18, 4096);
    }
}

uint64_t Emulator::guest_file(int fd) {
    auto it = guest_files_.find(fd);
    if (it != guest_files_.end()) return it->second;

    // The first three are allocated as one contiguous block, because a guest may
    // reach them through an imported _iob[] array rather than one at a time -
    // and CRT code computes `stderr` as `_iob + 2 * sizeof(FILE)`, so the stride
    // must be the *CRT's* FILE size, not a number of our choosing, or the
    // pointer lands between objects and stderr silently resolves elsewhere.
    uint64_t stride = file_object_stride();
    if (guest_files_.empty()) {
        std::vector<uint8_t> blob(static_cast<size_t>(3 * stride), 0);
        uint64_t base = alloc_guest_data(blob.data(), blob.size());
        for (int i = 0; i < 3; ++i) {
            uint64_t obj = base + static_cast<uint64_t>(i) * stride;
            write_guest_file_object(obj, i);
            guest_files_[i] = obj;
            guest_file_fds_[obj] = i;
        }
        if (fd >= 0 && fd <= 2) return guest_files_[fd];
    }

    std::vector<uint8_t> blob(static_cast<size_t>(stride), 0);
    uint64_t obj = alloc_guest_data(blob.data(), blob.size());
    write_guest_file_object(obj, fd);
    guest_files_[fd] = obj;
    guest_file_fds_[obj] = fd;
    return obj;
}

int Emulator::host_fd(uint64_t ptr) const {
    auto it = guest_file_fds_.find(ptr);
    if (it != guest_file_fds_.end()) return it->second;
    // A guest that arrived at a FILE* by arithmetic - stepping through an
    // imported `_iob` array, say - still deserves an answer, and the object
    // itself carries the descriptor in the field a CRT calls `_file`.  Only
    // objects inside our own allocations are read this way: anywhere else the
    // bytes would be someone's data.
    if (ptr && ptr >= misc_base_ && ptr < misc_next_) {
        try {
            uint64_t flags_at = is64() ? 0x14 : 0x0C;
            if (mem.read32(ptr + flags_at) != 0) {  // a stream with no direction is closed
                int fd = static_cast<int>(mem.read32(ptr + (is64() ? 0x18 : 0x10)));
                if (fd >= 0 && fd < 4096) return fd;
            }
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
    std::string cmd = raw_command_line_;
    if (cmd.empty()) {
        for (const auto& a : args) {
            if (!cmd.empty()) cmd += ' ';
            cmd += a;
        }
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

    // The environment.  A guest whose parent set one (execve) gets exactly
    // that; a root process gets a standard PATH rather than the host's
    // Windows variables - gcc's collect2 finds `ld` through PATH, and a
    // Linux guest reading LANG=Japanese_Japan.932 would be worse off than
    // reading nothing.
    std::vector<std::pair<std::string, std::string>> guest_env;
    if (env_explicit_)
        guest_env = env_;
    else
        guest_env.emplace_back("PATH",
                               "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    std::vector<uint64_t> env_ptrs;
    for (const auto& [k, v] : guest_env) env_ptrs.push_back(push_bytes(k + "=" + v));
    // 16 random bytes for AT_RANDOM, which libc uses to seed stack guards.
    uint8_t random[16] = {0x5A, 0x17, 0x3C, 0x91, 0x2B, 0x44, 0xE0, 0x77,
                          0x1F, 0x63, 0xB8, 0x0A, 0xD5, 0x29, 0x8E, 0x46};
    sp -= sizeof random;
    uint64_t at_random = sp;
    mem.write(sp, random, sizeof random);

    struct Aux {
        uint64_t key, val;
    };
    std::vector<Aux> auxv = {
        {6, 0x1000},                        // AT_PAGESZ
        {3, image_.phdr_addr},              // AT_PHDR
        {4, image_.phent_size},             // AT_PHENT
        {5, image_.phnum},                  // AT_PHNUM
        {9, image_.entry},                  // AT_ENTRY  (the real program, even under ld.so)
        {11, 0}, {12, 0}, {13, 0}, {14, 0}, // AT_UID/EUID/GID/EGID
        {25, at_random},                    // AT_RANDOM
        {23, 0},                            // AT_SECURE
    };
    // AT_BASE tells the dynamic loader where it was itself mapped, so it can
    // relocate its own code before doing anything else.
    if (image_.is_dynamic && image_.interp_entry)
        auxv.push_back({7, image_.interp_base});   // AT_BASE
    auxv.push_back({0, 0});                         // AT_NULL

    // Total slots: argc + argv + NULL + envp + NULL + auxv pairs.
    uint64_t slots = 1 + argv_ptrs.size() + 1 + env_ptrs.size() + 1 + auxv.size() * 2;
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
    for (uint64_t a : env_ptrs) put(a);
    put(0);  // end of environment
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
    // A child process inherits its parent's environment, which set_environment
    // installed; only a root process starts from the host's.
    if (!env_explicit_) seed_environment();

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
    // A Windows CRT block-buffers stdout unless it is a terminal.  Matching that
    // is what makes printf and WriteFile interleave the same way they would on
    // Windows; a terminal writes straight through so output stays live.
    if (os_kind == Os::Windows) {
        auto* out = files.get(1);
        buffer_stdout_ = out && !out->is_tty;
    }

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
        install_thread_hooks();
        install_win32_hooks();
        install_win32_extra_hooks();
        install_win32_fs_hooks();
        install_ucrt_hooks();
        install_process_hooks();
        install_cl_hooks();
        install_link_hooks();
        // Last, so that its real implementations win over the stubs the files
        // above register for a guest that cannot be supported yet.
        install_exception_hooks();
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
        // Real DLLs are mapped above the executable, well clear of it - and,
        // in a 32-bit guest, clear of the *stack*: the exe ends near 0x500000
        // and the stack occupies 0x140000..0x540000, so "just past the exe"
        // loaded msvcp140 into memory the guest's own stack frames grow into.
        // c1.dll's initialisers, whose locals run to 33 KB, overwrote its code
        // and the crash surfaced two DLL loads later, inside mspdbcore.
        dll_next_base_ = (exe.base + exe.size + 0xFFFFF) & ~0xFFFFFull;
        if (!is64() && dll_next_base_ < 0x60000000ull) dll_next_base_ = 0x60000000ull;
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
        // The PIE base has to fit the guest's pointer size: the 64-bit default
        // truncates to 0x55554000 in a 32-bit guest, which is not where the
        // pages went.  0x56555000 is where a 32-bit Linux kernel puts one.
        image_ = load_elf(file, mem, is64() ? 0x555555554000ull : 0x56555000ull);
        // A dynamic (PIE) executable names an interpreter (ld.so) in PT_INTERP.
        // Map it at its own base and enter there first; it relocates the program
        // and the shared libraries and then jumps to the real entry (AT_ENTRY).
        if (image_.is_dynamic && !image_.interp.empty()) {
            // The base must fit the guest's pointer size: the 64-bit constant
            // truncated to 32 bits landed ld-linux.so.2 in unmapped memory and
            // the first indirect jump went with it.
            const uint64_t interp_base =
                is64() ? 0x00007F0000000000ull : 0x60000000ull;
            std::vector<uint8_t> ld = read_file(FileTable::host_path(image_.interp));
            LoadedImage li = load_elf(ld, mem, interp_base);
            image_.interp_base = li.load_bias;
            image_.interp_entry = li.entry;
        }
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

    // A dynamic executable enters its loader (ld.so) first; the loader jumps to
    // image_.entry itself once relocation is done. A static one enters directly.
    cpu_->rip = (image_.is_dynamic && image_.interp_entry) ? image_.interp_entry
                                                           : image_.entry;

    // The program itself is thread 0.  Registering it means the scheduler has a
    // single code path whether or not the guest ever creates another thread.
    {
        auto main_thread = std::make_unique<GuestThread>();
        main_thread->id = next_thread_id_++;
        main_thread->stack_base = stack_base_;
        main_thread->stack_size = stack_size_;
        main_thread->teb = teb_base_;
        main_thread->tls_array = tls_array_;
        main_thread->handle = create_sync_object(SyncObject::Kind::Thread, true, false, 0);
        sync_object(main_thread->handle)->owner = main_thread->id;
        threads_.push_back(std::move(main_thread));
        current_thread_ = 0;
        // Its context is whatever the CPU already holds; switch_to_thread saves
        // that on the way out, so nothing needs copying in now.
    }

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
    struct FlushOnExit {
        Emulator* e;
        ~FlushOnExit() { e->flush_guest_output(); }
    } flush_guard{this};

    // The System schedules processes the way this emulator schedules threads;
    // with no children it degenerates to the plain interpreter loop.
    System sys(this);
    int code = sys.run();
    std::fflush(stdout);
    return code;
}

Emulator::SliceStatus Emulator::run_slice(uint64_t quantum) {
    if (cpu_->halted) return SliceStatus::Exited;

    // Wake anything whose wait is satisfied, and choose who runs this slice.
    size_t next = pick_runnable();
    if (next >= threads_.size()) return SliceStatus::Idle;
    switch_to_thread(next);

    uint64_t deadline = cpu_->instructions_executed + quantum;
    reschedule_ = false;
    while (!cpu_->halted && !reschedule_ && cpu_->instructions_executed < deadline) {
        try {
            cpu_->step();
        } catch (const UnwindTransfer& transfer) {
            // An exception found its handler.  The host frames between the throw
            // and here - nested interpreter loops, one per language handler the
            // dispatcher called - are gone with the C++ throw that got us here;
            // the guest continues from the context the unwinder built.
            apply_unwind_transfer(transfer);
        }
        if (opt_.max_instructions && cpu_->instructions_executed >= opt_.max_instructions)
            throw CpuError(cpu_->rip, "instruction limit reached (possible infinite loop)");
    }
    return cpu_->halted ? SliceStatus::Exited : SliceStatus::Ran;
}

uint64_t Emulator::next_timer_wake() const {
    uint64_t earliest = 0;
    for (const auto& t : threads_) {
        if (t->state != GuestThread::State::Blocked || !t->wake_at) continue;
        if (!earliest || t->wake_at < earliest) earliest = t->wake_at;
    }
    return earliest;
}

void Emulator::block_hook_retry(std::function<bool()> pred) {
    GuestThread* t = current_thread();
    if (!t) throw CpuError(cpu_->rip, "cannot block: no current thread");
    t->state = GuestThread::State::Blocked;
    t->wait_predicate = std::move(pred);
    retry_current_call();
    yield_now();
}

void Emulator::block_syscall_retry(std::function<bool()> pred) {
    GuestThread* t = current_thread();
    if (!t) throw CpuError(cpu_->rip, "cannot block: no current thread");
    // Both `syscall` (0F 05) and `int 0x80` (CD 80) are two bytes; stepping back
    // makes the whole call happen again once the wait is over.
    cpu_->rip -= 2;
    t->state = GuestThread::State::Blocked;
    t->wait_predicate = std::move(pred);
    syscall_blocked_ = true;  // tells the dispatcher to leave RAX (the number) alone
    yield_now();
}

bool Emulator::take_syscall_block() {
    bool b = syscall_blocked_;
    syscall_blocked_ = false;
    return b;
}

void Emulator::request_exec(ExecRequest req) {
    exec_request_ = std::make_unique<ExecRequest>(std::move(req));
    GuestThread* t = current_thread();
    if (t) {
        exec_waiter_tid_ = t->id;
        // Parked until the System either swaps the image (this thread ends with
        // it) or reports failure through fail_exec().
        t->state = GuestThread::State::Blocked;
        t->wait_predicate = [] { return false; };
    }
    yield_now();
}

void Emulator::fail_exec(int64_t err) {
    for (auto& t : threads_) {
        if (t->id != exec_waiter_tid_) continue;
        t->state = GuestThread::State::Runnable;
        t->wait_predicate = nullptr;
        // The thread's context is live in the CPU if it is still the current
        // one (nothing else ran since it blocked), saved otherwise.
        if (threads_[current_thread_].get() == t.get())
            cpu_->regs[RAX] = static_cast<uint64_t>(err);
        else
            t->regs[RAX] = static_cast<uint64_t>(err);
        break;
    }
}

void Emulator::set_environment(std::vector<std::pair<std::string, std::string>> env) {
    env_ = std::move(env);
    env_explicit_ = true;
}

std::unique_ptr<Emulator> Emulator::fork_clone() {
    if (os() != Os::Linux)
        throw CpuError(cpu_->rip, "fork() is only supported for Linux guests");

    auto child = std::make_unique<Emulator>(opt_);
    child->image_ = image_;
    child->args_ = args_;
    child->env_ = env_;
    child->env_explicit_ = true;
    child->raw_command_line_ = raw_command_line_;
    child->output_sink = output_sink;

    child->mem.clone_from(mem);
    child->cpu_ = std::make_unique<Cpu>(child->mem, image_.mode);
    Cpu& c = *child->cpu_;
    std::memcpy(c.regs, cpu_->regs, sizeof c.regs);
    std::memcpy(c.xmm, cpu_->xmm, sizeof c.xmm);
    std::memcpy(c.st, cpu_->st, sizeof c.st);
    std::memcpy(c.st_used, cpu_->st_used, sizeof c.st_used);
    c.st_top = cpu_->st_top;
    c.fpu_control = cpu_->fpu_control;
    c.fpu_status = cpu_->fpu_status;
    c.mxcsr = cpu_->mxcsr;
    c.rip = cpu_->rip;  // already past the syscall instruction
    c.rflags = cpu_->rflags;
    c.fs_base = cpu_->fs_base;
    c.gs_base = cpu_->gs_base;
    c.instructions_executed = cpu_->instructions_executed;
    c.trace = cpu_->trace;
    c.regs[RAX] = 0;  // fork() returns 0 in the child

    child->files = files.clone();

    // The guest layout is state, not configuration; the child continues from
    // the parent's exact allocation frontier.
    child->hook_base_ = hook_base_;
    child->stack_base_ = stack_base_;
    child->stack_size_ = stack_size_;
    child->stack_top_ = stack_top_;
    child->heap_base_ = heap_base_;
    child->heap_next_ = heap_next_;
    child->heap_limit_ = heap_limit_;
    child->mmap_next_ = mmap_next_;
    child->mmap_limit_ = mmap_limit_;
    child->misc_base_ = misc_base_;
    child->misc_next_ = misc_next_;
    child->teb_base_ = teb_base_;
    child->brk_ = brk_;
    child->heap_blocks_ = heap_blocks_;
    child->guest_files_ = guest_files_;
    child->guest_file_fds_ = guest_file_fds_;
    child->last_error_ = last_error_;
    child->three_digit_exponents_ = three_digit_exponents_;
    child->stdout_buffer_ = stdout_buffer_;
    child->buffer_stdout_ = buffer_stdout_;
    child->errno_address_ = errno_address_;
    child->lconv_address_ = lconv_address_;
    child->tls_array_ = tls_array_;
    child->next_tls_slot_ = next_tls_slot_;
    child->tls_templates_ = tls_templates_;
    child->next_dynamic_tls_slot_ = next_dynamic_tls_slot_;
    child->atexit_funcs_ = atexit_funcs_;
    child->onexit_tables_ = onexit_tables_;
    child->sync_objects_ = sync_objects_;
    child->next_sync_handle_ = next_sync_handle_;
    child->find_handles_ = find_handles_;
    child->next_find_handle_ = next_find_handle_;

    // Hooks are installed in the same order load_bytes() uses for a Linux
    // guest, which reproduces the same addresses - although a Linux guest never
    // calls them by address anyway, only the two thunks matter.
    child->exit_thunk_ = child->add_hook("__emu_exit__", 0, [](Emulator& e) {
        e.exit_process(static_cast<int>(static_cast<int32_t>(e.cpu().regs[RAX])));
    });
    child->nested_return_ = child->add_hook("__emu_nested_return__", 0, [](Emulator&) {});
    child->install_library_hooks();
    child->install_math_hooks();
    child->install_file_hooks();
    child->install_libc_hooks();
    Emulator* raw = child.get();
    child->cpu_->on_hook_call = [raw](uint64_t addr) { return raw->dispatch_hook(addr); };
    child->install_syscall_handlers();

    // fork() keeps only the calling thread.
    auto t = std::make_unique<GuestThread>();
    const GuestThread& cur = *threads_[current_thread_];
    t->id = cur.id;
    t->handle = cur.handle;
    t->stack_base = cur.stack_base;
    t->stack_size = cur.stack_size;
    t->teb = cur.teb;
    t->tls_array = cur.tls_array;
    t->tls_slots = cur.tls_slots;
    t->clear_child_tid = cur.clear_child_tid;
    child->threads_.push_back(std::move(t));
    child->current_thread_ = 0;
    child->next_thread_id_ = next_thread_id_;

    return child;
}

}  // namespace x86emu
