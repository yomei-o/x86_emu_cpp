// The one header that says which guest this copy of the translator serves.
//
// Everything else under jit/ is written against the names declared here, so the
// translation cache, the threaded and WebAssembly backends and the verifier can be
// shared between emulators for different CPUs: each repository carries the same
// files plus its own glue.h, one frontend, and the code for the ops that only its
// ISA has (flags, special addressing).
//
// This is the x86 / x86-64 one.
#pragma once

#include <cstdint>
#include <string>

#include "../cpu.h"

namespace jit {

using GCpu = x86emu::Cpu;
using GMemory = x86emu::Memory;
using GObserver = x86emu::CodeObserver;
using GFault = x86emu::MemoryFault;

// Names of the environment variables that control the translator.
#define JIT_ENV(n) "X86EMU_" n

// Byte offsets, from the start of the guest register file, of the cells translated
// code uses.  The first four are needed by every guest; the rest are x86's.
struct GuestSlots {
    int32_t zero = 0;      // a cell that always reads zero
    int32_t rip = 0;       // the program counter
    int32_t tmp0 = 0;      // the first temporary
    int32_t ntmp = 0;      // how many temporaries
    int32_t rflags = 0, fs_base = 0, gs_base = 0;
    int32_t cc_a = 0, cc_b = 0, cc_kind = 0, cc_sz = 0;   // deferred flags
};

// Settles deferred flags (Cpu::cc_kind) into rflags.
void materialize_flags(GCpu& cpu);

// A guest's machine state as the verifier compares it.
struct GuestState {
    uint64_t regs[16];
    GCpu::Xmm xmm[16];
    uint32_t mxcsr;
    double st[8];
    bool st_used[8];
    int st_top;
    uint16_t fpu_control, fpu_status;
    uint64_t rip, rflags, fs_base, gs_base, icount;
    bool halted;
};

struct Glue {
    // The register file, which is also where the temporaries live.
    static uint8_t* env(GCpu& c) { return reinterpret_cast<uint8_t*>(c.regs); }
    static void fill_slots(GuestSlots& s, GCpu& c);

    static uint64_t pc(const GCpu& c) { return c.rip; }
    static void set_pc(GCpu& c, uint64_t v) { c.rip = v; }
    static uint64_t icount(const GCpu& c) { return c.instructions_executed; }
    static void add_icount(GCpu& c, uint64_t n) { c.instructions_executed += n; }
    static bool halted(const GCpu& c) { return c.halted; }
    // Addresses the host answers for (hooks): never translated.
    static bool in_hook(const GCpu& c, uint64_t pc) { return pc >= c.hook_low && pc <= c.hook_high; }
    // One instruction through the interpreter.
    static void step(GCpu& c) { c.step(); }
    // Make the architectural state exact: settle anything translated code deferred.
    static void settle(GCpu& c) { if (c.cc_kind) materialize_flags(c); }
    static bool is64(const GCpu& c) { return c.is64(); }

    // The verifier.
    static void take(const GCpu& c, GuestState& s);
    static void put(GCpu& c, const GuestState& s);
    static std::string diff(const GuestState& a, const GuestState& b);
    static const char* reg_name(int i) { return GCpu::reg_name(i, 8); }
};

}  // namespace jit
