// The x86 guest's side of the translator: how the engine finds the registers, and
// the Cpu entry points that hand control to it.
#include <cstring>
#include <string>

#include "engine.h"

namespace jit {

void Glue::fill_slots(GuestSlots& s, GCpu& cpu) {
    auto off = [&](const void* p) {
        return static_cast<int32_t>(reinterpret_cast<const uint8_t*>(p) -
                                    reinterpret_cast<const uint8_t*>(cpu.regs));
    };
    s.zero = off(&cpu.jit_tmp[0]);
    s.tmp0 = off(&cpu.jit_tmp[1]);
    s.ntmp = static_cast<int32_t>(sizeof(cpu.jit_tmp) / sizeof(cpu.jit_tmp[0])) - 1;
    s.rflags = off(&cpu.rflags);
    s.rip = off(&cpu.rip);
    s.fs_base = off(&cpu.fs_base);
    s.gs_base = off(&cpu.gs_base);
    s.cc_a = off(&cpu.cc_a);
    s.cc_b = off(&cpu.cc_b);
    s.cc_kind = off(&cpu.cc_kind);
    s.cc_sz = off(&cpu.cc_sz);
}

void Glue::take(const GCpu& c, GuestState& s) {
    std::memcpy(s.regs, c.regs, sizeof s.regs);
    std::memcpy(s.xmm, c.xmm, sizeof s.xmm);
    s.mxcsr = c.mxcsr;
    std::memcpy(s.st, c.st, sizeof s.st);
    std::memcpy(s.st_used, c.st_used, sizeof s.st_used);
    s.st_top = c.st_top;
    s.fpu_control = c.fpu_control;
    s.fpu_status = c.fpu_status;
    s.rip = c.rip;
    s.rflags = c.rflags;
    s.fs_base = c.fs_base;
    s.gs_base = c.gs_base;
    s.icount = c.instructions_executed;
    s.halted = c.halted;
}

void Glue::put(GCpu& c, const GuestState& s) {
    std::memcpy(c.regs, s.regs, sizeof s.regs);
    std::memcpy(c.xmm, s.xmm, sizeof s.xmm);
    c.mxcsr = s.mxcsr;
    std::memcpy(c.st, s.st, sizeof s.st);
    std::memcpy(c.st_used, s.st_used, sizeof s.st_used);
    c.st_top = s.st_top;
    c.fpu_control = s.fpu_control;
    c.fpu_status = s.fpu_status;
    c.rip = s.rip;
    c.rflags = s.rflags;
    c.fs_base = s.fs_base;
    c.gs_base = s.gs_base;
    c.instructions_executed = s.icount;
    c.halted = s.halted;
}

std::string Glue::diff(const GuestState& s1, const GuestState& s2) {
    std::string diff;
    char buf[256];
    auto note = [&](const char* what, uint64_t a, uint64_t c) {
        std::snprintf(buf, sizeof buf, "  %s: jit %016llX  interp %016llX\n", what,
                      (unsigned long long)a, (unsigned long long)c);
        diff += buf;
    };
    for (int i = 0; i < 16; ++i)
        if (s1.regs[i] != s2.regs[i]) note(GCpu::reg_name(i, 8), s1.regs[i], s2.regs[i]);
    if (s1.rip != s2.rip) note("rip", s1.rip, s2.rip);
    if (s1.rflags != s2.rflags) note("rflags", s1.rflags, s2.rflags);
    if (s1.icount != s2.icount) note("icount", s1.icount, s2.icount);
    if (s1.halted != s2.halted) note("halted", s1.halted, s2.halted);
    if (s1.fs_base != s2.fs_base) note("fs_base", s1.fs_base, s2.fs_base);
    if (s1.gs_base != s2.gs_base) note("gs_base", s1.gs_base, s2.gs_base);
    if (std::memcmp(s1.xmm, s2.xmm, sizeof s1.xmm) != 0) diff += "  xmm differ\n";
    if (std::memcmp(s1.st, s2.st, sizeof s1.st) != 0 || s1.st_top != s2.st_top ||
        s1.fpu_status != s2.fpu_status || s1.fpu_control != s2.fpu_control)
        diff += "  x87 differs\n";
    if (s1.mxcsr != s2.mxcsr) diff += "  mxcsr differs\n";
    return diff;
}

}  // namespace jit

namespace x86emu {

Cpu::~Cpu() { delete jit_; }

void Cpu::enable_jit(bool on) {
    if (on == (jit_ != nullptr)) return;
    if (on) {
        jit_ = new jit::Engine(*this, mem_);
    } else {
        delete jit_;
        jit_ = nullptr;
    }
}

bool Cpu::jit_run(uint64_t deadline, uint64_t stop_pc, const bool* yield) {
    return jit_->run(deadline, stop_pc, yield);
}

bool Cpu::jit_run_block() {
    if (rip >= hook_low && rip <= hook_high) return false;
    return jit_->run_block();
}

}  // namespace x86emu
