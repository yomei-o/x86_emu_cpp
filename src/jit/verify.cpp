// X86EMU_JIT_VERIFY=1: run every block twice, translated and then interpreted
// from the same starting state, and stop at the first difference.
//
// This is how the translator is checked against the interpreter on code nobody
// wrote a test for.  What it compares is what the rest of the emulator can see
// when a block ends: the registers, rip, all the flags (a block must leave the
// flags exact at its end even though it skips writes nobody reads inside it),
// the vector and x87 state, and every page either run wrote.
//
// Blocks containing an instruction with outside effects - a system call, an
// interrupt - are run once and not compared: doing them twice would be visible.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "../cpu.h"
#include "engine.h"

namespace jit {

using x86emu::Cpu;
using x86emu::Memory;

namespace {

struct Snap {
    uint64_t regs[16];
    Cpu::Xmm xmm[16];
    uint32_t mxcsr;
    double st[8];
    bool st_used[8];
    int st_top;
    uint16_t fpu_control, fpu_status;
    uint64_t rip, rflags, fs_base, gs_base, icount;
    bool halted;
};

void take(const Cpu& c, Snap& s) {
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

void put(Cpu& c, const Snap& s) {
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

}  // namespace

bool Engine::run_verified(Block* b) {
    if (b->effects) return run_plain(b);
    Snap s0, s1, s2;
    take(cpu, s0);

    mem.journal_begin();
    try {
        run_plain(b);
    } catch (...) {
        mem.journal_end();
        throw;
    }
    mem.journal_end();
    take(cpu, s1);
    const uint64_t n = s1.icount - s0.icount;

    // What the translated run left in every page it wrote; then put it all back.
    auto old1 = std::move(mem.journal());
    std::unordered_map<uint64_t, std::vector<uint8_t>> after;
    for (auto& kv : old1) {
        uint8_t* p = mem.page_ptr(kv.first);
        after[kv.first].assign(p, p + Memory::kPageSize);
        std::memcpy(p, kv.second->data(), Memory::kPageSize);
    }
    put(cpu, s0);

    mem.journal_begin();
    try {
        for (uint64_t i = 0; i < n; ++i) cpu.step();
    } catch (...) {
        mem.journal_end();
        throw;
    }
    mem.journal_end();
    take(cpu, s2);

    std::string diff;
    char buf[256];
    auto note = [&](const char* what, uint64_t a, uint64_t c) {
        std::snprintf(buf, sizeof buf, "  %s: jit %016llX  interp %016llX\n", what,
                      (unsigned long long)a, (unsigned long long)c);
        diff += buf;
    };
    for (int i = 0; i < 16; ++i)
        if (s1.regs[i] != s2.regs[i]) note(Cpu::reg_name(i, 8), s1.regs[i], s2.regs[i]);
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

    auto cmp_page = [&](uint64_t page, const uint8_t* jit_img) {
        const uint8_t* cur = mem.page_ptr(page);
        if (std::memcmp(jit_img, cur, Memory::kPageSize) == 0) return;
        for (uint64_t k = 0; k < Memory::kPageSize; ++k) {
            if (jit_img[k] != cur[k]) {
                std::snprintf(buf, sizeof buf, "  memory %016llX: jit %02X  interp %02X\n",
                              (unsigned long long)((page << Memory::kPageBits) + k), jit_img[k],
                              cur[k]);
                diff += buf;
                break;
            }
        }
    };
    for (auto& kv : after) cmp_page(kv.first, kv.second.data());
    for (auto& kv : mem.journal())
        if (!after.count(kv.first)) cmp_page(kv.first, kv.second->data());

    if (!diff.empty()) {
        std::string bytes;
        for (uint32_t i = 0; i < b->guest_bytes && i < 96; ++i) {
            std::snprintf(buf, sizeof buf, "%02X ", mem.read8(b->start + i));
            bytes += buf;
        }
        std::fprintf(stderr, "jit verify: block at %016llX (%u native insns) differs\n%s  bytes: %s\n",
                     (unsigned long long)b->start, b->insns, diff.c_str(), bytes.c_str());
        std::abort();
    }
    return true;
}

}  // namespace jit
