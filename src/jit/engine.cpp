#include "engine.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

#include "../cpu.h"

namespace jit {

using x86emu::Cpu;
using x86emu::Memory;

Engine::Engine(Cpu& c, Memory& m) : cpu(c), mem(m) {
    auto off = [&](const void* p) {
        return static_cast<int32_t>(reinterpret_cast<const uint8_t*>(p) -
                                    reinterpret_cast<const uint8_t*>(cpu.regs));
    };
    slots.zero = off(&cpu.jit_tmp[0]);
    slots.tmp0 = off(&cpu.jit_tmp[1]);
    slots.ntmp = static_cast<int32_t>(sizeof(cpu.jit_tmp) / sizeof(cpu.jit_tmp[0])) - 1;
    slots.rflags = off(&cpu.rflags);
    slots.rip = off(&cpu.rip);
    slots.fs_base = off(&cpu.fs_base);
    slots.gs_base = off(&cpu.gs_base);
    mem.set_code_observer(this);
    if (const char* sv = std::getenv("X86EMU_JIT_STATS")) {
        stats_every_ = std::strtoull(sv, nullptr, 10);
        static Engine* first = this;
        std::atexit([] { first->print_stats(); });
    }
    if (const char* v = std::getenv("X86EMU_JIT_VERIFY")) verify = v[0] == '1';
    if (const char* v = std::getenv("X86EMU_JIT_PROFILE")) profile = v[0] == '1';
}

Engine::~Engine() {
    mem.set_code_observer(nullptr);
    if (std::getenv("X86EMU_JIT_STATS")) print_stats();
}

// Where the time goes, from the blocks' run counts: the ops executed by kind, and
// the hottest blocks with the ops they are made of.
void Engine::print_profile() {
    static const char* names[] = {"Nop", "Mov", "MovI", "Add", "AddI", "Sub", "SubI", "And", "AndI", "Or",
        "OrI", "Xor", "XorI", "Lea", "Ext", "Put", "GetH", "Ld", "LdS", "St", "Sel", "SetFl", "Exit",
        "ExitInd", "JccFl", "Alu", "AluI", "IncDec", "ShlI", "ShrI", "SarI", "Shift", "ShiftI", "ShiftSlow",
        "Imul", "ImulI", "Group3", "CcSet", "CcSetI", "CcMat", "CcClear", "JccCmp", "JccCmpI", "Push", "PushI", "Pop", "Ret", "Call", "Interp",
        "ChkFlush"};
    constexpr size_t kNames = sizeof names / sizeof names[0];
    std::vector<uint64_t> by_kind(256, 0);
    uint64_t total_ops = 0, total_hits = 0;
    std::vector<Block*> blocks;
    for (auto& b : all_) {
        if (!b->hits) continue;
        blocks.push_back(b.get());
        total_hits += b->hits;
        for (const Uop& u : b->code) { by_kind[u.kind] += b->hits; total_ops += b->hits; }
    }
    std::fprintf(stderr, "[prof] %llu block runs, %llu ops (%.2f per block)\n", (unsigned long long)total_hits,
                 (unsigned long long)total_ops, total_hits ? double(total_ops) / double(total_hits) : 0.0);
    std::vector<int> order;
    for (int k = 0; k < 256; ++k) if (by_kind[k]) order.push_back(k);
    std::sort(order.begin(), order.end(), [&](int a, int b) { return by_kind[a] > by_kind[b]; });
    for (size_t i = 0; i < order.size() && i < 24; ++i)
        std::fprintf(stderr, "[prof]   %-10s %5.1f%%\n", order[i] < (int)kNames ? names[order[i]] : "?",
                     100.0 * double(by_kind[order[i]]) / double(total_ops));
    std::sort(blocks.begin(), blocks.end(), [](Block* a, Block* b) {
        return a->hits * a->code.size() > b->hits * b->code.size();
    });
    for (size_t i = 0; i < blocks.size() && i < 12; ++i) {
        Block* b = blocks[i];
        std::fprintf(stderr, "[prof] block %llX  runs %llu  insns %u  ops:", (unsigned long long)b->start,
                     (unsigned long long)b->hits, b->insns);
        for (const Uop& u : b->code)
            std::fprintf(stderr, " %s", u.kind < kNames ? names[u.kind] : "?");
        std::fprintf(stderr, "\n");
    }
}

void Engine::print_stats() {
    if (profile) print_profile();
    std::fprintf(stderr,
                 "[jit] translated %llu blocks, ran %llu (%llu native insns, %llu interpreted), invalidated %llu, stub hits %llu\n",
                 (unsigned long long)n_translated, (unsigned long long)n_blocks_run,
                 (unsigned long long)n_insns_native, (unsigned long long)n_interp,
                 (unsigned long long)n_invalidated, (unsigned long long)n_stub_hits);
    for (int k = 0; k < 14; ++k) {
        int best = -1;
        for (int i = 0; i < 512; ++i)
            if (interp_ops[i] && (best < 0 || interp_ops[i] > interp_ops[best])) best = i;
        if (best < 0) break;
        std::fprintf(stderr, "[jit]   interp %s%02X  %llu\n", best >= 256 ? "0F " : "", best & 255,
                     (unsigned long long)interp_ops[best]);
        interp_ops[best] = 0;
    }
}

Block* Engine::lookup(uint64_t pc) {
    Block*& slot = table_[(pc ^ (pc >> kTableBits)) & ((1u << kTableBits) - 1)];
    Block* b = slot;
    if (b && b->start == pc && b->valid) return b;
    auto it = map_.find(pc);
    if (it == map_.end()) return nullptr;
    slot = it->second;
    return it->second;
}

Block* Engine::translate(uint64_t pc) {
    const uint64_t page = pc >> Memory::kPageBits;
    auto blk = std::make_unique<Block>();
    blk->start = pc;
    blk->page = page;
    bool watch = true;

    if (banned_.count(page)) {
        blk->stub = true;
        watch = false;   // never translated, so nothing to invalidate
    } else {
        IrBlock ir;
        if (translate_x86(cpu, slots, pc, ir)) {
            compile_threaded(*this, ir, *blk);
            blk->insns = ir.insns;
            blk->effects = ir.effects;
            blk->guest_bytes = ir.guest_bytes;
            ++n_translated;
        } else {
            blk->stub = true;
        }
        if (!mem.mark_code_page(page)) {
            blk->stub = true;
            blk->code.clear();
            watch = false;
        }
    }

    Block* raw = blk.get();
    all_.push_back(std::move(blk));
    map_[pc] = raw;
    if (watch) by_page_[page].push_back(raw);
    else if (raw->stub) {
        // Stubs on unwatched pages stay valid; nothing changes under them
        // without a map/unmap, which flushes everything.
    }
    table_[(pc ^ (pc >> kTableBits)) & ((1u << kTableBits) - 1)] = raw;
    return raw;
}

void Engine::reclaim() {
    if (dead_ < 8192 || depth_ > 0) return;
    for (auto& s : table_)
        if (s && !s->valid) s = nullptr;
    size_t w = 0;
    for (size_t r = 0; r < all_.size(); ++r) {
        if (all_[r]->valid) {
            if (w != r) all_[w] = std::move(all_[r]);
            ++w;
        }
    }
    all_.resize(w);
    dead_ = 0;
}

bool Engine::run_block() {
    const uint64_t pc = cpu.rip;
    Block* b = lookup(pc);
    if (!b) {
        reclaim();
        b = translate(pc);
    }
    if (b->stub) {
        ++n_stub_hits;
        return false;
    }
    return verify ? run_verified(b) : run_plain(b);
}

// Runs translated blocks one after another for as long as there are any to run:
// until the instruction counter reaches `deadline`, rip reaches `stop_pc`, the
// guest halts, `*yield` is set, or rip is somewhere that is not translated code
// (a host hook, a stub).  Returns whether at least one block ran.
//
// Staying in here between blocks is most of the point.  Blocks average four or
// five guest instructions, so the work of getting into and out of the engine
// was as large as the blocks themselves.
bool Engine::run(uint64_t deadline, uint64_t stop_pc, const bool* yield) {
    if (verify) {
        // One block at a time, each checked against the interpreter.
        const uint64_t pc = cpu.rip;
        if (pc == stop_pc || (pc >= cpu.hook_low && pc <= cpu.hook_high)) return false;
        return run_block();
    }
    reclaim();
    Ctx ctx{reinterpret_cast<uint8_t*>(cpu.regs), &cpu, &mem, this, 0, -1, false, nullptr};
    const Uop* u = nullptr;
    Block* b = nullptr;
    bool any = false;
    ++depth_;
    try {
        for (;;) {
            const uint64_t pc = cpu.rip;
            if (pc == stop_pc || (pc >= cpu.hook_low && pc <= cpu.hook_high)) break;
            b = lookup(pc);
            if (!b) b = translate(pc);
            if (b->stub) {
                ++n_stub_hits;
                break;
            }
            ctx.epoch0 = epoch;
            ctx.partial = -1;
            ctx.cur = nullptr;
            if (profile) ++b->hits;
            u = b->code.data();
            while (u) u = u->fn(&ctx, u);
            const uint32_t done = ctx.partial >= 0 ? static_cast<uint32_t>(ctx.partial) : b->insns;
            cpu.instructions_executed += done;
            ++n_blocks_run;
            n_insns_native += done;
            any = true;
            if (stats_every_ && n_blocks_run % stats_every_ == 0) print_stats();
            if (cpu.halted || (yield && *yield) || cpu.instructions_executed >= deadline) break;
        }
    } catch (const x86emu::MemoryFault&) {
        if (cpu.cc_kind) materialize_flags(cpu);
        --depth_;
        // Report the fault at the start of the instruction that made it, which
        // is where an exception handler would restart it - unless it came out
        // of an interpreted instruction, which has already said where it was.
        if (ctx.cur && !ctx.in_interp) cpu.rip = b->start + ctx.cur->pc;
        throw;
    } catch (...) {
        if (cpu.cc_kind) materialize_flags(cpu);
        --depth_;
        throw;
    }
    if (cpu.cc_kind) materialize_flags(cpu);
    --depth_;
    return any;
}

bool Engine::run_plain(Block* b) {
    Ctx ctx{reinterpret_cast<uint8_t*>(cpu.regs), &cpu, &mem, this, epoch, -1, false, nullptr};
    ++depth_;
    const Uop* u = b->code.data();
    try {
        while (u) u = u->fn(&ctx, u);
    } catch (const x86emu::MemoryFault&) {
        --depth_;
        // Report the fault at the start of the instruction that made it, which
        // is where an exception handler would restart it.
        if (ctx.cur) cpu.rip = b->start + ctx.cur->pc;
        throw;
    } catch (...) {
        --depth_;
        throw;
    }
    if (cpu.cc_kind) materialize_flags(cpu);
    --depth_;
    const uint32_t done = ctx.partial >= 0 ? static_cast<uint32_t>(ctx.partial) : b->insns;
    cpu.instructions_executed += done;
    ++n_blocks_run;
    if (stats_every_ && n_blocks_run % stats_every_ == 0) print_stats();
    n_insns_native += done;
    return true;
}

void Engine::on_code_write(uint64_t page) {
    ++n_invalidated;
    auto it = by_page_.find(page);
    if (it != by_page_.end()) {
        for (Block* b : it->second) {
            if (!b->valid) continue;
            b->valid = false;
            auto m = map_.find(b->start);
            if (m != map_.end() && m->second == b) map_.erase(m);
            ++dead_;
        }
        by_page_.erase(it);
    }
    ++epoch;
    // A page that keeps being written to is data that happens to be executed
    // from, or code that rewrites itself in a loop; translating it again each
    // time costs more than interpreting it.
    if (++inval_count_[page] > 24) banned_.insert(page);
}

void Engine::on_code_unmap(uint64_t page) { on_code_write(page); }

void Engine::on_code_flush_all() {
    for (auto& kv : by_page_)
        for (Block* b : kv.second)
            if (b->valid) { b->valid = false; ++dead_; }
    by_page_.clear();
    // Stubs on unwatched pages are not in by_page_; drop them too.
    for (auto& b : all_)
        if (b->valid) { b->valid = false; ++dead_; }
    map_.clear();
    banned_.clear();
    inval_count_.clear();
    ++epoch;
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
