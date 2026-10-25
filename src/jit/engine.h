// The translation cache and the loop that runs it.
//
// run_block() looks up (or translates) the block at the CPU's rip and runs it.
// It returns false when there is nothing to run there - the address is a host
// hook, the page is not allowed to be translated, or the first instruction is
// one the frontend will not touch - and the caller then steps the interpreter
// once, exactly as it would have without a JIT.
#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../memory.h"
#include "ir.h"

namespace x86emu {
class Cpu;
}

namespace jit {

class Engine;

struct Ctx {
    uint8_t* env;
    x86emu::Cpu* cpu;
    x86emu::Memory* mem;
    Engine* eng;
    uint64_t epoch0;   // Engine::epoch when this block started
    int partial;       // set by an op that leaves early: native insns finished
};

struct Uop {
    const Uop* (*fn)(Ctx*, const Uop*);
    int32_t d, a, b, c;
    int64_t imm, imm2;
    uint32_t pc;
    uint16_t ni;
    uint8_t sz, cc, flags;
};

struct Block {
    uint64_t start = 0;
    uint32_t insns = 0;
    bool valid = true;
    bool stub = false;       // nothing translated here: step the interpreter
    bool effects = false;    // see IrBlock::effects: cannot be run twice for verification
    uint32_t guest_bytes = 0;
    uint64_t page = 0;
    std::vector<Uop> code;
};

class Engine : public x86emu::CodeObserver {
public:
    Engine(x86emu::Cpu& cpu, x86emu::Memory& mem);
    ~Engine() override;

    bool run_block();

    // X86EMU_JIT_VERIFY=1: run every block twice - translated, then through the
    // interpreter from the same starting state - and stop at the first
    // difference (verify.cpp).
    bool verify = false;

    // CodeObserver
    void on_code_write(uint64_t page) override;
    void on_code_flush_all() override;
    void on_code_unmap(uint64_t page) override;

    // Slots (byte offsets from the CPU's register file) the frontend needs.
    struct Slots {
        int32_t zero, rflags, rip, fs_base, gs_base;
        int32_t tmp0;   // first of the temporaries; tmp0 - 8 * 0 is zero
        int32_t ntmp;
    } slots;

    // Counts invalidations.  A running block compares it with the value it
    // started with, which stays right when blocks nest (a hook that calls back
    // into the guest runs blocks of its own inside an interpreted instruction).
    uint64_t epoch = 0;

    // Statistics (X86EMU_JIT_STATS=1)
    uint64_t n_translated = 0, n_blocks_run = 0, n_insns_native = 0, n_invalidated = 0;
    uint64_t n_stub_hits = 0;
    uint64_t stats_every_ = 0;   // X86EMU_JIT_STATS=N prints every N blocks
    uint64_t n_interp = 0;
    uint64_t interp_ops[512] = {};   // which interpreted opcodes ran (0F xx at 256+xx)
    void print_stats();

    x86emu::Cpu& cpu;
    x86emu::Memory& mem;

private:
    static constexpr uint32_t kTableBits = 13;
    bool run_plain(Block* b);
    bool run_verified(Block* b);
    Block* lookup(uint64_t pc);
    Block* translate(uint64_t pc);
    void reclaim();

    Block* table_[1u << kTableBits] = {};
    std::unordered_map<uint64_t, Block*> map_;
    std::unordered_map<uint64_t, std::vector<Block*>> by_page_;
    std::unordered_map<uint64_t, uint32_t> inval_count_;
    std::unordered_set<uint64_t> banned_;
    std::vector<std::unique_ptr<Block>> all_;
    size_t dead_ = 0;
    int depth_ = 0;           // blocks running now; nothing is freed while > 0
};

// Per-guest-ISA translation.  The x86 one is the only implementation so far.
bool translate_x86(x86emu::Cpu& cpu, const Engine::Slots& slots, uint64_t pc, IrBlock& out);
// Lowers IR to something runnable.
void compile_threaded(Engine& eng, const IrBlock& ir, Block& out);

}  // namespace jit
