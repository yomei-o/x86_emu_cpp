// x86 interpreter covering both IA-32 (protected mode, flat) and x86-64
// (long mode) user-space integer code.
//
// State is always stored 64-bit wide; `mode` decides the default operand size,
// how many registers are visible, whether REX prefixes exist, and how wide the
// stack slots are.  There is no MMU, no segmentation (all segment bases are 0),
// no privilege levels, and no x87/SSE.  Anything unimplemented raises CpuError
// rather than being silently skipped.
#pragma once

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include "memory.h"

namespace x86emu {

struct CpuError : std::runtime_error {
    uint64_t rip;
    CpuError(uint64_t rip_, const std::string& what)
        : std::runtime_error(what), rip(rip_) {}
};

enum class Mode { X86_32, X86_64 };

// Register indices.  0-7 are the classic registers (with the x86-64 names);
// 8-15 only exist in long mode via REX.
enum Reg {
    RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
};

// RFLAGS bit positions we model.
enum : uint64_t {
    FLAG_CF = 1ull << 0,
    FLAG_PF = 1ull << 2,
    FLAG_AF = 1ull << 4,
    FLAG_ZF = 1ull << 6,
    FLAG_SF = 1ull << 7,
    FLAG_TF = 1ull << 8,
    FLAG_IF = 1ull << 9,
    FLAG_DF = 1ull << 10,
    FLAG_OF = 1ull << 11,
};

class Cpu {
public:
    Cpu(Memory& mem, Mode mode) : mem_(mem), mode_(mode) {}

    // A 128-bit SSE register, viewed as whatever the current instruction needs.
    union Xmm {
        uint8_t b[16];
        uint16_t w[8];
        uint32_t d[4];
        uint64_t q[2];
        float f32[4];
        double f64[2];
    };

    // ---- state ----------------------------------------------------------
    uint64_t regs[16] = {};
    Xmm xmm[16] = {};
    uint32_t mxcsr = 0x1F80;

    // x87 state.  The register stack is kept as host doubles rather than true
    // 80-bit extended values: results can therefore differ in the last bits from
    // real hardware, which is a deliberate trade for a great deal of simplicity.
    double st[8] = {};
    bool st_used[8] = {};
    int st_top = 0;
    uint16_t fpu_control = 0x037F;
    uint16_t fpu_status = 0;
    uint64_t rip = 0;
    uint64_t rflags = FLAG_IF | 0x2;  // bit 1 reads as 1 on real hardware

    // Thread-information block base, i.e. what fs:/gs: resolve to.  Win32
    // guests read the TEB through fs (32-bit) or gs (64-bit).
    uint64_t fs_base = 0;
    uint64_t gs_base = 0;
    // 32-bit Linux TLS: set_thread_area fills a slot's base, and a later
    // `mov %gs, sel` (see opcode 0x8E) points gs_base at it.
    static constexpr unsigned kGdtSlots = 32;
    uint64_t gdt_base[kGdtSlots] = {};
    uint16_t fs_selector = 0, gs_selector = 0;

    bool halted = false;
    int exit_code = 0;

    // Called before each instruction fetch.  If the address belongs to a host
    // hook the callback performs the whole call, including the return, and
    // returns true.
    std::function<bool(uint64_t /*addr*/)> on_hook_call;

    // `int n` (Linux int 0x80) and the `syscall` instruction.
    std::function<void(uint8_t /*vector*/)> on_interrupt;
    std::function<void()> on_syscall;

    uint64_t instructions_executed = 0;
    bool trace = false;

    // A ring buffer of the addresses of the last instructions executed, kept
    // when history_size() > 0.  A fault deep inside a large guest is otherwise
    // almost impossible to place: --trace produces gigabytes, while the last
    // few hundred addresses name the loop or the call that got there.
    void enable_history(size_t entries) {
        history_.assign(entries, 0);
        history_pos_ = 0;
        history_filled_ = 0;
    }
    size_t history_size() const { return history_.size(); }
    // The addresses, oldest first.
    std::vector<uint64_t> history() const;

    Mode mode() const { return mode_; }
    bool is64() const { return mode_ == Mode::X86_64; }
    int stack_width() const { return is64() ? 8 : 4; }

    // ---- execution ------------------------------------------------------
    void step();
    void run(uint64_t max_instructions = 0);

    // ---- helpers for loaders and hooks -----------------------------------
    void push(uint64_t v) {
        regs[RSP] -= stack_width();
        mem_.write_sized(regs[RSP], stack_width(), v);
    }
    uint64_t pop() {
        uint64_t v = mem_.read_sized(regs[RSP], stack_width());
        regs[RSP] += stack_width();
        return v;
    }

    Memory& mem() { return mem_; }
    std::string state_line() const;

    // The 32-bit ABI returns floating point in ST(0), so a hook standing in for
    // a math function needs access to the x87 stack.
    void fpu_push(double v);
    double fpu_pop();
    static const char* reg_name(int i, int size);

    bool flag(uint64_t f) const { return (rflags & f) != 0; }
    void set_flag(uint64_t f, bool v) { rflags = v ? (rflags | f) : (rflags & ~f); }

private:
    struct Prefixes {
        bool opsize16 = false;  // 0x66
        bool addr_override = false;  // 0x67
        bool rep = false;       // 0xF3
        bool repne = false;     // 0xF2
        bool lock = false;      // 0xF0
        bool has_rex = false;
        bool rex_w = false;     // 64-bit operand size
        bool rex_r = false;     // extends ModRM.reg
        bool rex_x = false;     // extends SIB.index
        bool rex_b = false;     // extends ModRM.rm / SIB.base / opcode reg
        uint64_t seg_base = 0;  // fs:/gs: override, 0 otherwise
        bool seg_override = false;
    };

    // A decoded ModRM operand: a register index, or a linear address.
    struct RM {
        bool is_reg = false;
        uint8_t reg = 0;
        uint64_t addr = 0;
        bool rip_relative = false;  // address still needs the immediate length
    };

    // ---- instruction stream ---------------------------------------------
    uint8_t fetch8() { return mem_.read8(rip++); }
    uint16_t fetch16() {
        uint16_t v = mem_.read16(rip);
        rip += 2;
        return v;
    }
    uint32_t fetch32() {
        uint32_t v = mem_.read32(rip);
        rip += 4;
        return v;
    }
    uint64_t fetch64() {
        uint64_t v = mem_.read64(rip);
        rip += 8;
        return v;
    }
    // Immediate for an operand of `size` bytes.  A 64-bit operand still takes
    // a 32-bit immediate, sign extended (only MOV r64, imm64 differs).
    uint64_t fetch_imm(int size);
    static int imm_size_for(int opsize) { return opsize == 8 ? 4 : opsize; }

    // ---- register access -------------------------------------------------
    uint8_t reg8(int i) const {
        // Without REX, indices 4-7 mean AH/CH/DH/BH; with REX they mean the
        // low byte of RSP/RBP/RSI/RDI.
        if (i < 4 || pfx_.has_rex) return static_cast<uint8_t>(regs[i]);
        return static_cast<uint8_t>(regs[i - 4] >> 8);
    }
    void set_reg8(int i, uint8_t v) {
        if (i < 4 || pfx_.has_rex)
            regs[i] = (regs[i] & ~0xFFull) | v;
        else
            regs[i - 4] = (regs[i - 4] & ~0xFF00ull) | (static_cast<uint64_t>(v) << 8);
    }
    uint64_t reg_read(int i, int size) const {
        switch (size) {
            case 1: return reg8(i);
            case 2: return regs[i] & 0xFFFFull;
            case 4: return regs[i] & 0xFFFFFFFFull;
            default: return regs[i];
        }
    }
    void reg_write(int i, int size, uint64_t v) {
        switch (size) {
            case 1: set_reg8(i, static_cast<uint8_t>(v)); break;
            case 2: regs[i] = (regs[i] & ~0xFFFFull) | (v & 0xFFFFull); break;
            // A 32-bit write zero extends into the upper half - this is what
            // makes `mov eax, eax` a valid zero extension in long mode.
            case 4: regs[i] = v & 0xFFFFFFFFull; break;
            default: regs[i] = v; break;
        }
    }

    // ---- ModRM -----------------------------------------------------------
    // imm_bytes is the number of immediate bytes that follow the ModRM (and
    // its displacement); RIP-relative addressing is measured from the end of
    // the whole instruction, so the decoder needs to know.
    RM decode_modrm(int imm_bytes = 0);
    // Applies a late correction once a sub-opcode reveals it has an immediate.
    void fixup_rip_relative(RM& rm, int imm_bytes) const {
        if (rm.rip_relative) rm.addr += static_cast<uint64_t>(imm_bytes);
    }
    uint64_t rm_read(const RM& rm, int size) const;
    void rm_write(const RM& rm, int size, uint64_t v);

    // ---- flags -----------------------------------------------------------
    void set_flags_add(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t res, int size);
    void set_flags_sub(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t res, int size);
    void set_flags_logic(uint64_t res, int size);
    void set_szp(uint64_t res, int size);
    bool cond(uint8_t cc) const;

    // ---- operation groups -------------------------------------------------
    uint64_t alu(int op, uint64_t a, uint64_t b, int size);  // 0..7 = ADD..CMP
    uint64_t shift(int op, uint64_t v, uint64_t count, int size);
    void group3(RM& rm, int size, int op);
    void group5(const RM& rm, int size, int op);
    void do_string_op(uint8_t opcode, int size);
    void execute_0f();
    // SSE/SSE2 lives in sse.cpp; returns false if the opcode is not one of its
    // own, so execute_0f() can fall through to the general-purpose forms.
    bool execute_sse(uint8_t op);
    // x87 lives in x87.cpp; handles the 0xD8-0xDF opcode block.
    void execute_x87(uint8_t op);
    double& fpu_reg(int i);  // i counts down from the top of the stack
    Xmm xmm_read(const RM& rm);           // 128-bit operand
    void xmm_write(const RM& rm, const Xmm& v);
    uint64_t xmm_read_q(const RM& rm);    // low 64 bits of an operand
    uint32_t xmm_read_d(const RM& rm);    // low 32 bits of an operand

    [[noreturn]] void unsupported(const char* what, uint8_t opcode, uint64_t start_rip);

    std::vector<uint64_t> history_;
    size_t history_pos_ = 0;
    size_t history_filled_ = 0;

    Memory& mem_;
    Mode mode_;
    Prefixes pfx_{};
    int opsize_ = 4;         // operand size in bytes for the current instruction
    int addrsize_ = 4;       // address size in bytes
    uint8_t modrm_reg_ = 0;  // the /r field of the last decoded ModRM byte
};

}  // namespace x86emu
