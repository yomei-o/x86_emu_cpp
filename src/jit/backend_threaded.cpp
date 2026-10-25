// The portable backend: IR ops become `Uop`s, each carrying a pointer to a
// handler that does exactly that op and returns the next one.  Running a block
// is `while (u) u = u->fn(ctx, u)`.
//
// This is not machine code, and it is deliberately the first backend: it runs
// on every host this emulator builds for, WebAssembly included, where nothing
// can be generated at run time without leaving the sandbox.  What it removes
// from the interpreter is the per-execution work - prefix scanning, opcode
// dispatch, ModRM decoding, the width switches - all of which are decided once,
// when the handler is chosen.
#include <cstdio>
#include <cstdlib>

#include "../cpu.h"
#include "engine.h"

namespace jit {

namespace {

using x86emu::Cpu;

#define S(o) (*reinterpret_cast<uint64_t*>(c->env + (o)))

struct ParityTable {
    uint8_t v[256];
    constexpr ParityTable() : v() {
        for (int i = 0; i < 256; ++i) {
            int x = i, n = 0;
            while (x) { n += x & 1; x >>= 1; }
            v[i] = (n & 1) ? 0 : 4;   // PF is set on even parity
        }
    }
};
constexpr ParityTable kParity;

template <int SZ> constexpr uint64_t mask_of() {
    return SZ == 8 ? ~0ull : ((1ull << (SZ * 8)) - 1);
}
template <int SZ> constexpr uint64_t sign_of() { return 1ull << (SZ * 8 - 1); }

constexpr uint64_t kArith = 0x8D5;   // CF PF AF ZF SF OF

// ---- moves and plain arithmetic -------------------------------------------

const Uop* h_nop(Ctx*, const Uop* u) { return u + 1; }
const Uop* h_mov(Ctx* c, const Uop* u) { S(u->d) = S(u->a); return u + 1; }
const Uop* h_movi(Ctx* c, const Uop* u) { S(u->d) = static_cast<uint64_t>(u->imm); return u + 1; }
const Uop* h_add(Ctx* c, const Uop* u) { S(u->d) = S(u->a) + S(u->b); return u + 1; }
const Uop* h_addi(Ctx* c, const Uop* u) { S(u->d) = S(u->a) + static_cast<uint64_t>(u->imm); return u + 1; }
const Uop* h_sub(Ctx* c, const Uop* u) { S(u->d) = S(u->a) - S(u->b); return u + 1; }
const Uop* h_subi(Ctx* c, const Uop* u) { S(u->d) = S(u->a) - static_cast<uint64_t>(u->imm); return u + 1; }
const Uop* h_and(Ctx* c, const Uop* u) { S(u->d) = S(u->a) & S(u->b); return u + 1; }
const Uop* h_andi(Ctx* c, const Uop* u) { S(u->d) = S(u->a) & static_cast<uint64_t>(u->imm); return u + 1; }
const Uop* h_or(Ctx* c, const Uop* u) { S(u->d) = S(u->a) | S(u->b); return u + 1; }
const Uop* h_ori(Ctx* c, const Uop* u) { S(u->d) = S(u->a) | static_cast<uint64_t>(u->imm); return u + 1; }
const Uop* h_xor(Ctx* c, const Uop* u) { S(u->d) = S(u->a) ^ S(u->b); return u + 1; }
const Uop* h_xori(Ctx* c, const Uop* u) { S(u->d) = S(u->a) ^ static_cast<uint64_t>(u->imm); return u + 1; }

template <int SZ>
const Uop* h_lea(Ctx* c, const Uop* u) {
    uint64_t v = S(u->a) + (S(u->c) << u->cc) + static_cast<uint64_t>(u->imm);
    S(u->d) = v & mask_of<SZ>();
    return u + 1;
}

template <int SRC, bool SIGNED, int DST>
const Uop* h_ext(Ctx* c, const Uop* u) {
    uint64_t v = S(u->a);
    if (SIGNED) {
        int64_t s = SRC == 1 ? static_cast<int8_t>(v) : SRC == 2 ? static_cast<int16_t>(v)
                                                                 : static_cast<int32_t>(v);
        v = static_cast<uint64_t>(s);
    } else {
        v &= mask_of<SRC>();
    }
    S(u->d) = v & mask_of<DST>();
    return u + 1;
}

const Uop* h_put1(Ctx* c, const Uop* u) { S(u->d) = (S(u->a) & ~0xFFull) | (S(u->b) & 0xFF); return u + 1; }
const Uop* h_put2(Ctx* c, const Uop* u) { S(u->d) = (S(u->a) & ~0xFFFFull) | (S(u->b) & 0xFFFF); return u + 1; }
const Uop* h_puth(Ctx* c, const Uop* u) { S(u->d) = (S(u->a) & ~0xFF00ull) | ((S(u->b) & 0xFF) << 8); return u + 1; }
const Uop* h_geth(Ctx* c, const Uop* u) { S(u->d) = (S(u->a) >> 8) & 0xFF; return u + 1; }
const Uop* h_sel(Ctx* c, const Uop* u) { S(u->d) = S(u->c) ? S(u->a) : S(u->b); return u + 1; }

// ---- memory ---------------------------------------------------------------

template <bool A32>
inline uint64_t ea(Ctx* c, const Uop* u) {
    uint64_t a = S(u->a) + (S(u->c) << u->cc) + static_cast<uint64_t>(u->imm);
    return A32 ? (a & 0xFFFFFFFFull) : a;
}

template <int SZ, bool A32>
const Uop* h_ld(Ctx* c, const Uop* u) {
    uint64_t a = ea<A32>(c, u);
    uint64_t v;
    if (SZ == 1) v = c->mem->read8(a);
    else if (SZ == 2) v = c->mem->read16(a);
    else if (SZ == 4) v = c->mem->read32(a);
    else v = c->mem->read64(a);
    S(u->d) = v;
    return u + 1;
}

// Sign extending load; b = destination width (4 or 8).
template <int SZ, bool A32, int DST>
const Uop* h_lds(Ctx* c, const Uop* u) {
    uint64_t a = ea<A32>(c, u);
    int64_t v;
    if (SZ == 1) v = static_cast<int8_t>(c->mem->read8(a));
    else if (SZ == 2) v = static_cast<int16_t>(c->mem->read16(a));
    else v = static_cast<int32_t>(c->mem->read32(a));
    S(u->d) = static_cast<uint64_t>(v) & mask_of<DST>();
    return u + 1;
}

template <int SZ, bool A32>
const Uop* h_st(Ctx* c, const Uop* u) {
    uint64_t a = ea<A32>(c, u);
    uint64_t v = S(u->b);
    if (SZ == 1) c->mem->write8(a, static_cast<uint8_t>(v));
    else if (SZ == 2) c->mem->write16(a, static_cast<uint16_t>(v));
    else if (SZ == 4) c->mem->write32(a, static_cast<uint32_t>(v));
    else c->mem->write64(a, v);
    return u + 1;
}

// ---- flags ----------------------------------------------------------------

template <int SZ>
inline void flags_arith(Ctx* c, const Uop* u, uint64_t a, uint64_t b, uint64_t r, bool sub) {
    constexpr uint64_t SG = sign_of<SZ>();
    uint64_t cf = sub ? (a < b) : (r < a);
    uint64_t of = sub ? (((a ^ b) & (a ^ r) & SG) != 0) : (((a ^ r) & (b ^ r) & SG) != 0);
    uint64_t fl = cf | kParity.v[r & 0xFF] | ((a ^ b ^ r) & 0x10) | (r == 0 ? 0x40 : 0) |
                  ((r & SG) ? 0x80 : 0) | (of ? 0x800 : 0);
    uint64_t& rf = S(c->eng->slots.rflags);
    rf = (rf & ~kArith) | fl;
}

template <int SZ>
inline void flags_logic(Ctx* c, uint64_t r) {
    constexpr uint64_t SG = sign_of<SZ>();
    uint64_t fl = kParity.v[r & 0xFF] | (r == 0 ? 0x40 : 0) | ((r & SG) ? 0x80 : 0);
    uint64_t& rf = S(c->eng->slots.rflags);
    rf = (rf & ~kArith) | fl;
}

// x86 operation numbers: 0 ADD 1 OR 4 AND 5 SUB 6 XOR 7 CMP, 8 TEST
template <int OP, int SZ, bool FL, bool IMM>
const Uop* h_alu(Ctx* c, const Uop* u) {
    constexpr uint64_t M = mask_of<SZ>();
    uint64_t a = S(u->a) & M;
    uint64_t b = IMM ? (static_cast<uint64_t>(u->imm) & M) : (S(u->b) & M);
    uint64_t r;
    switch (OP) {
        case 0: r = (a + b) & M; break;
        case 1: r = a | b; break;
        case 4: r = a & b; break;
        case 5: case 7: r = (a - b) & M; break;
        case 6: r = a ^ b; break;
        default: r = a & b; break;   // 8: TEST
    }
    if (OP != 7 && OP != 8) S(u->d) = r;
    if (FL) {
        if (OP == 0) flags_arith<SZ>(c, u, a, b, r, false);
        else if (OP == 5 || OP == 7) flags_arith<SZ>(c, u, a, b, r, true);
        else flags_logic<SZ>(c, r);
    }
    return u + 1;
}

template <bool DEC, int SZ, bool FL>
const Uop* h_incdec(Ctx* c, const Uop* u) {
    constexpr uint64_t M = mask_of<SZ>();
    uint64_t a = S(u->a) & M;
    uint64_t r = (DEC ? a - 1 : a + 1) & M;
    S(u->d) = r;
    if (FL) {
        uint64_t& rf = S(c->eng->slots.rflags);
        uint64_t keep = rf & 1;   // CF survives
        flags_arith<SZ>(c, u, a, 1, r, DEC);
        rf = (rf & ~1ull) | keep;
    }
    return u + 1;
}

template <int CC>
inline bool test_cc(uint64_t rf) {
    bool cf = rf & 1, pf = rf & 4, zf = rf & 0x40, sf = rf & 0x80, of = rf & 0x800;
    bool r;
    switch (CC >> 1) {
        case 0: r = of; break;
        case 1: r = cf; break;
        case 2: r = zf; break;
        case 3: r = cf || zf; break;
        case 4: r = sf; break;
        case 5: r = pf; break;
        case 6: r = sf != of; break;
        default: r = zf || (sf != of); break;
    }
    return (CC & 1) ? !r : r;
}

template <int CC>
const Uop* h_setfl(Ctx* c, const Uop* u) {
    S(u->d) = test_cc<CC>(S(c->eng->slots.rflags)) ? 1 : 0;
    return u + 1;
}

// ---- exits ----------------------------------------------------------------

const Uop* h_exit(Ctx* c, const Uop* u) { c->cpu->rip = static_cast<uint64_t>(u->imm); return nullptr; }
const Uop* h_exit_ind(Ctx* c, const Uop* u) { c->cpu->rip = S(u->a); return nullptr; }

template <int CC>
const Uop* h_jccfl(Ctx* c, const Uop* u) {
    c->cpu->rip = static_cast<uint64_t>(test_cc<CC>(S(c->eng->slots.rflags)) ? u->imm : u->imm2);
    return nullptr;
}

const Uop* h_chkflush(Ctx* c, const Uop* u) {
    if (c->eng->epoch != c->epoch0) {
        c->partial = u->ni;
        c->cpu->rip = static_cast<uint64_t>(u->imm);
        return nullptr;
    }
    return u + 1;
}

// The interpreter, for one instruction.  If it leaves rip anywhere but the
// expected next instruction - a jump, a blocked system call, a thread switch -
// the block is over and rip is whatever it made it.
const Uop* h_interp(Ctx* c, const Uop* u) {
    Cpu* cpu = c->cpu;
    cpu->rip = static_cast<uint64_t>(u->imm);
    ++c->eng->n_interp;
    ++c->eng->interp_ops[u->c & 0x1FF];
    cpu->step();
    if (cpu->rip != static_cast<uint64_t>(u->imm2) || cpu->halted || c->eng->epoch != c->epoch0) {
        c->partial = u->ni;
        return nullptr;
    }
    return u + 1;
}

// ---- selection -------------------------------------------------------------

template <int OP, int SZ, bool FL, bool IMM>
auto pick_alu_sz() { return &h_alu<OP, SZ, FL, IMM>; }

template <int OP, bool FL, bool IMM>
auto pick_alu_fl(int sz) {
    switch (sz) {
        case 1: return &h_alu<OP, 1, FL, IMM>;
        case 2: return &h_alu<OP, 2, FL, IMM>;
        case 4: return &h_alu<OP, 4, FL, IMM>;
        default: return &h_alu<OP, 8, FL, IMM>;
    }
}

template <int OP>
auto pick_alu_op(int sz, bool fl, bool imm) {
    if (fl) return imm ? pick_alu_fl<OP, true, true>(sz) : pick_alu_fl<OP, true, false>(sz);
    return imm ? pick_alu_fl<OP, false, true>(sz) : pick_alu_fl<OP, false, false>(sz);
}

using Fn = const Uop* (*)(Ctx*, const Uop*);

Fn pick_alu(int op, int sz, bool fl, bool imm) {
    switch (op) {
        case 0: return pick_alu_op<0>(sz, fl, imm);
        case 1: return pick_alu_op<1>(sz, fl, imm);
        case 4: return pick_alu_op<4>(sz, fl, imm);
        case 5: return pick_alu_op<5>(sz, fl, imm);
        case 6: return pick_alu_op<6>(sz, fl, imm);
        case 7: return pick_alu_op<7>(sz, fl, imm);
        default: return pick_alu_op<8>(sz, fl, imm);
    }
}

template <bool DEC, bool FL>
Fn pick_incdec_sz(int sz) {
    switch (sz) {
        case 1: return &h_incdec<DEC, 1, FL>;
        case 2: return &h_incdec<DEC, 2, FL>;
        case 4: return &h_incdec<DEC, 4, FL>;
        default: return &h_incdec<DEC, 8, FL>;
    }
}

template <int SZ>
Fn pick_ld_a(bool a32) { return a32 ? &h_ld<SZ, true> : &h_ld<SZ, false>; }
template <int SZ>
Fn pick_st_a(bool a32) { return a32 ? &h_st<SZ, true> : &h_st<SZ, false>; }

template <int SZ, int DST>
Fn pick_lds_a(bool a32) { return a32 ? &h_lds<SZ, true, DST> : &h_lds<SZ, false, DST>; }

Fn pick_cc(int cc, int which) {
#define CASE(N) case N: return which == 0 ? &h_setfl<N> : &h_jccfl<N>;
    switch (cc & 15) {
        CASE(0) CASE(1) CASE(2) CASE(3) CASE(4) CASE(5) CASE(6) CASE(7)
        CASE(8) CASE(9) CASE(10) CASE(11) CASE(12) CASE(13) CASE(14) default: return which == 0 ? &h_setfl<15> : &h_jccfl<15>;
    }
#undef CASE
}

template <int SRC, bool SIGNED>
Fn pick_ext_dst(int dst) { return dst == 8 ? &h_ext<SRC, SIGNED, 8> : &h_ext<SRC, SIGNED, 4>; }

Fn pick_ext(int src, bool sgn, int dst) {
    switch (src) {
        case 1: return sgn ? pick_ext_dst<1, true>(dst) : pick_ext_dst<1, false>(dst);
        case 2: return sgn ? pick_ext_dst<2, true>(dst) : pick_ext_dst<2, false>(dst);
        default: return sgn ? pick_ext_dst<4, true>(dst) : pick_ext_dst<4, false>(dst);
    }
}

Fn select(const Op& o) {
    const bool a32 = (o.flags & kFlagA32) != 0;
    const bool fl = (o.flags & kFlagEager) != 0;
    switch (o.kind) {
        case OpKind::Nop: return h_nop;
        case OpKind::Mov: return h_mov;
        case OpKind::MovI: return h_movi;
        case OpKind::Add: return h_add;
        case OpKind::AddI: return h_addi;
        case OpKind::Sub: return h_sub;
        case OpKind::SubI: return h_subi;
        case OpKind::And: return h_and;
        case OpKind::AndI: return h_andi;
        case OpKind::Or: return h_or;
        case OpKind::OrI: return h_ori;
        case OpKind::Xor: return h_xor;
        case OpKind::XorI: return h_xori;
        case OpKind::Lea: return o.sz == 4 ? &h_lea<4> : &h_lea<8>;
        case OpKind::Ext: return pick_ext(o.sz, (o.flags & kFlagSigned) != 0, o.cc);
        case OpKind::Put: return o.sz == 1 ? h_put1 : o.sz == 2 ? h_put2 : h_puth;
        case OpKind::GetH: return h_geth;
        case OpKind::Ld:
            switch (o.sz) {
                case 1: return pick_ld_a<1>(a32);
                case 2: return pick_ld_a<2>(a32);
                case 4: return pick_ld_a<4>(a32);
                default: return pick_ld_a<8>(a32);
            }
        case OpKind::LdS:
            switch (o.sz) {
                case 1: return o.imm2 == 8 ? pick_lds_a<1, 8>(a32) : pick_lds_a<1, 4>(a32);
                case 2: return o.imm2 == 8 ? pick_lds_a<2, 8>(a32) : pick_lds_a<2, 4>(a32);
                default: return o.imm2 == 8 ? pick_lds_a<4, 8>(a32) : pick_lds_a<4, 4>(a32);
            }
        case OpKind::St:
            switch (o.sz) {
                case 1: return pick_st_a<1>(a32);
                case 2: return pick_st_a<2>(a32);
                case 4: return pick_st_a<4>(a32);
                default: return pick_st_a<8>(a32);
            }
        case OpKind::Sel: return h_sel;
        case OpKind::SetFl: return pick_cc(o.cc, 0);
        case OpKind::JccFl: return pick_cc(o.cc, 1);
        case OpKind::Exit: return h_exit;
        case OpKind::ExitInd: return h_exit_ind;
        case OpKind::Alu: return pick_alu(o.cc, o.sz, fl, false);
        case OpKind::AluI: return pick_alu(o.cc, o.sz, fl, true);
        case OpKind::IncDec: return o.cc ? (fl ? pick_incdec_sz<true, true>(o.sz) : pick_incdec_sz<true, false>(o.sz))
                                          : (fl ? pick_incdec_sz<false, true>(o.sz) : pick_incdec_sz<false, false>(o.sz));
        case OpKind::Interp: return h_interp;
        case OpKind::ChkFlush: return h_chkflush;
    }
    std::fprintf(stderr, "jit: no handler for op %d\n", static_cast<int>(o.kind));
    std::abort();
}

}  // namespace

void compile_threaded(Engine&, const IrBlock& ir, Block& out) {
    out.code.clear();
    out.code.reserve(ir.ops.size());
    for (const Op& o : ir.ops) {
        Uop u;
        u.fn = select(o);
        u.d = o.d; u.a = o.a; u.b = o.b; u.c = o.c;
        u.imm = o.imm; u.imm2 = o.imm2;
        u.pc = o.pc; u.ni = o.ni; u.sz = o.sz; u.cc = o.cc; u.flags = o.flags;
        out.code.push_back(u);
    }
}

}  // namespace jit
