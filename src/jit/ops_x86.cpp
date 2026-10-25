// The x86 guest's ops for the threaded backend: the arithmetic that sets flags,
// deferred flags and the conditions read from them, shifts, multiplies, the
// interpreter's group 3, stack operations, and the table that picks a handler for
// each of them.
#include <cstdio>
#include <cstdlib>

#include "threaded.h"

namespace jit {

// Friend of Cpu: the few places where translated code calls the interpreter's
// own private routines rather than re-implement them.
struct Access {
    static uint64_t shift(x86emu::Cpu& c, int op, uint64_t v, uint64_t count, int size) {
        return c.shift(op, v, count, size);
    }
    static void group3(x86emu::Cpu& c, bool is_reg, int reg, uint64_t addr, int size, int op,
                       bool rex) {
        x86emu::Cpu::RM rm;
        rm.is_reg = is_reg;
        rm.reg = static_cast<uint8_t>(reg);
        rm.addr = addr;
        c.pfx_.has_rex = rex;
        c.group3(rm, size, op);
    }
};

namespace {

using x86emu::Cpu;

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

constexpr uint64_t kArith = 0x8D5;   // CF PF AF ZF SF OF



// ---- stack ------------------------------------------------------------------

constexpr int kRsp = 4 * 8;   // rsp is register 4, and registers are slots 0, 8, 16...

template <int W>
const Uop* h_push(Ctx* c, const Uop* u) {
    c->cur = u;
    const uint64_t sp = S(kRsp) - W;
    S(kRsp) = sp;
    const uint64_t v = S(u->a);
    if (W == 4) c->mem->write32(sp, static_cast<uint32_t>(v));
    else c->mem->write64(sp, v);
    CHK_FLUSH();
    NEXT();
}

template <int W>
const Uop* h_pushi(Ctx* c, const Uop* u) {
    c->cur = u;
    const uint64_t sp = S(kRsp) - W;
    S(kRsp) = sp;
    const uint64_t v = static_cast<uint64_t>(u->imm);
    if (W == 4) c->mem->write32(sp, static_cast<uint32_t>(v));
    else c->mem->write64(sp, v);
    CHK_FLUSH();
    NEXT();
}

template <int W>
const Uop* h_pop(Ctx* c, const Uop* u) {
    c->cur = u;
    const uint64_t sp = S(kRsp);
    const uint64_t v = W == 4 ? c->mem->read32(sp) : c->mem->read64(sp);
    S(kRsp) = sp + W;
    S(u->d) = v;   // after the increment: POP ESP keeps the loaded value
    NEXT();
}

template <int W>
const Uop* h_ret(Ctx* c, const Uop* u) {
    c->cur = u;
    const uint64_t sp = S(kRsp);
    const uint64_t v = W == 4 ? c->mem->read32(sp) : c->mem->read64(sp);
    S(kRsp) = sp + W + static_cast<uint64_t>(u->imm);
    c->cpu->rip = v;
    return nullptr;
}

template <int W>
const Uop* h_call(Ctx* c, const Uop* u) {
    c->cur = u;
    const uint64_t sp = S(kRsp) - W;
    S(kRsp) = sp;
    if (W == 4) c->mem->write32(sp, static_cast<uint32_t>(u->imm2));
    else c->mem->write64(sp, static_cast<uint64_t>(u->imm2));
    c->cpu->rip = static_cast<uint64_t>(u->imm);
    return nullptr;
}

// ---- flags ----------------------------------------------------------------

// The arithmetic flag bits of `a OP b = r`, as they sit in rflags.
template <int SZ>
inline uint64_t arith_fl(uint64_t a, uint64_t b, uint64_t r, bool sub) {
    constexpr uint64_t SG = sign_of<SZ>();
    uint64_t cf = sub ? (a < b) : (r < a);
    uint64_t of = sub ? (((a ^ b) & (a ^ r) & SG) != 0) : (((a ^ r) & (b ^ r) & SG) != 0);
    return cf | kParity.v[r & 0xFF] | ((a ^ b ^ r) & 0x10) | (r == 0 ? 0x40 : 0) |
           ((r & SG) ? 0x80 : 0) | (of ? 0x800 : 0);
}

template <int SZ>
inline uint64_t logic_fl(uint64_t r) {
    constexpr uint64_t SG = sign_of<SZ>();
    return kParity.v[r & 0xFF] | (r == 0 ? 0x40 : 0) | ((r & SG) ? 0x80 : 0);
}

template <int SZ>
inline void flags_arith(Ctx* c, const Uop* u, uint64_t a, uint64_t b, uint64_t r, bool sub) {
    uint64_t& rf = S(c->eng->slots.rflags);
    rf = (rf & ~kArith) | arith_fl<SZ>(a, b, r, sub);
}

template <int SZ>
inline void flags_logic(Ctx* c, uint64_t r) {
    uint64_t& rf = S(c->eng->slots.rflags);
    rf = (rf & ~kArith) | logic_fl<SZ>(r);
}

// ---- deferred flags ----------------------------------------------------------

template <int SZ> inline int64_t sext_sz(uint64_t v);
template <int CC> inline bool test_cc(uint64_t rf);

template <int SZ>
void materialize_sz(Cpu& cpu) {
    constexpr uint64_t M = mask_of<SZ>();
    const uint64_t a = cpu.cc_a & M, b = cpu.cc_b & M;
    uint64_t fl;
    switch (cpu.cc_kind) {
        case 1: fl = arith_fl<SZ>(a, b, (a + b) & M, false); break;
        case 2: fl = arith_fl<SZ>(a, b, (a - b) & M, true); break;
        case 3: fl = logic_fl<SZ>(a & b); break;
        case 4: fl = logic_fl<SZ>(a | b); break;
        default: fl = logic_fl<SZ>(a ^ b); break;
    }
    cpu.rflags = (cpu.rflags & ~kArith) | fl;
    cpu.cc_kind = 0;
}

// Condition `CC` of the flags that `a OP b` would leave, evaluated without
// leaving them anywhere.  a and b arrive already masked to SZ bytes.
template <int KIND, int SZ, int CC>
inline bool eval_cc(uint64_t a, uint64_t b);

template <int SZ, int CC>
inline bool eval_sub(uint64_t a, uint64_t b) {
    constexpr uint64_t M = mask_of<SZ>();
    constexpr uint64_t SG = sign_of<SZ>();
    const uint64_t r = (a - b) & M;
    switch (CC) {
        case 0: return ((a ^ b) & (a ^ r) & SG) != 0;
        case 1: return ((a ^ b) & (a ^ r) & SG) == 0;
        case 2: return a < b;
        case 3: return a >= b;
        case 4: return a == b;
        case 5: return a != b;
        case 6: return a <= b;
        case 7: return a > b;
        case 8: return (r & SG) != 0;
        case 9: return (r & SG) == 0;
        case 10: return kParity.v[r & 0xFF] != 0;
        case 11: return kParity.v[r & 0xFF] == 0;
        case 12: return sext_sz<SZ>(a) < sext_sz<SZ>(b);
        case 13: return sext_sz<SZ>(a) >= sext_sz<SZ>(b);
        case 14: return sext_sz<SZ>(a) <= sext_sz<SZ>(b);
        default: return sext_sz<SZ>(a) > sext_sz<SZ>(b);
    }
}

// AND / OR / XOR: CF and OF come out clear.
template <int SZ, int CC>
inline bool eval_logic(uint64_t r) {
    constexpr uint64_t SG = sign_of<SZ>();
    switch (CC) {
        case 0: return false;
        case 1: return true;
        case 2: return false;
        case 3: return true;
        case 4: return r == 0;
        case 5: return r != 0;
        case 6: return r == 0;
        case 7: return r != 0;
        case 8: return (r & SG) != 0;
        case 9: return (r & SG) == 0;
        case 10: return kParity.v[r & 0xFF] != 0;
        case 11: return kParity.v[r & 0xFF] == 0;
        case 12: return (r & SG) != 0;
        case 13: return (r & SG) == 0;
        case 14: return (r & SG) != 0 || r == 0;
        default: return (r & SG) == 0 && r != 0;
    }
}

template <int KIND, int SZ, int CC>
inline bool eval_cc(uint64_t a, uint64_t b) {
    constexpr uint64_t M = mask_of<SZ>();
    if (KIND == 2) return eval_sub<SZ, CC>(a, b);
    if (KIND == 3) return eval_logic<SZ, CC>(a & b);
    if (KIND == 4) return eval_logic<SZ, CC>(a | b);
    if (KIND == 5) return eval_logic<SZ, CC>(a ^ b);
    return test_cc<CC>(arith_fl<SZ>(a, b, (a + b) & M, false));   // ADD
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
    NEXT();
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
    NEXT();
}

const Uop* h_shli(Ctx* c, const Uop* u) { S(u->d) = S(u->a) << (u->imm & 63); NEXT(); }
const Uop* h_shri(Ctx* c, const Uop* u) { S(u->d) = S(u->a) >> (u->imm & 63); NEXT(); }
const Uop* h_sari(Ctx* c, const Uop* u) {
    S(u->d) = static_cast<uint64_t>(static_cast<int64_t>(S(u->a)) >> (u->imm & 63));
    NEXT();
}

template <int SZ>
inline int64_t sext_sz(uint64_t v) {
    if (SZ == 1) return static_cast<int8_t>(v);
    if (SZ == 2) return static_cast<int16_t>(v);
    if (SZ == 4) return static_cast<int32_t>(v);
    return static_cast<int64_t>(v);
}

// CF OF SF ZF PF written, AF left alone: what the shifts and IMUL do.
inline void flags_cfof_szp(Ctx* c, uint64_t cf, uint64_t of, uint64_t r, uint64_t sign) {
    uint64_t fl = cf | (of ? 0x800 : 0) | kParity.v[r & 0xFF] | (r == 0 ? 0x40 : 0) |
                  ((r & sign) ? 0x80 : 0);
    uint64_t& rf = S(c->eng->slots.rflags);
    rf = (rf & ~0x8C5ull) | fl;
}

// OP: 4 SHL, 5 SHR, 7 SAR
template <int OP, int SZ, bool FL, bool IMM>
const Uop* h_shift(Ctx* c, const Uop* u) {
    constexpr uint64_t M = mask_of<SZ>();
    constexpr uint64_t SG = sign_of<SZ>();
    constexpr uint64_t bits = SZ * 8;
    constexpr uint64_t cmask = SZ == 8 ? 0x3F : 0x1F;
    const uint64_t v = S(u->a) & M;
    const uint64_t cnt = (IMM ? static_cast<uint64_t>(u->imm) : S(u->b)) & cmask;
    if (cnt == 0) {
        S(u->d) = v;
        NEXT();
    }
    uint64_t r, cf, of;
    if (OP == 4) {
        cf = cnt > bits ? 0 : ((v >> (bits - cnt)) & 1);
        r = cnt >= bits ? 0 : ((v << cnt) & M);
        of = cf != ((r & SG) != 0);
    } else if (OP == 5) {
        cf = (v >> (cnt - 1)) & 1;
        r = cnt >= bits ? 0 : (v >> cnt);
        of = (v & SG) != 0;
    } else {
        int64_t sv = sext_sz<SZ>(v);
        uint64_t sh = cnt >= bits ? bits - 1 : cnt;
        cf = (static_cast<uint64_t>(sv >> (sh ? sh - 1 : 0))) & 1;
        r = static_cast<uint64_t>(sv >> sh) & M;
        of = 0;
    }
    S(u->d) = r;
    if (FL) flags_cfof_szp(c, cf, of, r, SG);
    NEXT();
}

const Uop* h_shift_slow(Ctx* c, const Uop* u) {
    uint64_t v = S(u->a);
    S(u->d) = Access::shift(*c->cpu, u->cc, v, S(u->b) & 0xFF, u->sz);
    NEXT();
}

template <int SZ, bool FL, bool IMM>
const Uop* h_imul(Ctx* c, const Uop* u) {
    constexpr uint64_t M = mask_of<SZ>();
    constexpr uint64_t SG = sign_of<SZ>();
    int64_t a = sext_sz<SZ>(S(u->a) & M);
    int64_t b = IMM ? sext_sz<SZ>(static_cast<uint64_t>(u->imm) & M) : sext_sz<SZ>(S(u->b) & M);
    uint64_t r;
    bool trunc;
    if (SZ == 8) {
#ifdef __SIZEOF_INT128__
        __int128 w = static_cast<__int128>(a) * b;
        r = static_cast<uint64_t>(w);
        trunc = w != static_cast<__int128>(static_cast<int64_t>(r));
#else
        // |a|, |b| < 2^63: the product overflows 64 bits iff it exceeds it
        // in magnitude; check through division.
        r = static_cast<uint64_t>(a) * static_cast<uint64_t>(b);
        int64_t sr = static_cast<int64_t>(r);
        trunc = (a != 0 && ((a == -1 && b == INT64_MIN) || (b == -1 && a == INT64_MIN) ||
                            (a != -1 && sr / a != b)));
#endif
    } else {
        int64_t res = a * b;
        r = static_cast<uint64_t>(res) & M;
        trunc = res != sext_sz<SZ>(r);
    }
    S(u->d) = r;
    if (FL) flags_cfof_szp(c, trunc ? 1 : 0, trunc ? 1 : 0, r, SG);
    NEXT();
}

const Uop* h_group3(Ctx* c, const Uop* u) {
    c->cur = u;
    c->cpu->rip = static_cast<uint64_t>(u->imm);
    bool mem = (u->flags & kFlagMem) != 0;
    Access::group3(*c->cpu, !mem, u->d, mem ? S(u->a) : 0, u->sz, u->cc, (u->flags & kFlagRex) != 0);
    NEXT();
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
    NEXT();
}

// ---- deferred flag ops ------------------------------------------------------

const Uop* h_ccset(Ctx* c, const Uop* u) {
    Cpu* cpu = c->cpu;
    cpu->cc_a = S(u->a);
    cpu->cc_b = S(u->b);
    cpu->cc_kind = u->cc;
    cpu->cc_sz = u->sz;
    NEXT();
}
const Uop* h_ccseti(Ctx* c, const Uop* u) {
    Cpu* cpu = c->cpu;
    cpu->cc_a = S(u->a);
    cpu->cc_b = static_cast<uint64_t>(u->imm);
    cpu->cc_kind = u->cc;
    cpu->cc_sz = u->sz;
    NEXT();
}
const Uop* h_ccmat(Ctx* c, const Uop* u) {
    if (c->cpu->cc_kind) materialize_flags(*c->cpu);
    NEXT();
}
const Uop* h_ccclear(Ctx* c, const Uop* u) {
    c->cpu->cc_kind = 0;
    NEXT();
}

// Compare and branch, leaving the comparison recorded for whoever reads the
// flags later.
template <int KIND, int SZ, int CC, bool IMM>
const Uop* h_jcccmp(Ctx* c, const Uop* u) {
    constexpr uint64_t M = mask_of<SZ>();
    const uint64_t a = S(u->a) & M;
    const uint64_t b = IMM ? (static_cast<uint64_t>(static_cast<int64_t>(u->d)) & M) : (S(u->b) & M);
    Cpu* cpu = c->cpu;
    cpu->cc_a = a;
    cpu->cc_b = b;
    cpu->cc_kind = KIND;
    cpu->cc_sz = SZ;
    cpu->rip = static_cast<uint64_t>(eval_cc<KIND, SZ, CC>(a, b) ? u->imm : u->imm2);
    return nullptr;
}


// ---- conditions on rflags ---------------------------------------------------

template <int CC>
const Uop* h_jccfl(Ctx* c, const Uop* u) {
    c->cpu->rip = static_cast<uint64_t>(test_cc<CC>(S(c->eng->slots.rflags)) ? u->imm : u->imm2);
    return nullptr;
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

template <int OP, bool FL, bool IMM>
Fn pick_shift_sz(int sz) {
    switch (sz) {
        case 1: return &h_shift<OP, 1, FL, IMM>;
        case 2: return &h_shift<OP, 2, FL, IMM>;
        case 4: return &h_shift<OP, 4, FL, IMM>;
        default: return &h_shift<OP, 8, FL, IMM>;
    }
}

template <int OP>
Fn pick_shift_op(int sz, bool fl, bool imm) {
    if (fl) return imm ? pick_shift_sz<OP, true, true>(sz) : pick_shift_sz<OP, true, false>(sz);
    return imm ? pick_shift_sz<OP, false, true>(sz) : pick_shift_sz<OP, false, false>(sz);
}

Fn pick_shift(int op, int sz, bool fl, bool imm) {
    switch (op) {
        case 4: return pick_shift_op<4>(sz, fl, imm);
        case 5: return pick_shift_op<5>(sz, fl, imm);
        default: return pick_shift_op<7>(sz, fl, imm);
    }
}

template <bool FL, bool IMM>
Fn pick_imul_fl(int sz) {
    switch (sz) {
        case 2: return &h_imul<2, FL, IMM>;
        case 4: return &h_imul<4, FL, IMM>;
        default: return &h_imul<8, FL, IMM>;
    }
}

Fn pick_imul(int sz, bool fl, bool imm) {
    if (fl) return imm ? pick_imul_fl<true, true>(sz) : pick_imul_fl<true, false>(sz);
    return imm ? pick_imul_fl<false, true>(sz) : pick_imul_fl<false, false>(sz);
}

template <int KIND, int SZ, bool IMM, int CC = 0>
Fn pick_jc_cc(int cc) {
    if (cc == CC) return &h_jcccmp<KIND, SZ, CC, IMM>;
    if constexpr (CC < 15) return pick_jc_cc<KIND, SZ, IMM, CC + 1>(cc);
    return nullptr;
}

template <int KIND, bool IMM>
Fn pick_jc_sz(int sz, int cc) {
    switch (sz) {
        case 1: return pick_jc_cc<KIND, 1, IMM>(cc);
        case 2: return pick_jc_cc<KIND, 2, IMM>(cc);
        case 4: return pick_jc_cc<KIND, 4, IMM>(cc);
        default: return pick_jc_cc<KIND, 8, IMM>(cc);
    }
}

Fn pick_jcccmp(int kind, int sz, int cc, bool imm) {
#define KINDCASE(K) case K: return imm ? pick_jc_sz<K, true>(sz, cc) : pick_jc_sz<K, false>(sz, cc);
    switch (kind) {
        KINDCASE(1) KINDCASE(2) KINDCASE(3) KINDCASE(4) default: return imm ? pick_jc_sz<5, true>(sz, cc) : pick_jc_sz<5, false>(sz, cc);
    }
#undef KINDCASE
}

Fn pick_cc(int cc, int which) {
#define CASE(N) case N: return which == 0 ? &h_setfl<N> : &h_jccfl<N>;
    switch (cc & 15) {
        CASE(0) CASE(1) CASE(2) CASE(3) CASE(4) CASE(5) CASE(6) CASE(7)
        CASE(8) CASE(9) CASE(10) CASE(11) CASE(12) CASE(13) CASE(14) default: return which == 0 ? &h_setfl<15> : &h_jccfl<15>;
    }
#undef CASE
}


Fn select_x86(const Op& o) {
    const bool fl = (o.flags & kFlagEager) != 0;
    switch (o.kind) {
        case OpKind::SetFl: return pick_cc(o.cc, 0);
        case OpKind::JccFl: return pick_cc(o.cc, 1);
        case OpKind::Alu: return pick_alu(o.cc, o.sz, fl, false);
        case OpKind::AluI: return pick_alu(o.cc, o.sz, fl, true);
        case OpKind::IncDec: return o.cc ? (fl ? pick_incdec_sz<true, true>(o.sz) : pick_incdec_sz<true, false>(o.sz))
                                          : (fl ? pick_incdec_sz<false, true>(o.sz) : pick_incdec_sz<false, false>(o.sz));
        case OpKind::ShlI: return h_shli;
        case OpKind::ShrI: return h_shri;
        case OpKind::SarI: return h_sari;
        case OpKind::Shift: return pick_shift(o.cc, o.sz, fl, false);
        case OpKind::ShiftI: return pick_shift(o.cc, o.sz, fl, true);
        case OpKind::ShiftSlow: return h_shift_slow;
        case OpKind::Imul: return pick_imul(o.sz, fl, false);
        case OpKind::ImulI: return pick_imul(o.sz, fl, true);
        case OpKind::Group3: return h_group3;
        case OpKind::CcSet: return h_ccset;
        case OpKind::CcSetI: return h_ccseti;
        case OpKind::CcMat: return h_ccmat;
        case OpKind::CcClear: return h_ccclear;
        case OpKind::JccCmp: return pick_jcccmp(o.c, o.sz, o.cc, false);
        case OpKind::JccCmpI: return pick_jcccmp(o.c, o.sz, o.cc, true);
        case OpKind::Push: return o.sz == 4 ? &h_push<4> : &h_push<8>;
        case OpKind::PushI: return o.sz == 4 ? &h_pushi<4> : &h_pushi<8>;
        case OpKind::Pop: return o.sz == 4 ? &h_pop<4> : &h_pop<8>;
        case OpKind::Ret: return o.sz == 4 ? &h_ret<4> : &h_ret<8>;
        case OpKind::Call: return o.sz == 4 ? &h_call<4> : &h_call<8>;
        default: return nullptr;
    }
}

}  // namespace

Fn guest_select(const Op& o) { return select_x86(o); }

void materialize_flags(x86emu::Cpu& cpu) {
    switch (cpu.cc_sz) {
        case 1: materialize_sz<1>(cpu); break;
        case 2: materialize_sz<2>(cpu); break;
        case 4: materialize_sz<4>(cpu); break;
        default: materialize_sz<8>(cpu); break;
    }
}

}  // namespace jit
