// The x86 guest's ops for the AArch64 native backend: conditions on rflags, the arithmetic that
// sets flags (the flag bits come from a small C++ function), the deferred-flag compare-and-
// branch (a host CMP / TST and a host B.cond), shifts, multiplies and the stack.  Anything not
// handled here runs through its threaded handler.
#include "native_gen_a64.h"

namespace jit {

#ifdef JIT_NATIVE_A64

using namespace a64;

namespace {

constexpr int kRsp = 4 * 8;           // rsp is register 4, and registers are slots 0, 8, 16...
constexpr uint64_t kArith = 0x8D5;    // CF PF AF ZF SF OF

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

// The arithmetic flag bits of `a OP b = r` at `sz` bytes, as they sit in rflags.  mode: 0 ADD,
// 1 SUB, 2 logic.  (The same arithmetic as ops_x86.cpp's arith_fl / logic_fl.)
uint64_t native_x86_flags(uint64_t a, uint64_t b, uint64_t r, uint64_t mode_sz) {
    const unsigned sz = static_cast<unsigned>(mode_sz >> 8);
    const unsigned mode = static_cast<unsigned>(mode_sz & 0xFF);
    const uint64_t SG = 1ull << (sz * 8 - 1);
    const uint64_t zf = r == 0 ? 0x40 : 0, sf = (r & SG) ? 0x80 : 0;
    if (mode == 2) return kParity.v[r & 0xFF] | zf | sf;
    const bool sub = mode == 1;
    const uint64_t cf = sub ? (a < b) : (r < a);
    const bool of = sub ? (((a ^ b) & (a ^ r) & SG) != 0) : (((a ^ r) & (b ^ r) & SG) != 0);
    return cf | kParity.v[r & 0xFF] | ((a ^ b ^ r) & 0x10) | zf | sf | (of ? 0x800 : 0);
}

void native_x86_materialize(Ctx* c) { materialize_flags(*c->cpu); }

// Tests the x86 condition `cc` on the rflags slot; returns the AArch64 condition that holds
// exactly when it does.
int test_cond(NativeGenA& g, int cc) {
    Asm& a = g.a;
    g.ld(0, g.s.rflags);
    auto test_mask = [&](uint64_t m) { a.mov_imm(1, m); a.tst(true, 0, 1); };
    switch (cc >> 1) {
        case 0: test_mask(0x800); break;
        case 1: test_mask(0x1); break;
        case 2: test_mask(0x40); break;
        case 3: test_mask(0x41); break;
        case 4: test_mask(0x80); break;
        case 5: test_mask(0x4); break;
        case 6:   // SF != OF
            a.lsr_imm(true, 1, 0, 4); a.alu(EOR, true, 1, 1, 0);
            a.mov_imm(2, 0x80); a.tst(true, 1, 2);
            break;
        default:  // ZF or SF != OF
            a.lsr_imm(true, 1, 0, 4); a.alu(EOR, true, 1, 1, 0);
            a.lsr_imm(true, 1, 1, 1); a.alu(ORR, true, 1, 1, 0);
            a.mov_imm(2, 0x40); a.tst(true, 1, 2);
            break;
    }
    return (cc & 1) ? EQ : NE;
}

// The AArch64 condition for x86 condition `cc` after a host CMP of the operands (a - b).
// -1: not expressible (parity).
int sub_cond(int cc) {
    static const int map[16] = {VS, VC, LO, HS, EQ, NE, LS, HI, MI, PL, -1, -1, LT, GE, LE, GT};
    return map[cc];
}

// After a host TST of the result: the condition for the logic kinds (CF and OF are clear).
// Returns -1 for parity, 100 for "never", 101 for "always".
int logic_cond(int cc) {
    switch (cc) {
        case 0: case 2: return 100;
        case 1: case 3: return 101;
        case 4: case 6: return EQ;
        case 5: case 7: return NE;
        case 8: case 12: return MI;
        case 9: case 13: return PL;
        case 14: return LE;
        case 15: return GT;
        default: return -1;
    }
}

// rflags = (rflags & ~clear) | bits, with `bits` in x0 and the clear mask an immediate.
void merge_flags(NativeGenA& g, uint64_t clear) {
    g.ld(1, g.s.rflags);
    g.a.mov_imm(2, ~clear);
    g.a.alu(AND, true, 1, 1, 2);
    g.a.alu(ORR, true, 1, 1, 0);
    g.st(g.s.rflags, 1);
}

}  // namespace

int guest_native_cells(const Op& o) {
    switch (o.kind) {
        case OpKind::Call: return 1;
        case OpKind::JccFl: case OpKind::JccCmp: case OpKind::JccCmpI: return 2;
        default: return 0;
    }
}

bool guest_native_emit(NativeGenA& g, const Op& o) {
    Asm& a = g.a;
    const GuestSlots& s = g.s;
    const int insns = g.insns;
    const bool eager = (o.flags & kFlagEager) != 0;
    const uint64_t rip_here = g.start + o.pc;
    auto mask_to = [&](int reg, int sz) {   // reg = low `sz` bytes of reg
        if (sz == 1) a.uxtb(reg, reg);
        else if (sz == 2) a.uxth(reg, reg);
        else if (sz == 4) a.mov_rr32(reg, reg);
    };
    switch (o.kind) {
    case OpKind::ShlI: case OpKind::ShrI: case OpKind::SarI: {
        g.ld(0, o.a);
        const int n = static_cast<int>(o.imm & 63);
        if (n) {
            if (o.kind == OpKind::ShlI) a.lsl_imm(true, 0, 0, n);
            else if (o.kind == OpKind::ShrI) a.lsr_imm(true, 0, 0, n);
            else a.asr_imm(true, 0, 0, n);
        }
        g.st(o.d, 0);
        return true;
    }

    case OpKind::SetFl: {
        const int hcc = test_cond(g, o.cc);
        a.cset(true, 0, hcc);
        g.st(o.d, 0);
        return true;
    }
    case OpKind::JccFl: {
        const int hcc = test_cond(g, o.cc);
        g.labels.emplace_back();
        Label* taken = &g.labels.back();
        a.b_cond(hcc, *taken);
        g.exit_static(static_cast<uint64_t>(o.imm2), insns);
        a.bind(*taken);
        g.exit_static(static_cast<uint64_t>(o.imm), insns);
        return true;
    }

    case OpKind::Alu: case OpKind::AluI: {
        const bool compare = o.cc == 7 || o.cc == 8;
        if (compare && !eager) return true;   // compares with dead flags do nothing
        const bool imm = o.kind == OpKind::AluI;
        const int sz = o.sz;
        const uint64_t mask = sz == 8 ? ~0ull : ((1ull << (sz * 8)) - 1);
        const bool x = sz == 8;
        g.ld_sz(0, o.a, sz);
        if (imm) a.mov_imm(1, static_cast<uint64_t>(o.imm) & mask);
        else g.ld_sz(1, o.b, sz);
        if (eager) { a.mov_rr(25, 0); a.mov_rr(26, 1); }   // the operands, for the flags
        switch (o.cc) {
            case 0: a.alu(ADD, x, 0, 0, 1); break;
            case 1: a.alu(ORR, x, 0, 0, 1); break;
            case 4: case 8: a.alu(AND, x, 0, 0, 1); break;
            case 5: case 7: a.alu(SUB, x, 0, 0, 1); break;
            default: a.alu(EOR, x, 0, 0, 1); break;
        }
        mask_to(0, sz);
        if (eager) {
            a.mov_rr(27, 0);
            a.mov_rr(0, 25); a.mov_rr(1, 26); a.mov_rr(2, 27);
            a.mov_imm(3, (static_cast<uint64_t>(sz) << 8) | ((o.cc == 0) ? 0 : (o.cc == 5 || o.cc == 7) ? 1 : 2));
            g.call(reinterpret_cast<const void*>(&native_x86_flags));
            merge_flags(g, kArith);
            a.mov_rr(0, 27);
        }
        if (!compare) g.st(o.d, 0);
        return true;
    }
    case OpKind::IncDec: {
        const int sz = o.sz;
        const bool x = sz == 8;
        g.ld_sz(0, o.a, sz);
        if (eager) a.mov_rr(25, 0);
        if (o.cc) a.sub_imm(x, 0, 0, 1); else a.add_imm(x, 0, 0, 1);
        mask_to(0, sz);
        if (eager) {
            a.mov_rr(27, 0);
            a.mov_rr(0, 25); a.mov_imm(1, 1); a.mov_rr(2, 27);
            a.mov_imm(3, (static_cast<uint64_t>(sz) << 8) | (o.cc ? 1 : 0));
            g.call(reinterpret_cast<const void*>(&native_x86_flags));
            a.mov_imm(2, 0x8D4);   // CF survives
            a.alu(AND, true, 0, 0, 2);
            merge_flags(g, 0x8D4);
            a.mov_rr(0, 27);
        }
        g.st(o.d, 0);
        return true;
    }
    case OpKind::Shift: case OpKind::ShiftI: {
        if (eager) return false;
        if (o.cc != 4 && o.cc != 5 && o.cc != 7) return false;
        const int sz = o.sz;
        const bool x = sz == 8;
        if (o.cc == 7) {   // SAR works on the sign extended value
            if (sz == 1) a.ldrsb(0, ra::ENV, o.a);
            else if (sz == 2) a.ldrsh(0, ra::ENV, o.a);
            else if (sz == 4) a.ldrsw(0, ra::ENV, o.a);
            else g.ld(0, o.a);
        } else {
            g.ld_sz(0, o.a, sz);
        }
        const int type = o.cc == 4 ? LSL : o.cc == 5 ? LSR : ASR;
        if (o.kind == OpKind::ShiftI) {
            const int n = static_cast<int>(o.imm & (x ? 63 : 31));
            if (n) {
                if (type == LSL) a.lsl_imm(x, 0, 0, n);
                else if (type == LSR) a.lsr_imm(x, 0, 0, n);
                else a.asr_imm(x, 0, 0, n);
            }
        } else {
            g.ld(1, o.b);
            a.shiftv(type, x, 0, 0, 1);
        }
        mask_to(0, sz);
        g.st(o.d, 0);
        return true;
    }

    case OpKind::CcSet: case OpKind::CcSetI:
        g.ld(0, o.a); g.st(s.cc_a, 0);
        if (o.kind == OpKind::CcSetI) g.st_imm(s.cc_b, o.imm);
        else { g.ld(0, o.b); g.st(s.cc_b, 0); }
        a.mov_imm(0, static_cast<uint64_t>(o.cc)); a.str32(0, ra::ENV, s.cc_kind);
        a.mov_imm(0, static_cast<uint64_t>(o.sz)); a.str32(0, ra::ENV, s.cc_sz);
        return true;
    case OpKind::CcClear:
        a.str32(XZR, ra::ENV, s.cc_kind);
        return true;
    case OpKind::CcMat: {
        a.ldr32(0, ra::ENV, s.cc_kind);
        Label skip;
        a.cbz(false, 0, skip);
        a.mov_rr(0, ra::CTX);
        g.call(reinterpret_cast<const void*>(&native_x86_materialize));
        a.bind(skip);
        return true;
    }
    case OpKind::JccCmp: case OpKind::JccCmpI: {
        if (!((o.c == 2 || o.c == 3 || o.c == 4 || o.c == 5) && (o.sz == 4 || o.sz == 8))) return false;
        const bool x = o.sz == 8;
        const int cc = o.cc;
        const int hcc = o.c == 2 ? sub_cond(cc) : logic_cond(cc);
        if (hcc < 0) return false;   // parity: the interpreter's way
        g.ld_sz(0, o.a, o.sz);
        if (o.kind == OpKind::JccCmpI) a.mov_imm(1, x ? static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(o.d)))
                                                     : static_cast<uint64_t>(static_cast<uint32_t>(o.d)));
        else g.ld_sz(1, o.b, o.sz);
        g.st(s.cc_a, 0);
        g.st(s.cc_b, 1);
        a.mov_imm(2, static_cast<uint64_t>(o.c)); a.str32(2, ra::ENV, s.cc_kind);
        a.mov_imm(2, static_cast<uint64_t>(o.sz)); a.str32(2, ra::ENV, s.cc_sz);
        switch (o.c) {
            case 2: a.cmp(x, 0, 1); break;
            case 3: a.tst(x, 0, 1); break;
            case 4: a.alu(ORR, x, 0, 0, 1); a.tst(x, 0, 0); break;
            default: a.alu(EOR, x, 0, 0, 1); a.tst(x, 0, 0); break;
        }
        if (hcc == 100 || hcc == 101) {   // CF and OF are clear after a logic operation
            if (hcc == 101) g.exit_static(static_cast<uint64_t>(o.imm), insns);
            else g.exit_static(static_cast<uint64_t>(o.imm2), insns);
            // (the other exit is never taken, but its word is still counted)
            g.next_cell();
            return true;
        }
        g.labels.emplace_back();
        Label* taken = &g.labels.back();
        a.b_cond(hcc, *taken);
        g.exit_static(static_cast<uint64_t>(o.imm2), insns);
        a.bind(*taken);
        g.exit_static(static_cast<uint64_t>(o.imm), insns);
        return true;
    }

    case OpKind::Imul: case OpKind::ImulI: {
        if (eager) return false;
        const int sz = o.sz;
        if (sz != 2 && sz != 4 && sz != 8) return false;
        const bool x = sz == 8;
        if (sz == 2) a.ldrsh(0, ra::ENV, o.a); else if (sz == 4) a.ldrsw(0, ra::ENV, o.a); else g.ld(0, o.a);
        if (o.kind == OpKind::ImulI) {
            int64_t v = o.imm;
            if (sz == 2) v = static_cast<int16_t>(v); else if (sz == 4) v = static_cast<int32_t>(v);
            a.mov_imm(1, static_cast<uint64_t>(v));
        } else if (sz == 2) {
            a.ldrsh(1, ra::ENV, o.b);
        } else if (sz == 4) {
            a.ldrsw(1, ra::ENV, o.b);
        } else {
            g.ld(1, o.b);
        }
        a.mul(x, 0, 0, 1);
        mask_to(0, sz);
        g.st(o.d, 0);
        return true;
    }

    case OpKind::Push: case OpKind::PushI: {
        if (o.sz != 4 && o.sz != 8) return false;
        g.ld(0, kRsp);
        a.sub_imm(true, 0, 0, static_cast<uint32_t>(o.sz));
        g.st(kRsp, 0);
        if (o.kind == OpKind::Push) g.ld(4, o.a); else a.mov_imm(4, static_cast<uint64_t>(o.imm));
        g.mem_write(o.sz, rip_here);
        if (o.flags & kFlagChk) g.chk_flush(static_cast<uint64_t>(o.imm2), o.ni);
        return true;
    }
    case OpKind::Pop: case OpKind::Ret: {
        if (o.sz != 4 && o.sz != 8) return false;
        g.ld(0, kRsp);
        g.mem_read(o.sz, rip_here);
        g.ld(1, kRsp);
        const int64_t adv = o.sz + (o.kind == OpKind::Ret ? o.imm : 0);
        if (adv < 4096) a.add_imm(true, 1, 1, static_cast<uint32_t>(adv));
        else { a.mov_imm(2, static_cast<uint64_t>(adv)); a.alu(ADD, true, 1, 1, 2); }
        g.st(kRsp, 1);
        if (o.kind == OpKind::Pop) {
            g.st(o.d, 0);   // after the increment: POP ESP keeps the loaded value
        } else {
            g.st(s.rip, 0);
            g.leave_indirect(insns);
        }
        return true;
    }
    case OpKind::Call: {
        if (o.sz != 4 && o.sz != 8) return false;
        g.ld(0, kRsp);
        a.sub_imm(true, 0, 0, static_cast<uint32_t>(o.sz));
        g.st(kRsp, 0);
        a.mov_imm(4, static_cast<uint64_t>(o.imm2));
        g.mem_write(o.sz, rip_here);
        g.exit_static(static_cast<uint64_t>(o.imm), insns);
        return true;
    }
    default:
        return false;
    }
}

#endif  // JIT_NATIVE_A64

}  // namespace jit
