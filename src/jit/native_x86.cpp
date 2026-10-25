// The x86 guest's ops for the native backend: conditions on rflags, the arithmetic that
// sets flags (the host's own flags are the guest's, so the instruction is run and its flags
// are read back with PUSHFQ), the deferred-flag compare-and-branch (a host CMP / TEST and
// a host Jcc), shifts and the stack.  Anything not handled here runs through its threaded
// handler.
#include "native_gen.h"

namespace jit {

#ifdef JIT_HAVE_NATIVE

using namespace x64;

namespace {

#ifdef _WIN32
constexpr int ARG1 = RCX, ARG2 = RDX, ARG3 = R8, ARG4 = R9;
#else
constexpr int ARG1 = RDI, ARG2 = RSI, ARG3 = RDX, ARG4 = RCX;
#endif

constexpr int kRsp = 4 * 8;           // rsp is register 4, and registers are slots 0, 8, 16...
constexpr int32_t kArith = 0x8D5;     // CF PF AF ZF SF OF

bool fits32(int64_t v) { return v >= INT32_MIN && v <= INT32_MAX; }

// Tests the x86 condition `cc` on the rflags slot; returns the host condition that holds
// exactly when it does.
int test_cond(NativeGen& g, int cc) {
    x64::Asm& a = g.a;
    g.a.load32(RAX, RBX, g.s.rflags);
    switch (cc >> 1) {
        case 0: a.test_ri(false, RAX, 0x800); break;
        case 1: a.test_ri(false, RAX, 0x1); break;
        case 2: a.test_ri(false, RAX, 0x40); break;
        case 3: a.test_ri(false, RAX, 0x41); break;
        case 4: a.test_ri(false, RAX, 0x80); break;
        case 5: a.test_ri(false, RAX, 0x4); break;
        case 6:   // SF != OF
            a.mov_rr32(RCX, RAX); a.shift_i(SHR, false, RCX, 4); a.alu_rr(XOR, false, RCX, RAX);
            a.test_ri(false, RCX, 0x80);
            break;
        default:  // ZF or SF != OF
            a.mov_rr32(RCX, RAX); a.shift_i(SHR, false, RCX, 4); a.alu_rr(XOR, false, RCX, RAX);
            a.shift_i(SHR, false, RCX, 1); a.alu_rr(OR, false, RCX, RAX);
            a.test_ri(false, RCX, 0x40);
            break;
    }
    return (cc & 1) ? E : NE;
}

// Stores the deferred-flag state: what the flags would be computed from.
void store_cc(NativeGen& g, int kind, int sz) {
    g.a.store32_imm(RBX, g.s.cc_kind, static_cast<uint32_t>(kind));
    g.a.store32_imm(RBX, g.s.cc_sz, static_cast<uint32_t>(sz));
}

// rflags = (rflags & ~clear) | (host flags & take), the host flags having just been set.
void merge_flags(NativeGen& g, int32_t clear, int32_t take) {
    g.a.pushfq();
    g.a.pop(RDX);
    g.a.alu_ri(AND, false, RDX, take);
    g.ld(R8, g.s.rflags);
    g.a.alu_ri(AND, true, R8, ~clear);
    g.a.alu_rr(OR, true, R8, RDX);
    g.st(g.s.rflags, R8);
}

void native_materialize(Ctx* c) { materialize_flags(*c->cpu); }

void call_abs(NativeGen& g, const void* fn) {
    g.a.movi(RAX, static_cast<int64_t>(reinterpret_cast<uintptr_t>(fn)));
    g.a.call_r(RAX);
}

}  // namespace

int guest_native_cells(const Op& o) {
    switch (o.kind) {
        case OpKind::Call: return 1;
        case OpKind::JccFl: case OpKind::JccCmp: case OpKind::JccCmpI: return 2;
        default: return 0;
    }
}

bool guest_native_emit(NativeGen& g, const Op& o) {
    x64::Asm& a = g.a;
    const GuestSlots& s = g.s;
    const int insns = g.insns;
    const bool eager = (o.flags & kFlagEager) != 0;
    const uint64_t rip_here = g.start + o.pc;
    auto meta = [&](int size) { return static_cast<int64_t>((rip_here << 8) | static_cast<uint64_t>(size)); };
    switch (o.kind) {
    case OpKind::ShlI: case OpKind::ShrI: case OpKind::SarI:
        g.ld(RAX, o.a);
        a.shift_i(o.kind == OpKind::ShlI ? SHL : o.kind == OpKind::ShrI ? SHR : SAR, true, RAX,
                  static_cast<int>(o.imm & 63));
        g.st(o.d, RAX);
        return true;

    case OpKind::SetFl: {
        const int hcc = test_cond(g, o.cc);
        a.setcc(hcc, RAX);
        a.movzx32(RAX, RAX, 8);
        g.st(o.d, RAX);
        return true;
    }
    case OpKind::JccFl: {
        const int hcc = test_cond(g, o.cc);
        x64::Label taken;
        a.jcc(hcc, taken);
        g.exit_static(static_cast<uint64_t>(o.imm2), insns);
        a.bind(taken);
        g.exit_static(static_cast<uint64_t>(o.imm), insns);
        return true;
    }

    case OpKind::Alu: case OpKind::AluI: {
        const bool compare = o.cc == 7 || o.cc == 8;
        if (compare && !eager) return true;   // compares with dead flags do nothing
        const bool imm = o.kind == OpKind::AluI;
        const int sz = o.sz;
        const uint64_t mask = sz == 8 ? ~0ull : ((1ull << (sz * 8)) - 1);
        if (eager && sz != 4 && sz != 8) return false;
        const bool w = sz == 8;
        g.ld_sz(RAX, o.a, sz);
        if (imm) a.movi(RCX, static_cast<int64_t>(static_cast<uint64_t>(o.imm) & mask));
        else g.ld_sz(RCX, o.b, sz);
        const bool bit32 = sz != 8;   // sizes 1, 2 and 4 run as 32-bit operations
        switch (o.cc) {
            case 0: a.alu_rr(ADD, !bit32, RAX, RCX); break;
            case 1: a.alu_rr(OR, !bit32, RAX, RCX); break;
            case 4: a.alu_rr(AND, !bit32, RAX, RCX); break;
            case 8: a.test_rr(w, RAX, RCX); break;
            case 5: a.alu_rr(SUB, !bit32, RAX, RCX); break;
            case 7: a.alu_rr(CMP, !bit32, RAX, RCX); break;
            default: a.alu_rr(XOR, !bit32, RAX, RCX); break;
        }
        // AF is architecturally undefined after a logic operation; the interpreter clears it.
        if (eager) {
            const bool arith = o.cc == 0 || o.cc == 5 || o.cc == 7;
            merge_flags(g, kArith, arith ? kArith : 0x8C5);
        }
        if (!compare) {
            if (sz == 1) a.movzx32(RAX, RAX, 8);
            else if (sz == 2) a.movzx32(RAX, RAX, 16);
            g.st(o.d, RAX);
        }
        return true;
    }
    case OpKind::IncDec: {
        const int sz = o.sz;
        if (eager && sz != 4 && sz != 8) return false;
        g.ld_sz(RAX, o.a, sz);
        a.alu_ri(o.cc ? SUB : ADD, sz == 8, RAX, 1);
        if (eager) merge_flags(g, 0x8D4, 0x8D4);   // CF survives
        if (sz == 1) a.movzx32(RAX, RAX, 8);
        else if (sz == 2) a.movzx32(RAX, RAX, 16);
        g.st(o.d, RAX);
        return true;
    }
    case OpKind::Shift: case OpKind::ShiftI: {
        if (eager) return false;
        if (o.cc != 4 && o.cc != 5 && o.cc != 7) return false;
        const int sz = o.sz;
        const bool w = sz == 8;
        if (o.cc == 7) {   // SAR works on the sign extended value
            if (sz == 1) a.load8s(RAX, RBX, o.a);
            else if (sz == 2) a.load16s(RAX, RBX, o.a);
            else g.ld_sz(RAX, o.a, sz);
        } else {
            g.ld_sz(RAX, o.a, sz);
        }
        const int sh = o.cc == 4 ? SHL : o.cc == 5 ? SHR : SAR;
        if (o.kind == OpKind::ShiftI) {
            const int n = static_cast<int>(o.imm & (w ? 63 : 31));
            if (n) a.shift_i(sh, w, RAX, n);
        } else {
            g.ld(RCX, o.b);
            a.shift_cl(sh, w, RAX);
        }
        if (sz == 1) a.movzx32(RAX, RAX, 8);
        else if (sz == 2) a.movzx32(RAX, RAX, 16);
        else if (sz == 4) a.mov_rr32(RAX, RAX);
        g.st(o.d, RAX);
        return true;
    }

    case OpKind::CcSet: case OpKind::CcSetI:
        g.ld(RAX, o.a); g.st(s.cc_a, RAX);
        if (o.kind == OpKind::CcSetI) g.st_imm(s.cc_b, o.imm);
        else { g.ld(RAX, o.b); g.st(s.cc_b, RAX); }
        store_cc(g, o.cc, o.sz);
        return true;
    case OpKind::CcClear:
        a.store32_imm(RBX, s.cc_kind, 0);
        return true;
    case OpKind::CcMat: {
        a.cmp_m32_imm(RBX, s.cc_kind, 0);
        x64::Label skip;
        a.jcc(E, skip);
        a.mov_rr(ARG1, R12);
        call_abs(g, reinterpret_cast<const void*>(&native_materialize));
        a.bind(skip);
        return true;
    }
    case OpKind::Imul: case OpKind::ImulI: {
        const int sz = o.sz;
        if (eager && sz != 4 && sz != 8) return false;
        if (sz != 2 && sz != 4 && sz != 8) return false;
        const bool w = sz == 8;
        // The operands are sign extended from their size; 16-bit multiplies run as 32-bit ones.
        if (sz == 2) a.load16s(RAX, RBX, o.a); else g.ld_sz(RAX, o.a, sz);
        if (o.kind == OpKind::ImulI) {
            int64_t v = o.imm;
            if (sz == 2) v = static_cast<int16_t>(v);
            else if (sz == 4) v = static_cast<int32_t>(v);
            a.movi(RCX, v);
        } else if (sz == 2) {
            a.load16s(RCX, RBX, o.b);
        } else {
            g.ld_sz(RCX, o.b, sz);
        }
        a.imul_rr(w, RAX, RCX);
        if (eager) {
            a.pushfq(); a.pop(RDX); a.alu_ri(AND, false, RDX, 0x801);   // CF = OF = the product did not fit
            a.test_rr(w, RAX, RAX);
            a.pushfq(); a.pop(R10); a.alu_ri(AND, false, R10, 0xC4);    // SF ZF PF of the result
            a.alu_rr(OR, false, RDX, R10);
            g.ld(R8, s.rflags);
            a.alu_ri(AND, true, R8, ~0x8C5);
            a.alu_rr(OR, true, R8, RDX);
            g.st(s.rflags, R8);
        }
        if (sz == 2) a.movzx32(RAX, RAX, 16);
        else if (sz == 4) a.mov_rr32(RAX, RAX);
        g.st(o.d, RAX);
        return true;
    }
    case OpKind::JccCmp: case OpKind::JccCmpI: {
        if (!((o.c == 2 || o.c == 3 || o.c == 4 || o.c == 5) && (o.sz == 4 || o.sz == 8))) return false;
        const bool w = o.sz == 8;
        g.ld_sz(RAX, o.a, o.sz);
        if (o.kind == OpKind::JccCmpI) a.movi(RCX, w ? static_cast<int64_t>(static_cast<int32_t>(o.d))
                                                     : static_cast<int64_t>(static_cast<uint32_t>(o.d)));
        else g.ld_sz(RCX, o.b, o.sz);
        g.st(s.cc_a, RAX);
        g.st(s.cc_b, RCX);
        store_cc(g, o.c, o.sz);
        switch (o.c) {
            case 2: a.alu_rr(CMP, w, RAX, RCX); break;
            case 3: a.test_rr(w, RAX, RCX); break;
            case 4: a.alu_rr(OR, w, RAX, RCX); break;
            default: a.alu_rr(XOR, w, RAX, RCX); break;
        }
        x64::Label taken;
        a.jcc(o.cc, taken);
        g.exit_static(static_cast<uint64_t>(o.imm2), insns);
        a.bind(taken);
        g.exit_static(static_cast<uint64_t>(o.imm), insns);
        return true;
    }

    case OpKind::Push: case OpKind::PushI: {
        if (o.sz != 4 && o.sz != 8) return false;
        g.ld(RAX, kRsp);
        a.alu_ri(SUB, true, RAX, o.sz);
        g.st(kRsp, RAX);
        if (o.kind == OpKind::Push) g.ld(R9, o.a); else a.movi(R9, o.imm);
        g.mem_write(o.sz, rip_here);
        if (o.flags & kFlagChk) g.chk_flush(static_cast<uint64_t>(o.imm2), o.ni);
        return true;
    }
    case OpKind::Pop: case OpKind::Ret: {
        if (o.sz != 4 && o.sz != 8) return false;
        g.ld(RAX, kRsp);
        g.mem_read(o.sz, rip_here);
        g.ld(RCX, kRsp);
        a.alu_ri(ADD, true, RCX, static_cast<int32_t>(o.sz + (o.kind == OpKind::Ret ? o.imm : 0)));
        g.st(kRsp, RCX);
        if (o.kind == OpKind::Pop) {
            g.st(o.d, RAX);   // after the increment: POP ESP keeps the loaded value
        } else {
            g.st(s.rip, RAX);
            g.leave_with(insns);
        }
        return true;
    }
    case OpKind::Call: {
        if (o.sz != 4 && o.sz != 8) return false;
        g.ld(RAX, kRsp);
        a.alu_ri(SUB, true, RAX, o.sz);
        g.st(kRsp, RAX);
        a.movi(R9, o.imm2);
        g.mem_write(o.sz, rip_here);
        g.exit_static(static_cast<uint64_t>(o.imm), insns);
        return true;
    }
    default:
        return false;
    }
}

#endif  // JIT_HAVE_NATIVE

}  // namespace jit
