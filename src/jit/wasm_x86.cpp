// The x86 guest's ops as WebAssembly: conditions on rflags, the arithmetic that
// sets flags (through a small flags function in every module), deferred-flag
// compare-and-branch, shifts and the stack.  Anything not handled here runs through
// its threaded handler.
#include <cstdio>
#include <string>

#include "wasm_gen.h"

namespace jit {

namespace {

using x86emu::Cpu;

struct X86Gen : Gen {
    explicit X86Gen(Gen& o) : Gen(o) {}

    // The x86 condition `cc` on rflags, as an i32 0/1.
    void cond_fl(int cc) {
        slot_get(e.slots.rflags);
        op(I32_WRAP);
        set(L_T);
        auto bit = [&](int n) { get(L_T); i32c(n); op(I32_SHR_U); i32c(1); op(I32_AND); };
        switch (cc >> 1) {
            case 0: bit(11); break;
            case 1: bit(0); break;
            case 2: bit(6); break;
            case 3: get(L_T); i32c(0x41); op(I32_AND); i32c(0); op(I32_NE); break;
            case 4: bit(7); break;
            case 5: bit(2); break;
            case 6: bit(7); bit(11); op(I32_XOR); break;
            default: bit(6); bit(7); bit(11); op(I32_XOR); op(I32_OR); break;
        }
        if (cc & 1) { i32c(1); op(I32_XOR); }
    }


    // rflags = (rflags & ~keep_clear) | flags(a, b, r) for the arithmetic flags of
    // an ADD (mode 0), SUB (1) or logic operation (2) whose operands are in
    // L_X and L_Y and whose result is in L_V, all masked to `sz` bytes.  `keep_cf`
    // leaves the carry flag as it was (INC, DEC).
    void eager_flags(int mode, int sz, bool keep_cf) {
        const int64_t SG = sz == 8 ? INT64_MIN : (1ll << (sz * 8 - 1));
        get(L_ENV);
        slot_get(e.slots.rflags);
        i64c(keep_cf ? ~0x8D4ll : ~0x8D5ll); op(I64_AND);
        get(L_X); get(L_Y); get(L_V); i32c(mode); i64c(SG);
        w.u8(0x10); w.uleb(e.extra_base);   // call $flags
        if (keep_cf) { i64c(~1ll); op(I64_AND); }
        op(I64_OR);
        st64(static_cast<uint32_t>(e.slots.rflags));
    }


    // Is a JccCmp of this kind and size one we do inline?
    static bool jcc_inline(const Op& o) {
        return (o.c == 2 || o.c == 3 || o.c == 4 || o.c == 5) && (o.sz == 4 || o.sz == 8);
    }

    // cond of "a OP b" for a JccCmp, with A in L_X and B in L_Y (both masked); an i32.
    void cmp_cond(int kind, int sz, int cc) {
        const int64_t SG = sz == 8 ? INT64_MIN : (1ll << (sz * 8 - 1));
        auto sx = [&](int l) {
            get(l);
            if (sz == 4) op(I64_EXT32);
        };
        auto parity_even_of = [&](auto result) {   // PF: even number of set bits in the low byte
            result();
            i64c(0xFF); op(I64_AND); op(I64_POPCNT); i64c(1); op(I64_AND); op(I64_EQZ);
        };
        if (kind == 2) {   // SUB
            auto r = [&] {
                get(L_X); get(L_Y); op(I64_SUB);
                if (sz == 4) { i64c(0xFFFFFFFFll); op(I64_AND); }
            };
            switch (cc) {
                case 0: case 1:
                    get(L_X); get(L_Y); op(I64_XOR); get(L_X); r(); op(I64_XOR); op(I64_AND);
                    i64c(SG); op(I64_AND); i64c(0); op(cc == 0 ? I64_NE : I64_EQ); break;
                case 2: get(L_X); get(L_Y); op(I64_LT_U); break;
                case 3: get(L_X); get(L_Y); op(I64_GE_U); break;
                case 4: get(L_X); get(L_Y); op(I64_EQ); break;
                case 5: get(L_X); get(L_Y); op(I64_NE); break;
                case 6: get(L_X); get(L_Y); op(I64_LE_U); break;
                case 7: get(L_X); get(L_Y); op(I64_GT_U); break;
                case 8: case 9:
                    r(); i64c(SG); op(I64_AND); i64c(0); op(cc == 8 ? I64_NE : I64_EQ); break;
                case 10: case 11:
                    parity_even_of(r);
                    if (cc == 11) op(I32_EQZ);
                    break;
                case 12: sx(L_X); sx(L_Y); op(I64_LT_S); break;
                case 13: sx(L_X); sx(L_Y); op(I64_GE_S); break;
                case 14: sx(L_X); sx(L_Y); op(I64_LE_S); break;
                default: sx(L_X); sx(L_Y); op(I64_GT_S); break;
            }
            return;
        }
        // AND / OR / XOR: CF and OF are clear
        auto r = [&] {
            get(L_X); get(L_Y);
            op(kind == 3 ? I64_AND : kind == 4 ? I64_OR : I64_XOR);
        };
        switch (cc) {
            case 0: case 2: i32c(0); break;
            case 1: case 3: i32c(1); break;
            case 4: case 6: r(); op(I64_EQZ); break;
            case 5: case 7: r(); op(I64_EQZ); op(I32_EQZ); break;
            case 8: case 12: r(); i64c(SG); op(I64_AND); i64c(0); op(I64_NE); break;
            case 9: case 13: r(); i64c(SG); op(I64_AND); i64c(0); op(I64_EQ); break;
            case 10: case 11:
                parity_even_of(r);
                if (cc == 11) op(I32_EQZ);
                break;
            case 14:   // SF or ZF
                r(); i64c(SG); op(I64_AND); i64c(0); op(I64_NE);
                r(); op(I64_EQZ); op(I32_OR); break;
            default:   // not SF and not ZF
                r(); i64c(SG); op(I64_AND); i64c(0); op(I64_EQ);
                r(); op(I64_EQZ); op(I32_EQZ); op(I32_AND); break;
        }
    }
};

// The body of $flags(a, b, r, mode, sg) -> the arithmetic flag bits of rflags
// (CF PF AF ZF SF OF in their rflags positions).  mode 0 = ADD, 1 = SUB, 2 = logic.
// Parameters: 0 a, 1 b, 2 r (i64), 3 mode (i32), 4 sign mask (i64).
void build_flags_function(Buf& code) {
    Buf b;
    auto get = [&](int l) { b.u8(0x20); b.uleb(l); };
    auto i64c = [&](int64_t v) { b.u8(0x42); b.sleb(v); };
    auto i32c = [&](int32_t v) { b.u8(0x41); b.sleb(v); };
    b.uleb(0);   // no locals beyond the parameters
    // arithmetic (mode < 2) ?
    get(3); i32c(2); b.u8(0x49);       // i32.lt_u
    b.u8(0x04); b.u8(0x7E);            // if (result i64)
      // cf: mode == 0 ? r < a : a < b
      get(3); b.u8(0x45);              // i32.eqz
      b.u8(0x04); b.u8(0x7E);
        get(2); get(0); b.u8(0x54); b.u8(0xAD);   // r <u a, as i64
      b.u8(0x05);
        get(0); get(1); b.u8(0x54); b.u8(0xAD);   // a <u b
      b.u8(0x0B);
      // af: (a ^ b ^ r) & 0x10
      get(0); get(1); b.u8(0x85); get(2); b.u8(0x85); i64c(0x10); b.u8(0x83); b.u8(0x84);
      // of: mode == 0 ? ((a^r) & (b^r) & sg) : ((a^b) & (a^r) & sg); nonzero -> bit 11
      get(3); b.u8(0x45);
      b.u8(0x04); b.u8(0x7E);
        get(0); get(2); b.u8(0x85); get(1); get(2); b.u8(0x85); b.u8(0x83); get(4); b.u8(0x83);
      b.u8(0x05);
        get(0); get(1); b.u8(0x85); get(0); get(2); b.u8(0x85); b.u8(0x83); get(4); b.u8(0x83);
      b.u8(0x0B);
      i64c(0); b.u8(0x52); b.u8(0xAD); i64c(11); b.u8(0x86); b.u8(0x84);   // != 0, << 11, or
    b.u8(0x05);
      i64c(0);
    b.u8(0x0B);
    // zf: r == 0 -> 0x40
    get(2); b.u8(0x50); b.u8(0xAD); i64c(6); b.u8(0x86); b.u8(0x84);
    // sf: (r & sg) != 0 -> 0x80
    get(2); get(4); b.u8(0x83); i64c(0); b.u8(0x52); b.u8(0xAD); i64c(7); b.u8(0x86); b.u8(0x84);
    // pf: even parity of the low byte -> 4
    get(2); i64c(0xFF); b.u8(0x83); b.u8(0x7B); i64c(1); b.u8(0x83); b.u8(0x50); b.u8(0xAD);
    i64c(2); b.u8(0x86); b.u8(0x84);
    b.u8(0x0B);   // end
    code.append(b);
}


}  // namespace

int guest_wasm_cells(const Op& o) {
    switch (o.kind) {
        case OpKind::Call: return 1;
        case OpKind::JccFl: case OpKind::JccCmp: case OpKind::JccCmpI: return 2;
        default: return 0;
    }
}

void guest_wasm_extras(std::vector<Buf>& bodies) {
    Buf f;
    build_flags_function(f);
    bodies.push_back(std::move(f));
}

bool guest_wasm_emit(BlockGen& bg) {
    X86Gen g(bg.g);
    const Op& o = bg.o;
    const Env& env = bg.env;
    const int pc = bg.pc;
    const int insns = bg.insns;
    const bool eager = bg.eager;
    const int rsp_slot = 4 * 8;
    auto fallback = bg.fallback;
    (void)pc;
    switch (o.kind) {
                case OpKind::SetFl:
                    g.get(L_ENV); g.cond_fl(o.cc); g.op(Gen::I64_EXT_U); g.st64(o.d); break;
                case OpKind::JccFl: {
                    g.cond_fl(o.cc);
                    const uint32_t ct = bg.next_cell(), cf = bg.next_cell();
                    g.jump_cond(o.imm, o.imm2, insns, ct, cf);
                    break;
                }
                case OpKind::Alu: case OpKind::AluI: {
                    const bool compare = o.cc == 7 || o.cc == 8;
                    if (compare && !eager) break;   // compares with dead flags do nothing
                    const bool imm = o.kind == OpKind::AluI;
                    const uint8_t binop = o.cc == 0 ? Gen::I64_ADD : o.cc == 1 ? Gen::I64_OR
                                          : (o.cc == 4 || o.cc == 8) ? Gen::I64_AND
                                          : (o.cc == 5 || o.cc == 7) ? Gen::I64_SUB : Gen::I64_XOR;
                    if (!eager) {
                        g.get(L_ENV);
                        g.slot_masked(o.a, o.sz);
                        if (imm) g.imm_masked(o.imm, o.sz); else g.slot_masked(o.b, o.sz);
                        g.op(binop);
                        g.mask(o.sz);
                        g.st64(o.d);
                        break;
                    }
                    g.slot_masked(o.a, o.sz); g.set(L_X);
                    if (imm) g.imm_masked(o.imm, o.sz); else g.slot_masked(o.b, o.sz);
                    g.set(L_Y);
                    g.get(L_X); g.get(L_Y); g.op(binop); g.mask(o.sz); g.set(L_V);
                    if (!compare) { g.get(L_ENV); g.get(L_V); g.st64(o.d); }
                    g.eager_flags(o.cc == 0 ? 0 : (o.cc == 5 || o.cc == 7) ? 1 : 2, o.sz, false);
                    break;
                }
                case OpKind::IncDec:
                    if (!eager) {
                        g.get(L_ENV); g.slot_masked(o.a, o.sz); g.i64c(1);
                        g.op(o.cc ? Gen::I64_SUB : Gen::I64_ADD); g.mask(o.sz); g.st64(o.d);
                        break;
                    }
                    g.slot_masked(o.a, o.sz); g.set(L_X);
                    g.i64c(1); g.set(L_Y);
                    g.get(L_X); g.get(L_Y); g.op(o.cc ? Gen::I64_SUB : Gen::I64_ADD); g.mask(o.sz); g.set(L_V);
                    g.get(L_ENV); g.get(L_V); g.st64(o.d);
                    g.eager_flags(o.cc ? 1 : 0, o.sz, true);
                    break;
                case OpKind::Shift: case OpKind::ShiftI: {
                    if (eager) { fallback(); break; }
                    // Flags dead: just the result.  A count of zero leaves the value.
                    const int cmask = o.sz == 8 ? 63 : 31;
                    g.get(L_ENV);
                    if (o.cc == 7) {   // SAR on the sign extended value
                        g.slot_get(o.a);
                        if (o.sz == 1) g.op(Gen::I64_EXT8);
                        else if (o.sz == 2) g.op(Gen::I64_EXT16);
                        else if (o.sz == 4) g.op(Gen::I64_EXT32);
                    } else {
                        g.slot_masked(o.a, o.sz);
                    }
                    if (o.kind == OpKind::ShiftI) g.i64c(o.imm & cmask);
                    else { g.slot_get(o.b); g.i64c(cmask); g.op(Gen::I64_AND); }
                    g.op(o.cc == 4 ? Gen::I64_SHL : o.cc == 5 ? Gen::I64_SHR_U : Gen::I64_SHR_S);
                    g.mask(o.sz);
                    g.st64(o.d);
                    break;
                }
                case OpKind::CcSet: case OpKind::CcSetI:
                    g.get(L_ENV); g.slot_get(o.a); g.st64(env.slots.cc_a);
                    g.get(L_ENV);
                    if (o.kind == OpKind::CcSetI) g.i64c(o.imm); else g.slot_get(o.b);
                    g.st64(env.slots.cc_b);
                    g.get(L_ENV); g.i32c(o.cc); g.st32(env.slots.cc_kind);
                    g.get(L_ENV); g.i32c(o.sz); g.st32(env.slots.cc_sz);
                    break;
                case OpKind::CcClear:
                    g.get(L_ENV); g.i32c(0); g.st32(env.slots.cc_kind); break;
                case OpKind::CcMat:
                    g.get(L_ENV); g.ld32(env.slots.cc_kind);
                    g.w.u8(0x04); g.w.u8(0x40);
                    fallback();
                    g.w.u8(0x0B);
                    break;
                case OpKind::JccCmp: case OpKind::JccCmpI: {
                    if (!X86Gen::jcc_inline(o)) { fallback(); break; }
                    g.slot_masked(o.a, o.sz); g.set(L_X);
                    if (o.kind == OpKind::JccCmpI) g.imm_masked(static_cast<int64_t>(o.d), o.sz);
                    else g.slot_masked(o.b, o.sz);
                    g.set(L_Y);
                    g.get(L_ENV); g.get(L_X); g.st64(env.slots.cc_a);
                    g.get(L_ENV); g.get(L_Y); g.st64(env.slots.cc_b);
                    g.get(L_ENV); g.i32c(o.c); g.st32(env.slots.cc_kind);
                    g.get(L_ENV); g.i32c(o.sz); g.st32(env.slots.cc_sz);
                    g.cmp_cond(o.c, o.sz, o.cc);
                    const uint32_t ct = bg.next_cell(), cf = bg.next_cell();
                    g.jump_cond(o.imm, o.imm2, insns, ct, cf);
                    break;
                }
                case OpKind::Push: case OpKind::PushI: {
                    g.slot_get(rsp_slot); g.i64c(o.sz); g.op(Gen::I64_SUB); g.set(L_A);
                    g.get(L_ENV); g.get(L_A); g.st64(rsp_slot);
                    if (o.kind == OpKind::Push) g.slot_get(o.a); else g.i64c(o.imm);
                    g.set(L_V);
                    g.emit_write(o.sz, pc);
                    g.chk_flush(o);
                    break;
                }
                case OpKind::Pop: {
                    g.slot_get(rsp_slot); g.set(L_A);
                    g.emit_read(o.sz, pc);
                    g.set(L_V);
                    g.get(L_ENV); g.get(L_A); g.i64c(o.sz); g.op(Gen::I64_ADD); g.st64(rsp_slot);
                    g.get(L_ENV); g.get(L_V); g.st64(o.d);   // after the increment: POP ESP keeps the loaded value
                    break;
                }
                case OpKind::Ret: {
                    g.slot_get(rsp_slot); g.set(L_A);
                    g.emit_read(o.sz, pc);
                    g.set(L_V);
                    g.get(L_ENV); g.get(L_A); g.i64c(o.sz + o.imm); g.op(Gen::I64_ADD); g.st64(rsp_slot);
                    g.get(L_ENV); g.get(L_V); g.st64(env.slots.rip);
                    g.ret(insns);
                    break;
                }
                case OpKind::Call: {
                    g.slot_get(rsp_slot); g.i64c(o.sz); g.op(Gen::I64_SUB); g.set(L_A);
                    g.get(L_ENV); g.get(L_A); g.st64(rsp_slot);
                    g.i64c(o.imm2); g.set(L_V);
                    g.emit_write(o.sz, pc);
                    g.get(L_ENV); g.i64c(o.imm); g.st64(env.slots.rip);
                    g.leave_static(bg.next_cell(), insns);
                    break;
                }
        default:
            return false;
    }
    return true;
}

}  // namespace jit
