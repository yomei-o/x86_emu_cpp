// The portable backend: IR ops become `Uop`s, each carrying a pointer to a
// handler that does exactly that op and hands over to the next.  This file has the
// handlers every guest uses - moves, integer arithmetic, address arithmetic,
// sign and zero extension, loads and stores, exits and the interpreter - and the
// loop that turns IR into Uops; the ops that belong to one ISA live with its glue
// (ops_x86.cpp for x86) and are reached through guest_select().
//
// This is not machine code, and it is deliberately the first backend: it runs
// on every host this emulator builds for, WebAssembly included, where nothing
// can be generated at run time without leaving the sandbox.  What it removes
// from the interpreter is the per-execution work - prefix scanning, opcode
// dispatch, ModRM decoding, the width switches - all of which are decided once,
// when the handler is chosen.
#include <cstdio>
#include <cstdlib>

#include "threaded.h"

namespace jit {

namespace {

// ---- moves and plain arithmetic -------------------------------------------

const Uop* h_nop(Ctx* c, const Uop* u) { NEXT(); }

// The op that follows a single op the wasm tier runs through its threaded
// handler: it says "that one did not end the block".
const Uop* h_stop(Ctx* c, const Uop*) {
    c->cont = true;
    return nullptr;
}
const Uop* h_mov(Ctx* c, const Uop* u) { S(u->d) = S(u->a); NEXT(); }
const Uop* h_movi(Ctx* c, const Uop* u) { S(u->d) = static_cast<uint64_t>(u->imm); NEXT(); }
const Uop* h_add(Ctx* c, const Uop* u) { S(u->d) = S(u->a) + S(u->b); NEXT(); }
const Uop* h_addi(Ctx* c, const Uop* u) { S(u->d) = S(u->a) + static_cast<uint64_t>(u->imm); NEXT(); }
const Uop* h_sub(Ctx* c, const Uop* u) { S(u->d) = S(u->a) - S(u->b); NEXT(); }
const Uop* h_subi(Ctx* c, const Uop* u) { S(u->d) = S(u->a) - static_cast<uint64_t>(u->imm); NEXT(); }
const Uop* h_and(Ctx* c, const Uop* u) { S(u->d) = S(u->a) & S(u->b); NEXT(); }
const Uop* h_andi(Ctx* c, const Uop* u) { S(u->d) = S(u->a) & static_cast<uint64_t>(u->imm); NEXT(); }
const Uop* h_or(Ctx* c, const Uop* u) { S(u->d) = S(u->a) | S(u->b); NEXT(); }
const Uop* h_ori(Ctx* c, const Uop* u) { S(u->d) = S(u->a) | static_cast<uint64_t>(u->imm); NEXT(); }
const Uop* h_xor(Ctx* c, const Uop* u) { S(u->d) = S(u->a) ^ S(u->b); NEXT(); }
const Uop* h_xori(Ctx* c, const Uop* u) { S(u->d) = S(u->a) ^ static_cast<uint64_t>(u->imm); NEXT(); }

template <int SZ>
const Uop* h_lea(Ctx* c, const Uop* u) {
    uint64_t v = S(u->a) + (S(u->c) << u->cc) + static_cast<uint64_t>(u->imm);
    S(u->d) = v & mask_of<SZ>();
    NEXT();
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
    NEXT();
}

const Uop* h_put1(Ctx* c, const Uop* u) { S(u->d) = (S(u->a) & ~0xFFull) | (S(u->b) & 0xFF); NEXT(); }
const Uop* h_put2(Ctx* c, const Uop* u) { S(u->d) = (S(u->a) & ~0xFFFFull) | (S(u->b) & 0xFFFF); NEXT(); }
const Uop* h_puth(Ctx* c, const Uop* u) { S(u->d) = (S(u->a) & ~0xFF00ull) | ((S(u->b) & 0xFF) << 8); NEXT(); }
const Uop* h_geth(Ctx* c, const Uop* u) { S(u->d) = (S(u->a) >> 8) & 0xFF; NEXT(); }
const Uop* h_sel(Ctx* c, const Uop* u) { S(u->d) = S(u->c) ? S(u->a) : S(u->b); NEXT(); }

// ---- memory ---------------------------------------------------------------

template <bool A32>
inline uint64_t ea(Ctx* c, const Uop* u) {
    uint64_t a = S(u->a) + (S(u->c) << u->cc) + static_cast<uint64_t>(u->imm);
    return A32 ? (a & 0xFFFFFFFFull) : a;
}

template <int SZ, bool A32>
const Uop* h_ld(Ctx* c, const Uop* u) {
    c->cur = u;
    uint64_t a = ea<A32>(c, u);
    uint64_t v;
    if (SZ == 1) v = c->mem->read8(a);
    else if (SZ == 2) v = c->mem->read16(a);
    else if (SZ == 4) v = c->mem->read32(a);
    else v = c->mem->read64(a);
    S(u->d) = v;
    NEXT();
}

// Sign extending load; b = destination width (4 or 8).
template <int SZ, bool A32, int DST>
const Uop* h_lds(Ctx* c, const Uop* u) {
    c->cur = u;
    uint64_t a = ea<A32>(c, u);
    int64_t v;
    if (SZ == 1) v = static_cast<int8_t>(c->mem->read8(a));
    else if (SZ == 2) v = static_cast<int16_t>(c->mem->read16(a));
    else v = static_cast<int32_t>(c->mem->read32(a));
    S(u->d) = static_cast<uint64_t>(v) & mask_of<DST>();
    NEXT();
}

template <int SZ, bool A32>
const Uop* h_st(Ctx* c, const Uop* u) {
    c->cur = u;
    uint64_t a = ea<A32>(c, u);
    uint64_t v = S(u->b);
    if (SZ == 1) c->mem->write8(a, static_cast<uint8_t>(v));
    else if (SZ == 2) c->mem->write16(a, static_cast<uint16_t>(v));
    else if (SZ == 4) c->mem->write32(a, static_cast<uint32_t>(v));
    else c->mem->write64(a, v);
    CHK_FLUSH();
    NEXT();
}

// ---- exits ----------------------------------------------------------------

const Uop* h_exit(Ctx* c, const Uop* u) { Glue::set_pc(*c->cpu, static_cast<uint64_t>(u->imm)); return nullptr; }
const Uop* h_exit_ind(Ctx* c, const Uop* u) { Glue::set_pc(*c->cpu, S(u->a)); return nullptr; }

const Uop* h_chkflush(Ctx* c, const Uop* u) {
    if (c->eng->epoch != c->epoch0) {
        c->partial = u->ni;
        Glue::set_pc(*c->cpu, static_cast<uint64_t>(u->imm));
        return nullptr;
    }
    NEXT();
}

// The interpreter, for one instruction.  If it leaves the program counter anywhere
// but the expected next instruction - a jump, a blocked system call, a thread
// switch - the block is over and the counter is whatever the instruction made it.
const Uop* h_interp(Ctx* c, const Uop* u) {
    GCpu* cpu = c->cpu;
    Glue::set_pc(*cpu, static_cast<uint64_t>(u->imm));
    ++c->eng->n_interp;
    ++c->eng->interp_ops[u->c & 0x1FF];
    c->in_interp = true;
    Glue::step(*cpu);
    c->in_interp = false;
    if (Glue::pc(*cpu) != static_cast<uint64_t>(u->imm2) || Glue::halted(*cpu) || c->eng->epoch != c->epoch0) {
        c->partial = u->ni;
        return nullptr;
    }
    NEXT();
}

// ---- selection -------------------------------------------------------------

template <int SZ>
Fn pick_ld_a(bool a32) { return a32 ? &h_ld<SZ, true> : &h_ld<SZ, false>; }
template <int SZ>
Fn pick_st_a(bool a32) { return a32 ? &h_st<SZ, true> : &h_st<SZ, false>; }

template <int SZ, int DST>
Fn pick_lds_a(bool a32) { return a32 ? &h_lds<SZ, true, DST> : &h_lds<SZ, false, DST>; }

template <int SRC, bool SIGNED>
Fn pick_ext_dst(int dst) { return dst == 8 ? &h_ext<SRC, SIGNED, 8> : &h_ext<SRC, SIGNED, 4>; }

Fn pick_ext(int src, bool sgn, int dst) {
    switch (src) {
        case 1: return sgn ? pick_ext_dst<1, true>(dst) : pick_ext_dst<1, false>(dst);
        case 2: return sgn ? pick_ext_dst<2, true>(dst) : pick_ext_dst<2, false>(dst);
        default: return sgn ? pick_ext_dst<4, true>(dst) : pick_ext_dst<4, false>(dst);
    }
}

Fn select_generic(const Op& o) {
    const bool a32 = (o.flags & kFlagA32) != 0;
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
        case OpKind::Exit: return h_exit;
        case OpKind::ExitInd: return h_exit_ind;
        case OpKind::Interp: return h_interp;
        case OpKind::ChkFlush: return h_chkflush;
        default: return nullptr;
    }
}

}  // namespace

// Runs one op through its handler (the wasm tier's way of doing what it does not
// translate itself).  `u` is followed by a stop op.  Returns 1 if the block goes
// on, 0 if that op ended it.
int32_t jit_generic(Ctx* c, const Uop* u) {
    ++c->eng->generic_calls[u->kind & 63];
    c->cont = false;
    c->cur = u;
    u->fn(c, u);
    return c->cont ? 1 : 0;
}

void make_stop_op(Uop& u) {
    u = Uop{};
    u.fn = h_stop;
}

void compile_threaded(Engine&, const IrBlock& ir, Block& out) {
    out.code.clear();
    out.code.reserve(ir.ops.size());
    for (const Op& o : ir.ops) {
        Uop u;
        u.fn = select_generic(o);
        if (!u.fn) u.fn = guest_select(o);
        if (!u.fn) {
            std::fprintf(stderr, "jit: no handler for op %d\n", static_cast<int>(o.kind));
            std::abort();
        }
        u.d = o.d; u.a = o.a; u.b = o.b; u.c = o.c;
        u.imm = o.imm; u.imm2 = o.imm2;
        u.pc = o.pc; u.ni = o.ni; u.sz = o.sz; u.cc = o.cc; u.flags = o.flags;
        u.kind = static_cast<uint8_t>(o.kind);
        out.code.push_back(u);
    }
}

}  // namespace jit
