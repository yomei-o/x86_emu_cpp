// The WebAssembly backend: hot blocks become WebAssembly functions built at run
// time.
//
// Only in the browser (and node) build, because it needs the JavaScript side to
// compile what it produces.  A block starts out in the threaded backend; once it
// has run a few dozen times its IR is turned into a function in a module that
// imports the emulator's own linear memory and function table, so the code it
// generates reads and writes the guest registers, probes the guest page cache
// and calls back into C++ exactly as the threaded handlers do - only without a
// handler call per op.
//
// What it translates itself: moves, integer arithmetic, address arithmetic, the
// guest memory accesses (the page cache probe is inline, a miss calls C++),
// stack operations, flag conditions and the block's exits.  Anything else - an
// instruction with eagerly computed flags, a multiply, a divide, the interpreter
// - is run by calling the op's threaded handler through `jit_generic`, so
// every op the frontend can produce already works here.
#include "engine.h"

#ifdef __EMSCRIPTEN__

#include <emscripten.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../cpu.h"

namespace jit {

namespace {

using x86emu::Cpu;
using x86emu::Memory;

// ---- helpers the generated code calls ---------------------------------------

uint64_t wr_read(Memory* m, uint64_t addr, uint32_t size) {
    switch (size) {
        case 1: return m->read8(addr);
        case 2: return m->read16(addr);
        case 4: return m->read32(addr);
        default: return m->read64(addr);
    }
}

void wr_write(Memory* m, uint64_t addr, uint32_t size, uint64_t v) {
    switch (size) {
        case 1: m->write8(addr, static_cast<uint8_t>(v)); break;
        case 2: m->write16(addr, static_cast<uint16_t>(v)); break;
        case 4: m->write32(addr, static_cast<uint32_t>(v)); break;
        default: m->write64(addr, v); break;
    }
}

// ---- a small WebAssembly assembler ------------------------------------------

struct Buf {
    std::vector<uint8_t> b;
    void u8(uint8_t v) { b.push_back(v); }
    void uleb(uint64_t v) {
        do {
            uint8_t x = v & 0x7F;
            v >>= 7;
            if (v) x |= 0x80;
            b.push_back(x);
        } while (v);
    }
    void sleb(int64_t v) {
        bool more = true;
        while (more) {
            uint8_t x = v & 0x7F;
            v >>= 7;
            if ((v == 0 && !(x & 0x40)) || (v == -1 && (x & 0x40))) more = false;
            else x |= 0x80;
            b.push_back(x);
        }
    }
    void bytes(const void* p, size_t n) {
        const uint8_t* s = static_cast<const uint8_t*>(p);
        b.insert(b.end(), s, s + n);
    }
    void name(const char* s) {
        size_t n = std::strlen(s);
        uleb(n);
        bytes(s, n);
    }
    void append(const Buf& o) { b.insert(b.end(), o.b.begin(), o.b.end()); }
};

// Local variable numbers in every generated function.
enum : int { L_ENV = 0, L_CTX = 1, L_E = 2, L_O = 3, L_T = 4, L_A = 5, L_PG = 6, L_V = 7, L_X = 8, L_Y = 9 };

// Function types: 0 = (i32, i32) -> i32 (a block, and jit_generic), 1 = the slow
// read, 2 = the slow write.
enum : int { T_BLOCK = 0, T_READ = 1, T_WRITE = 2, T_FLAGS = 3, T_GENERIC = 4, T_CHAIN = 5 };

// Everything the generator needs to know about the process it generates for.
struct Env {
    uint32_t tlb_read, tlb_write;     // addresses of the page caches
    uint32_t mem_ptr;                 // the Memory object
    uint32_t epoch_addr;              // &Engine::epoch
    uint32_t read_fn, write_fn, generic_fn;   // table indices of the helpers above
    uint32_t flags_fn;                        // the module's own flags function
    Engine::Slots slots;
};

struct Gen {
    Buf w;
    const Env& e;
    uint64_t start = 0;   // guest address of the block being generated
    explicit Gen(const Env& env) : e(env) {}

    void op(uint8_t o) { w.u8(o); }
    void get(int l) { w.u8(0x20); w.uleb(l); }
    void set(int l) { w.u8(0x21); w.uleb(l); }
    void tee(int l) { w.u8(0x22); w.uleb(l); }
    void i32c(int32_t v) { w.u8(0x41); w.sleb(v); }
    void i64c(int64_t v) { w.u8(0x42); w.sleb(v); }
    void ld64(uint32_t off) { w.u8(0x29); w.uleb(3); w.uleb(off); }
    void st64(uint32_t off) { w.u8(0x37); w.uleb(3); w.uleb(off); }
    void ld32(uint32_t off) { w.u8(0x28); w.uleb(2); w.uleb(off); }
    void st32(uint32_t off) { w.u8(0x36); w.uleb(2); w.uleb(off); }
    void call_indirect(int type) { w.u8(0x11); w.uleb(type); w.uleb(0); }

    // i64 / i32 arithmetic opcodes used below
    static constexpr uint8_t I64_EQZ = 0x50, I64_EQ = 0x51, I64_NE = 0x52, I64_LT_S = 0x53, I64_LT_U = 0x54,
                             I64_GT_S = 0x55, I64_GT_U = 0x56, I64_LE_S = 0x57, I64_LE_U = 0x58,
                             I64_GE_S = 0x59, I64_GE_U = 0x5A, I64_POPCNT = 0x7B, I64_ADD = 0x7C,
                             I64_SUB = 0x7D, I64_MUL = 0x7E, I64_AND = 0x83, I64_OR = 0x84, I64_XOR = 0x85,
                             I64_SHL = 0x86, I64_SHR_S = 0x87, I64_SHR_U = 0x88, I32_WRAP = 0xA7,
                             I64_EXT_U = 0xAD, I64_EXT8 = 0xC2, I64_EXT16 = 0xC3, I64_EXT32 = 0xC4;
    static constexpr uint8_t I32_EQZ = 0x45, I32_EQ = 0x46, I32_NE = 0x47, I32_LT_S = 0x48, I32_LE_U = 0x4D,
                             I32_ADD = 0x6A, I32_AND = 0x71, I32_OR = 0x72, I32_XOR = 0x73, I32_SHL = 0x74,
                             I32_SHR_U = 0x76;

    void slot_get(int off) { get(L_ENV); ld64(static_cast<uint32_t>(off)); }

    // Leaves slot `off` masked to `sz` bytes on the stack.
    void slot_masked(int off, int sz) {
        slot_get(off);
        mask(sz);
    }
    void mask(int sz) {
        if (sz >= 8) return;
        i64c(sz == 1 ? 0xFF : sz == 2 ? 0xFFFF : 0xFFFFFFFFll);
        op(I64_AND);
    }
    void imm_masked(int64_t v, int sz) {
        if (sz == 1) v &= 0xFF;
        else if (sz == 2) v &= 0xFFFF;
        else if (sz == 4) v &= 0xFFFFFFFFll;
        i64c(v);
    }

    // A block returns an i64: the count of native instructions it finished in the
    // low half, and in the high half the table index of the block to run next, if
    // it knows one (0: go back to C++, which will look rip up).
    void ret(int n) { i64c(n); op(0x0F); }

    // Leave through a static exit: `cell` is the address of a word that holds the
    // function index of the target block once there is one.  When there is not,
    // the address is left in the context so that C++ can fill it in after it
    // has run the target.  (Leaves nothing on the stack: it returns.)
    void leave_static(uint32_t cell, int insns) {
        i32c(static_cast<int32_t>(cell)); ld32(0); tee(L_O);
        op(I32_EQZ);
        w.u8(0x04); w.u8(0x40);
        get(L_CTX); i32c(static_cast<int32_t>(cell)); st32(offsetof(Ctx, pending_cell));
        w.u8(0x0B);
        get(L_O); op(I64_EXT_U); i64c(32); op(I64_SHL); i64c(insns); op(I64_OR);
        op(0x0F);
    }

    // rip = (cond on the stack, an i32) ? taken : fall; then leave by the matching cell.
    void jump_cond(int64_t taken, int64_t fall, int insns, uint32_t cell_taken, uint32_t cell_fall) {
        // stack: cond(i32).  select wants (val1, val2, cond): park the condition.
        set(L_T);
        get(L_ENV);
        i64c(taken);
        i64c(fall);
        get(L_T);
        op(0x1B);   // select
        st64(static_cast<uint32_t>(e.slots.rip));
        // the cell for the side taken
        i32c(static_cast<int32_t>(cell_taken));
        i32c(static_cast<int32_t>(cell_fall));
        get(L_T);
        op(0x1B);
        set(L_E);
        get(L_E); ld32(0); tee(L_O);
        op(I32_EQZ);
        w.u8(0x04); w.u8(0x40);
        get(L_CTX); get(L_E); st32(offsetof(Ctx, pending_cell));
        w.u8(0x0B);
        get(L_O); op(I64_EXT_U); i64c(32); op(I64_SHL); i64c(insns); op(I64_OR);
        op(0x0F);
    }

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

    // Probe the page cache for the address in L_A.  On a hit the host address of
    // the byte is left in L_E + L_O (E = entry, O = offset in the page) and the
    // code in `hit` runs; on a miss, `miss` does.  Both leave the same stack.
    template <typename Hit, typename Miss>
    void probe(uint32_t tlb, int size, int result_type, Hit hit, Miss miss) {
        get(L_A); i64c(12); op(I64_SHR_U); set(L_PG);
        get(L_PG); op(I32_WRAP); i32c(1023); op(I32_AND); i32c(4); op(I32_SHL);
        i32c(static_cast<int32_t>(tlb)); op(I32_ADD); set(L_E);
        get(L_E); ld64(0); get(L_PG); op(I64_EQ);
        get(L_A); op(I32_WRAP); i32c(4095); op(I32_AND); tee(L_O); i32c(size); op(I32_ADD); i32c(4096); op(I32_LE_U);
        op(I32_AND);
        w.u8(0x04); w.u8(static_cast<uint8_t>(result_type));   // if
        hit();
        w.u8(0x05);                                            // else
        miss();
        w.u8(0x0B);                                            // end
    }

    // Value of the guest memory read at L_A, zero extended, left on the stack.
    void emit_read(int size, int pc) {
        probe(e.tlb_read, size, 0x7E,
              [&] {
                  get(L_E); ld32(8); get(L_O); op(I32_ADD);
                  switch (size) {
                      case 1: w.u8(0x31); w.uleb(0); break;
                      case 2: w.u8(0x33); w.uleb(1); break;
                      case 4: w.u8(0x35); w.uleb(2); break;
                      default: w.u8(0x29); w.uleb(3); break;
                  }
                  w.uleb(0);
              },
              [&] {
                  get(L_CTX); i64c(static_cast<int64_t>(start + pc)); w.u8(0x37); w.uleb(3); w.uleb(offsetof(Ctx, fault_rip));
                  i32c(static_cast<int32_t>(e.mem_ptr)); get(L_A); i32c(size);
                  i32c(static_cast<int32_t>(e.read_fn)); call_indirect(T_READ);
              });
    }

    // Store L_V (low `size` bytes) at the guest address L_A.
    void emit_write(int size, int pc) {
        probe(e.tlb_write, size, 0x40,
              [&] {
                  get(L_E); ld32(8); get(L_O); op(I32_ADD); get(L_V);
                  switch (size) {
                      case 1: w.u8(0x3C); w.uleb(0); break;
                      case 2: w.u8(0x3D); w.uleb(1); break;
                      case 4: w.u8(0x3E); w.uleb(2); break;
                      default: w.u8(0x37); w.uleb(3); break;
                  }
                  w.uleb(0);
              },
              [&] {
                  get(L_CTX); i64c(static_cast<int64_t>(start + pc)); w.u8(0x37); w.uleb(3); w.uleb(offsetof(Ctx, fault_rip));
                  i32c(static_cast<int32_t>(e.mem_ptr)); get(L_A); i32c(size); get(L_V);
                  i32c(static_cast<int32_t>(e.write_fn)); call_indirect(T_WRITE);
              });
    }

    // Leave the block, at rip = next, if this store invalidated translated code.
    void chk_flush(const Op& o) {
        if (!(o.flags & kFlagChk)) return;
        i32c(static_cast<int32_t>(e.epoch_addr)); ld64(0);
        get(L_CTX); ld64(offsetof(Ctx, epoch0));
        op(I64_NE);
        w.u8(0x04); w.u8(0x40);
        get(L_ENV); i64c(o.imm2); st64(static_cast<uint32_t>(e.slots.rip));
        ret(o.ni);
        w.u8(0x0B);
    }

    // address = a + (c << cc) + imm, masked for 32-bit addressing, into L_A
    void address(const Op& o) {
        slot_get(o.a);
        slot_get(o.c); i64c(o.cc); op(I64_SHL); op(I64_ADD);
        if (o.imm) { i64c(o.imm); op(I64_ADD); }
        if (o.flags & kFlagA32) { i64c(0xFFFFFFFFll); op(I64_AND); }
        set(L_A);
    }

    // Run `idx`-th single-op program through its threaded handler.
    void generic(const Uop* single, int insns) {
        get(L_CTX); i32c(static_cast<int32_t>(reinterpret_cast<uintptr_t>(single)));
        i32c(static_cast<int32_t>(e.generic_fn)); call_indirect(T_GENERIC);
        op(I32_EQZ);
        w.u8(0x04); w.u8(0x40);
        // The op ended the block.  It says how far it got, if it knows.
        get(L_CTX); ld32(offsetof(Ctx, partial)); tee(L_T); i32c(0); op(I32_LT_S);
        w.u8(0x04); w.u8(0x7F);
        i32c(insns);
        w.u8(0x05);
        get(L_T);
        w.u8(0x0B);
        op(I64_EXT_U);
        op(0x0F);
        w.u8(0x0B);
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
        w.u8(0x10); w.uleb(e.flags_fn);   // call $flags
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
// $chain(env, ctx, fn, limit) -> instructions finished.  Runs block functions one
// after another - each returns the next one's table index in its high half - until
// one has no successor ready or `limit` instructions are done.
void build_chain_function(Buf& code) {
    Buf b;
    auto get = [&](int l) { b.u8(0x20); b.uleb(l); };
    auto set = [&](int l) { b.u8(0x21); b.uleb(l); };
    // params: 0 env, 1 ctx, 2 fn, 3 limit; locals: 4 total (i32), 5 r (i64)
    b.uleb(2);
    b.uleb(1); b.u8(0x7F);
    b.uleb(1); b.u8(0x7E);
    b.u8(0x02); b.u8(0x40);                 // block
    b.u8(0x03); b.u8(0x40);                 // loop
      get(0); get(1); get(2); b.u8(0x11); b.uleb(T_BLOCK); b.uleb(0);   // r = fn(env, ctx)
      set(5);
      get(4); get(5); b.u8(0xA7); b.u8(0x6A); set(4);                    // total += (i32) r
      get(5); b.u8(0x42); b.sleb(32); b.u8(0x88); b.u8(0xA7); set(2);    // fn = (i32)(r >> 32)
      get(2); b.u8(0x45); b.u8(0x0D); b.uleb(1);                         // fn == 0: leave
      get(4); get(3); b.u8(0x4F); b.u8(0x0D); b.uleb(1);                 // total >= limit (signed): leave
      b.u8(0x0C); b.uleb(0);                                             // again
    b.u8(0x0B);                              // end loop
    b.u8(0x0B);                              // end block
    get(4);
    b.u8(0x0B);                              // end func
    code.append(b);
}

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

// ---- the JavaScript half ------------------------------------------------------

// Instantiates a module of `n` functions f0..f(n-1) and puts them in the function
// table; returns the index of f0, or -1.
EM_JS(int, jitwasm_install, (const uint8_t* p, int len, int n), {
    try {
        var mod = new WebAssembly.Module(HEAPU8.slice(p, p + len));
        var inst = new WebAssembly.Instance(mod, {env: {memory: wasmMemory, table: wasmTable}});
        var base = wasmTable.length;
        wasmTable.grow(n + 1);
        for (var i = 0; i < n; i++) wasmTable.set(base + i, inst.exports['f' + i]);
        wasmTable.set(base + n, inst.exports['chain']);
        return base;
    } catch (e) {
        console.error('jit wasm: ' + e);
        return -1;
    }
});

void Engine::wasm_queue(Block* b) {
    if (std::getenv("X86EMU_JIT_DEBUG")) std::fprintf(stderr, "[jit] queue %llx\n", (unsigned long long)b->start);
    b->wasm_queued = true;
    wasm_pending_.push_back(b);
    if (wasm_pending_.size() >= wasm_batch) wasm_compile_pending();
}

void Engine::wasm_compile_pending() {
    if (wasm_pending_.empty()) return;
    std::vector<Block*> blocks;
    blocks.swap(wasm_pending_);

    Env env;
    env.tlb_read = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(mem.tlb_read_base()));
    env.tlb_write = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(mem.tlb_write_base()));
    env.mem_ptr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&mem));
    env.epoch_addr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&epoch));
    env.read_fn = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&wr_read));
    env.write_fn = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&wr_write));
    env.generic_fn = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&jit_generic));
    env.flags_fn = 0;   // set below, once we know how many block functions there are
    env.slots = slots;

    std::vector<Buf> bodies;
    std::vector<Block*> used;
    {
        size_t n = 0;
        for (Block* b : blocks) if (b->valid && !b->stub && !b->ir_ops.empty()) ++n;
        env.flags_fn = static_cast<uint32_t>(n);   // the helper is the function after the blocks
    }
    for (Block* b : blocks) {
        if (!b->valid || b->stub || b->ir_ops.empty()) continue;
        const std::vector<Op>& ops = b->ir_ops;
        // The one-op programs for the ops done by calling their handlers.
        b->single.clear();
        Gen g(env);
        g.start = b->start;
        // One word per static exit: where the next block's function goes once it has one.
        size_t ncells = 0;
        for (const Op& q : ops)
            ncells += (q.kind == OpKind::Exit || q.kind == OpKind::Call) ? 1
                      : (q.kind == OpKind::JccFl || q.kind == OpKind::JccCmp || q.kind == OpKind::JccCmpI) ? 2 : 0;
        b->cells.reset(new uint32_t[ncells ? ncells : 1]());
        size_t cell_next = 0;
        auto cell_addr = [&](size_t k) {
            return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&b->cells[k]));
        };
        const int insns = static_cast<int>(b->insns);
        const int rsp_slot = 4 * 8;

        for (size_t i = 0; i < ops.size(); ++i) {
            const Op& o = ops[i];
            const int pc = static_cast<int>(o.pc);
            const bool eager = (o.flags & kFlagEager) != 0;
            auto fallback = [&] {
                ++wasm_fallbacks[static_cast<size_t>(o.kind)];
                std::unique_ptr<Uop[]> two(new Uop[2]);
                two[0] = b->code[i];
                make_stop_op(two[1]);
                g.generic(two.get(), insns);
                b->single.push_back(std::move(two));
            };
            switch (o.kind) {
                case OpKind::Nop: break;
                case OpKind::Mov:
                    g.get(L_ENV); g.slot_get(o.a); g.st64(o.d); break;
                case OpKind::MovI:
                    g.get(L_ENV); g.i64c(o.imm); g.st64(o.d); break;
                case OpKind::Add: case OpKind::Sub: case OpKind::And: case OpKind::Or: case OpKind::Xor: {
                    g.get(L_ENV); g.slot_get(o.a); g.slot_get(o.b);
                    g.op(o.kind == OpKind::Add ? Gen::I64_ADD : o.kind == OpKind::Sub ? Gen::I64_SUB
                         : o.kind == OpKind::And ? Gen::I64_AND : o.kind == OpKind::Or ? Gen::I64_OR : Gen::I64_XOR);
                    g.st64(o.d);
                    break;
                }
                case OpKind::AddI: case OpKind::SubI: case OpKind::AndI: case OpKind::OrI: case OpKind::XorI: {
                    g.get(L_ENV); g.slot_get(o.a); g.i64c(o.imm);
                    g.op(o.kind == OpKind::AddI ? Gen::I64_ADD : o.kind == OpKind::SubI ? Gen::I64_SUB
                         : o.kind == OpKind::AndI ? Gen::I64_AND : o.kind == OpKind::OrI ? Gen::I64_OR : Gen::I64_XOR);
                    g.st64(o.d);
                    break;
                }
                case OpKind::Lea:
                    g.get(L_ENV);
                    g.slot_get(o.a); g.slot_get(o.c); g.i64c(o.cc); g.op(Gen::I64_SHL); g.op(Gen::I64_ADD);
                    if (o.imm) { g.i64c(o.imm); g.op(Gen::I64_ADD); }
                    if (o.sz == 4) { g.i64c(0xFFFFFFFFll); g.op(Gen::I64_AND); }
                    g.st64(o.d);
                    break;
                case OpKind::Ext: {
                    g.get(L_ENV); g.slot_get(o.a);
                    if (o.flags & kFlagSigned) {
                        g.op(o.sz == 1 ? Gen::I64_EXT8 : o.sz == 2 ? Gen::I64_EXT16 : Gen::I64_EXT32);
                        if (o.cc == 4) { g.i64c(0xFFFFFFFFll); g.op(Gen::I64_AND); }
                    } else {
                        g.mask(o.sz);
                    }
                    g.st64(o.d);
                    break;
                }
                case OpKind::Put:
                    g.get(L_ENV);
                    if (o.sz == 1) {
                        g.slot_get(o.a); g.i64c(~0xFFll); g.op(Gen::I64_AND);
                        g.slot_get(o.b); g.i64c(0xFF); g.op(Gen::I64_AND); g.op(Gen::I64_OR);
                    } else if (o.sz == 2) {
                        g.slot_get(o.a); g.i64c(~0xFFFFll); g.op(Gen::I64_AND);
                        g.slot_get(o.b); g.i64c(0xFFFF); g.op(Gen::I64_AND); g.op(Gen::I64_OR);
                    } else {
                        g.slot_get(o.a); g.i64c(~0xFF00ll); g.op(Gen::I64_AND);
                        g.slot_get(o.b); g.i64c(0xFF); g.op(Gen::I64_AND); g.i64c(8); g.op(Gen::I64_SHL); g.op(Gen::I64_OR);
                    }
                    g.st64(o.d);
                    break;
                case OpKind::GetH:
                    g.get(L_ENV); g.slot_get(o.a); g.i64c(8); g.op(Gen::I64_SHR_U); g.i64c(0xFF); g.op(Gen::I64_AND);
                    g.st64(o.d); break;
                case OpKind::Sel:
                    g.get(L_ENV); g.slot_get(o.a); g.slot_get(o.b); g.slot_get(o.c); g.i64c(0); g.op(Gen::I64_NE);
                    g.op(0x1B); g.st64(o.d); break;
                case OpKind::Ld: {
                    g.address(o);
                    g.emit_read(o.sz, pc);
                    g.set(L_V);
                    g.get(L_ENV); g.get(L_V); g.st64(o.d);
                    break;
                }
                case OpKind::LdS: {
                    g.address(o);
                    g.emit_read(o.sz, pc);
                    g.op(o.sz == 1 ? Gen::I64_EXT8 : o.sz == 2 ? Gen::I64_EXT16 : Gen::I64_EXT32);
                    if (o.imm2 == 4) { g.i64c(0xFFFFFFFFll); g.op(Gen::I64_AND); }
                    g.set(L_V);
                    g.get(L_ENV); g.get(L_V); g.st64(o.d);
                    break;
                }
                case OpKind::St: {
                    g.address(o);
                    g.slot_get(o.b); g.set(L_V);
                    g.emit_write(o.sz, pc);
                    g.chk_flush(o);
                    break;
                }
                case OpKind::SetFl:
                    g.get(L_ENV); g.cond_fl(o.cc); g.op(Gen::I64_EXT_U); g.st64(o.d); break;
                case OpKind::Exit:
                    g.get(L_ENV); g.i64c(o.imm); g.st64(env.slots.rip);
                    g.leave_static(cell_addr(cell_next++), insns);
                    break;
                case OpKind::ExitInd:
                    g.get(L_ENV); g.slot_get(o.a); g.st64(env.slots.rip); g.ret(insns); break;
                case OpKind::JccFl: {
                    g.cond_fl(o.cc);
                    const uint32_t ct = cell_addr(cell_next++), cf = cell_addr(cell_next++);
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
                case OpKind::ShlI: case OpKind::ShrI: case OpKind::SarI:
                    g.get(L_ENV); g.slot_get(o.a); g.i64c(o.imm & 63);
                    g.op(o.kind == OpKind::ShlI ? Gen::I64_SHL : o.kind == OpKind::ShrI ? Gen::I64_SHR_U : Gen::I64_SHR_S);
                    g.st64(o.d); break;
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
                    if (!Gen::jcc_inline(o)) { fallback(); break; }
                    g.slot_masked(o.a, o.sz); g.set(L_X);
                    if (o.kind == OpKind::JccCmpI) g.imm_masked(static_cast<int64_t>(o.d), o.sz);
                    else g.slot_masked(o.b, o.sz);
                    g.set(L_Y);
                    g.get(L_ENV); g.get(L_X); g.st64(env.slots.cc_a);
                    g.get(L_ENV); g.get(L_Y); g.st64(env.slots.cc_b);
                    g.get(L_ENV); g.i32c(o.c); g.st32(env.slots.cc_kind);
                    g.get(L_ENV); g.i32c(o.sz); g.st32(env.slots.cc_sz);
                    g.cmp_cond(o.c, o.sz, o.cc);
                    const uint32_t ct = cell_addr(cell_next++), cf = cell_addr(cell_next++);
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
                    g.leave_static(cell_addr(cell_next++), insns);
                    break;
                }
                default:
                    fallback();
                    break;
            }
        }
        // Every block ends in an exit that returns; this is for the validator.
        g.i64c(insns);
        g.op(0x0B);

        Buf body;
        // locals: 3 x i32, 5 x i64
        Buf code;
        code.uleb(2);
        code.uleb(3); code.u8(0x7F);
        code.uleb(5); code.u8(0x7E);
        code.append(g.w);
        body.uleb(code.b.size());
        body.append(code);
        bodies.push_back(std::move(body));
        used.push_back(b);
    }
    if (bodies.empty()) return;

    Buf m;
    const uint8_t header[] = {0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00};
    m.bytes(header, sizeof header);
    auto section = [&](uint8_t id, const Buf& content) {
        m.u8(id);
        m.uleb(content.b.size());
        m.append(content);
    };
    {   // types
        Buf s;
        s.uleb(6);
        const uint8_t t0[] = {0x60, 2, 0x7F, 0x7F, 1, 0x7E};                 // a block: (env, ctx) -> i64
        const uint8_t t1[] = {0x60, 3, 0x7F, 0x7E, 0x7F, 1, 0x7E};           // slow read
        const uint8_t t2[] = {0x60, 4, 0x7F, 0x7E, 0x7F, 0x7E, 0};           // slow write
        const uint8_t t3[] = {0x60, 5, 0x7E, 0x7E, 0x7E, 0x7F, 0x7E, 1, 0x7E};   // flags
        const uint8_t t4[] = {0x60, 2, 0x7F, 0x7F, 1, 0x7F};                 // jit_generic
        const uint8_t t5[] = {0x60, 4, 0x7F, 0x7F, 0x7F, 0x7F, 1, 0x7F};     // chain
        s.bytes(t0, sizeof t0); s.bytes(t1, sizeof t1); s.bytes(t2, sizeof t2); s.bytes(t3, sizeof t3);
        s.bytes(t4, sizeof t4); s.bytes(t5, sizeof t5);
        section(1, s);
    }
    {   // imports: the emulator's memory and function table
        Buf s;
        s.uleb(2);
        s.name("env"); s.name("memory"); s.u8(0x02); s.u8(0x00); s.uleb(1);
        s.name("env"); s.name("table"); s.u8(0x01); s.u8(0x70); s.u8(0x00); s.uleb(0);
        section(2, s);
    }
    {   // functions
        Buf s;
        s.uleb(bodies.size() + 2);
        for (size_t i = 0; i < bodies.size(); ++i) s.uleb(T_BLOCK);
        s.uleb(T_FLAGS);
        s.uleb(T_CHAIN);
        section(3, s);
    }
    {   // exports f0, f1, ...
        Buf s;
        s.uleb(bodies.size() + 1);
        for (size_t i = 0; i < bodies.size(); ++i) {
            std::string n = "f" + std::to_string(i);
            s.name(n.c_str());
            s.u8(0x00);
            s.uleb(i);
        }
        s.name("chain");
        s.u8(0x00);
        s.uleb(bodies.size() + 1);
        section(7, s);
    }
    {   // code
        Buf s;
        s.uleb(bodies.size() + 2);
        for (const Buf& b : bodies) s.append(b);
        Buf fb;
        build_flags_function(fb);
        s.uleb(fb.b.size());
        s.append(fb);
        Buf cb;
        build_chain_function(cb);
        s.uleb(cb.b.size());
        s.append(cb);
        section(10, s);
    }

    int base = jitwasm_install(m.b.data(), static_cast<int>(m.b.size()), static_cast<int>(bodies.size()));
    ++n_wasm_modules;
    if (base < 0) {
        wasm_on = false;   // something in the generator is wrong; stay with the threaded tier
        return;
    }
    wasm_chain_fn = static_cast<uint32_t>(base) + static_cast<uint32_t>(used.size());
    for (size_t i = 0; i < used.size(); ++i) used[i]->wasm_fn = static_cast<uint32_t>(base) + static_cast<uint32_t>(i);
    n_wasm_blocks += used.size();
    if (stats_every_ && n_wasm_modules % 20 == 0) print_stats();
}

}  // namespace jit

#else   // not the browser build: there is no wasm tier

namespace jit {
void Engine::wasm_queue(Block*) {}
void Engine::wasm_compile_pending() {}
}  // namespace jit

#endif
