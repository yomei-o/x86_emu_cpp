// A small register-memory IR for dynamic translation.
//
// Nothing in this header knows about x86.  A frontend (one per guest ISA)
// turns a straight-line run of guest instructions into a vector of `Op`; a
// backend (the threaded interpreter in backend_threaded.cpp today, a WebAssembly
// or native code emitter later) turns that into something runnable.
//
// Values live in *slots*: byte offsets from the base of the guest state
// (`env`).  Guest registers are slots, and so are the temporaries - a block runs
// with its temporaries in the same memory as the registers, so every operand is
// just an offset and there is no register allocation to do.  A backend that
// wants machine registers (a native emitter) caches slots in them; the IR does
// not care.  A useful consequence: because nothing is cached outside `env`, a
// block can be left at any op boundary and the interpreter picks up from the
// state in memory.
//
// All slot values are 64 bits.  Operations narrower than that say so in `sz`
// and leave the result zero extended, which is what makes a 32-bit register
// write come out right for free.
#pragma once

#include <cstdint>
#include <vector>

namespace jit {

enum class OpKind : uint8_t {
    Nop,
    Mov,    // d = a
    MovI,   // d = imm
    Add, AddI, Sub, SubI, And, AndI, Or, OrI, Xor, XorI,
    // d = (a + (c << cc) + imm), truncated to `sz` bytes (4 or 8)
    Lea,
    // d = extend(a) from `sz` bytes to `cc` bytes (4 or 8); flags&kFlagSigned
    Ext,
    // sub-register write: sz=1 -> low byte of a replaced by b; sz=2 -> low
    // word; sz=0x81 -> bits 8..15 (AH, CH, DH, BH)
    Put,
    // d = (a >> 8) & 0xFF
    GetH,
    // d = load(a + (c << cc) + imm), `sz` bytes.  LdS sign extends to `c`...
    // see the backend: LdS keeps the destination width in `b`.
    Ld, LdS,
    // store(a + (c << cc) + imm) = b, `sz` bytes
    St,
    // d = slot[c] ? a : b
    Sel,
    // d = x86 condition `cc` evaluated on rflags
    SetFl,
    // Exits.  The block ends; rip is set.
    Exit,      // rip = imm
    ExitInd,   // rip = slot a
    JccFl,     // rip = cond(cc, rflags) ? imm : imm2
    // x86 ALU: d = a OP b (cc = x86 op number 0..7, 8 = TEST), sz bytes,
    // kFlagEager computes the guest flags.  AluI takes the immediate in imm.
    Alu, AluI,
    // INC/DEC (cc = 0 / 1): CF is preserved
    IncDec,
    // d = a << imm, a >> imm (logical / arithmetic), 64-bit
    ShlI, ShrI, SarI,
    // x86 shifts SHL SHR SAR (cc = 4, 5, 7) of the low `sz` bytes of a by the
    // count in slot b (Shift) or in imm (ShiftI).  The count is masked as the
    // hardware does; a count of zero changes no flag.  kFlagEager sets CF OF
    // SF ZF PF and leaves AF alone.
    Shift, ShiftI,
    // Rotates (cc = 0 ROL, 1 ROR, 2 RCL, 3 RCR): the interpreter's own code
    ShiftSlow,
    // d = a * b (signed, low sz bytes).  kFlagEager: CF = OF = overflow, SF ZF PF
    // from the result, AF untouched.  ImulI takes the multiplier in imm.
    Imul, ImulI,
    // MUL / IMUL / DIV / IDIV on rAX (cc = 4..7), through the interpreter's code.
    // The operand is register d, or the memory at slot a with kFlagMem set.
    Group3,
    // Deferred flags.  CcSet records "the arithmetic flags are those of a OP b"
    // (cc = kind: 1 ADD 2 SUB 3 AND 4 OR 5 XOR) in the CPU instead of computing
    // them; CcSetI takes b from imm.  CcMat computes them if recorded.  CcClear
    // says rflags is current again.
    CcSet, CcSetI, CcMat, CcClear,
    // Compare-and-branch in one: records the flags as CcSet does, then
    // rip = cond(a OP b) ? imm : imm2.  cc = x86 condition, c = kind.
    // JccCmpI takes b as the 32-bit immediate in d.
    JccCmp, JccCmpI,
    // Stack operations on the pointer-width stack (sz = 4 or 8; rsp is slot 32).
    //   Push: rsp -= sz, store slot a.  PushI: the same with the value in imm.
    //   Pop: load into slot d, rsp += sz.  Ret: pop into rip, then rsp += imm.
    //   Call: push imm2 (the return address), rip = imm.
    // A store carrying kFlagChk leaves the block, with rip = imm2, if translated
    // code was invalidated by it (PushI / Push keep the next pc in imm2 then;
    // Call does not use the check - it ends the block anyway).
    Push, PushI, Pop, Ret, Call,
    // Run the guest instruction at (block start + pc) with the interpreter.
    // imm2 = the address the block expects to be at afterwards; anything else
    // ends the block.
    Interp,
    // After an instruction that stored to memory: leave if translated code was
    // just invalidated.  rip = imm.
    ChkFlush,
};

struct Op {
    OpKind kind = OpKind::Nop;
    uint8_t sz = 8;
    uint8_t cc = 0;
    uint8_t flags = 0;
    uint32_t pc = 0;        // offset of the guest instruction from the block start
    uint16_t ni = 0;        // natively translated instructions finished once this op is done (an
                            // Interp op does not count itself: the interpreter does)
    int32_t d = 0, a = 0, b = 0, c = 0;
    int64_t imm = 0, imm2 = 0;
};

enum : uint8_t {
    kFlagEager = 1,   // compute the guest flags too
    kFlagA32 = 2,     // addresses wrap at 32 bits
    kFlagSigned = 4,  // Ext: sign extend
    kFlagMem = 8,     // Group3: the operand is in memory
    kFlagRex = 16,    // Group3: a REX prefix was present (byte register numbering)
    kFlagChk = 32,    // a store: check for invalidated code afterwards; next pc in imm2
};

struct IrBlock {
    uint64_t start = 0;
    uint32_t guest_bytes = 0;
    uint32_t insns = 0;      // guest instructions run natively (not Interp)
    bool effects = false;    // an interpreted instruction has effects beyond CPU state and memory
    std::vector<Op> ops;
};

}  // namespace jit
