// x86 / x86-64 frontend: guest bytes -> IR.
//
// Two passes over a straight-line run of instructions.  The first decodes them
// and works out which flag writes anyone can see; the second emits ops.
//
// What it does not know how to translate it does not refuse: it emits an
// `Interp` op, which runs that one instruction through the ordinary
// interpreter.  So the set of natively translated instructions can be grown
// one opcode at a time with the rest of the program unaffected, and a block
// need not end at an instruction the frontend has never heard of.  The only
// things it must get right for those are the instruction's *length* (to find
// the next one) and whether it touches the flags - and a wrong length is caught
// at run time, because the interpreter leaves rip where the instruction really
// ended and the block stops if that is not where the frontend thought.
#include <cstdio>
#include <cstring>

#include "../cpu.h"
#include "engine.h"

namespace jit {

namespace {

using x86emu::Cpu;

enum ImmKind : uint8_t {
    IM_NONE = 0, IM_8, IM_16, IM_Z, IM_ZQ /*B8+: 8 bytes with REX.W*/, IM_MOFFS, IM_REL32, IM_G3_8, IM_G3_Z,
};

struct Info {
    bool ok = false;
    bool modrm = false;
    ImmKind imm = IM_NONE;
};

Info mk(bool modrm, ImmKind imm) { Info i; i.ok = true; i.modrm = modrm; i.imm = imm; return i; }

Info info1(uint8_t op, bool is64) {
    if (op < 0x40) {
        int lo = op & 7;
        if (op == 0x0F) return {};
        if (lo < 4) return mk(true, IM_NONE);
        if (lo == 4) return mk(false, IM_8);
        if (lo == 5) return mk(false, IM_Z);
        return {};
    }
    if (op < 0x50) return is64 ? Info{} : mk(false, IM_NONE);
    if (op < 0x60) return mk(false, IM_NONE);
    switch (op) {
        case 0x60: case 0x61: return is64 ? Info{} : mk(false, IM_NONE);
        case 0x63: return mk(true, IM_NONE);
        case 0x68: return mk(false, IM_Z);
        case 0x69: return mk(true, IM_Z);
        case 0x6A: return mk(false, IM_8);
        case 0x6B: return mk(true, IM_8);
        case 0x80: case 0x83: return mk(true, IM_8);
        case 0x81: return mk(true, IM_Z);
        case 0xC0: case 0xC1: case 0xC6: return mk(true, IM_8);
        case 0xC7: return mk(true, IM_Z);
        case 0xC2: return mk(false, IM_16);
        case 0xE8: case 0xE9: return mk(false, IM_REL32);
        case 0xEB: case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xCD: return mk(false, IM_8);
        case 0xF6: return mk(true, IM_G3_8);
        case 0xF7: return mk(true, IM_G3_Z);
        case 0xA8: return mk(false, IM_8);
        case 0xA9: return mk(false, IM_Z);
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: return mk(false, IM_MOFFS);
        default: break;
    }
    if (op >= 0x70 && op <= 0x7F) return mk(false, IM_8);
    if (op >= 0xB0 && op <= 0xB7) return mk(false, IM_8);
    if (op >= 0xB8 && op <= 0xBF) return mk(false, IM_ZQ);
    if (op >= 0x84 && op <= 0x8F) return mk(true, IM_NONE);
    if ((op >= 0x90 && op <= 0x99) || (op >= 0x9B && op <= 0x9F)) return mk(false, IM_NONE);
    if (op >= 0xA4 && op <= 0xAF) return mk(false, IM_NONE);
    if (op == 0xC3 || op == 0xC9 || op == 0xF4 || op == 0xF5 || (op >= 0xF8 && op <= 0xFD))
        return mk(false, IM_NONE);
    if (op >= 0xD0 && op <= 0xD3) return mk(true, IM_NONE);
    if (op >= 0xD8 && op <= 0xDF) return mk(true, IM_NONE);
    if (op == 0xFE || op == 0xFF) return mk(true, IM_NONE);
    return {};
}

Info info2(uint8_t op) {
    switch (op) {
        case 0x05: case 0x31: case 0x77: case 0xA2: return mk(false, IM_NONE);
        case 0x38: return mk(true, IM_NONE);
        case 0x3A: return mk(true, IM_8);
        case 0xA4: case 0xAC: case 0xBA: case 0xC2: case 0xC4: case 0xC5: case 0xC6:
            return mk(true, IM_8);
        default: break;
    }
    if (op == 0x0D || (op >= 0x10 && op <= 0x17) || (op >= 0x18 && op <= 0x1F) ||
        (op >= 0x28 && op <= 0x2F) || (op >= 0x40 && op <= 0x6F) || (op >= 0x74 && op <= 0x76) ||
        (op >= 0x7C && op <= 0x7F) || (op >= 0x90 && op <= 0x9F) || op == 0xA3 || op == 0xA5 ||
        op == 0xAB || op == 0xAD || op == 0xAE || op == 0xAF || op == 0xB0 || op == 0xB1 ||
        op == 0xB3 || op == 0xB6 || op == 0xB7 || op == 0xBB || op == 0xBC || op == 0xBD ||
        op == 0xBE || op == 0xBF || op == 0xC0 || op == 0xC1 || op == 0xC3 || op == 0xC7 ||
        op >= 0xD0)
        return mk(true, IM_NONE);
    if (op >= 0x70 && op <= 0x73) return mk(true, IM_8);
    if (op >= 0x80 && op <= 0x8F) return mk(false, IM_REL32);
    if (op >= 0xC8 && op <= 0xCF) return mk(false, IM_NONE);
    return {};
}

struct D {
    uint64_t pc = 0;
    int len = 0;
    // prefixes
    bool op16 = false, a67 = false, rep = false, repne = false;
    bool rex = false, rw = false, rr = false, rx = false, rb = false;
    int seg = 0;   // 0 none, 1 fs, 2 gs
    uint8_t op = 0;
    bool tb = false;       // 0F xx
    uint8_t op3 = 0;       // third byte of 0F 38 / 0F 3A
    // modrm
    bool has_modrm = false;
    uint8_t mod = 0, reg = 0, rm = 0;   // reg / rm include the REX extension
    bool mem = false;
    int base = -1, idx = -1, scale = 0;
    int64_t disp = 0;
    bool riprel = false;
    int64_t imm = 0;       // sign extended immediate / displacement
    bool has_imm = false;
    int opsize = 4;
    // classification
    bool terminator = false;
    bool native = false;
};

struct Reader {
    const uint8_t* p;
    const uint8_t* end;
    bool bad = false;
    uint8_t u8() { if (p >= end) { bad = true; return 0; } return *p++; }
    uint32_t u32() { if (end - p < 4) { bad = true; p = end; return 0; } uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; }
    uint64_t u64() { if (end - p < 8) { bad = true; p = end; return 0; } uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; }
    uint16_t u16() { if (end - p < 2) { bad = true; p = end; return 0; } uint16_t v; std::memcpy(&v, p, 2); p += 2; return v; }
};

bool decode(const uint8_t* p0, const uint8_t* end, uint64_t pc, bool is64, D& d) {
    Reader r{p0, end};
    d.pc = pc;
    bool more = true;
    while (more) {
        if (r.p >= end) return false;
        uint8_t b = *r.p;
        switch (b) {
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                if (!is64) { more = false; break; }
                d.rex = true; d.rw = b & 8; d.rr = b & 4; d.rx = b & 2; d.rb = b & 1;
                ++r.p; more = false; break;
            case 0x66: d.op16 = true; ++r.p; break;
            case 0x67: d.a67 = true; ++r.p; break;
            case 0xF0: ++r.p; break;
            case 0xF2: d.repne = true; ++r.p; break;
            case 0xF3: d.rep = true; ++r.p; break;
            case 0x64: d.seg = 1; ++r.p; break;
            case 0x65: d.seg = 2; ++r.p; break;
            case 0x2E: case 0x36: case 0x3E: case 0x26: ++r.p; break;
            default: more = false; break;
        }
        if (r.p - p0 > 14) return false;
    }
    d.opsize = d.rw ? 8 : (d.op16 ? 2 : 4);
    d.op = r.u8();
    Info in;
    if (d.op == 0x0F) {
        d.tb = true;
        d.op = r.u8();
        in = info2(d.op);
        if (in.ok && (d.op == 0x38 || d.op == 0x3A)) d.op3 = r.u8();
    } else {
        in = info1(d.op, is64);
    }
    if (r.bad || !in.ok) return false;

    if (in.modrm) {
        uint8_t m = r.u8();
        d.has_modrm = true;
        d.mod = m >> 6;
        d.reg = static_cast<uint8_t>(((d.rr ? 8 : 0) | ((m >> 3) & 7)));
        uint8_t rmf = m & 7;
        if (d.mod == 3) {
            d.rm = static_cast<uint8_t>((d.rb ? 8 : 0) | rmf);
        } else {
            d.mem = true;
            if (!is64 && d.a67) return false;   // 16-bit addressing
            if (rmf == 4) {
                uint8_t sib = r.u8();
                d.scale = sib >> 6;
                int il = (sib >> 3) & 7, bl = sib & 7;
                if (il != 4 || d.rx) d.idx = (d.rx ? 8 : 0) | il;
                if (bl == 5 && d.mod == 0) {
                    d.disp = static_cast<int32_t>(r.u32());
                } else {
                    d.base = (d.rb ? 8 : 0) | bl;
                }
            } else if (rmf == 5 && d.mod == 0) {
                int32_t disp = static_cast<int32_t>(r.u32());
                if (is64) { d.riprel = true; d.disp = disp; }
                else d.disp = static_cast<uint32_t>(disp);
            } else {
                d.base = (d.rb ? 8 : 0) | rmf;
            }
            if (d.mod == 1) d.disp += static_cast<int8_t>(r.u8());
            else if (d.mod == 2) d.disp += static_cast<int32_t>(r.u32());
        }
    }

    // immediates
    int immsz = 0;
    switch (in.imm) {
        case IM_NONE: break;
        case IM_8: immsz = 1; break;
        case IM_16: immsz = 2; break;
        case IM_Z: immsz = d.op16 ? 2 : 4; break;
        case IM_ZQ: immsz = d.rw ? 8 : (d.op16 ? 2 : 4); break;
        case IM_MOFFS: immsz = is64 ? (d.a67 ? 4 : 8) : (d.a67 ? 2 : 4); break;
        case IM_REL32: if (d.op16) return false; immsz = 4; break;
        case IM_G3_8: immsz = ((d.reg & 7) < 2) ? 1 : 0; break;
        case IM_G3_Z: immsz = ((d.reg & 7) < 2) ? (d.op16 ? 2 : 4) : 0; break;
    }
    // 8-bit immediates are sign extended, the others read as they are encoded;
    // 64-bit operands sign extend a 32-bit immediate.
    switch (immsz) {
        case 0: break;
        case 1: d.imm = static_cast<int8_t>(r.u8()); d.has_imm = true; break;
        case 2: d.imm = static_cast<int16_t>(r.u16()); d.has_imm = true; break;
        case 4: d.imm = static_cast<int32_t>(r.u32()); d.has_imm = true; break;
        case 8: d.imm = static_cast<int64_t>(r.u64()); d.has_imm = true; break;
    }
    if (r.bad) return false;
    d.len = static_cast<int>(r.p - p0);
    if (d.len > 15) return false;
    if (d.riprel) d.disp += static_cast<int64_t>(pc) + d.len;
    return true;
}

// ---------------------------------------------------------------------------
// Flag behaviour, for deciding which flag writes can be skipped
// ---------------------------------------------------------------------------

struct FlagUse {
    bool reads = true;       // may look at an arithmetic flag
    bool writes_all = false; // overwrites all six
};

FlagUse flag_use(const D& d, bool native) {
    FlagUse f;
    if (native) {
        if (!d.tb) {
            if (d.op < 0x40 && (d.op & 7) < 6) {
                int aluop = (d.op >> 3) & 7;
                if (aluop != 2 && aluop != 3) { f.reads = false; f.writes_all = true; }
                return f;
            }
            switch (d.op) {
                case 0x80: case 0x81: case 0x83: {
                    int aluop = d.reg & 7;
                    if (aluop != 2 && aluop != 3) { f.reads = false; f.writes_all = true; }
                    return f;
                }
                case 0x84: case 0x85: case 0xA8: case 0xA9:
                    f.reads = false; f.writes_all = true; return f;
                case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8D: case 0xC6: case 0xC7:
                case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
                case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                case 0x68: case 0x6A: case 0xE8: case 0xE9: case 0xEB: case 0xC3: case 0xC2:
                case 0xC9: case 0x63: case 0x90:
                case 0xA0: case 0xA1: case 0xA2: case 0xA3: case 0x98: case 0x99:
                case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
                    f.reads = false; return f;
                case 0xF6: case 0xF7: {
                    int sub = d.reg & 7;
                    if (sub < 2 || sub == 3) { f.reads = false; f.writes_all = true; }
                    else if (sub == 2) f.reads = false;
                    return f;
                }
                case 0xFF: {
                    int sub = d.reg & 7;
                    if (sub >= 2) f.reads = false;
                    return f;
                }
                default: break;
            }
            if (d.op >= 0xB0 && d.op <= 0xBF) f.reads = false;
            return f;
        }
        if (d.op == 0xB6 || d.op == 0xB7 || d.op == 0xBE || d.op == 0xBF) f.reads = false;
        return f;
    }
    // Interpreted instructions: assume the worst, except the families that are
    // known to leave the arithmetic flags alone.
    if (!d.tb) {
        if (d.op >= 0xD8 && d.op <= 0xDF) {
            // x87: FCOMI/FUCOMI/FCMOV are the exceptions, and need the register form.
            f.reads = false;
            uint8_t m = static_cast<uint8_t>((d.mod << 6) | ((d.reg & 7) << 3) | (d.rm & 7));
            if (d.mod == 3) {
                if (d.op == 0xDB && (m < 0xE0 || m >= 0xE8)) f.reads = true;
                if (d.op == 0xDA && m < 0xE0) f.reads = true;
                if (d.op == 0xDF && m >= 0xE8) f.reads = true;
            }
            return f;
        }
        switch (d.op) {
            case 0x86: case 0x87: case 0x8C: case 0x8E: case 0x8F: case 0x9B:
            case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            case 0xA4: case 0xA5: case 0xAA: case 0xAB: case 0xAC: case 0xAD:
            case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
            case 0x98: case 0x99:
                f.reads = false; return f;
            default: return f;
        }
    }
    // 0F xx: SSE is flag neutral apart from COMISS/UCOMISS and the 0F 38 / 0F 3A groups.
    if (d.op != 0x2E && d.op != 0x2F && d.op != 0x38 && d.op != 0x3A &&
        ((d.op >= 0x10 && d.op <= 0x17) || (d.op >= 0x28 && d.op <= 0x2D) ||
         (d.op >= 0x50 && d.op <= 0x7F) || d.op == 0xC2 || (d.op >= 0xC4 && d.op <= 0xC6) ||
         d.op >= 0xD0 || d.op == 0xAE || d.op == 0x18 || d.op == 0x0D))
        f.reads = false;
    return f;
}

// ---------------------------------------------------------------------------
// Translation
// ---------------------------------------------------------------------------

struct Tr {
    Cpu& cpu;
    const Engine::Slots& s;
    bool is64;
    IrBlock& ir;
    int tmp_next = 1;
    // A CMP or TEST whose flags the block's final Jcc will consume directly.
    struct Pend { bool valid; int kind; int sz; int a; int b; bool imm; int64_t immv; } pend{};
    uint32_t cur_off = 0;   // offset of the current instruction from the block start
    bool stored = false;    // the current instruction wrote memory
    bool last = false;      // the current instruction ends the block

    Tr(Cpu& c, const Engine::Slots& sl, bool w, IrBlock& b) : cpu(c), s(sl), is64(w), ir(b) {}

    static int R(int i) { return i * 8; }
    int newtmp() { return s.tmp0 + 8 * (tmp_next++); }

    Op& emit(OpKind k) {
        ir.ops.emplace_back();
        Op& o = ir.ops.back();
        o.kind = k;
        o.pc = cur_off;
        o.ni = static_cast<uint16_t>(ir.insns);
        return o;
    }
    void mov(int d, int a) { Op& o = emit(OpKind::Mov); o.d = d; o.a = a; }
    void movi(int d, int64_t v) { Op& o = emit(OpKind::MovI); o.d = d; o.imm = v; }
    void bin(OpKind k, int d, int a, int b) { Op& o = emit(k); o.d = d; o.a = a; o.b = b; }
    void bini(OpKind k, int d, int a, int64_t v) { Op& o = emit(k); o.d = d; o.a = a; o.imm = v; }
    void ext(int d, int a, int src, bool sgn, int dst) {
        Op& o = emit(OpKind::Ext); o.d = d; o.a = a; o.sz = static_cast<uint8_t>(src);
        o.cc = static_cast<uint8_t>(dst); o.flags = sgn ? kFlagSigned : 0;
    }

    // ---- operands ----
    struct Addr { int a, c, cc; int64_t imm; bool a32; };

    Addr address(const D& d) {
        const bool a32 = !is64 || d.a67;
        Addr ad;
        if (d.riprel) {
            ad = {s.zero, s.zero, 0, d.disp, a32};
        } else {
            ad = {d.base >= 0 ? R(d.base) : s.zero, d.idx >= 0 ? R(d.idx) : s.zero, d.scale, d.disp, a32};
        }
        if (d.seg) {
            int t = newtmp();
            Op& o = emit(OpKind::Lea);
            o.d = t; o.a = ad.a; o.c = ad.c; o.cc = static_cast<uint8_t>(ad.cc); o.imm = ad.imm;
            o.sz = a32 ? 4 : 8;
            bin(OpKind::Add, t, t, d.seg == 1 ? s.fs_base : s.gs_base);
            ad = {t, s.zero, 0, 0, false};
        }
        return ad;
    }

    void ld(int dst, const Addr& ad, int sz) {
        Op& o = emit(OpKind::Ld);
        o.d = dst; o.a = ad.a; o.c = ad.c; o.cc = static_cast<uint8_t>(ad.cc); o.imm = ad.imm;
        o.sz = static_cast<uint8_t>(sz); o.flags = ad.a32 ? kFlagA32 : 0;
    }
    void lds(int dst, const Addr& ad, int sz, int dstsz) {
        Op& o = emit(OpKind::LdS);
        o.d = dst; o.a = ad.a; o.c = ad.c; o.cc = static_cast<uint8_t>(ad.cc); o.imm = ad.imm;
        o.sz = static_cast<uint8_t>(sz); o.imm2 = dstsz; o.flags = ad.a32 ? kFlagA32 : 0;
    }
    void st(const Addr& ad, int val, int sz) {
        Op& o = emit(OpKind::St);
        o.a = ad.a; o.c = ad.c; o.cc = static_cast<uint8_t>(ad.cc); o.imm = ad.imm; o.b = val;
        o.sz = static_cast<uint8_t>(sz); o.flags = ad.a32 ? kFlagA32 : 0;
        stored = true;
    }

    // 8-bit register access: without REX, indexes 4-7 are AH CH DH BH.
    int reg8_read(const D& d, int idx) {
        if (idx < 4 || d.rex) return R(idx);
        int t = newtmp();
        Op& o = emit(OpKind::GetH); o.d = t; o.a = R(idx - 4);
        return t;
    }
    void reg8_write(const D& d, int idx, int val) {
        if (idx < 4 || d.rex) { Op& o = emit(OpKind::Put); o.sz = 1; o.d = R(idx); o.a = R(idx); o.b = val; }
        else { Op& o = emit(OpKind::Put); o.sz = 0x81; o.d = R(idx - 4); o.a = R(idx - 4); o.b = val; }
    }
    // The value of general register `idx` at operand size sz (consumers mask).
    int reg_read(const D& d, int idx, int sz) { return sz == 1 ? reg8_read(d, idx) : R(idx); }
    // Writes `val` (already masked to sz for sz >= 4 when `clean`) into a register.
    void reg_write(const D& d, int idx, int sz, int val, bool clean) {
        if (sz == 1) { reg8_write(d, idx, val); return; }
        if (sz == 8) { if (val != R(idx)) mov(R(idx), val); return; }
        if (sz == 2) { Op& o = emit(OpKind::Put); o.sz = 2; o.d = R(idx); o.a = R(idx); o.b = val; return; }
        // sz == 4: zero extends
        if (clean) { if (val != R(idx)) mov(R(idx), val); }
        else ext(R(idx), val, 4, false, 4);
    }

    // The r/m operand's value.
    int rm_read(const D& d, int sz) {
        if (!d.mem) return reg_read(d, d.rm, sz);
        Addr ad = address(d);
        int t = newtmp();
        ld(t, ad, sz);
        return t;
    }

    void flush_check(uint64_t next_pc) {
        if (!stored || last) return;
        Op& o = emit(OpKind::ChkFlush);
        o.imm = static_cast<int64_t>(next_pc);
    }
};

struct Plan {
    D d;
    bool native = false;
};

bool is_term(const D& d) {
    if (!d.tb) {
        switch (d.op) {
            case 0xE8: case 0xE9: case 0xEB: case 0xC3: case 0xC2: case 0xF4:
            case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xCD:
                return true;
            case 0xFF: { int sub = d.reg & 7; return sub == 2 || sub == 4 || sub == 3 || sub == 5; }
            default: return d.op >= 0x70 && d.op <= 0x7F;
        }
    }
    return d.op == 0x05 || (d.op >= 0x80 && d.op <= 0x8F);
}

bool is_jcc(const D& d) {
    return d.native && ((!d.tb && d.op >= 0x70 && d.op <= 0x7F) || (d.tb && d.op >= 0x80 && d.op <= 0x8F));
}

// CMP and TEST: the flag writers that change nothing else, so their operands are
// still there for a Jcc that follows.
bool is_compare(const D& d) {
    if (!d.native) return false;
    if (!d.tb) {
        const uint8_t op = d.op;
        if (op < 0x40 && (op & 7) < 6) return ((op >> 3) & 7) == 7;
        switch (op) {
            case 0x80: case 0x81: case 0x83: return (d.reg & 7) == 7;
            case 0x84: case 0x85: case 0xA8: case 0xA9: return true;
            case 0xF6: case 0xF7: return (d.reg & 7) < 2;
            default: return false;
        }
    }
    return false;
}

// Whether the frontend translates this instruction itself.
bool is_native(const D& d, bool is64) {
    const int sz = d.opsize;
    const bool wide = sz == 4 || sz == 8;
    const bool w248 = sz == 2 || sz == 4 || sz == 8;   // operand sizes the generic paths handle
    const bool a_ok = is64 || !d.a67;
    if (d.rep || d.repne) {
        // F3 90 (pause) is a nop; F2/F3 on anything else changes meaning
        return !d.tb && d.op == 0x90 && !d.repne;
    }
    if (!d.tb) {
        uint8_t op = d.op;
        if (op < 0x40 && (op & 7) < 6) {
            int aluop = (op >> 3) & 7;
            if (aluop == 2 || aluop == 3) return false;
            if ((op & 7) == 0 || (op & 7) == 2 || (op & 7) == 4) return a_ok;
            return w248 && a_ok;
        }
        switch (op) {
            case 0x80: { int a = d.reg & 7; return a != 2 && a != 3 && a_ok; }
            case 0x81: case 0x83: { int a = d.reg & 7; return a != 2 && a != 3 && w248 && a_ok; }
            case 0x84: return a_ok;
            case 0x85: return w248 && a_ok;
            case 0x88: case 0x8A: return a_ok;
            case 0x89: case 0x8B: return w248 && a_ok;
            case 0x8D: return wide && d.mem && a_ok && !d.a67;
            case 0xC6: return (d.reg & 7) == 0 && a_ok;
            case 0xC7: return (d.reg & 7) == 0 && w248 && a_ok;
            case 0xA8: return true;
            case 0xA9: return w248;
            case 0x90: return true;
            case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
            case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            case 0x68: case 0x6A:
                return !d.op16 && (is64 ? true : true);
            case 0xE8: case 0xE9: case 0xEB: case 0xC3: case 0xC2:
                return !d.op16;
            case 0xC9: return !d.op16;
            case 0xC0: case 0xD0: case 0xD2: return a_ok;
            case 0xC1: case 0xD1: case 0xD3: return w248 && a_ok;
            case 0xF6: return a_ok;
            case 0xF7: return w248 && a_ok;
            case 0x69: case 0x6B: return w248 && a_ok;
            case 0xA0: case 0xA2: return a_ok && !d.a67;
            case 0xA1: case 0xA3: return w248 && a_ok && !d.a67;
            case 0x98: case 0x99: return wide;
            case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97: return w248;
            case 0x63: return is64 && d.rw && a_ok;
            case 0xFE: { int sub = d.reg & 7; return sub < 2 && a_ok; }
            case 0xFF: {
                int sub = d.reg & 7;
                if (sub < 2) return w248 && a_ok;
                return (sub == 2 || sub == 4 || sub == 6) && !d.op16 && a_ok;
            }
            default: break;
        }
        if (op >= 0x40 && op <= 0x4F) return !is64 && w248;
        if (op >= 0x70 && op <= 0x7F) return true;
        if (op >= 0xB0 && op <= 0xB7) return true;
        if (op >= 0xB8 && op <= 0xBF) return w248;
        return false;
    }
    switch (d.op) {
        case 0xB6: case 0xB7: case 0xBE: case 0xBF: return wide && a_ok;
        case 0xAF: return w248 && a_ok;
        default: break;
    }
    if (d.op >= 0x80 && d.op <= 0x8F) return true;
    if (d.op >= 0x90 && d.op <= 0x9F) return a_ok;
    if (d.op >= 0x40 && d.op <= 0x4F) return w248 && a_ok;
    return false;
}

// Emits one natively translated instruction.  `flags` says whether anyone can
// observe the flags this instruction writes.
void emit_native(Tr& t, const D& d, int fmode, uint64_t next_pc) {
    const bool is64 = t.is64;
    const int sz = d.opsize;
    // fmode: 0 nobody sees this instruction's flags; 1 compute them now; 2 record
    // them for later (CcSet) - nothing in this block reads them; 3 this is the
    // CMP / TEST in front of the block's closing Jcc, which will do both at once.
    const uint8_t fl = fmode == 1 ? kFlagEager : 0;
    const int ptr = is64 ? 8 : 4;
    const int rsp = Tr::R(x86emu::RSP);

    auto alu_op = [&](int aluop, int osz, int dst, int a, int b, bool imm, int64_t immv) {
        const bool compare = aluop == 7 || aluop == 8;
        if (fmode == 0 && compare) return;   // nothing to compute, nothing to write
        if (fmode >= 2) {
            const int kind = aluop == 0 ? 1 : (aluop == 5 || aluop == 7) ? 2
                             : (aluop == 4 || aluop == 8) ? 3 : aluop == 1 ? 4 : 5;
            if (fmode == 3) {   // the Jcc after this does the work
                t.pend = {true, kind, osz, a, b, imm, immv};
                return;
            }
            Op& s = t.emit(imm ? OpKind::CcSetI : OpKind::CcSet);
            s.cc = static_cast<uint8_t>(kind); s.sz = static_cast<uint8_t>(osz);
            s.a = a; s.b = b; s.imm = immv;
            if (compare) return;
        }
        Op& o = t.emit(imm ? OpKind::AluI : OpKind::Alu);
        o.cc = static_cast<uint8_t>(aluop);
        o.sz = static_cast<uint8_t>(osz);
        o.d = dst; o.a = a; o.b = b; o.imm = immv;
        o.flags = fl;
    };

    // ALU on r/m, with a register or immediate source.  The caller has decided
    // `aluop`; CMP (7) and TEST (8) write nothing back.
    auto alu_rm = [&](int aluop, int osz, int src, bool imm, int64_t immv) {
        const bool writes = aluop != 7 && aluop != 8;
        if (!d.mem) {
            int a = t.reg_read(d, d.rm, osz);
            if (osz >= 4 || !writes) {
                alu_op(aluop, osz, writes ? Tr::R(d.rm) : 0, a, src, imm, immv);
            } else {
                int r = t.newtmp();
                alu_op(aluop, osz, r, a, src, imm, immv);
                t.reg_write(d, d.rm, osz, r, true);
            }
        } else {
            Tr::Addr ad = t.address(d);
            int v = t.newtmp();
            t.ld(v, ad, osz);
            if (writes) {
                alu_op(aluop, osz, v, v, src, imm, immv);
                t.st(ad, v, osz);
            } else {
                alu_op(aluop, osz, 0, v, src, imm, immv);
            }
        }
    };
    // ALU into a register from r/m or an immediate.
    auto alu_reg = [&](int aluop, int osz, int reg, int b, bool imm, int64_t immv) {
        const bool writes = aluop != 7 && aluop != 8;
        int a = t.reg_read(d, reg, osz);
        if (osz >= 4 || !writes) {
            alu_op(aluop, osz, writes ? Tr::R(reg) : 0, a, b, imm, immv);
        } else {
            int r = t.newtmp();
            alu_op(aluop, osz, r, a, b, imm, immv);
            t.reg_write(d, reg, osz, r, true);
        }
    };

    auto push_val = [&](int val) {
        t.bini(OpKind::SubI, rsp, rsp, ptr);
        Tr::Addr ad{rsp, t.s.zero, 0, 0, false};
        t.st(ad, val, ptr);
    };
    auto pop_to_tmp = [&]() {
        int v = t.newtmp();
        Tr::Addr ad{rsp, t.s.zero, 0, 0, false};
        t.ld(v, ad, ptr);
        t.bini(OpKind::AddI, rsp, rsp, ptr);
        return v;
    };
    auto exit_to = [&](uint64_t target) {
        Op& o = t.emit(OpKind::Exit);
        o.imm = static_cast<int64_t>(target);
    };
    auto jcc = [&](int cc, uint64_t taken, uint64_t fall) {
        if (t.pend.valid) {
            Op& o = t.emit(t.pend.imm ? OpKind::JccCmpI : OpKind::JccCmp);
            o.cc = static_cast<uint8_t>(cc);
            o.c = t.pend.kind;
            o.sz = static_cast<uint8_t>(t.pend.sz);
            o.a = t.pend.a;
            o.b = t.pend.b;
            o.d = static_cast<int32_t>(t.pend.immv);
            o.imm = static_cast<int64_t>(taken);
            o.imm2 = static_cast<int64_t>(fall);
            t.pend.valid = false;
            return;
        }
        Op& o = t.emit(OpKind::JccFl);
        o.cc = static_cast<uint8_t>(cc);
        o.imm = static_cast<int64_t>(taken);
        o.imm2 = static_cast<int64_t>(fall);
    };

    if (!d.tb) {
        const uint8_t op = d.op;
        if (op < 0x40 && (op & 7) < 6) {
            int aluop = (op >> 3) & 7;
            int lo = op & 7;
            int osz = (lo == 0 || lo == 2 || lo == 4) ? 1 : sz;
            if (lo <= 1) {                       // rm <- rm op reg
                int src = t.reg_read(d, d.reg, osz);
                alu_rm(aluop, osz, src, false, 0);
            } else if (lo <= 3) {                // reg <- reg op rm
                int b = t.rm_read(d, osz);
                alu_reg(aluop, osz, d.reg, b, false, 0);
            } else {                             // accumulator, immediate
                alu_reg(aluop, osz, 0, 0, true, d.imm);
            }
            t.flush_check(next_pc);
            return;
        }
        switch (op) {
            case 0x80: case 0x81: case 0x83: {
                int osz = op == 0x80 ? 1 : sz;
                alu_rm(d.reg & 7, osz, 0, true, d.imm);
                t.flush_check(next_pc);
                return;
            }
            case 0x84: case 0x85: {
                int osz = op == 0x84 ? 1 : sz;
                int src = t.reg_read(d, d.reg, osz);
                alu_rm(8, osz, src, false, 0);
                return;
            }
            case 0xA8: alu_reg(8, 1, 0, 0, true, d.imm); return;
            case 0xA9: alu_reg(8, sz, 0, 0, true, d.imm); return;
            case 0x88: case 0x89: {
                int osz = op == 0x88 ? 1 : sz;
                int src = t.reg_read(d, d.reg, osz);
                if (!d.mem) {
                    if (osz >= 4) t.reg_write(d, d.rm, osz, src, false);
                    else t.reg_write(d, d.rm, osz, src, false);
                } else {
                    Tr::Addr ad = t.address(d);
                    t.st(ad, src, osz);
                    t.flush_check(next_pc);
                }
                return;
            }
            case 0x8A: case 0x8B: {
                int osz = op == 0x8A ? 1 : sz;
                if (d.mem && osz >= 4) {
                    Tr::Addr ad = t.address(d);
                    t.ld(Tr::R(d.reg), ad, osz);   // zero extends, which is the 32-bit write rule
                } else {
                    int v = t.rm_read(d, osz);
                    bool clean = d.mem;
                    t.reg_write(d, d.reg, osz, v, clean);
                }
                return;
            }
            case 0x8D: {
                if (!d.mem) return;   // not reachable: is_native excluded it
                Op& o = t.emit(OpKind::Lea);
                o.d = Tr::R(d.reg);
                if (d.riprel) {
                    o.a = t.s.zero; o.c = t.s.zero; o.imm = d.disp;
                } else {
                    o.a = d.base >= 0 ? Tr::R(d.base) : t.s.zero;
                    o.c = d.idx >= 0 ? Tr::R(d.idx) : t.s.zero;
                    o.cc = static_cast<uint8_t>(d.scale);
                    o.imm = d.disp;
                }
                o.sz = static_cast<uint8_t>(sz == 8 ? 8 : 4);
                return;
            }
            case 0xC6: case 0xC7: {
                int osz = op == 0xC6 ? 1 : sz;
                int v = t.newtmp();
                t.movi(v, osz == 8 ? d.imm
                          : osz == 4 ? static_cast<int64_t>(static_cast<uint32_t>(d.imm))
                          : osz == 2 ? (d.imm & 0xFFFF) : (d.imm & 0xFF));
                if (!d.mem) {
                    t.reg_write(d, d.rm, osz, v, true);
                } else {
                    Tr::Addr ad = t.address(d);
                    t.st(ad, v, osz);
                    t.flush_check(next_pc);
                }
                return;
            }
            case 0x90: return;
            case 0x63: {
                if (!d.mem) { t.ext(Tr::R(d.reg), Tr::R(d.rm), 4, true, 8); }
                else { Tr::Addr ad = t.address(d); t.lds(Tr::R(d.reg), ad, 4, 8); }
                return;
            }
            case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {   // shifts and rotates
                const int osz = (op & 1) ? sz : 1;
                const int sub = d.reg & 7;
                const bool bycl = op == 0xD2 || op == 0xD3;
                const int64_t cnt = (op == 0xD0 || op == 0xD1) ? 1 : (d.imm & 0xFF);
                auto shift_op = [&](int dst, int a) {
                    if (sub >= 4) {
                        Op& o = t.emit(bycl ? OpKind::Shift : OpKind::ShiftI);
                        o.cc = static_cast<uint8_t>(sub == 6 ? 4 : sub);
                        o.sz = static_cast<uint8_t>(osz);
                        o.d = dst; o.a = a; o.flags = fl;
                        if (bycl) o.b = Tr::R(x86emu::RCX); else o.imm = cnt;
                    } else {
                        int cs = Tr::R(x86emu::RCX);
                        if (!bycl) { cs = t.newtmp(); t.movi(cs, cnt); }
                        Op& o = t.emit(OpKind::ShiftSlow);
                        o.cc = static_cast<uint8_t>(sub); o.sz = static_cast<uint8_t>(osz);
                        o.d = dst; o.a = a; o.b = cs;
                    }
                };
                if (!d.mem) {
                    int a = t.reg_read(d, d.rm, osz);
                    if (osz >= 4) shift_op(Tr::R(d.rm), a);
                    else { int r = t.newtmp(); shift_op(r, a); t.reg_write(d, d.rm, osz, r, true); }
                } else {
                    Tr::Addr ad = t.address(d);
                    int v = t.newtmp();
                    t.ld(v, ad, osz);
                    shift_op(v, v);
                    t.st(ad, v, osz);
                    t.flush_check(next_pc);
                }
                return;
            }
            case 0xF6: case 0xF7: {   // group 3
                const int osz = op == 0xF6 ? 1 : sz;
                const int sub = d.reg & 7;
                if (sub < 2) { alu_rm(8, osz, 0, true, d.imm); return; }
                if (sub == 2 || sub == 3) {
                    auto unary = [&](int dst, int a) {
                        if (sub == 2) {
                            Op& o = t.emit(OpKind::AluI);
                            o.cc = 6; o.sz = static_cast<uint8_t>(osz); o.d = dst; o.a = a; o.imm = -1;
                        } else {
                            alu_op(5, osz, dst, t.s.zero, a, false, 0);   // 0 - a
                        }
                    };
                    if (!d.mem) {
                        int a = t.reg_read(d, d.rm, osz);
                        if (osz >= 4) unary(Tr::R(d.rm), a);
                        else { int r = t.newtmp(); unary(r, a); t.reg_write(d, d.rm, osz, r, true); }
                    } else {
                        Tr::Addr ad = t.address(d);
                        int v = t.newtmp();
                        t.ld(v, ad, osz);
                        unary(v, v);
                        t.st(ad, v, osz);
                        t.flush_check(next_pc);
                    }
                    return;
                }
                // MUL / IMUL / DIV / IDIV through the interpreter's own code
                if (!d.mem) {
                    Op& o = t.emit(OpKind::Group3);
                    o.cc = static_cast<uint8_t>(sub); o.sz = static_cast<uint8_t>(osz);
                    o.d = d.rm; o.imm = static_cast<int64_t>(next_pc);
                    o.flags = d.rex ? kFlagRex : 0;
                } else {
                    Tr::Addr ad = t.address(d);
                    int a = t.newtmp();
                    Op& l = t.emit(OpKind::Lea);
                    l.d = a; l.a = ad.a; l.c = ad.c; l.cc = static_cast<uint8_t>(ad.cc); l.imm = ad.imm;
                    l.sz = ad.a32 ? 4 : 8;
                    Op& o = t.emit(OpKind::Group3);
                    o.cc = static_cast<uint8_t>(sub); o.sz = static_cast<uint8_t>(osz);
                    o.a = a; o.imm = static_cast<int64_t>(next_pc);
                    o.flags = static_cast<uint8_t>(kFlagMem | (d.rex ? kFlagRex : 0));
                }
                return;
            }
            case 0x69: case 0x6B: {   // IMUL r, r/m, imm
                int src = t.rm_read(d, sz);
                int dst = sz >= 4 ? Tr::R(d.reg) : t.newtmp();
                Op& o = t.emit(OpKind::ImulI);
                o.sz = static_cast<uint8_t>(sz); o.d = dst; o.a = src; o.imm = d.imm; o.flags = fl;
                if (sz == 2) t.reg_write(d, d.reg, 2, dst, true);
                return;
            }
            case 0xA0: case 0xA1: case 0xA2: case 0xA3: {   // MOV AL/eAX, moffs and back
                const int osz = (op & 1) ? sz : 1;
                D dd = d;
                dd.base = -1; dd.idx = -1; dd.scale = 0; dd.riprel = false; dd.mem = true;
                dd.disp = is64 ? d.imm : static_cast<int64_t>(static_cast<uint32_t>(d.imm));
                Tr::Addr ad = t.address(dd);
                if (op < 0xA2) {
                    if (osz >= 4) t.ld(Tr::R(0), ad, osz);
                    else { int v = t.newtmp(); t.ld(v, ad, osz); t.reg_write(d, 0, osz, v, true); }
                } else {
                    t.st(ad, t.reg_read(d, 0, osz), osz);
                    t.flush_check(next_pc);
                }
                return;
            }
            case 0x98:   // CWDE / CDQE
                if (sz == 8) t.ext(Tr::R(0), Tr::R(0), 4, true, 8);
                else t.ext(Tr::R(0), Tr::R(0), 2, true, 4);
                return;
            case 0x99: {   // CDQ / CQO
                int tt = t.newtmp();
                if (sz == 8) {
                    t.bini(OpKind::SarI, tt, Tr::R(0), 63);
                    t.mov(Tr::R(2), tt);
                } else {
                    t.ext(tt, Tr::R(0), 4, true, 8);
                    t.bini(OpKind::SarI, tt, tt, 63);
                    t.ext(Tr::R(2), tt, 4, false, 4);
                }
                return;
            }
            case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97: {   // XCHG eAX, r
                int r = (d.rb ? 8 : 0) | (op & 7);
                int old = t.newtmp();
                t.mov(old, Tr::R(0));
                t.reg_write(d, 0, sz, Tr::R(r), false);
                t.reg_write(d, r, sz, old, false);
                return;
            }
            case 0xC9: {   // LEAVE
                t.mov(rsp, Tr::R(x86emu::RBP));
                int v = pop_to_tmp();
                t.mov(Tr::R(x86emu::RBP), v);
                return;
            }
            case 0xE8: {   // CALL rel32
                int v = t.newtmp();
                t.movi(v, static_cast<int64_t>(next_pc));
                push_val(v);
                t.flush_check(next_pc);
                exit_to(next_pc + static_cast<uint64_t>(d.imm));
                return;
            }
            case 0xE9: case 0xEB: exit_to(next_pc + static_cast<uint64_t>(d.imm)); return;
            case 0xC3: {
                int v = pop_to_tmp();
                Op& o = t.emit(OpKind::ExitInd); o.a = v;
                return;
            }
            case 0xC2: {
                int v = pop_to_tmp();
                t.bini(OpKind::AddI, rsp, rsp, static_cast<uint16_t>(d.imm));
                Op& o = t.emit(OpKind::ExitInd); o.a = v;
                return;
            }
            case 0xFE: case 0xFF: {
                int sub = d.reg & 7;
                int osz = op == 0xFE ? 1 : sz;
                if (sub < 2) {
                    auto incdec = [&](int dst, int a, int w) {
                        Op& o = t.emit(OpKind::IncDec);
                        o.cc = static_cast<uint8_t>(sub); o.sz = static_cast<uint8_t>(w);
                        o.d = dst; o.a = a; o.flags = fl;
                    };
                    if (!d.mem) {
                        int a = t.reg_read(d, d.rm, osz);
                        if (osz >= 4) incdec(Tr::R(d.rm), a, osz);
                        else { int r = t.newtmp(); incdec(r, a, osz); t.reg_write(d, d.rm, osz, r, true); }
                    } else {
                        Tr::Addr ad = t.address(d);
                        int v = t.newtmp();
                        t.ld(v, ad, osz);
                        incdec(v, v, osz);
                        t.st(ad, v, osz);
                        t.flush_check(next_pc);
                    }
                    return;
                }
                if (sub == 6) {   // PUSH rm
                    int v = t.rm_read(d, ptr);
                    if (!d.mem && d.rm == x86emu::RSP) { int c = t.newtmp(); t.mov(c, v); v = c; }
                    push_val(v);
                    t.flush_check(next_pc);
                    return;
                }
                // CALL / JMP rm
                int target = t.rm_read(d, ptr);
                if (!d.mem && !is64) { int c = t.newtmp(); t.ext(c, target, 4, false, 4); target = c; }
                if (sub == 2) {
                    int v = t.newtmp();
                    t.movi(v, static_cast<int64_t>(next_pc));
                    push_val(v);
                    t.flush_check(next_pc);
                }
                Op& o = t.emit(OpKind::ExitInd); o.a = target;
                return;
            }
            default: break;
        }
        if (op >= 0x50 && op <= 0x57) {
            int r = (d.rb ? 8 : 0) | (op & 7);
            int v = Tr::R(r);
            if (r == x86emu::RSP) { v = t.newtmp(); t.mov(v, Tr::R(r)); }
            push_val(v);
            t.flush_check(next_pc);
            return;
        }
        if (op >= 0x58 && op <= 0x5F) {
            int r = (d.rb ? 8 : 0) | (op & 7);
            int v = pop_to_tmp();
            t.reg_write(d, r, ptr, v, true);
            return;
        }
        if (op == 0x68 || op == 0x6A) {
            int v = t.newtmp();
            t.movi(v, d.imm);
            push_val(v);
            t.flush_check(next_pc);
            return;
        }
        if (op >= 0x40 && op <= 0x4F) {   // 32-bit INC/DEC reg
            int r = op & 7;
            int dst = sz == 2 ? t.newtmp() : Tr::R(r);
            Op& o = t.emit(OpKind::IncDec);
            o.cc = op >= 0x48; o.sz = static_cast<uint8_t>(sz); o.d = dst; o.a = Tr::R(r); o.flags = fl;
            if (sz == 2) t.reg_write(d, r, 2, dst, true);
            return;
        }
        if (op >= 0x70 && op <= 0x7F) { jcc(op & 15, next_pc + static_cast<uint64_t>(d.imm), next_pc); return; }
        if (op >= 0xB0 && op <= 0xB7) {
            int r = (d.rb ? 8 : 0) | (op & 7);
            int v = t.newtmp();
            t.movi(v, d.imm & 0xFF);
            t.reg_write(d, r, 1, v, true);
            return;
        }
        if (op >= 0xB8 && op <= 0xBF) {
            int r = (d.rb ? 8 : 0) | (op & 7);
            if (sz == 8) { t.movi(Tr::R(r), d.imm); }
            else if (sz == 2) { int v = t.newtmp(); t.movi(v, d.imm & 0xFFFF); t.reg_write(d, r, 2, v, true); }
            else t.movi(Tr::R(r), static_cast<uint32_t>(d.imm));
            return;
        }
        return;
    }

    // ---- 0F xx ----
    const uint8_t op = d.op;
    if (op >= 0x80 && op <= 0x8F) { jcc(op & 15, next_pc + static_cast<uint64_t>(d.imm), next_pc); return; }
    if (op >= 0x90 && op <= 0x9F) {   // SETcc
        int v = t.newtmp();
        Op& o = t.emit(OpKind::SetFl); o.d = v; o.cc = op & 15;
        if (!d.mem) { t.reg8_write(d, d.rm, v); }
        else { Tr::Addr ad = t.address(d); t.st(ad, v, 1); t.flush_check(next_pc); }
        return;
    }
    if (op == 0xAF) {   // IMUL r, r/m
        int src = t.rm_read(d, sz);
        int dst = sz >= 4 ? Tr::R(d.reg) : t.newtmp();
        Op& o = t.emit(OpKind::Imul);
        o.sz = static_cast<uint8_t>(sz); o.d = dst; o.a = Tr::R(d.reg); o.b = src; o.flags = fl;
        if (sz == 2) t.reg_write(d, d.reg, 2, dst, true);
        return;
    }
    if (op >= 0x40 && op <= 0x4F) {   // CMOVcc
        int src = t.rm_read(d, sz);
        int c = t.newtmp();
        Op& o = t.emit(OpKind::SetFl); o.d = c; o.cc = op & 15;
        int res = t.newtmp();
        Op& s = t.emit(OpKind::Sel); s.d = res; s.a = src; s.b = Tr::R(d.reg); s.c = c;
        t.reg_write(d, d.reg, sz, res, false);
        return;
    }
    if (op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF) {   // MOVZX / MOVSX
        int srcsz = (op & 1) ? 2 : 1;
        bool sgn = op >= 0xBE;
        if (d.mem && !(sgn == false && false)) {
            Tr::Addr ad = t.address(d);
            if (sgn) {
                t.lds(Tr::R(d.reg), ad, srcsz, sz);
            } else {
                t.ld(Tr::R(d.reg), ad, srcsz);
            }
        } else {
            int v = srcsz == 1 ? t.reg8_read(d, d.rm) : Tr::R(d.rm);
            t.ext(Tr::R(d.reg), v, srcsz, sgn, sz);
        }
        return;
    }
}

}  // namespace

bool translate_x86(Cpu& cpu, const Engine::Slots& slots, uint64_t pc, IrBlock& out) {
    const bool is64 = cpu.is64();
    const uint8_t* end = nullptr;
    const uint8_t* p0 = nullptr;
    try {
        p0 = cpu.mem().code_window(pc, &end);
    } catch (const x86emu::MemoryFault&) {
        return false;
    }

    std::vector<D> plans;
    {
        const uint8_t* p = p0;
        uint64_t cur = pc;
        while (plans.size() < 48) {
            D d;
            if (!decode(p, end, cur, is64, d)) break;
            d.native = is_native(d, is64);
            d.terminator = is_term(d);
            plans.push_back(d);
            p += d.len;
            cur += d.len;
            if (d.terminator) break;
        }
    }
    if (plans.empty()) return false;

    // Which flag writes can anyone see?  At the end of the block, everyone can.
    const size_t n = plans.size();
    std::vector<FlagUse> fu(n);
    for (size_t i = 0; i < n; ++i) fu[i] = flag_use(plans[i], plans[i].native);
    std::vector<char> live_after(n);
    {
        bool live = true;
        for (size_t i = n; i-- > 0;) {
            live_after[i] = live;
            if (fu[i].writes_all) live = false;
            if (fu[i].reads) live = true;
        }
    }
    // Does the block look at flags it did not itself set?  Then whatever the
    // previous block left pending has to be settled first.
    bool live_in = false;
    for (size_t i = 0; i < n; ++i) {
        if (fu[i].reads) { live_in = true; break; }
        if (fu[i].writes_all) break;
    }

    // How each flag-writing instruction gets its flags to whoever wants them:
    //   0 nobody does   1 computed now (a later instruction in the block reads them)
    //   2 recorded, not computed (only whatever runs after this block can read them)
    //   3 a CMP / TEST directly in front of the closing Jcc, which does both at once
    std::vector<char> mode(n, 0);
    int last_full = -1;
    for (size_t i = 0; i < n; ++i) {
        if (!live_after[i]) continue;
        if (!fu[i].writes_all) { mode[i] = 1; continue; }
        last_full = static_cast<int>(i);
        size_t j = i + 1;
        bool reader_later = false;
        for (; j < n; ++j) {
            if (fu[j].reads) { reader_later = true; break; }
            if (fu[j].writes_all) break;
        }
        if (!reader_later) mode[i] = 2;
        else if (j == i + 1 && j == n - 1 && is_jcc(plans[j]) && is_compare(plans[i])) mode[i] = 3;
        else mode[i] = 1;
    }

    out.start = pc;
    Tr t(cpu, slots, is64, out);
    if (live_in) {
        t.cur_off = 0;
        t.emit(OpKind::CcMat);
    }
    uint64_t cur = pc;
    for (size_t i = 0; i < plans.size(); ++i) {
        const D& d = plans[i];
        uint64_t next = cur + static_cast<uint64_t>(d.len);
        t.cur_off = static_cast<uint32_t>(cur - pc);
        t.tmp_next = 1;
        t.stored = false;
        t.last = i + 1 == plans.size();
        if (d.native) {
            ++out.insns;
            emit_native(t, d, mode[i], next);
            // The flags the block ends with were computed outright, so anything an
            // earlier block left pending is out of date.
            if (static_cast<int>(i) == last_full && mode[i] == 1 && !live_in) t.emit(OpKind::CcClear);
        } else {
            Op& o = t.emit(OpKind::Interp);
            o.imm = static_cast<int64_t>(cur);
            o.imm2 = static_cast<int64_t>(next);
            o.c = d.tb ? 256 + d.op : d.op;   // for the statistics
            // Instructions whose effects are not just CPU and memory state: running
            // one twice (for the verifier) would repeat them.
            if ((d.tb && (d.op == 0x05 || d.op == 0x31)) || (!d.tb && (d.op == 0xCD || d.op == 0xF4)))
                out.effects = true;
        }
        cur = next;
    }
    out.guest_bytes = static_cast<uint32_t>(cur - pc);
    const D& last = plans.back();
    if (!(last.native && last.terminator)) {
        t.cur_off = static_cast<uint32_t>(cur - pc);
        Op& o = t.emit(OpKind::Exit);
        o.imm = static_cast<int64_t>(cur);
    }
    return out.insns > 0;
}

}  // namespace jit
