#include "cpu.h"

#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace x86emu {

namespace {

// ---------------------------------------------------------------------------
// Address census, for diffing an execution against qemu's (tools/qemu-diff).
// Enabled by environment variables so it needs no special build:
//   X86EMU_CENSUS_FILTER  file of hex addresses, one per line (qemu's block set)
//   X86EMU_CENSUS_OUT     binary stream this appends to, 8 bytes per execution
// Consecutive duplicates are collapsed, matching what seq.awk does to qemu's
// stream (qemu re-enters the block once per REP iteration; we run the whole
// REP in one step).
struct Census {
    std::unordered_set<uint64_t> filter;
    std::FILE* out = nullptr;
    uint64_t last = ~0ull;
    Census() {
        const char* ff = std::getenv("X86EMU_CENSUS_FILTER");
        const char* of = std::getenv("X86EMU_CENSUS_OUT");
        if (!ff || !of) return;
        std::FILE* f = std::fopen(ff, "r");
        if (!f) return;
        char line[64];
        while (std::fgets(line, sizeof line, f))
            filter.insert(std::strtoull(line, nullptr, 16));
        std::fclose(f);
        out = std::fopen(of, "wb");
    }
    void record(uint64_t addr) {
        if (addr == last || !filter.count(addr)) return;
        last = addr;
        std::fwrite(&addr, 8, 1, out);
    }
};

// Resolved once, at load.  A function-local static costs a guarded load on
// every instruction executed, and Cpu::step is the hottest path there is.
Census* const g_census = [] {
    static Census c;
    return c.out ? &c : nullptr;
}();

uint64_t mask_of(int size) {
    return size == 8 ? ~0ull : ((1ull << (size * 8)) - 1);
}
uint64_t msb_of(int size) {
    return 1ull << (size * 8 - 1);
}
// PF reflects the parity of the low 8 bits only, and is set on *even* parity.
bool even_parity(uint64_t v) {
    v &= 0xFF;
    v ^= v >> 4;
    v ^= v >> 2;
    v ^= v >> 1;
    return (v & 1) == 0;
}
int64_t sign_ext(uint64_t v, int size) {
    switch (size) {
        case 1: return static_cast<int8_t>(v);
        case 2: return static_cast<int16_t>(v);
        case 4: return static_cast<int32_t>(v);
        default: return static_cast<int64_t>(v);
    }
}

// 128-bit helpers for the 64-bit MUL/DIV forms.  Written out by hand instead of
// using __int128 so the emulator also builds with MSVC.
struct U128 {
    uint64_t lo, hi;
};

U128 mul_u64(uint64_t a, uint64_t b) {
    uint64_t a0 = a & 0xFFFFFFFFull, a1 = a >> 32;
    uint64_t b0 = b & 0xFFFFFFFFull, b1 = b >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xFFFFFFFFull) + (p10 & 0xFFFFFFFFull);
    U128 r;
    r.lo = (p00 & 0xFFFFFFFFull) | (mid << 32);
    r.hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    return r;
}

uint64_t abs_u64(int64_t v) {
    // Avoids UB on INT64_MIN.
    return v < 0 ? ~static_cast<uint64_t>(v) + 1 : static_cast<uint64_t>(v);
}

void neg_u128(U128& v) {
    v.lo = ~v.lo;
    v.hi = ~v.hi;
    if (++v.lo == 0) ++v.hi;
}

U128 mul_s64(int64_t a, int64_t b) {
    U128 r = mul_u64(abs_u64(a), abs_u64(b));
    if ((a < 0) != (b < 0)) neg_u128(r);
    return r;
}

// Shift-subtract long division.  False means the quotient would not fit in 64
// bits, which on real hardware is #DE.
bool div_u128(U128 n, uint64_t d, uint64_t& q, uint64_t& r) {
    if (d == 0 || n.hi >= d) return false;
    uint64_t rem = n.hi, quot = 0;
    for (int i = 63; i >= 0; --i) {
        bool overflowed = (rem >> 63) != 0;
        rem = (rem << 1) | ((n.lo >> i) & 1);
        // If the shift pushed a bit out, the true remainder exceeds 2^64 and is
        // therefore certainly >= d; the wrapped subtraction below is still the
        // correct low 64 bits.
        if (overflowed || rem >= d) {
            rem -= d;
            quot |= (1ull << i);
        }
    }
    q = quot;
    r = rem;
    return true;
}

}  // namespace

uint64_t Cpu::fetch_imm(int size) {
    switch (size) {
        case 1: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(fetch8())));
        case 2: return fetch16();
        // A 64-bit operand takes a sign-extended 32-bit immediate.
        case 8: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(fetch32())));
        default: return fetch32();
    }
}

// ---------------------------------------------------------------------------
// ModRM / operands
// ---------------------------------------------------------------------------

Cpu::RM Cpu::decode_modrm(int imm_bytes) {
    uint8_t modrm = fetch8();
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & 7;
    modrm_reg_ = static_cast<uint8_t>(((pfx_.rex_r ? 8 : 0) | ((modrm >> 3) & 7)));

    RM out;
    if (mod == 3) {
        out.is_reg = true;
        out.reg = static_cast<uint8_t>((pfx_.rex_b ? 8 : 0) | rm);
        return out;
    }
    // 16-bit addressing exists but no 32/64-bit compiler emits it.
    if (!is64() && addrsize_ == 2)
        throw CpuError(rip, "16-bit addressing mode not supported");

    uint64_t addr = 0;
    bool rip_rel = false;

    if (rm == 4) {  // SIB byte follows
        uint8_t sib = fetch8();
        int scale = 1 << (sib >> 6);
        int index_lo = (sib >> 3) & 7;
        int base_lo = sib & 7;
        int index = (pfx_.rex_x ? 8 : 0) | index_lo;
        int base = (pfx_.rex_b ? 8 : 0) | base_lo;
        // index_lo == 4 without REX.X encodes "no index".
        if (index_lo != 4 || pfx_.rex_x) addr += regs[index] * static_cast<uint64_t>(scale);
        if (base_lo == 5 && mod == 0)
            addr += static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(fetch32())));
        else
            addr += regs[base];
    } else if (rm == 5 && mod == 0) {
        int32_t disp = static_cast<int32_t>(fetch32());
        if (is64()) {
            // RIP-relative: measured from the end of the entire instruction, so
            // the caller has to tell us how many immediate bytes still follow.
            rip_rel = true;
            addr = static_cast<uint64_t>(static_cast<int64_t>(disp)) + rip +
                   static_cast<uint64_t>(imm_bytes);
        } else {
            addr = static_cast<uint32_t>(disp);
        }
    } else {
        addr = regs[(pfx_.rex_b ? 8 : 0) | rm];
    }

    if (mod == 1)
        addr += static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(fetch8())));
    else if (mod == 2)
        addr += static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(fetch32())));

    // A 0x67 prefix in long mode truncates the effective address to 32 bits;
    // in 32-bit mode the address is 32-bit anyway.
    if (addrsize_ == 4) addr &= 0xFFFFFFFFull;

    out.addr = addr + pfx_.seg_base;
    out.rip_relative = rip_rel;
    return out;
}

uint64_t Cpu::rm_read(const RM& rm, int size) const {
    if (rm.is_reg) return reg_read(rm.reg, size);
    return mem_.read_sized(rm.addr, size);
}

void Cpu::rm_write(const RM& rm, int size, uint64_t v) {
    if (rm.is_reg) {
        reg_write(rm.reg, size, v);
        return;
    }
    mem_.write_sized(rm.addr, size, v);
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

void Cpu::set_szp(uint64_t res, int size) {
    res &= mask_of(size);
    set_flag(FLAG_ZF, res == 0);
    set_flag(FLAG_SF, (res & msb_of(size)) != 0);
    set_flag(FLAG_PF, even_parity(res));
}

void Cpu::set_flags_add(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t res, int size) {
    uint64_t m = mask_of(size), sign = msb_of(size);
    a &= m;
    b &= m;
    res &= m;
    bool cf;
    if (size == 8)
        cf = (res < a) || (carry_in && res == a);
    else
        cf = ((a + b + carry_in) >> (size * 8)) != 0;
    set_flag(FLAG_CF, cf);
    set_flag(FLAG_AF, ((a ^ b ^ res) & 0x10) != 0);
    // Overflow when both inputs share a sign that the result does not.
    set_flag(FLAG_OF, ((~(a ^ b) & (a ^ res)) & sign) != 0);
    set_szp(res, size);
}

void Cpu::set_flags_sub(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t res, int size) {
    uint64_t m = mask_of(size), sign = msb_of(size);
    a &= m;
    b &= m;
    res &= m;
    // Written this way so that b + borrow_in cannot overflow at size 8.
    set_flag(FLAG_CF, borrow_in ? (a <= b) : (a < b));
    set_flag(FLAG_AF, ((a ^ b ^ res) & 0x10) != 0);
    set_flag(FLAG_OF, (((a ^ b) & (a ^ res)) & sign) != 0);
    set_szp(res, size);
}

void Cpu::set_flags_logic(uint64_t res, int size) {
    set_flag(FLAG_CF, false);
    set_flag(FLAG_OF, false);
    set_flag(FLAG_AF, false);
    set_szp(res, size);
}

bool Cpu::cond(uint8_t cc) const {
    switch (cc & 0xF) {
        case 0x0: return flag(FLAG_OF);                                     // O
        case 0x1: return !flag(FLAG_OF);                                    // NO
        case 0x2: return flag(FLAG_CF);                                     // B
        case 0x3: return !flag(FLAG_CF);                                    // AE
        case 0x4: return flag(FLAG_ZF);                                     // E
        case 0x5: return !flag(FLAG_ZF);                                    // NE
        case 0x6: return flag(FLAG_CF) || flag(FLAG_ZF);                    // BE
        case 0x7: return !flag(FLAG_CF) && !flag(FLAG_ZF);                  // A
        case 0x8: return flag(FLAG_SF);                                     // S
        case 0x9: return !flag(FLAG_SF);                                    // NS
        case 0xA: return flag(FLAG_PF);                                     // P
        case 0xB: return !flag(FLAG_PF);                                    // NP
        case 0xC: return flag(FLAG_SF) != flag(FLAG_OF);                    // L
        case 0xD: return flag(FLAG_SF) == flag(FLAG_OF);                    // GE
        case 0xE: return flag(FLAG_ZF) || (flag(FLAG_SF) != flag(FLAG_OF)); // LE
        default: return !flag(FLAG_ZF) && (flag(FLAG_SF) == flag(FLAG_OF)); // G
    }
}

// ---------------------------------------------------------------------------
// ALU / shifts
// ---------------------------------------------------------------------------

uint64_t Cpu::alu(int op, uint64_t a, uint64_t b, int size) {
    uint64_t m = mask_of(size);
    a &= m;
    b &= m;
    uint64_t r = 0;
    switch (op) {
        case 0:  // ADD
            r = (a + b) & m;
            set_flags_add(a, b, 0, r, size);
            break;
        case 1:  // OR
            r = (a | b) & m;
            set_flags_logic(r, size);
            break;
        case 2: {  // ADC
            uint64_t c = flag(FLAG_CF) ? 1 : 0;
            r = (a + b + c) & m;
            set_flags_add(a, b, c, r, size);
            break;
        }
        case 3: {  // SBB
            uint64_t c = flag(FLAG_CF) ? 1 : 0;
            r = (a - b - c) & m;
            set_flags_sub(a, b, c, r, size);
            break;
        }
        case 4:  // AND
            r = (a & b) & m;
            set_flags_logic(r, size);
            break;
        case 5:  // SUB
        case 7:  // CMP (the caller discards the result)
            r = (a - b) & m;
            set_flags_sub(a, b, 0, r, size);
            break;
        default:  // 6: XOR
            r = (a ^ b) & m;
            set_flags_logic(r, size);
            break;
    }
    return r;
}

uint64_t Cpu::shift(int op, uint64_t v, uint64_t count, int size) {
    uint64_t m = mask_of(size), sign = msb_of(size);
    const int bits = size * 8;
    v &= m;
    // x86 masks the count to 5 bits, or 6 for 64-bit operands.
    count &= (size == 8) ? 0x3Full : 0x1Full;
    if (count == 0) return v;

    uint64_t r = v;
    switch (op) {
        case 0: {  // ROL
            uint64_t c = count % static_cast<uint64_t>(bits);
            if (c) r = ((v << c) | (v >> (bits - c))) & m;
            set_flag(FLAG_CF, (r & 1) != 0);
            set_flag(FLAG_OF, ((r & sign) != 0) != ((r & 1) != 0));
            break;
        }
        case 1: {  // ROR
            uint64_t c = count % static_cast<uint64_t>(bits);
            if (c) r = ((v >> c) | (v << (bits - c))) & m;
            set_flag(FLAG_CF, (r & sign) != 0);
            set_flag(FLAG_OF, ((r & sign) != 0) != ((r & (sign >> 1)) != 0));
            break;
        }
        case 2: {  // RCL
            uint64_t c = count % static_cast<uint64_t>(bits + 1);
            for (uint64_t i = 0; i < c; ++i) {
                bool new_cf = (r & sign) != 0;
                r = ((r << 1) | (flag(FLAG_CF) ? 1ull : 0ull)) & m;
                set_flag(FLAG_CF, new_cf);
            }
            set_flag(FLAG_OF, ((r & sign) != 0) != flag(FLAG_CF));
            break;
        }
        case 3: {  // RCR
            uint64_t c = count % static_cast<uint64_t>(bits + 1);
            for (uint64_t i = 0; i < c; ++i) {
                bool new_cf = (r & 1) != 0;
                r = ((r >> 1) | (flag(FLAG_CF) ? sign : 0ull)) & m;
                set_flag(FLAG_CF, new_cf);
            }
            break;
        }
        case 4:
        case 6: {  // SHL / SAL
            // The count can exceed the operand width for 8/16-bit operands,
            // since masking uses the register width, not the operand width.
            bool cf = count > static_cast<uint64_t>(bits)
                          ? false
                          : ((v >> (bits - count)) & 1) != 0;
            r = (count >= static_cast<uint64_t>(bits)) ? 0ull : ((v << count) & m);
            set_flag(FLAG_CF, cf);
            set_flag(FLAG_OF, cf != ((r & sign) != 0));
            set_szp(r, size);
            return r;
        }
        case 5: {  // SHR
            bool cf = ((v >> (count - 1)) & 1) != 0;
            r = (count >= static_cast<uint64_t>(bits)) ? 0ull : (v >> count);
            set_flag(FLAG_CF, cf);
            set_flag(FLAG_OF, (v & sign) != 0);
            set_szp(r, size);
            return r;
        }
        default: {  // 7: SAR
            int64_t sv = sign_ext(v, size);
            uint64_t sh = count >= static_cast<uint64_t>(bits)
                              ? static_cast<uint64_t>(bits - 1)
                              : count;
            bool cf = ((sv >> (sh ? sh - 1 : 0)) & 1) != 0;
            r = static_cast<uint64_t>(sv >> sh) & m;
            set_flag(FLAG_CF, cf);
            set_flag(FLAG_OF, false);
            set_szp(r, size);
            return r;
        }
    }
    return r;
}

// ---------------------------------------------------------------------------
// Opcode groups
// ---------------------------------------------------------------------------

void Cpu::group3(RM& rm, int size, int op) {
    uint64_t m = mask_of(size);
    if (op <= 1) {  // TEST rm, imm
        int imm_bytes = imm_size_for(size);
        uint64_t imm = fetch_imm(size);
        fixup_rip_relative(rm, imm_bytes);
        set_flags_logic((rm_read(rm, size) & imm) & m, size);
        return;
    }
    uint64_t v = rm_read(rm, size);
    switch (op) {
        case 2:  // NOT (flags unaffected)
            rm_write(rm, size, ~v & m);
            break;
        case 3: {  // NEG
            uint64_t r = (0ull - v) & m;
            set_flags_sub(0, v, 0, r, size);
            set_flag(FLAG_CF, (v & m) != 0);
            rm_write(rm, size, r);
            break;
        }
        case 4: {  // MUL (unsigned)
            bool upper_nonzero;
            if (size == 8) {
                U128 res = mul_u64(regs[RAX], v);
                regs[RAX] = res.lo;
                regs[RDX] = res.hi;
                upper_nonzero = res.hi != 0;
                set_szp(res.lo, size);
            } else {
                uint64_t res = reg_read(RAX, size) * (v & m);
                if (size == 1) {
                    reg_write(RAX, 2, res & 0xFFFF);
                } else {
                    reg_write(RAX, size, res);
                    reg_write(RDX, size, res >> (size * 8));
                }
                upper_nonzero = (res >> (size * 8)) != 0;
                set_szp(res, size);
            }
            set_flag(FLAG_CF, upper_nonzero);
            set_flag(FLAG_OF, upper_nonzero);
            break;
        }
        case 5: {  // IMUL (signed, one operand)
            bool trunc;
            if (size == 8) {
                U128 res = mul_s64(static_cast<int64_t>(regs[RAX]), sign_ext(v, 8));
                regs[RAX] = res.lo;
                regs[RDX] = res.hi;
                // The upper half must be a pure sign extension of the lower.
                trunc = res.hi != ((res.lo & msb_of(8)) ? ~0ull : 0ull);
                set_szp(res.lo, size);
            } else {
                int64_t res = sign_ext(reg_read(RAX, size), size) * sign_ext(v, size);
                uint64_t ures = static_cast<uint64_t>(res);
                if (size == 1) {
                    reg_write(RAX, 2, ures & 0xFFFF);
                } else {
                    reg_write(RAX, size, ures);
                    reg_write(RDX, size, ures >> (size * 8));
                }
                trunc = res != sign_ext(ures & m, size);
                set_szp(ures, size);
            }
            set_flag(FLAG_CF, trunc);
            set_flag(FLAG_OF, trunc);
            break;
        }
        case 6: {  // DIV (unsigned)
            uint64_t d = v & m;
            if (d == 0) throw CpuError(rip, "divide by zero");
            if (size == 1) {
                uint32_t num = static_cast<uint32_t>(reg_read(RAX, 2));
                uint32_t q = num / static_cast<uint32_t>(d), r = num % static_cast<uint32_t>(d);
                if (q > 0xFF) throw CpuError(rip, "divide overflow");
                reg_write(RAX, 2, (r << 8) | (q & 0xFF));
            } else if (size == 8) {
                U128 num{regs[RAX], regs[RDX]};
                uint64_t q, r;
                if (!div_u128(num, d, q, r)) throw CpuError(rip, "divide overflow");
                regs[RAX] = q;
                regs[RDX] = r;
            } else {
                uint64_t num = (reg_read(RDX, size) << (size * 8)) | reg_read(RAX, size);
                uint64_t q = num / d, r = num % d;
                if (q > m) throw CpuError(rip, "divide overflow");
                reg_write(RAX, size, q);
                reg_write(RDX, size, r);
            }
            break;
        }
        default: {  // 7: IDIV (signed)
            int64_t d = sign_ext(v, size);
            if (d == 0) throw CpuError(rip, "divide by zero");
            if (size == 1) {
                int32_t num = static_cast<int16_t>(reg_read(RAX, 2));
                int32_t q = num / static_cast<int32_t>(d), r = num % static_cast<int32_t>(d);
                if (q > 127 || q < -128) throw CpuError(rip, "divide overflow");
                reg_write(RAX, 2, ((static_cast<uint64_t>(r) & 0xFF) << 8) |
                                      (static_cast<uint64_t>(q) & 0xFF));
            } else if (size == 8) {
                U128 num{regs[RAX], regs[RDX]};
                bool num_neg = (num.hi & msb_of(8)) != 0;
                if (num_neg) neg_u128(num);
                uint64_t uq, ur;
                if (!div_u128(num, abs_u64(d), uq, ur)) throw CpuError(rip, "divide overflow");
                bool q_neg = num_neg != (d < 0);
                int64_t q = q_neg ? -static_cast<int64_t>(uq) : static_cast<int64_t>(uq);
                int64_t r = num_neg ? -static_cast<int64_t>(ur) : static_cast<int64_t>(ur);
                if (!q_neg && (uq & msb_of(8))) throw CpuError(rip, "divide overflow");
                regs[RAX] = static_cast<uint64_t>(q);
                regs[RDX] = static_cast<uint64_t>(r);
            } else {
                int64_t num = sign_ext((reg_read(RDX, size) << (size * 8)) | reg_read(RAX, size),
                                       size * 2);
                int64_t q = num / d, r = num % d;
                int64_t lim = static_cast<int64_t>(msb_of(size));
                if (q >= lim || q < -lim) throw CpuError(rip, "divide overflow");
                reg_write(RAX, size, static_cast<uint64_t>(q));
                reg_write(RDX, size, static_cast<uint64_t>(r));
            }
            break;
        }
    }
}

void Cpu::group5(const RM& rm, int size, int op) {
    switch (op) {
        case 0: {  // INC (CF preserved)
            uint64_t v = rm_read(rm, size);
            uint64_t r = (v + 1) & mask_of(size);
            bool cf = flag(FLAG_CF);
            set_flags_add(v, 1, 0, r, size);
            set_flag(FLAG_CF, cf);
            rm_write(rm, size, r);
            break;
        }
        case 1: {  // DEC (CF preserved)
            uint64_t v = rm_read(rm, size);
            uint64_t r = (v - 1) & mask_of(size);
            bool cf = flag(FLAG_CF);
            set_flags_sub(v, 1, 0, r, size);
            set_flag(FLAG_CF, cf);
            rm_write(rm, size, r);
            break;
        }
        // CALL/JMP/PUSH through ModRM default to the full pointer width.
        case 2:
            push(rip);
            rip = rm_read(rm, is64() ? 8 : 4);
            break;
        case 4:
            rip = rm_read(rm, is64() ? 8 : 4);
            break;
        case 6:
            push(rm_read(rm, is64() ? 8 : 4));
            break;
        case 3:
        case 5:
            throw CpuError(rip, "far call/jmp not supported");
        default:
            throw CpuError(rip, "invalid group 5 opcode");
    }
}

void Cpu::do_string_op(uint8_t opcode, int size) {
    int64_t delta = flag(FLAG_DF) ? -size : size;
    bool repeating = pfx_.rep || pfx_.repne;
    uint64_t addr_mask = (addrsize_ == 4) ? 0xFFFFFFFFull : ~0ull;
    // ECX vs RCX for the repeat count.
    int count_size = addrsize_;

    for (;;) {
        if (repeating && reg_read(RCX, count_size) == 0) break;

        uint64_t src = regs[RSI] & addr_mask;
        uint64_t dst = regs[RDI] & addr_mask;
        switch (opcode) {
            case 0xA4:
            case 0xA5:  // MOVS
                mem_.write_sized(dst, size, mem_.read_sized(src, size));
                regs[RSI] += static_cast<uint64_t>(delta);
                regs[RDI] += static_cast<uint64_t>(delta);
                break;
            case 0xAA:
            case 0xAB:  // STOS
                mem_.write_sized(dst, size, reg_read(RAX, size));
                regs[RDI] += static_cast<uint64_t>(delta);
                break;
            case 0xAC:
            case 0xAD:  // LODS
                reg_write(RAX, size, mem_.read_sized(src, size));
                regs[RSI] += static_cast<uint64_t>(delta);
                break;
            case 0xA6:
            case 0xA7:  // CMPS
                alu(7, mem_.read_sized(src, size), mem_.read_sized(dst, size), size);
                regs[RSI] += static_cast<uint64_t>(delta);
                regs[RDI] += static_cast<uint64_t>(delta);
                break;
            default:  // 0xAE / 0xAF: SCAS
                alu(7, reg_read(RAX, size), mem_.read_sized(dst, size), size);
                regs[RDI] += static_cast<uint64_t>(delta);
                break;
        }

        if (!repeating) break;
        reg_write(RCX, count_size, reg_read(RCX, count_size) - 1);
        // CMPS/SCAS additionally stop on the ZF condition selected by the prefix.
        bool compares = opcode == 0xA6 || opcode == 0xA7 || opcode == 0xAE || opcode == 0xAF;
        if (compares) {
            if (pfx_.rep && !flag(FLAG_ZF)) break;
            if (pfx_.repne && flag(FLAG_ZF)) break;
        }
        if (reg_read(RCX, count_size) == 0) break;
    }
}

// ---------------------------------------------------------------------------
// 0x0F escape opcodes
// ---------------------------------------------------------------------------

void Cpu::execute_0f() {
    uint64_t start = rip - 1;
    uint8_t op = fetch8();

    // SSE shares this opcode space, distinguished by a mandatory prefix; it
    // returns false for anything that is a general-purpose instruction.
    if (execute_sse(op)) return;

    if (op >= 0x80 && op <= 0x8F) {  // Jcc rel32
        int32_t rel = static_cast<int32_t>(fetch32());
        if (cond(op & 0xF)) rip += static_cast<uint64_t>(static_cast<int64_t>(rel));
        return;
    }
    if (op >= 0x90 && op <= 0x9F) {  // SETcc rm8
        RM rm = decode_modrm();
        rm_write(rm, 1, cond(op & 0xF) ? 1 : 0);
        return;
    }
    if (op >= 0x40 && op <= 0x4F) {  // CMOVcc reg, rm
        RM rm = decode_modrm();
        uint64_t v = rm_read(rm, opsize_);
        // The destination is written even when the condition fails at operand
        // size 4, because that is what zero extension into the upper half means.
        if (cond(op & 0xF))
            reg_write(modrm_reg_, opsize_, v);
        else if (opsize_ == 4)
            reg_write(modrm_reg_, 4, reg_read(modrm_reg_, 4));
        return;
    }
    if (op >= 0xC8 && op <= 0xCF) {  // BSWAP
        int r = ((pfx_.rex_b ? 8 : 0) | (op - 0xC8));
        uint64_t v = regs[r];
        if (opsize_ == 8) {
            uint64_t s = 0;
            for (int i = 0; i < 8; ++i) s |= ((v >> (i * 8)) & 0xFF) << ((7 - i) * 8);
            regs[r] = s;
        } else {
            uint32_t x = static_cast<uint32_t>(v);
            reg_write(r, 4, (x >> 24) | ((x >> 8) & 0xFF00u) | ((x << 8) & 0xFF0000u) | (x << 24));
        }
        return;
    }

    switch (op) {
        case 0x05:  // SYSCALL
            if (!on_syscall) throw CpuError(start, "syscall with no handler installed");
            on_syscall();
            return;
        case 0x0B:
            throw CpuError(start, "UD2 executed");
        case 0x0D:  // prefetch hints
        case 0x18:
        case 0x19:
        case 0x1A:
        case 0x1B:
        case 0x1C:
        case 0x1D:
        case 0x1E:
        case 0x1F:  // multi-byte NOP
            decode_modrm();
            return;
        case 0x31:  // RDTSC - the instruction counter is a fine monotonic clock
            reg_write(RAX, 4, instructions_executed & 0xFFFFFFFFull);
            reg_write(RDX, 4, instructions_executed >> 32);
            return;
        case 0xA2: {
            // CPUID must advertise exactly what this emulator implements and no
            // more: a libc picks its memcpy/strlen implementation from these
            // bits, so claiming AVX or SSE4.2 here would make it jump straight
            // into instructions that do not exist.  SSE2 and CMOV are safe (see
            // sse.cpp); POPCNT and everything newer are not.  MMX and FXSR are
            // advertised because glibc's ld.so refuses to load anything marked
            // x86-64-baseline without them (and SCE below, likewise): FXSAVE/
            // FXRSTOR are real (sse.cpp), and nothing on x86-64 emits actual
            // MMX code once SSE2 is there.
            enum : uint32_t {
                EDX_FPU = 1u << 0,
                EDX_TSC = 1u << 4,
                EDX_CX8 = 1u << 8,
                EDX_CMOV = 1u << 15,
                EDX_MMX = 1u << 23,
                EDX_FXSR = 1u << 24,
                EDX_SSE = 1u << 25,
                EDX_SSE2 = 1u << 26,
                ECX_PCLMULQDQ = 1u << 1,
                ECX_AES = 1u << 25,
            };
            switch (static_cast<uint32_t>(regs[RAX])) {
                case 0:
                    // Highest basic leaf 1: nothing here answers leaf 7, and
                    // saying so keeps a libc from probing for AVX2.
                    regs[RAX] = 1;
                    regs[RBX] = 0x756E6547;  // "Genu"
                    regs[RDX] = 0x49656E69;  // "ineI"
                    regs[RCX] = 0x6C65746E;  // "ntel"
                    break;
                case 1:
                    regs[RAX] = 0x000306C3;  // a Haswell-era family/model/stepping
                    regs[RBX] = 0x00000800;  // one logical processor, CLFLUSH 64B
                    // AES and PCLMULQDQ are the exception to "advertise nothing
                    // in ECX": both are implemented (sse.cpp), and neither is a
                    // bit glibc's IFUNC dispatch consults, so turning them on
                    // does not drag memcpy into SSSE3 code that is not here.
                    // A crypto library that finds no AES bit does not reliably
                    // fall back to software - it can decline to transform the
                    // data at all, and hand its caller the input unchanged.
                    regs[RCX] = ECX_PCLMULQDQ | ECX_AES;
                    regs[RDX] = EDX_FPU | EDX_TSC | EDX_CX8 | EDX_CMOV | EDX_MMX |
                                EDX_FXSR | EDX_SSE | EDX_SSE2;
                    break;
                case 0x80000000:
                    regs[RAX] = 0x80000001;
                    regs[RBX] = regs[RCX] = regs[RDX] = 0;
                    break;
                case 0x80000001:
                    regs[RAX] = regs[RBX] = regs[RCX] = 0;
                    // Long mode, and SYSCALL (bit 11) - the instruction is real
                    // here, and glibc's baseline ISA check insists on the bit.
                    regs[RDX] = is64() ? (1u << 29) | (1u << 11) : 0;
                    break;
                default:
                    regs[RAX] = regs[RBX] = regs[RCX] = regs[RDX] = 0;
                    break;
            }
            return;
        }
        case 0xAF: {  // IMUL reg, rm
            RM rm = decode_modrm();
            int64_t a = sign_ext(reg_read(modrm_reg_, opsize_), opsize_);
            int64_t b = sign_ext(rm_read(rm, opsize_), opsize_);
            uint64_t r;
            bool trunc;
            if (opsize_ == 8) {
                U128 res = mul_s64(a, b);
                r = res.lo;
                trunc = res.hi != ((r & msb_of(8)) ? ~0ull : 0ull);
            } else {
                int64_t res = a * b;
                r = static_cast<uint64_t>(res) & mask_of(opsize_);
                trunc = res != sign_ext(r, opsize_);
            }
            set_flag(FLAG_CF, trunc);
            set_flag(FLAG_OF, trunc);
            set_szp(r, opsize_);
            reg_write(modrm_reg_, opsize_, r);
            return;
        }
        case 0xB6:
        case 0xB7: {  // MOVZX
            int src = op == 0xB6 ? 1 : 2;
            RM rm = decode_modrm();
            reg_write(modrm_reg_, opsize_, rm_read(rm, src) & mask_of(src));
            return;
        }
        case 0xBE:
        case 0xBF: {  // MOVSX
            int src = op == 0xBE ? 1 : 2;
            RM rm = decode_modrm();
            reg_write(modrm_reg_, opsize_, static_cast<uint64_t>(sign_ext(rm_read(rm, src), src)));
            return;
        }
        case 0xBC:
        case 0xBD: {  // BSF / BSR
            RM rm = decode_modrm();
            uint64_t v = rm_read(rm, opsize_) & mask_of(opsize_);
            set_flag(FLAG_ZF, v == 0);
            if (v != 0) {
                int idx;
                if (op == 0xBC) {
                    idx = 0;
                    while (!((v >> idx) & 1)) ++idx;
                } else {
                    idx = opsize_ * 8 - 1;
                    while (!((v >> idx) & 1)) --idx;
                }
                reg_write(modrm_reg_, opsize_, static_cast<uint64_t>(idx));
            }
            return;
        }
        case 0xA3:
        case 0xAB:
        case 0xB3:
        case 0xBB: {  // BT / BTS / BTR / BTC, register bit index
            RM rm = decode_modrm();
            RM target = rm;
            uint64_t bit;
            if (rm.is_reg) {
                bit = reg_read(modrm_reg_, opsize_) & (opsize_ * 8 - 1);
            } else {
                // With a memory destination the offset is *not* truncated to the
                // operand width: it is signed and addresses a bit anywhere in
                // memory, so the operand moves with it.  Truncating instead
                // silently rewrites the wrong bit of the wrong word, which is
                // how a guest's bitmap (GCC's, for one) quietly corrupts itself.
                int bits = opsize_ * 8;
                int shift = opsize_ == 8 ? 6 : opsize_ == 4 ? 5 : 4;
                int64_t offset = sign_ext(reg_read(modrm_reg_, opsize_), opsize_);
                // An arithmetic shift floors, which is the rounding negative
                // offsets need.
                target.addr = rm.addr + static_cast<uint64_t>((offset >> shift) * opsize_);
                bit = static_cast<uint64_t>(offset) & static_cast<uint64_t>(bits - 1);
            }
            uint64_t v = rm_read(target, opsize_);
            set_flag(FLAG_CF, ((v >> bit) & 1) != 0);
            if (op == 0xAB) v |= (1ull << bit);
            if (op == 0xB3) v &= ~(1ull << bit);
            if (op == 0xBB) v ^= (1ull << bit);
            if (op != 0xA3) rm_write(target, opsize_, v);
            return;
        }
        case 0xBA: {  // BT/BTS/BTR/BTC, immediate bit index
            RM rm = decode_modrm(1);
            int sub = modrm_reg_ & 7;
            uint64_t bit = fetch8() & (opsize_ * 8 - 1);
            uint64_t v = rm_read(rm, opsize_);
            set_flag(FLAG_CF, ((v >> bit) & 1) != 0);
            if (sub == 5) v |= (1ull << bit);
            if (sub == 6) v &= ~(1ull << bit);
            if (sub == 7) v ^= (1ull << bit);
            if (sub != 4) rm_write(rm, opsize_, v);
            return;
        }
        case 0xA4:
        case 0xAC:
        case 0xA5:
        case 0xAD: {  // SHLD / SHRD; the count is an immediate or CL
            bool from_cl = op == 0xA5 || op == 0xAD;
            bool left = op == 0xA4 || op == 0xA5;
            RM rm = decode_modrm(from_cl ? 0 : 1);
            uint64_t src = reg_read(modrm_reg_, opsize_);
            uint64_t count = (from_cl ? regs[RCX] : fetch8()) & (opsize_ == 8 ? 63 : 31);
            uint64_t dst = rm_read(rm, opsize_);
            int bits = opsize_ * 8;
            if (count == 0) {
                // A count of zero shifts nothing and touches no flag, but the
                // destination register is still written - and a 32-bit write
                // zeroes the upper half.  Returning without writing leaves the
                // old upper half in place, which is a different 64-bit value.
                if (rm.is_reg) rm_write(rm, opsize_, dst);
                return;
            }
            if (count < static_cast<uint64_t>(bits)) {
                uint64_t r = left ? ((dst << count) | (src >> (bits - count)))
                                  : ((dst >> count) | (src << (bits - count)));
                r &= mask_of(opsize_);
                set_flag(FLAG_CF, left ? ((dst >> (bits - count)) & 1) != 0
                                       : ((dst >> (count - 1)) & 1) != 0);
                set_szp(r, opsize_);
                // OF is defined for a count of one only, and then it says the
                // sign changed.  For any other count it is undefined and left
                // alone deliberately.
                if (count == 1) {
                    uint64_t sign = 1ull << (bits - 1);
                    set_flag(FLAG_OF, ((dst ^ r) & sign) != 0);
                }
                rm_write(rm, opsize_, r);
            }
            return;
        }
        case 0xB0:
        case 0xB1: {  // CMPXCHG
            int size = op == 0xB0 ? 1 : opsize_;
            RM rm = decode_modrm();
            uint64_t dst = rm_read(rm, size);
            uint64_t acc = reg_read(RAX, size);
            alu(7, acc, dst, size);
            if (acc == dst)
                rm_write(rm, size, reg_read(modrm_reg_, size));
            else
                reg_write(RAX, size, dst);
            return;
        }
        case 0xC7: {  // group 9: CMPXCHG8B / CMPXCHG16B
            RM rm = decode_modrm();
            int sub = modrm_reg_ & 7;
            if (sub != 1 || rm.is_reg) throw CpuError(start, "unsupported 0F C7 form");
            if (pfx_.rex_w) {  // CMPXCHG16B m128
                uint64_t lo = mem_.read64(rm.addr), hi = mem_.read64(rm.addr + 8);
                if (lo == regs[RAX] && hi == regs[RDX]) {
                    mem_.write64(rm.addr, regs[RBX]);
                    mem_.write64(rm.addr + 8, regs[RCX]);
                    set_flag(FLAG_ZF, true);
                } else {
                    regs[RAX] = lo;
                    regs[RDX] = hi;
                    set_flag(FLAG_ZF, false);
                }
                return;
            }
            // CMPXCHG8B m64: compare EDX:EAX, exchange with ECX:EBX.
            uint64_t cur = mem_.read64(rm.addr);
            uint64_t want = (regs[RDX] << 32) | (regs[RAX] & 0xFFFFFFFFull);
            if (cur == want) {
                mem_.write64(rm.addr, (regs[RCX] << 32) | (regs[RBX] & 0xFFFFFFFFull));
                set_flag(FLAG_ZF, true);
            } else {
                reg_write(RAX, 4, cur & 0xFFFFFFFFull);
                reg_write(RDX, 4, cur >> 32);
                set_flag(FLAG_ZF, false);
            }
            return;
        }
        case 0xC0:
        case 0xC1: {  // XADD
            int size = op == 0xC0 ? 1 : opsize_;
            RM rm = decode_modrm();
            uint64_t dst = rm_read(rm, size);
            uint64_t src = reg_read(modrm_reg_, size);
            uint64_t r = alu(0, dst, src, size);
            reg_write(modrm_reg_, size, dst);
            rm_write(rm, size, r);
            return;
        }
        default:
            unsupported("0F opcode", op, start);
    }
}

// ---------------------------------------------------------------------------
// Main dispatch
// ---------------------------------------------------------------------------

// Where the samples fell, by mapping, commonest first.
//
// Regions can overlap - map() is called with a name more than once over the
// same span - so a sample is attributed to the *last* one that contains it,
// which is the same rule the fault message uses and keeps the two consistent.
std::string Cpu::profile_report() const {
    if (profile_samples_.empty()) return {};
    const auto& regions = mem_.regions();
    std::unordered_map<std::string, uint64_t> hits;
    uint64_t unattributed = 0;
    for (uint64_t rip : profile_samples_) {
        const std::string* where = nullptr;
        for (const auto& r : regions)
            if (rip >= r.base && rip < r.base + r.size) where = &r.name;
        if (where)
            hits[*where]++;
        else
            unattributed++;
    }
    std::vector<std::pair<uint64_t, std::string>> sorted;
    for (const auto& [name, n] : hits) sorted.push_back({n, name});
    if (unattributed) sorted.push_back({unattributed, "(unmapped or hooks)"});
    std::sort(sorted.rbegin(), sorted.rend());

    std::string out = "[profile] " + std::to_string(profile_samples_.size()) +
                      " samples, one every " + std::to_string(profile_every_) +
                      " instructions\n";
    char line[256];
    double total = static_cast<double>(profile_samples_.size());
    for (const auto& [n, name] : sorted) {
        std::snprintf(line, sizeof line, "[profile] %6.2f %%  %8llu  %s\n",
                      100.0 * static_cast<double>(n) / total,
                      static_cast<unsigned long long>(n), name.c_str());
        out += line;
    }
    return out;
}

void Cpu::unsupported(const char* what, uint8_t opcode, uint64_t start_rip) {
    // Show a few raw bytes so an unknown encoding can be looked up quickly.
    char bytes[64] = {};
    int n = 0;
    for (int i = 0; i < 8 && n < static_cast<int>(sizeof(bytes)) - 4; ++i) {
        try {
            n += std::snprintf(bytes + n, sizeof(bytes) - n, "%02X ", mem_.read8(start_rip + i));
        } catch (const MemoryFault&) {
            break;
        }
    }
    // Which mapping the address is in.  A bare address says nothing when a
    // dozen libraries are loaded; the name says whether this is the guest's own
    // code, the C library, or some third-party .so that wants an instruction
    // set this emulator does not have.
    std::string where;
    for (const auto& r : mem_.regions())
        if (start_rip >= r.base && start_rip < r.base + r.size) where = r.name;

    char buf[256];
    std::snprintf(buf, sizeof buf, "unsupported %s 0x%02X at 0x%llX [%s]%s%s", what, opcode,
                  static_cast<unsigned long long>(start_rip), bytes,
                  where.empty() ? "" : " in ", where.c_str());
    throw CpuError(start_rip, buf);
}

void Cpu::step() {
    // A hook address is not real code: hand control to the host implementation.
    if (on_hook_call && on_hook_call(rip)) {
        ++instructions_executed;
        return;
    }

    uint64_t start = rip;
    g_watch_rip = start;
    if (--profile_countdown_ == 0) {
        profile_countdown_ = profile_every_ ? profile_every_ : ~0ull;
        if (profile_every_) profile_samples_.push_back(start);
    }
    if (g_census) g_census->record(start);
    if (!history_.empty()) {
        history_[history_pos_] = start;
        history_pos_ = (history_pos_ + 1) % history_.size();
        if (history_filled_ < history_.size()) ++history_filled_;
    }
    pfx_ = Prefixes{};

    // Prefix bytes.  Segment overrides other than fs:/gs: are accepted and
    // ignored, because the loaders set up a flat address space.
    //
    // A switch, not a chain of comparisons: this runs for every instruction the
    // guest executes, and the chain it replaces tested nine other things before
    // reaching REX - which is the commonest prefix there is in 64-bit code, and
    // "no prefix at all" was the tenth.
    bool more_prefixes = true;
    while (more_prefixes) {
        uint8_t b = mem_.read8(rip);
        switch (b) {
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                // In 32-bit mode these are INC/DEC, not prefixes.
                if (!is64()) {
                    more_prefixes = false;
                    break;
                }
                pfx_.has_rex = true;
                pfx_.rex_w = (b & 8) != 0;
                pfx_.rex_r = (b & 4) != 0;
                pfx_.rex_x = (b & 2) != 0;
                pfx_.rex_b = (b & 1) != 0;
                ++rip;
                more_prefixes = false;  // REX must be the last prefix
                break;
            case 0x66: pfx_.opsize16 = true; ++rip; break;
            case 0x67: pfx_.addr_override = true; ++rip; break;
            case 0xF0: pfx_.lock = true; ++rip; break;
            case 0xF2: pfx_.repne = true; ++rip; break;
            case 0xF3: pfx_.rep = true; ++rip; break;
            case 0x64: pfx_.seg_base = fs_base; pfx_.seg_override = true; ++rip; break;
            case 0x65: pfx_.seg_base = gs_base; pfx_.seg_override = true; ++rip; break;
            // cs:/ss:/ds:/es: - all zero based here
            case 0x2E: case 0x36: case 0x3E: case 0x26: ++rip; break;
            default: more_prefixes = false; break;
        }
    }

    opsize_ = pfx_.rex_w ? 8 : (pfx_.opsize16 ? 2 : 4);
    if (is64())
        addrsize_ = pfx_.addr_override ? 4 : 8;
    else
        addrsize_ = pfx_.addr_override ? 2 : 4;

    if (trace) std::fprintf(stderr, "%s\n", state_line().c_str());

    uint8_t op = fetch8();
    ++instructions_executed;

    // 0x00-0x3F: the eight ALU operations, six encodings each.  (0x0F is the
    // escape byte and the x/7 slots are BCD instructions, both excluded.)
    if (op < 0x40 && (op & 7) < 6 && op != 0x0F) {
        int aluop = (op >> 3) & 7;
        int lo = op & 7;
        int size = (lo == 0 || lo == 2 || lo == 4) ? 1 : opsize_;
        if (lo <= 3) {
            RM rm = decode_modrm();
            if (lo <= 1) {  // rm <- rm op reg
                uint64_t r = alu(aluop, rm_read(rm, size), reg_read(modrm_reg_, size), size);
                if (aluop != 7) rm_write(rm, size, r);
            } else {  // reg <- reg op rm
                uint64_t r = alu(aluop, reg_read(modrm_reg_, size), rm_read(rm, size), size);
                if (aluop != 7) reg_write(modrm_reg_, size, r);
            }
        } else {  // accumulator, immediate
            uint64_t imm = fetch_imm(size);
            uint64_t r = alu(aluop, reg_read(RAX, size), imm, size);
            if (aluop != 7) reg_write(RAX, size, r);
        }
        return;
    }

    const int ptr_size = is64() ? 8 : opsize_;  // push/pop/call/jmp width

    switch (op) {
        case 0x0F:
            execute_0f();
            return;

        case 0x27:
        case 0x2F:
        case 0x37:
        case 0x3F:
            unsupported("BCD opcode", op, start);

        // 0x40-0x4F are REX prefixes in long mode, handled above; here they can
        // only be the short INC/DEC forms of 32-bit mode.
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
            RM rm{true, static_cast<uint8_t>(op & 7), 0, false};
            group5(rm, opsize_, (op < 0x48) ? 0 : 1);
            return;
        }

        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
            push(regs[(pfx_.rex_b ? 8 : 0) | (op & 7)]);
            return;

        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            reg_write((pfx_.rex_b ? 8 : 0) | (op & 7), ptr_size, pop());
            return;

        case 0x60: {  // PUSHAD (32-bit only)
            if (is64()) unsupported("opcode", op, start);
            uint64_t sp = regs[RSP];
            for (int r = 0; r < 8; ++r) push(r == RSP ? sp : regs[r]);
            return;
        }
        case 0x61: {  // POPAD (the saved ESP slot is discarded)
            if (is64()) unsupported("opcode", op, start);
            for (int r = 7; r >= 0; --r) {
                uint64_t v = pop();
                if (r != RSP) regs[r] = v;
            }
            return;
        }

        case 0x63: {  // MOVSXD (long mode) / ARPL (legacy)
            if (!is64()) unsupported("opcode", op, start);
            RM rm = decode_modrm();
            reg_write(modrm_reg_, opsize_, static_cast<uint64_t>(sign_ext(rm_read(rm, 4), 4)));
            return;
        }

        case 0x68:  // PUSH imm32 (sign extended to the pointer width)
            push(fetch_imm(is64() ? 8 : opsize_));
            return;
        case 0x6A:  // PUSH imm8
            push(static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(fetch8()))));
            return;

        case 0x69:
        case 0x6B: {  // IMUL reg, rm, imm
            int imm_bytes = op == 0x6B ? 1 : imm_size_for(opsize_);
            RM rm = decode_modrm(imm_bytes);
            int64_t a = sign_ext(rm_read(rm, opsize_), opsize_);
            int64_t b = op == 0x6B ? static_cast<int8_t>(fetch8())
                                   : sign_ext(fetch_imm(opsize_), opsize_);
            uint64_t r;
            bool trunc;
            if (opsize_ == 8) {
                U128 res = mul_s64(a, b);
                r = res.lo;
                trunc = res.hi != ((r & msb_of(8)) ? ~0ull : 0ull);
            } else {
                int64_t res = a * b;
                r = static_cast<uint64_t>(res) & mask_of(opsize_);
                trunc = res != sign_ext(r, opsize_);
            }
            set_flag(FLAG_CF, trunc);
            set_flag(FLAG_OF, trunc);
            set_szp(r, opsize_);
            reg_write(modrm_reg_, opsize_, r);
            return;
        }

        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F: {  // Jcc rel8
            int8_t rel = static_cast<int8_t>(fetch8());
            if (cond(op & 0xF)) rip += static_cast<uint64_t>(static_cast<int64_t>(rel));
            return;
        }

        case 0x80:
        case 0x81:
        case 0x83: {  // group 1: ALU rm, imm
            int size = op == 0x80 ? 1 : opsize_;
            int imm_bytes = op == 0x83 ? 1 : imm_size_for(size);
            RM rm = decode_modrm(imm_bytes);
            int aluop = modrm_reg_ & 7;
            uint64_t imm =
                op == 0x83
                    ? static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(fetch8())))
                    : fetch_imm(size);
            uint64_t r = alu(aluop, rm_read(rm, size), imm, size);
            if (aluop != 7) rm_write(rm, size, r);
            return;
        }

        case 0x84:
        case 0x85: {  // TEST rm, reg
            int size = op == 0x84 ? 1 : opsize_;
            RM rm = decode_modrm();
            set_flags_logic(rm_read(rm, size) & reg_read(modrm_reg_, size), size);
            return;
        }

        case 0x86:
        case 0x87: {  // XCHG rm, reg
            int size = op == 0x86 ? 1 : opsize_;
            RM rm = decode_modrm();
            uint64_t a = rm_read(rm, size), b = reg_read(modrm_reg_, size);
            rm_write(rm, size, b);
            reg_write(modrm_reg_, size, a);
            return;
        }

        case 0x88:
        case 0x89: {  // MOV rm, reg
            int size = op == 0x88 ? 1 : opsize_;
            RM rm = decode_modrm();
            rm_write(rm, size, reg_read(modrm_reg_, size));
            return;
        }
        case 0x8A:
        case 0x8B: {  // MOV reg, rm
            int size = op == 0x8A ? 1 : opsize_;
            RM rm = decode_modrm();
            reg_write(modrm_reg_, size, rm_read(rm, size));
            return;
        }

        case 0x8D: {  // LEA (no memory access, and no segment base either)
            RM rm = decode_modrm();
            if (rm.is_reg) throw CpuError(start, "LEA with a register operand");
            reg_write(modrm_reg_, opsize_, rm.addr - pfx_.seg_base);
            return;
        }

        case 0x8C:    // MOV r/m16, Sreg
        case 0x8E: {  // MOV Sreg, r/m16
            // Segment registers exist here only as far as 32-bit TLS needs
            // them: set_thread_area fills a GDT slot's base, glibc loads
            // %gs (or %fs) with `entry*8 | 3`, and from then on gs:/fs:
            // resolve through that base.  Everything else about selectors
            // is not modelled.
            RM rm = decode_modrm();
            const unsigned sreg = modrm_reg_ & 7;
            if (op == 0x8C) {
                rm_write(rm, 2, sreg == 5 ? gs_selector : sreg == 4 ? fs_selector : 0);
                return;
            }
            const uint16_t sel = static_cast<uint16_t>(rm_read(rm, 2));
            const unsigned slot = sel >> 3;
            if (sreg == 5) {  // GS
                gs_selector = sel;
                if (slot < kGdtSlots && gdt_base[slot]) gs_base = gdt_base[slot];
            } else if (sreg == 4) {  // FS
                fs_selector = sel;
                if (slot < kGdtSlots && gdt_base[slot]) fs_base = gdt_base[slot];
            }
            // Loads of ds/es/ss with a flat selector change nothing.
            return;
        }

        case 0x8F: {  // POP rm
            RM rm = decode_modrm();
            rm_write(rm, ptr_size, pop());
            return;
        }

        case 0x90:
            return;  // NOP (also XCHG eax, eax)
        case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97: {  // XCHG eAX, reg
            int r = (pfx_.rex_b ? 8 : 0) | (op & 7);
            uint64_t t = reg_read(RAX, opsize_);
            reg_write(RAX, opsize_, reg_read(r, opsize_));
            reg_write(r, opsize_, t);
            return;
        }

        case 0x98:  // CBW / CWDE / CDQE
            if (opsize_ == 8)
                regs[RAX] = static_cast<uint64_t>(sign_ext(regs[RAX], 4));
            else if (opsize_ == 4)
                reg_write(RAX, 4, static_cast<uint64_t>(sign_ext(regs[RAX], 2)));
            else
                reg_write(RAX, 2, static_cast<uint64_t>(sign_ext(regs[RAX], 1)));
            return;
        case 0x99:  // CWD / CDQ / CQO
            reg_write(RDX, opsize_, (reg_read(RAX, opsize_) & msb_of(opsize_)) ? ~0ull : 0ull);
            return;

        case 0x9C:  // PUSHF
            push(rflags);
            return;
        case 0x9D:  // POPF
            rflags = (pop() & 0x00254DD5ull) | 0x2;
            return;
        case 0x9E:  // SAHF
            rflags = (rflags & ~0xFFull) | ((regs[RAX] >> 8) & 0xD5ull) | 0x2;
            return;
        case 0x9F:  // LAHF
            regs[RAX] = (regs[RAX] & ~0xFF00ull) | ((rflags & 0xFF) << 8);
            return;

        case 0xA0:
        case 0xA1: {  // MOV eAX, moffs
            int size = op == 0xA0 ? 1 : opsize_;
            uint64_t addr = (is64() ? fetch64() : fetch32()) + pfx_.seg_base;
            reg_write(RAX, size, mem_.read_sized(addr, size));
            return;
        }
        case 0xA2:
        case 0xA3: {  // MOV moffs, eAX
            int size = op == 0xA2 ? 1 : opsize_;
            uint64_t addr = (is64() ? fetch64() : fetch32()) + pfx_.seg_base;
            mem_.write_sized(addr, size, reg_read(RAX, size));
            return;
        }

        case 0xA4: case 0xA5: case 0xA6: case 0xA7:
        case 0xAA: case 0xAB: case 0xAC: case 0xAD:
        case 0xAE: case 0xAF:  // string operations
            do_string_op(op, (op & 1) == 0 ? 1 : opsize_);
            return;

        case 0xA8:
        case 0xA9: {  // TEST eAX, imm
            int size = op == 0xA8 ? 1 : opsize_;
            uint64_t imm = fetch_imm(size);
            set_flags_logic(reg_read(RAX, size) & imm, size);
            return;
        }

        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:  // MOV r8, imm8
            set_reg8((pfx_.rex_b ? 8 : 0) | (op & 7), fetch8());
            return;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: {  // MOV reg, imm
            int r = (pfx_.rex_b ? 8 : 0) | (op & 7);
            // This is the one encoding that carries a full 64-bit immediate.
            reg_write(r, opsize_, opsize_ == 8 ? fetch64() : fetch_imm(opsize_));
            return;
        }

        case 0xC0:
        case 0xC1: {  // group 2: shift rm, imm8
            int size = op == 0xC0 ? 1 : opsize_;
            RM rm = decode_modrm(1);
            int sub = modrm_reg_ & 7;
            uint64_t count = fetch8();
            rm_write(rm, size, shift(sub, rm_read(rm, size), count, size));
            return;
        }
        case 0xD0:
        case 0xD1: {  // shift rm, 1
            int size = op == 0xD0 ? 1 : opsize_;
            RM rm = decode_modrm();
            rm_write(rm, size, shift(modrm_reg_ & 7, rm_read(rm, size), 1, size));
            return;
        }
        case 0xD2:
        case 0xD3: {  // shift rm, CL
            int size = op == 0xD2 ? 1 : opsize_;
            RM rm = decode_modrm();
            rm_write(rm, size, shift(modrm_reg_ & 7, rm_read(rm, size), regs[RCX] & 0xFF, size));
            return;
        }

        case 0xC2: {  // RET imm16
            uint16_t n = fetch16();
            rip = pop();
            regs[RSP] += n;
            return;
        }
        case 0xC3:  // RET
            rip = pop();
            return;

        case 0xC6:
        case 0xC7: {  // MOV rm, imm
            int size = op == 0xC6 ? 1 : opsize_;
            RM rm = decode_modrm(imm_size_for(size));
            uint64_t imm = fetch_imm(size);
            rm_write(rm, size, imm);
            return;
        }

        case 0xC8: {  // ENTER imm16, imm8
            uint16_t frame = fetch16();
            uint8_t level = fetch8();
            if (level != 0) throw CpuError(start, "nested ENTER not supported");
            push(regs[RBP]);
            regs[RBP] = regs[RSP];
            regs[RSP] -= frame;
            return;
        }
        case 0xC9:  // LEAVE
            regs[RSP] = regs[RBP];
            regs[RBP] = pop();
            return;

        case 0xCC:
            throw CpuError(start, "INT3 breakpoint");
        case 0xCD: {  // INT imm8
            uint8_t vec = fetch8();
            if (!on_interrupt) throw CpuError(start, "software interrupt with no handler");
            on_interrupt(vec);
            return;
        }

        case 0xE0:
        case 0xE1:
        case 0xE2: {  // LOOPNE / LOOPE / LOOP
            int8_t rel = static_cast<int8_t>(fetch8());
            reg_write(RCX, addrsize_, reg_read(RCX, addrsize_) - 1);
            bool take = reg_read(RCX, addrsize_) != 0;
            if (op == 0xE0) take = take && !flag(FLAG_ZF);
            if (op == 0xE1) take = take && flag(FLAG_ZF);
            if (take) rip += static_cast<uint64_t>(static_cast<int64_t>(rel));
            return;
        }
        case 0xE3: {  // JECXZ / JRCXZ
            int8_t rel = static_cast<int8_t>(fetch8());
            if (reg_read(RCX, addrsize_) == 0)
                rip += static_cast<uint64_t>(static_cast<int64_t>(rel));
            return;
        }

        case 0xE8: {  // CALL rel32
            int32_t rel = static_cast<int32_t>(fetch32());
            push(rip);
            rip += static_cast<uint64_t>(static_cast<int64_t>(rel));
            return;
        }
        case 0xE9: {  // JMP rel32
            int32_t rel = static_cast<int32_t>(fetch32());
            rip += static_cast<uint64_t>(static_cast<int64_t>(rel));
            return;
        }
        case 0xEB: {  // JMP rel8
            int8_t rel = static_cast<int8_t>(fetch8());
            rip += static_cast<uint64_t>(static_cast<int64_t>(rel));
            return;
        }

        case 0xF4:  // HLT
            halted = true;
            return;
        case 0xF5:
            set_flag(FLAG_CF, !flag(FLAG_CF));
            return;
        case 0xF8:
            set_flag(FLAG_CF, false);
            return;
        case 0xF9:
            set_flag(FLAG_CF, true);
            return;
        case 0xFA:  // CLI / STI - there is no interrupt model to gate
        case 0xFB:
            return;
        case 0xFC:
            set_flag(FLAG_DF, false);
            return;
        case 0xFD:
            set_flag(FLAG_DF, true);
            return;

        case 0xF6:
        case 0xF7: {  // group 3
            int size = op == 0xF6 ? 1 : opsize_;
            // The sub-opcode is only known after the ModRM byte, so a possible
            // immediate is accounted for inside group3().
            RM rm = decode_modrm(0);
            group3(rm, size, modrm_reg_ & 7);
            return;
        }

        case 0xFE: {  // group 4: INC/DEC rm8
            RM rm = decode_modrm();
            group5(rm, 1, modrm_reg_ & 7);
            return;
        }
        case 0xFF: {  // group 5
            RM rm = decode_modrm();
            group5(rm, opsize_, modrm_reg_ & 7);
            return;
        }

        case 0x9B:  // FWAIT - no asynchronous FPU exceptions to wait for
            return;

        case 0xD8: case 0xD9: case 0xDA: case 0xDB:
        case 0xDC: case 0xDD: case 0xDE: case 0xDF:
            execute_x87(op);
            return;

        default:
            unsupported("opcode", op, start);
    }
}

void Cpu::run(uint64_t max_instructions) {
    while (!halted) {
        if (max_instructions && instructions_executed >= max_instructions)
            throw CpuError(rip, "instruction limit reached (possible infinite loop)");
        step();
    }
}

const char* Cpu::reg_name(int i, int size) {
    static const char* n64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                  "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
    static const char* n32[16] = {"eax", "ecx", "edx",  "ebx",  "esp",  "ebp",  "esi",  "edi",
                                  "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
    return size == 8 ? n64[i & 15] : n32[i & 15];
}

std::vector<uint64_t> Cpu::history() const {
    std::vector<uint64_t> out;
    if (history_.empty() || history_filled_ == 0) return out;
    out.reserve(history_filled_);
    // The oldest entry is the one after the newest when the buffer has wrapped.
    size_t start = history_filled_ < history_.size() ? 0 : history_pos_;
    for (size_t i = 0; i < history_filled_; ++i)
        out.push_back(history_[(start + i) % history_.size()]);
    return out;
}

std::string Cpu::state_line() const {
    char buf[320];
    const char* fl = "";
    (void)fl;
    if (is64()) {
        std::snprintf(buf, sizeof buf,
                      "rip=%012llX rax=%016llX rcx=%016llX rdx=%016llX rbx=%016llX "
                      "rsp=%016llX rbp=%016llX rsi=%016llX rdi=%016llX [%c%c%c%c%c]",
                      (unsigned long long)rip, (unsigned long long)regs[RAX],
                      (unsigned long long)regs[RCX], (unsigned long long)regs[RDX],
                      (unsigned long long)regs[RBX], (unsigned long long)regs[RSP],
                      (unsigned long long)regs[RBP], (unsigned long long)regs[RSI],
                      (unsigned long long)regs[RDI], flag(FLAG_CF) ? 'C' : '-',
                      flag(FLAG_PF) ? 'P' : '-', flag(FLAG_ZF) ? 'Z' : '-',
                      flag(FLAG_SF) ? 'S' : '-', flag(FLAG_OF) ? 'O' : '-');
    } else {
        std::snprintf(buf, sizeof buf,
                      "eip=%08X eax=%08X ecx=%08X edx=%08X ebx=%08X esp=%08X ebp=%08X "
                      "esi=%08X edi=%08X [%c%c%c%c%c]",
                      (unsigned)rip, (unsigned)regs[RAX], (unsigned)regs[RCX],
                      (unsigned)regs[RDX], (unsigned)regs[RBX], (unsigned)regs[RSP],
                      (unsigned)regs[RBP], (unsigned)regs[RSI], (unsigned)regs[RDI],
                      flag(FLAG_CF) ? 'C' : '-', flag(FLAG_PF) ? 'P' : '-',
                      flag(FLAG_ZF) ? 'Z' : '-', flag(FLAG_SF) ? 'S' : '-',
                      flag(FLAG_OF) ? 'O' : '-');
    }
    return buf;
}

}  // namespace x86emu
