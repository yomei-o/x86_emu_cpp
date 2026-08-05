// SSE / SSE2 (plus the handful of SSE3/SSSE3/SSE4.1 opcodes compilers reach
// for).  This is not optional decoration: MSVC and glibc both use SSE2 for
// ordinary double arithmetic, for zeroing registers, and inside memcpy/strlen,
// so a real compiler's output cannot run without it.
//
// The `0F xx` space is shared with the general-purpose instructions, and which
// SSE instruction a byte means depends on a mandatory prefix (none / 66 / F3 /
// F2).  execute_sse() returns false for anything it does not own so that
// execute_0f() can carry on with the integer forms.
#include <cmath>
#include <cstring>

#include "cpu.h"

namespace x86emu {
namespace {

// The prefix that selects between the four variants of an SSE opcode.
enum class Sel { None, P66, PF3, PF2 };

double to_double(uint64_t bits) {
    double d;
    std::memcpy(&d, &bits, 8);
    return d;
}
float to_float(uint32_t bits) {
    float f;
    std::memcpy(&f, &bits, 4);
    return f;
}

// MXCSR carries the same rounding-mode field as the x87 control word, in bits
// 13-14.
double round_by_mxcsr(uint32_t mxcsr, double v) {
    switch ((mxcsr >> 13) & 3) {
        case 1: return std::floor(v);
        case 2: return std::ceil(v);
        case 3: return std::trunc(v);
        default: return std::nearbyint(v);
    }
}

}  // namespace

Cpu::Xmm Cpu::xmm_read(const RM& rm) {
    if (rm.is_reg) return xmm[rm.reg];
    Xmm v;
    mem_.read(rm.addr, v.b, 16);
    return v;
}

void Cpu::xmm_write(const RM& rm, const Xmm& v) {
    if (rm.is_reg)
        xmm[rm.reg] = v;
    else
        mem_.write(rm.addr, v.b, 16);
}

uint64_t Cpu::xmm_read_q(const RM& rm) {
    return rm.is_reg ? xmm[rm.reg].q[0] : mem_.read64(rm.addr);
}

uint32_t Cpu::xmm_read_d(const RM& rm) {
    return rm.is_reg ? xmm[rm.reg].d[0] : mem_.read32(rm.addr);
}

bool Cpu::execute_sse(uint8_t op) {
    const Sel sel = pfx_.repne ? Sel::PF2
                  : pfx_.rep  ? Sel::PF3
                  : pfx_.opsize16 ? Sel::P66
                                  : Sel::None;
    const uint64_t start = rip - 2;  // the 0F and the opcode byte

    // Applies a binary operation to a packed or scalar float operand pair.
    // `lanes` is how many elements take part; the rest of the destination is
    // left alone, which is exactly the scalar (SS/SD) behaviour.
    auto pd_op = [&](Xmm& dst, const Xmm& src, int lanes, double (*fn)(double, double)) {
        for (int i = 0; i < lanes; ++i)
            dst.f64[i] = fn(dst.f64[i], src.f64[i]);
    };
    auto ps_op = [&](Xmm& dst, const Xmm& src, int lanes, float (*fn)(float, float)) {
        for (int i = 0; i < lanes; ++i)
            dst.f32[i] = fn(dst.f32[i], src.f32[i]);
    };

    switch (op) {
        // ---- moves -------------------------------------------------------
        case 0x10:
        case 0x11: {  // MOVUPS/MOVUPD/MOVSS/MOVSD, load (0x10) or store (0x11)
            RM rm = decode_modrm();
            int r = modrm_reg_;
            bool load = op == 0x10;
            if (sel == Sel::PF3) {  // MOVSS: 32 bits
                if (load) {
                    uint32_t v = xmm_read_d(rm);
                    if (rm.is_reg) {
                        xmm[r].d[0] = v;  // register form leaves the upper bits
                    } else {
                        xmm[r] = Xmm{};   // memory form zeroes them
                        xmm[r].d[0] = v;
                    }
                } else if (rm.is_reg) {
                    xmm[rm.reg].d[0] = xmm[r].d[0];
                } else {
                    mem_.write32(rm.addr, xmm[r].d[0]);
                }
            } else if (sel == Sel::PF2) {  // MOVSD: 64 bits
                if (load) {
                    uint64_t v = xmm_read_q(rm);
                    if (rm.is_reg) {
                        xmm[r].q[0] = v;
                    } else {
                        xmm[r] = Xmm{};
                        xmm[r].q[0] = v;
                    }
                } else if (rm.is_reg) {
                    xmm[rm.reg].q[0] = xmm[r].q[0];
                } else {
                    mem_.write64(rm.addr, xmm[r].q[0]);
                }
            } else {  // MOVUPS / MOVUPD: the whole register
                if (load)
                    xmm[r] = xmm_read(rm);
                else
                    xmm_write(rm, xmm[r]);
            }
            return true;
        }
        case 0x28:
        case 0x29: {  // MOVAPS / MOVAPD (alignment is not enforced here)
            RM rm = decode_modrm();
            if (op == 0x28)
                xmm[modrm_reg_] = xmm_read(rm);
            else
                xmm_write(rm, xmm[modrm_reg_]);
            return true;
        }
        case 0x12:
        case 0x13: {  // MOVLPS/MOVLPD, and MOVDDUP under F2
            RM rm = decode_modrm();
            if (op == 0x12 && sel == Sel::PF2) {  // MOVDDUP
                uint64_t v = xmm_read_q(rm);
                xmm[modrm_reg_].q[0] = v;
                xmm[modrm_reg_].q[1] = v;
                return true;
            }
            if (op == 0x12)
                xmm[modrm_reg_].q[0] = xmm_read_q(rm);
            else if (rm.is_reg)
                xmm[rm.reg].q[0] = xmm[modrm_reg_].q[0];
            else
                mem_.write64(rm.addr, xmm[modrm_reg_].q[0]);
            return true;
        }
        case 0x16:
        case 0x17: {  // MOVHPS / MOVHPD
            RM rm = decode_modrm();
            if (op == 0x16)
                xmm[modrm_reg_].q[1] = xmm_read_q(rm);
            else if (rm.is_reg)
                xmm[rm.reg].q[0] = xmm[modrm_reg_].q[1];
            else
                mem_.write64(rm.addr, xmm[modrm_reg_].q[1]);
            return true;
        }
        case 0x14: {  // UNPCKLPS / UNPCKLPD
            RM rm = decode_modrm();
            Xmm a = xmm[modrm_reg_], b = xmm_read(rm), r{};
            if (sel == Sel::P66) {
                r.q[0] = a.q[0];
                r.q[1] = b.q[0];
            } else {
                r.d[0] = a.d[0];
                r.d[1] = b.d[0];
                r.d[2] = a.d[1];
                r.d[3] = b.d[1];
            }
            xmm[modrm_reg_] = r;
            return true;
        }
        case 0x15: {  // UNPCKHPS / UNPCKHPD
            RM rm = decode_modrm();
            Xmm a = xmm[modrm_reg_], b = xmm_read(rm), r{};
            if (sel == Sel::P66) {
                r.q[0] = a.q[1];
                r.q[1] = b.q[1];
            } else {
                r.d[0] = a.d[2];
                r.d[1] = b.d[2];
                r.d[2] = a.d[3];
                r.d[3] = b.d[3];
            }
            xmm[modrm_reg_] = r;
            return true;
        }
        case 0x2B: {  // MOVNTPS / MOVNTPD - a plain store as far as we care
            RM rm = decode_modrm();
            xmm_write(rm, xmm[modrm_reg_]);
            return true;
        }
        case 0x6E: {  // MOVD / MOVQ xmm, r/m
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            xmm[modrm_reg_] = Xmm{};
            if (opsize_ == 8)
                xmm[modrm_reg_].q[0] = rm_read(rm, 8);
            else
                xmm[modrm_reg_].d[0] = static_cast<uint32_t>(rm_read(rm, 4));
            return true;
        }
        case 0x7E: {  // MOVD/MOVQ r/m, xmm (66) or MOVQ xmm, xmm/m64 (F3)
            if (sel != Sel::P66 && sel != Sel::PF3) return false;
            RM rm = decode_modrm();
            if (sel == Sel::PF3) {
                uint64_t v = xmm_read_q(rm);
                xmm[modrm_reg_] = Xmm{};
                xmm[modrm_reg_].q[0] = v;
                return true;
            }
            if (opsize_ == 8)
                rm_write(rm, 8, xmm[modrm_reg_].q[0]);
            else
                rm_write(rm, 4, xmm[modrm_reg_].d[0]);
            return true;
        }
        case 0xD6: {  // MOVQ r/m64, xmm
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            if (rm.is_reg) {
                xmm[rm.reg] = Xmm{};
                xmm[rm.reg].q[0] = xmm[modrm_reg_].q[0];
            } else {
                mem_.write64(rm.addr, xmm[modrm_reg_].q[0]);
            }
            return true;
        }
        case 0x6F:
        case 0x7F: {  // MOVDQA (66) / MOVDQU (F3)
            if (sel != Sel::P66 && sel != Sel::PF3) return false;
            RM rm = decode_modrm();
            if (op == 0x6F)
                xmm[modrm_reg_] = xmm_read(rm);
            else
                xmm_write(rm, xmm[modrm_reg_]);
            return true;
        }
        case 0xE7: {  // MOVNTDQ
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            xmm_write(rm, xmm[modrm_reg_]);
            return true;
        }

        // ---- conversions --------------------------------------------------
        case 0x2A: {  // CVTSI2SS / CVTSI2SD
            if (sel != Sel::PF3 && sel != Sel::PF2) return false;
            RM rm = decode_modrm();
            int64_t v = opsize_ == 8 ? static_cast<int64_t>(rm_read(rm, 8))
                                     : static_cast<int32_t>(rm_read(rm, 4));
            if (sel == Sel::PF2)
                xmm[modrm_reg_].f64[0] = static_cast<double>(v);
            else
                xmm[modrm_reg_].f32[0] = static_cast<float>(v);
            return true;
        }
        case 0x2C:
        case 0x2D: {  // CVT(T)SS2SI / CVT(T)SD2SI
            if (sel != Sel::PF3 && sel != Sel::PF2) return false;
            RM rm = decode_modrm();
            double v;
            if (sel == Sel::PF2)
                v = to_double(xmm_read_q(rm));
            else
                v = to_float(xmm_read_d(rm));
            // 0x2C truncates; 0x2D rounds to nearest (the default MXCSR mode).
            double r = op == 0x2C ? std::trunc(v) : round_by_mxcsr(mxcsr, v);
            if (opsize_ == 8)
                reg_write(modrm_reg_, 8, static_cast<uint64_t>(static_cast<int64_t>(r)));
            else
                reg_write(modrm_reg_, 4,
                          static_cast<uint32_t>(static_cast<int32_t>(r)));
            return true;
        }
        case 0x5A: {  // CVTSS2SD / CVTSD2SS / CVTPS2PD / CVTPD2PS
            RM rm = decode_modrm();
            if (sel == Sel::PF3) {
                xmm[modrm_reg_].f64[0] = to_float(xmm_read_d(rm));
            } else if (sel == Sel::PF2) {
                xmm[modrm_reg_].f32[0] = static_cast<float>(to_double(xmm_read_q(rm)));
            } else if (sel == Sel::P66) {  // CVTPD2PS
                Xmm s = xmm_read(rm), r{};
                r.f32[0] = static_cast<float>(s.f64[0]);
                r.f32[1] = static_cast<float>(s.f64[1]);
                xmm[modrm_reg_] = r;
            } else {  // CVTPS2PD
                Xmm s = xmm_read(rm), r{};
                r.f64[0] = s.f32[0];
                r.f64[1] = s.f32[1];
                xmm[modrm_reg_] = r;
            }
            return true;
        }
        case 0x5B: {  // CVTDQ2PS / CVTPS2DQ / CVTTPS2DQ
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm), r{};
            if (sel == Sel::None) {
                for (int i = 0; i < 4; ++i)
                    r.f32[i] = static_cast<float>(static_cast<int32_t>(s.d[i]));
            } else {
                for (int i = 0; i < 4; ++i) {
                    float f = s.f32[i];
                    r.d[i] = static_cast<uint32_t>(static_cast<int32_t>(
                        sel == Sel::PF3 ? std::trunc(f) : round_by_mxcsr(mxcsr, f)));
                }
            }
            xmm[modrm_reg_] = r;
            return true;
        }
        case 0xE6: {  // CVTDQ2PD (F3) / CVTTPD2DQ (66) / CVTPD2DQ (F2)
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm), r{};
            if (sel == Sel::PF3) {
                r.f64[0] = static_cast<int32_t>(s.d[0]);
                r.f64[1] = static_cast<int32_t>(s.d[1]);
            } else {
                for (int i = 0; i < 2; ++i)
                    r.d[i] = static_cast<uint32_t>(static_cast<int32_t>(
                        sel == Sel::P66 ? std::trunc(s.f64[i]) : round_by_mxcsr(mxcsr, s.f64[i])));
            }
            xmm[modrm_reg_] = r;
            return true;
        }

        // ---- comparisons ---------------------------------------------------
        case 0x2E:
        case 0x2F: {  // UCOMISS/UCOMISD and COMISS/COMISD
            RM rm = decode_modrm();
            double a, b;
            if (sel == Sel::P66) {
                a = xmm[modrm_reg_].f64[0];
                b = to_double(xmm_read_q(rm));
            } else {
                a = xmm[modrm_reg_].f32[0];
                b = to_float(xmm_read_d(rm));
            }
            // Unordered sets ZF, PF and CF together; otherwise PF is clear.
            bool unordered = std::isnan(a) || std::isnan(b);
            set_flag(FLAG_OF, false);
            set_flag(FLAG_AF, false);
            set_flag(FLAG_SF, false);
            if (unordered) {
                set_flag(FLAG_ZF, true);
                set_flag(FLAG_PF, true);
                set_flag(FLAG_CF, true);
            } else {
                set_flag(FLAG_PF, false);
                set_flag(FLAG_ZF, a == b);
                set_flag(FLAG_CF, a < b);
            }
            return true;
        }
        case 0xC2: {  // CMPPS / CMPSS / CMPSD / CMPPD
            RM rm = decode_modrm(1);
            Xmm src = xmm_read(rm);
            uint8_t imm = fetch8() & 7;
            auto compare = [imm](double x, double y) -> bool {
                bool un = std::isnan(x) || std::isnan(y);
                switch (imm) {
                    case 0: return x == y;
                    case 1: return !un && x < y;
                    case 2: return !un && x <= y;
                    case 3: return un;
                    case 4: return un || x != y;
                    case 5: return un || x >= y;
                    case 6: return un || x > y;
                    default: return !un;
                }
            };
            Xmm& dst = xmm[modrm_reg_];
            if (sel == Sel::PF2) {
                dst.q[0] = compare(dst.f64[0], src.f64[0]) ? ~0ull : 0ull;
            } else if (sel == Sel::PF3) {
                dst.d[0] = compare(dst.f32[0], src.f32[0]) ? ~0u : 0u;
            } else if (sel == Sel::P66) {
                for (int i = 0; i < 2; ++i)
                    dst.q[i] = compare(dst.f64[i], src.f64[i]) ? ~0ull : 0ull;
            } else {
                for (int i = 0; i < 4; ++i)
                    dst.d[i] = compare(dst.f32[i], src.f32[i]) ? ~0u : 0u;
            }
            return true;
        }
        case 0x50: {  // MOVMSKPS / MOVMSKPD
            RM rm = decode_modrm();
            if (!rm.is_reg) unsupported("MOVMSKPS with a memory operand", op, start);
            uint32_t mask = 0;
            if (sel == Sel::P66) {
                for (int i = 0; i < 2; ++i)
                    if (xmm[rm.reg].q[i] >> 63) mask |= 1u << i;
            } else {
                for (int i = 0; i < 4; ++i)
                    if (xmm[rm.reg].d[i] >> 31) mask |= 1u << i;
            }
            reg_write(modrm_reg_, 4, mask);
            return true;
        }
        case 0xD7: {  // PMOVMSKB - the workhorse of SSE2 string routines
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            if (!rm.is_reg) unsupported("PMOVMSKB with a memory operand", op, start);
            uint32_t mask = 0;
            for (int i = 0; i < 16; ++i)
                if (xmm[rm.reg].b[i] & 0x80) mask |= 1u << i;
            reg_write(modrm_reg_, 4, mask);
            return true;
        }

        // ---- float arithmetic ----------------------------------------------
        case 0x51: {  // SQRT
            RM rm = decode_modrm();
            if (sel == Sel::PF2)
                xmm[modrm_reg_].f64[0] = std::sqrt(to_double(xmm_read_q(rm)));
            else if (sel == Sel::PF3)
                xmm[modrm_reg_].f32[0] = std::sqrt(to_float(xmm_read_d(rm)));
            else {
                Xmm s = xmm_read(rm);
                if (sel == Sel::P66)
                    for (int i = 0; i < 2; ++i) xmm[modrm_reg_].f64[i] = std::sqrt(s.f64[i]);
                else
                    for (int i = 0; i < 4; ++i) xmm[modrm_reg_].f32[i] = std::sqrt(s.f32[i]);
            }
            return true;
        }
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57: {  // ANDPS / ANDNPS / ORPS / XORPS (bitwise, size irrelevant)
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            for (int i = 0; i < 2; ++i) {
                switch (op) {
                    case 0x54: d.q[i] &= s.q[i]; break;
                    case 0x55: d.q[i] = ~d.q[i] & s.q[i]; break;
                    case 0x56: d.q[i] |= s.q[i]; break;
                    default: d.q[i] ^= s.q[i]; break;
                }
            }
            return true;
        }
        case 0x58:
        case 0x59:
        case 0x5C:
        case 0x5D:
        case 0x5E:
        case 0x5F: {  // ADD / MUL / SUB / MIN / DIV / MAX
            RM rm = decode_modrm();
            Xmm src;
            if (sel == Sel::PF2) {
                src = Xmm{};
                src.q[0] = xmm_read_q(rm);
            } else if (sel == Sel::PF3) {
                src = Xmm{};
                src.d[0] = xmm_read_d(rm);
            } else {
                src = xmm_read(rm);
            }
            Xmm& dst = xmm[modrm_reg_];
            const bool is_double = sel == Sel::PF2 || sel == Sel::P66;
            const int lanes = (sel == Sel::PF2 || sel == Sel::PF3) ? 1 : (is_double ? 2 : 4);

            if (is_double) {
                switch (op) {
                    case 0x58: pd_op(dst, src, lanes, [](double a, double b) { return a + b; }); break;
                    case 0x59: pd_op(dst, src, lanes, [](double a, double b) { return a * b; }); break;
                    case 0x5C: pd_op(dst, src, lanes, [](double a, double b) { return a - b; }); break;
                    case 0x5E: pd_op(dst, src, lanes, [](double a, double b) { return a / b; }); break;
                    // MIN/MAX return the second operand when either is NaN, per
                    // the hardware definition.
                    case 0x5D: pd_op(dst, src, lanes, [](double a, double b) {
                                   return (std::isnan(a) || std::isnan(b) || b < a) ? b : a; });
                               break;
                    default: pd_op(dst, src, lanes, [](double a, double b) {
                                 return (std::isnan(a) || std::isnan(b) || b > a) ? b : a; });
                             break;
                }
            } else {
                switch (op) {
                    case 0x58: ps_op(dst, src, lanes, [](float a, float b) { return a + b; }); break;
                    case 0x59: ps_op(dst, src, lanes, [](float a, float b) { return a * b; }); break;
                    case 0x5C: ps_op(dst, src, lanes, [](float a, float b) { return a - b; }); break;
                    case 0x5E: ps_op(dst, src, lanes, [](float a, float b) { return a / b; }); break;
                    case 0x5D: ps_op(dst, src, lanes, [](float a, float b) {
                                   return (std::isnan(a) || std::isnan(b) || b < a) ? b : a; });
                               break;
                    default: ps_op(dst, src, lanes, [](float a, float b) {
                                 return (std::isnan(a) || std::isnan(b) || b > a) ? b : a; });
                             break;
                }
            }
            return true;
        }

        // ---- integer SIMD ---------------------------------------------------
        case 0x63: case 0x67: case 0x6B: {  // PACKSSWB / PACKUSWB / PACKSSDW (signed/unsigned saturate)
            if (sel != Sel::P66) return false;   // MMX form (no 66) unsupported
            RM rm = decode_modrm();
            Xmm a = xmm[modrm_reg_], b = xmm_read(rm), r{};
            auto sat_sb = [](int32_t v) -> uint8_t { return v < -128 ? 0x80 : v > 127 ? 0x7F : static_cast<uint8_t>(v); };
            auto sat_ub = [](int32_t v) -> uint8_t { return v < 0 ? 0 : v > 255 ? 0xFF : static_cast<uint8_t>(v); };
            auto sat_sw = [](int32_t v) -> uint16_t { return v < -32768 ? 0x8000 : v > 32767 ? 0x7FFF : static_cast<uint16_t>(v); };
            if (op == 0x6B) {  // PACKSSDW: 4 dwords from each -> 8 signed-saturated words
                for (int i = 0; i < 4; ++i) r.w[i] = sat_sw(static_cast<int32_t>(a.d[i]));
                for (int i = 0; i < 4; ++i) r.w[4 + i] = sat_sw(static_cast<int32_t>(b.d[i]));
            } else {  // PACKSSWB (0x63) / PACKUSWB (0x67): 8 words from each -> 16 bytes
                for (int i = 0; i < 8; ++i) {
                    int16_t av = static_cast<int16_t>(a.w[i]), bv = static_cast<int16_t>(b.w[i]);
                    r.b[i]     = op == 0x63 ? sat_sb(av) : sat_ub(av);
                    r.b[8 + i] = op == 0x63 ? sat_sb(bv) : sat_ub(bv);
                }
            }
            xmm[modrm_reg_] = r;
            return true;
        }
        case 0x60: case 0x61: case 0x62: case 0x68: case 0x69: case 0x6A:
        case 0x6C: case 0x6D: {  // PUNPCK{L,H}{BW,WD,DQ,QDQ}
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm a = xmm[modrm_reg_], b = xmm_read(rm), r{};
            // 0x68-0x6A are the "unpack high" forms, but the quadword pair
            // breaks the pattern: 0x6C is PUNPCKLQDQ and only 0x6D is high.
            bool high = (op >= 0x68 && op <= 0x6A) || op == 0x6D;
            int half = high ? 8 : 0;
            switch (op) {
                case 0x60: case 0x68:  // BW
                    for (int i = 0; i < 8; ++i) {
                        r.b[i * 2] = a.b[half + i];
                        r.b[i * 2 + 1] = b.b[half + i];
                    }
                    break;
                case 0x61: case 0x69:  // WD
                    for (int i = 0; i < 4; ++i) {
                        r.w[i * 2] = a.w[(high ? 4 : 0) + i];
                        r.w[i * 2 + 1] = b.w[(high ? 4 : 0) + i];
                    }
                    break;
                case 0x62: case 0x6A:  // DQ
                    for (int i = 0; i < 2; ++i) {
                        r.d[i * 2] = a.d[(high ? 2 : 0) + i];
                        r.d[i * 2 + 1] = b.d[(high ? 2 : 0) + i];
                    }
                    break;
                default:  // 0x6C/0x6D: QDQ
                    r.q[0] = high ? a.q[1] : a.q[0];
                    r.q[1] = high ? b.q[1] : b.q[0];
                    break;
            }
            xmm[modrm_reg_] = r;
            return true;
        }
        case 0x70: {  // PSHUFD / PSHUFLW / PSHUFHW
            RM rm = decode_modrm(1);
            Xmm s = xmm_read(rm);
            uint8_t imm = fetch8();
            Xmm r = s;
            if (sel == Sel::P66) {
                for (int i = 0; i < 4; ++i) r.d[i] = s.d[(imm >> (i * 2)) & 3];
            } else if (sel == Sel::PF2) {  // PSHUFLW
                for (int i = 0; i < 4; ++i) r.w[i] = s.w[(imm >> (i * 2)) & 3];
            } else if (sel == Sel::PF3) {  // PSHUFHW
                for (int i = 0; i < 4; ++i) r.w[4 + i] = s.w[4 + ((imm >> (i * 2)) & 3)];
            } else {
                unsupported("PSHUFW (MMX) is not supported", op, start);
            }
            xmm[modrm_reg_] = r;
            return true;
        }
        case 0x71:
        case 0x72:
        case 0x73: {  // shift groups, immediate count
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm(1);
            int sub = modrm_reg_ & 7;
            uint8_t count = fetch8();
            if (!rm.is_reg) unsupported("SSE shift with a memory operand", op, start);
            Xmm& v = xmm[rm.reg];
            auto shift_lanes = [&](int width) {
                for (int i = 0; i < 16 / width; ++i) {
                    uint64_t lane = width == 2 ? v.w[i] : width == 4 ? v.d[i] : v.q[i];
                    int bits = width * 8;
                    uint64_t out;
                    if (sub == 2) {  // logical right
                        out = count >= bits ? 0 : lane >> count;
                    } else if (sub == 4) {  // left
                        out = count >= bits ? 0 : lane << count;
                    } else {  // 6: arithmetic right
                        int64_t s = width == 2 ? static_cast<int16_t>(lane)
                                  : width == 4 ? static_cast<int32_t>(lane)
                                               : static_cast<int64_t>(lane);
                        out = static_cast<uint64_t>(s >> (count >= bits ? bits - 1 : count));
                    }
                    if (width == 2) v.w[i] = static_cast<uint16_t>(out);
                    else if (width == 4) v.d[i] = static_cast<uint32_t>(out);
                    else v.q[i] = out;
                }
            };
            if (op == 0x73 && (sub == 3 || sub == 7)) {
                // PSRLDQ / PSLLDQ shift the whole register by whole bytes.
                Xmm r{};
                int n = count > 16 ? 16 : count;
                for (int i = 0; i < 16 - n; ++i) {
                    if (sub == 3)
                        r.b[i] = v.b[i + n];
                    else
                        r.b[i + n] = v.b[i];
                }
                v = r;
                return true;
            }
            shift_lanes(op == 0x71 ? 2 : op == 0x72 ? 4 : 8);
            return true;
        }
        case 0x74:
        case 0x75:
        case 0x76: {  // PCMPEQB / PCMPEQW / PCMPEQD
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            if (op == 0x74)
                for (int i = 0; i < 16; ++i) d.b[i] = d.b[i] == s.b[i] ? 0xFF : 0;
            else if (op == 0x75)
                for (int i = 0; i < 8; ++i) d.w[i] = d.w[i] == s.w[i] ? 0xFFFF : 0;
            else
                for (int i = 0; i < 4; ++i) d.d[i] = d.d[i] == s.d[i] ? 0xFFFFFFFFu : 0;
            return true;
        }
        case 0x64:
        case 0x65:
        case 0x66: {  // PCMPGTB / PCMPGTW / PCMPGTD (signed)
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            if (op == 0x64)
                for (int i = 0; i < 16; ++i)
                    d.b[i] = static_cast<int8_t>(d.b[i]) > static_cast<int8_t>(s.b[i]) ? 0xFF : 0;
            else if (op == 0x65)
                for (int i = 0; i < 8; ++i)
                    d.w[i] = static_cast<int16_t>(d.w[i]) > static_cast<int16_t>(s.w[i]) ? 0xFFFF : 0;
            else
                for (int i = 0; i < 4; ++i)
                    d.d[i] = static_cast<int32_t>(d.d[i]) > static_cast<int32_t>(s.d[i])
                                 ? 0xFFFFFFFFu : 0;
            return true;
        }
        case 0xDA:
        case 0xDE: {  // PMINUB / PMAXUB
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            for (int i = 0; i < 16; ++i)
                d.b[i] = op == 0xDA ? (s.b[i] < d.b[i] ? s.b[i] : d.b[i])
                                    : (s.b[i] > d.b[i] ? s.b[i] : d.b[i]);
            return true;
        }
        case 0xDB:
        case 0xDF:
        case 0xEB:
        case 0xEF: {  // PAND / PANDN / POR / PXOR
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            for (int i = 0; i < 2; ++i) {
                switch (op) {
                    case 0xDB: d.q[i] &= s.q[i]; break;
                    case 0xDF: d.q[i] = ~d.q[i] & s.q[i]; break;
                    case 0xEB: d.q[i] |= s.q[i]; break;
                    default: d.q[i] ^= s.q[i]; break;
                }
            }
            return true;
        }
        case 0xD4:
        case 0xFC:
        case 0xFD:
        case 0xFE:
        case 0xF8:
        case 0xF9:
        case 0xFA:
        case 0xFB: {  // PADDQ/PADDB/PADDW/PADDD and PSUBB/PSUBW/PSUBD/PSUBQ
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            switch (op) {
                case 0xFC: for (int i = 0; i < 16; ++i) d.b[i] = static_cast<uint8_t>(d.b[i] + s.b[i]); break;
                case 0xFD: for (int i = 0; i < 8; ++i) d.w[i] = static_cast<uint16_t>(d.w[i] + s.w[i]); break;
                case 0xFE: for (int i = 0; i < 4; ++i) d.d[i] += s.d[i]; break;
                case 0xD4: for (int i = 0; i < 2; ++i) d.q[i] += s.q[i]; break;
                case 0xF8: for (int i = 0; i < 16; ++i) d.b[i] = static_cast<uint8_t>(d.b[i] - s.b[i]); break;
                case 0xF9: for (int i = 0; i < 8; ++i) d.w[i] = static_cast<uint16_t>(d.w[i] - s.w[i]); break;
                case 0xFA: for (int i = 0; i < 4; ++i) d.d[i] -= s.d[i]; break;
                default: for (int i = 0; i < 2; ++i) d.q[i] -= s.q[i]; break;
            }
            return true;
        }
        // PINSRW takes a 16-bit source from a general register or memory and
        // PEXTRW writes one to a general register.  They are the only SSE2
        // instructions that move a *word* between the two register files, which is
        // why compilers reach for them when packing a small struct - link.exe
        // stores a PE header field this way.
        case 0xC4: {  // PINSRW xmm, r32/m16, imm8
            if (sel != Sel::P66) {
                unsupported("PINSRW (MMX) is not supported", op, start);
                return true;
            }
            RM rm = decode_modrm(1);
            uint16_t value = static_cast<uint16_t>(rm.is_reg ? regs[rm.reg] : mem_.read16(rm.addr));
            uint8_t imm = fetch8();
            xmm[modrm_reg_].w[imm & 7] = value;
            return true;
        }
        case 0xC5: {  // PEXTRW r32, xmm, imm8
            if (sel != Sel::P66) {
                unsupported("PEXTRW (MMX) is not supported", op, start);
                return true;
            }
            // The source is always a register here: there is no memory form, so
            // the mod field is 11 and the r/m field names the xmm register while
            // the reg field names the destination.
            RM rm = decode_modrm(1);
            uint8_t imm = fetch8();
            uint16_t value = xmm[rm.is_reg ? rm.reg : modrm_reg_].w[imm & 7];
            // The result is zero-extended to the full 32 or 64 bits.
            regs[modrm_reg_] = value;
            return true;
        }
        case 0xC6: {  // SHUFPS / SHUFPD
            RM rm = decode_modrm(1);
            Xmm s = xmm_read(rm);
            uint8_t imm = fetch8();
            Xmm a = xmm[modrm_reg_], r{};
            if (sel == Sel::P66) {
                r.q[0] = (imm & 1) ? a.q[1] : a.q[0];
                r.q[1] = (imm & 2) ? s.q[1] : s.q[0];
            } else {
                r.d[0] = a.d[imm & 3];
                r.d[1] = a.d[(imm >> 2) & 3];
                r.d[2] = s.d[(imm >> 4) & 3];
                r.d[3] = s.d[(imm >> 6) & 3];
            }
            xmm[modrm_reg_] = r;
            return true;
        }

        // ---- MXCSR ----------------------------------------------------------
        case 0xAE: {  // LDMXCSR / STMXCSR / the fences
            RM rm = decode_modrm();
            int sub = modrm_reg_ & 7;
            if (sub == 2)
                mxcsr = static_cast<uint32_t>(rm_read(rm, 4));
            else if (sub == 3)
                rm_write(rm, 4, mxcsr);
            // sub 5/6/7 are LFENCE/MFENCE/SFENCE: nothing to order here.
            return true;
        }

        // ---- three-byte escapes ---------------------------------------------
        case 0x38: {
            uint8_t op3 = fetch8();
            if (op3 == 0x00 && sel == Sel::P66) {  // PSHUFB
                RM rm = decode_modrm();
                Xmm s = xmm_read(rm), a = xmm[modrm_reg_], r{};
                for (int i = 0; i < 16; ++i)
                    r.b[i] = (s.b[i] & 0x80) ? 0 : a.b[s.b[i] & 0x0F];
                xmm[modrm_reg_] = r;
                return true;
            }
            if (op3 == 0x17 && sel == Sel::P66) {  // PTEST
                RM rm = decode_modrm();
                Xmm s = xmm_read(rm), d = xmm[modrm_reg_];
                bool zf = ((s.q[0] & d.q[0]) | (s.q[1] & d.q[1])) == 0;
                bool cf = ((s.q[0] & ~d.q[0]) | (s.q[1] & ~d.q[1])) == 0;
                set_flag(FLAG_ZF, zf);
                set_flag(FLAG_CF, cf);
                set_flag(FLAG_OF, false);
                set_flag(FLAG_SF, false);
                set_flag(FLAG_PF, false);
                set_flag(FLAG_AF, false);
                return true;
            }
            unsupported("0F 38 opcode", op3, start);
        }
        case 0x3A: {
            uint8_t op3 = fetch8();
            if ((op3 == 0x0A || op3 == 0x0B) && sel == Sel::P66) {  // ROUNDSS / ROUNDSD
                RM rm = decode_modrm(1);
                Xmm s = xmm_read(rm);
                uint8_t imm = fetch8() & 0xF;
                auto round = [imm](double v) {
                    switch (imm & 3) {
                        case 0: return std::nearbyint(v);
                        case 1: return std::floor(v);
                        case 2: return std::ceil(v);
                        default: return std::trunc(v);
                    }
                };
                if (op3 == 0x0B)
                    xmm[modrm_reg_].f64[0] = round(s.f64[0]);
                else
                    xmm[modrm_reg_].f32[0] = static_cast<float>(round(s.f32[0]));
                return true;
            }
            if (op3 == 0x0F && sel == Sel::P66) {  // PALIGNR
                RM rm = decode_modrm(1);
                Xmm s = xmm_read(rm), a = xmm[modrm_reg_], r{};
                uint8_t n = fetch8();
                for (int i = 0; i < 16; ++i) {
                    int idx = i + n;
                    r.b[i] = idx < 16 ? s.b[idx] : (idx < 32 ? a.b[idx - 16] : 0);
                }
                xmm[modrm_reg_] = r;
                return true;
            }
            unsupported("0F 3A opcode", op3, start);
        }

        default:
            return false;
    }
}

}  // namespace x86emu
