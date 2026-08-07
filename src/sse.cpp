// SSE / SSE2 (plus the handful of SSE3/SSSE3/SSE4.1 opcodes compilers reach
// for).  This is not optional decoration: MSVC and glibc both use SSE2 for
// ordinary double arithmetic, for zeroing registers, and inside memcpy/strlen,
// so a real compiler's output cannot run without it.
//
// The `0F xx` space is shared with the general-purpose instructions, and which
// SSE instruction a byte means depends on a mandatory prefix (none / 66 / F3 /
// F2).  execute_sse() returns false for anything it does not own so that
// execute_0f() can carry on with the integer forms.
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "cpu.h"

namespace x86emu {
namespace {

// X86EMU_AES_COUNT reports at exit how many AES-NI instructions actually ran.
// It is the cheapest way to tell "the decrypt never happened" from "the decrypt
// happened and something after it is wrong", and it costs an increment when the
// guest is doing AES at all - which no guest that is not doing AES ever is.
struct AesCensus {
    unsigned long long imc = 0, enc = 0, enclast = 0, dec = 0, declast = 0, keygen = 0;
    ~AesCensus() {
        if (!std::getenv("X86EMU_AES_COUNT")) return;
        std::fprintf(stderr,
                     "[aes] aesimc=%llu aesenc=%llu aesenclast=%llu aesdec=%llu "
                     "aesdeclast=%llu aeskeygenassist=%llu\n",
                     imc, enc, enclast, dec, declast, keygen);
        std::fflush(stderr);
    }
};
AesCensus g_aes;

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

// ---- AES-NI ---------------------------------------------------------------
// The AES round exactly as FIPS-197 defines it.  The 128-bit register holds the
// state column by column: byte 4c+r is row r of column c, which is the only
// thing about these instructions that is not in the standard.
const uint8_t kAesSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

uint8_t aes_inv_sbox(uint8_t v) {
    static const std::array<uint8_t, 256> table = [] {
        std::array<uint8_t, 256> t{};
        for (int i = 0; i < 256; ++i) t[kAesSbox[i]] = static_cast<uint8_t>(i);
        return t;
    }();
    return table[v];
}

// Multiplication in GF(2^8) modulo the AES polynomial.
uint8_t aes_gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) r ^= a;
        bool high = (a & 0x80) != 0;
        a = static_cast<uint8_t>(a << 1);
        if (high) a ^= 0x1B;
        b = static_cast<uint8_t>(b >> 1);
    }
    return r;
}

Cpu::Xmm aes_xor(Cpu::Xmm a, const Cpu::Xmm& b) {
    a.q[0] ^= b.q[0];
    a.q[1] ^= b.q[1];
    return a;
}

// ShiftRows followed by SubBytes, or their inverses.  The two commute, and the
// instructions are specified in this order.
Cpu::Xmm aes_sub_shift(const Cpu::Xmm& s, bool inverse) {
    Cpu::Xmm r{};
    for (int col = 0; col < 4; ++col)
        for (int row = 0; row < 4; ++row) {
            int src = inverse ? (col - row + 4) % 4 : (col + row) % 4;
            uint8_t v = s.b[4 * src + row];
            r.b[4 * col + row] = inverse ? aes_inv_sbox(v) : kAesSbox[v];
        }
    return r;
}

Cpu::Xmm aes_mix_columns(const Cpu::Xmm& s) {
    Cpu::Xmm r{};
    for (int c = 0; c < 4; ++c) {
        const uint8_t* v = &s.b[4 * c];
        r.b[4 * c + 0] = aes_gmul(v[0], 2) ^ aes_gmul(v[1], 3) ^ v[2] ^ v[3];
        r.b[4 * c + 1] = v[0] ^ aes_gmul(v[1], 2) ^ aes_gmul(v[2], 3) ^ v[3];
        r.b[4 * c + 2] = v[0] ^ v[1] ^ aes_gmul(v[2], 2) ^ aes_gmul(v[3], 3);
        r.b[4 * c + 3] = aes_gmul(v[0], 3) ^ v[1] ^ v[2] ^ aes_gmul(v[3], 2);
    }
    return r;
}

Cpu::Xmm aes_inv_mix_columns(const Cpu::Xmm& s) {
    Cpu::Xmm r{};
    for (int c = 0; c < 4; ++c) {
        const uint8_t* v = &s.b[4 * c];
        r.b[4 * c + 0] = aes_gmul(v[0], 14) ^ aes_gmul(v[1], 11) ^ aes_gmul(v[2], 13) ^
                         aes_gmul(v[3], 9);
        r.b[4 * c + 1] = aes_gmul(v[0], 9) ^ aes_gmul(v[1], 14) ^ aes_gmul(v[2], 11) ^
                         aes_gmul(v[3], 13);
        r.b[4 * c + 2] = aes_gmul(v[0], 13) ^ aes_gmul(v[1], 9) ^ aes_gmul(v[2], 14) ^
                         aes_gmul(v[3], 11);
        r.b[4 * c + 3] = aes_gmul(v[0], 11) ^ aes_gmul(v[1], 13) ^ aes_gmul(v[2], 9) ^
                         aes_gmul(v[3], 14);
    }
    return r;
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
                // With a register operand this is MOVHLPS - the *high* half of
                // the source.  xmm_read_q would hand back the low half, which
                // moves the wrong pointer without disturbing control flow: cc1
                // lost a basic block's loop_father exactly this way.
                xmm[modrm_reg_].q[0] = rm.is_reg ? xmm[rm.reg].q[1] : mem_.read64(rm.addr);
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
                reg_write(modrm_reg_, 8, static_cast<uint64_t>(to_int64_x86(r)));
            else
                reg_write(modrm_reg_, 4, static_cast<uint32_t>(to_int32_x86(r)));
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
                    r.d[i] = static_cast<uint32_t>(to_int32_x86(
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
                    r.d[i] = static_cast<uint32_t>(to_int32_x86(
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
        case 0x52:
        case 0x53: {  // RSQRTPS / RSQRTSS / RCPPS / RCPSS
            // These are the *approximate* reciprocal instructions: hardware
            // answers them to about twelve bits and the exact value differs
            // between CPU generations, so the architecture only bounds the
            // relative error at 1.5 * 2^-12.  Computing them exactly in single
            // precision sits well inside that, and every caller either refines
            // with a Newton step or does not care - which is why MLAS reaches
            // for them in the first place.
            if (sel == Sel::P66 || sel == Sel::PF2) return false;  // no double form
            RM rm = decode_modrm();
            auto approx = [op](float v) {
                return op == 0x52 ? 1.0f / std::sqrt(v) : 1.0f / v;
            };
            if (sel == Sel::PF3) {
                xmm[modrm_reg_].f32[0] = approx(to_float(xmm_read_d(rm)));
            } else {
                Xmm s = xmm_read(rm);
                for (int i = 0; i < 4; ++i) xmm[modrm_reg_].f32[i] = approx(s.f32[i]);
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
                    // MIN is "if SRC1 < SRC2 then SRC1 else SRC2", exactly, and
                    // the "else" carries two cases worth naming: either operand
                    // NaN gives SRC2, and so does a tie - which is how MINPD
                    // tells +0.0 from -0.0.  Testing b < a instead returns SRC1
                    // on a tie, which is wrong for -0.0 and for the NaN in SRC1.
                    case 0x5D: pd_op(dst, src, lanes, [](double a, double b) {
                                   return a < b ? a : b; });
                               break;
                    default: pd_op(dst, src, lanes, [](double a, double b) {
                                 return a > b ? a : b; });
                             break;
                }
            } else {
                switch (op) {
                    case 0x58: ps_op(dst, src, lanes, [](float a, float b) { return a + b; }); break;
                    case 0x59: ps_op(dst, src, lanes, [](float a, float b) { return a * b; }); break;
                    case 0x5C: ps_op(dst, src, lanes, [](float a, float b) { return a - b; }); break;
                    case 0x5E: ps_op(dst, src, lanes, [](float a, float b) { return a / b; }); break;
                    case 0x5D: ps_op(dst, src, lanes, [](float a, float b) {
                                   return a < b ? a : b; });
                               break;
                    default: ps_op(dst, src, lanes, [](float a, float b) {
                                 return a > b ? a : b; });
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
                    // The /reg field picks the direction: /2 PSRLx, /4 PSRAx,
                    // /6 PSLLx.  Four and six are not interchangeable and were
                    // swapped here, which made every PSLLQ an arithmetic shift
                    // right - invisible to a compiler's output and fatal to
                    // hand-written SIMD.
                    if (sub == 2) {  // logical right
                        out = count >= bits ? 0 : lane >> count;
                    } else if (sub == 6) {  // left
                        out = count >= bits ? 0 : lane << count;
                    } else {  // 4: arithmetic right (no quadword form exists)
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
        case 0xD5:
        case 0xE4:
        case 0xE5:
        case 0xF4:
        case 0xF5: {  // PMULLW / PMULHUW / PMULHW / PMULUDQ / PMADDWD
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            switch (op) {
                case 0xD5:
                    for (int i = 0; i < 8; ++i)
                        d.w[i] = static_cast<uint16_t>(d.w[i] * s.w[i]);
                    break;
                case 0xE4:
                    for (int i = 0; i < 8; ++i)
                        d.w[i] = static_cast<uint16_t>((static_cast<uint32_t>(d.w[i]) * s.w[i]) >> 16);
                    break;
                case 0xE5:
                    for (int i = 0; i < 8; ++i)
                        d.w[i] = static_cast<uint16_t>(
                            (static_cast<int32_t>(static_cast<int16_t>(d.w[i])) *
                             static_cast<int16_t>(s.w[i])) >> 16);
                    break;
                case 0xF4:
                    d.q[0] = static_cast<uint64_t>(d.d[0]) * s.d[0];
                    d.q[1] = static_cast<uint64_t>(d.d[2]) * s.d[2];
                    break;
                default: {  // PMADDWD: pairwise signed multiply-add into dwords
                    for (int i = 0; i < 4; ++i) {
                        int32_t lo = static_cast<int16_t>(d.w[i * 2]) *
                                     static_cast<int16_t>(s.w[i * 2]);
                        int32_t hi = static_cast<int16_t>(d.w[i * 2 + 1]) *
                                     static_cast<int16_t>(s.w[i * 2 + 1]);
                        d.d[i] = static_cast<uint32_t>(lo + hi);
                    }
                    break;
                }
            }
            return true;
        }
        case 0xF6: {  // PSADBW: sums of absolute byte differences per half
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            for (int half = 0; half < 2; ++half) {
                uint32_t sum = 0;
                for (int i = 0; i < 8; ++i) {
                    int diff = d.b[half * 8 + i] - s.b[half * 8 + i];
                    sum += static_cast<uint32_t>(diff < 0 ? -diff : diff);
                }
                d.q[half] = sum;
            }
            return true;
        }
        case 0xE0:
        case 0xE3: {  // PAVGB / PAVGW (rounded unsigned average)
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            if (op == 0xE0)
                for (int i = 0; i < 16; ++i)
                    d.b[i] = static_cast<uint8_t>((d.b[i] + s.b[i] + 1) >> 1);
            else
                for (int i = 0; i < 8; ++i)
                    d.w[i] = static_cast<uint16_t>((d.w[i] + s.w[i] + 1) >> 1);
            return true;
        }
        case 0xD8:
        case 0xD9:
        case 0xDC:
        case 0xDD:
        case 0xE8:
        case 0xE9:
        case 0xEC:
        case 0xED: {  // saturating PSUBUS/PADDUS/PSUBS/PADDS, bytes and words
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            auto sat_u8 = [](int v) { return static_cast<uint8_t>(v < 0 ? 0 : v > 255 ? 255 : v); };
            auto sat_u16 = [](int v) { return static_cast<uint16_t>(v < 0 ? 0 : v > 65535 ? 65535 : v); };
            auto sat_s8 = [](int v) { return static_cast<uint8_t>(v < -128 ? -128 : v > 127 ? 127 : v); };
            auto sat_s16 = [](int v) { return static_cast<uint16_t>(v < -32768 ? -32768 : v > 32767 ? 32767 : v); };
            switch (op) {
                case 0xD8: for (int i = 0; i < 16; ++i) d.b[i] = sat_u8(d.b[i] - s.b[i]); break;
                case 0xD9: for (int i = 0; i < 8; ++i) d.w[i] = sat_u16(d.w[i] - s.w[i]); break;
                case 0xDC: for (int i = 0; i < 16; ++i) d.b[i] = sat_u8(d.b[i] + s.b[i]); break;
                case 0xDD: for (int i = 0; i < 8; ++i) d.w[i] = sat_u16(d.w[i] + s.w[i]); break;
                case 0xE8: for (int i = 0; i < 16; ++i) d.b[i] = sat_s8(static_cast<int8_t>(d.b[i]) - static_cast<int8_t>(s.b[i])); break;
                case 0xE9: for (int i = 0; i < 8; ++i) d.w[i] = sat_s16(static_cast<int16_t>(d.w[i]) - static_cast<int16_t>(s.w[i])); break;
                case 0xEC: for (int i = 0; i < 16; ++i) d.b[i] = sat_s8(static_cast<int8_t>(d.b[i]) + static_cast<int8_t>(s.b[i])); break;
                default: for (int i = 0; i < 8; ++i) d.w[i] = sat_s16(static_cast<int16_t>(d.w[i]) + static_cast<int16_t>(s.w[i])); break;
            }
            return true;
        }
        case 0xEA:
        case 0xEE: {  // PMINSW / PMAXSW
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            Xmm s = xmm_read(rm);
            Xmm& d = xmm[modrm_reg_];
            for (int i = 0; i < 8; ++i) {
                int16_t a = static_cast<int16_t>(d.w[i]), b = static_cast<int16_t>(s.w[i]);
                d.w[i] = static_cast<uint16_t>(op == 0xEA ? (b < a ? b : a) : (b > a ? b : a));
            }
            return true;
        }
        case 0xD1:
        case 0xD2:
        case 0xD3:
        case 0xE1:
        case 0xE2:
        case 0xF1:
        case 0xF2:
        case 0xF3: {  // PSRL/PSRA/PSLL with the count in an xmm or m128
            if (sel != Sel::P66) return false;
            RM rm = decode_modrm();
            uint64_t count = xmm_read(rm).q[0];
            Xmm& d = xmm[modrm_reg_];
            bool arith = op == 0xE1 || op == 0xE2;
            bool left = op >= 0xF1;
            int elem = (op == 0xD1 || op == 0xE1 || op == 0xF1)   ? 2
                       : (op == 0xD2 || op == 0xE2 || op == 0xF2) ? 4
                                                                  : 8;
            int bits = elem * 8;
            for (int i = 0; i < 16 / elem; ++i) {
                if (elem == 2) {
                    uint16_t& v = d.w[i];
                    if (count >= static_cast<uint64_t>(bits))
                        v = arith ? static_cast<uint16_t>(static_cast<int16_t>(v) >> 15) : 0;
                    else if (left)
                        v = static_cast<uint16_t>(v << count);
                    else if (arith)
                        v = static_cast<uint16_t>(static_cast<int16_t>(v) >> count);
                    else
                        v = static_cast<uint16_t>(v >> count);
                } else if (elem == 4) {
                    uint32_t& v = d.d[i];
                    if (count >= static_cast<uint64_t>(bits))
                        v = arith ? static_cast<uint32_t>(static_cast<int32_t>(v) >> 31) : 0;
                    else if (left)
                        v = v << count;
                    else if (arith)
                        v = static_cast<uint32_t>(static_cast<int32_t>(v) >> count);
                    else
                        v = v >> count;
                } else {
                    uint64_t& v = d.q[i];
                    if (count >= static_cast<uint64_t>(bits))
                        v = 0;  // there is no PSRAQ in SSE2
                    else if (left)
                        v = v << count;
                    else
                        v = v >> count;
                }
            }
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
        case 0xAE: {  // FXSAVE / FXRSTOR / LDMXCSR / STMXCSR / the fences
            RM rm = decode_modrm();
            int sub = modrm_reg_ & 7;
            if (sub == 0 && !rm.is_reg) {  // FXSAVE
                // The 512-byte area, as far as anything here consumes it: the
                // control words, MXCSR, the x87 stack and the xmm registers.
                // ST values are stored as the host doubles they are kept in
                // (8 bytes into the 16-byte slot, the rest zero), which is not
                // the 80-bit hardware format - only our own FXRSTOR reads them
                // back, and a guest that does (glibc's lazy-PLT resolver, a
                // setjmp) only ever round-trips the block unmodified.
                uint8_t area[512] = {};
                auto put16 = [&](int off, uint16_t v) { std::memcpy(area + off, &v, 2); };
                auto put32 = [&](int off, uint32_t v) { std::memcpy(area + off, &v, 4); };
                put16(0, fpu_control);
                uint16_t sw = static_cast<uint16_t>((fpu_status & ~0x3800u) |
                                                    ((st_top & 7) << 11));
                put16(2, sw);
                uint8_t ftw = 0;
                for (int i = 0; i < 8; ++i)
                    if (st_used[i]) ftw |= static_cast<uint8_t>(1u << i);
                area[4] = ftw;
                put32(24, mxcsr);
                put32(28, 0x0000FFFF);  // MXCSR_MASK
                for (int i = 0; i < 8; ++i)
                    std::memcpy(area + 32 + i * 16, &st[i], 8);
                int nxmm = is64() ? 16 : 8;
                for (int i = 0; i < nxmm; ++i)
                    std::memcpy(area + 160 + i * 16, xmm[i].b, 16);
                mem_.write(rm.addr, area, sizeof area);
                return true;
            }
            if (sub == 1 && !rm.is_reg) {  // FXRSTOR
                uint8_t area[512];
                mem_.read(rm.addr, area, sizeof area);
                std::memcpy(&fpu_control, area + 0, 2);
                uint16_t sw;
                std::memcpy(&sw, area + 2, 2);
                fpu_status = sw;
                st_top = (sw >> 11) & 7;
                uint8_t ftw = area[4];
                for (int i = 0; i < 8; ++i) st_used[i] = (ftw >> i) & 1;
                std::memcpy(&mxcsr, area + 24, 4);
                for (int i = 0; i < 8; ++i)
                    std::memcpy(&st[i], area + 32 + i * 16, 8);
                int nxmm = is64() ? 16 : 8;
                for (int i = 0; i < nxmm; ++i)
                    std::memcpy(xmm[i].b, area + 160 + i * 16, 16);
                return true;
            }
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
            // AES-NI.  A guest reaches these only when CPUID says AES, and the
            // reason to implement them is that the alternative is worse than
            // not running: a library that finds no AES bit does not always fall
            // back to software, it can decline the work and hand its caller
            // bytes it never transformed.
            if (sel == Sel::P66 && op3 >= 0xDB && op3 <= 0xDF) {
                RM rm = decode_modrm();
                Xmm s = xmm_read(rm), d = xmm[modrm_reg_], r{};
                switch (op3) {
                    case 0xDB:  // AESIMC: the equivalent-inverse key schedule
                        r = aes_inv_mix_columns(s);
                        ++g_aes.imc;
                        break;
                    case 0xDC:  // AESENC
                        r = aes_xor(aes_mix_columns(aes_sub_shift(d, false)), s);
                        ++g_aes.enc;
                        break;
                    case 0xDD:  // AESENCLAST - the final round omits MixColumns
                        r = aes_xor(aes_sub_shift(d, false), s);
                        ++g_aes.enclast;
                        break;
                    case 0xDE:  // AESDEC
                        r = aes_xor(aes_inv_mix_columns(aes_sub_shift(d, true)), s);
                        ++g_aes.dec;
                        break;
                    default:    // 0xDF, AESDECLAST
                        r = aes_xor(aes_sub_shift(d, true), s);
                        ++g_aes.declast;
                        break;
                }
                xmm[modrm_reg_] = r;
                return true;
            }
            // ---- SSSE3 and SSE4.1 -------------------------------------
            // CPUID does not advertise these yet, but implementing them is
            // what makes advertising them possible - and ONNX Runtime's SSE2
            // fallback kernels are the slowest path it has.  Every one of
            // them is checked against a real CPU and qemu by isatest.
            if (sel == Sel::P66 && ((op3 >= 0x01 && op3 <= 0x0B) ||
                                    (op3 >= 0x1C && op3 <= 0x1E))) {  // SSSE3
                RM rm = decode_modrm();
                Xmm a = xmm[modrm_reg_], b = xmm_read(rm), r{};
                auto sat_sw = [](int32_t v) -> uint16_t {
                    return v < -32768 ? 0x8000 : v > 32767 ? 0x7FFF : static_cast<uint16_t>(v);
                };
                auto sw = [](uint16_t v) { return static_cast<int16_t>(v); };
                switch (op3) {
                    case 0x01:  // PHADDW: pairs within the destination, then the source
                    case 0x05:  // PHSUBW
                        for (int i = 0; i < 4; ++i) {
                            r.w[i] = static_cast<uint16_t>(op3 == 0x01 ? a.w[2 * i] + a.w[2 * i + 1]
                                                                      : a.w[2 * i] - a.w[2 * i + 1]);
                            r.w[4 + i] = static_cast<uint16_t>(
                                op3 == 0x01 ? b.w[2 * i] + b.w[2 * i + 1]
                                            : b.w[2 * i] - b.w[2 * i + 1]);
                        }
                        break;
                    case 0x02:  // PHADDD
                    case 0x06:  // PHSUBD
                        for (int i = 0; i < 2; ++i) {
                            r.d[i] = op3 == 0x02 ? a.d[2 * i] + a.d[2 * i + 1]
                                                 : a.d[2 * i] - a.d[2 * i + 1];
                            r.d[2 + i] = op3 == 0x02 ? b.d[2 * i] + b.d[2 * i + 1]
                                                     : b.d[2 * i] - b.d[2 * i + 1];
                        }
                        break;
                    case 0x03:  // PHADDSW
                    case 0x07:  // PHSUBSW
                        for (int i = 0; i < 4; ++i) {
                            r.w[i] = sat_sw(op3 == 0x03 ? sw(a.w[2 * i]) + sw(a.w[2 * i + 1])
                                                        : sw(a.w[2 * i]) - sw(a.w[2 * i + 1]));
                            r.w[4 + i] = sat_sw(op3 == 0x03 ? sw(b.w[2 * i]) + sw(b.w[2 * i + 1])
                                                            : sw(b.w[2 * i]) - sw(b.w[2 * i + 1]));
                        }
                        break;
                    case 0x04:  // PMADDUBSW: the destination is unsigned, the source signed
                        for (int i = 0; i < 8; ++i) {
                            int32_t lo = static_cast<int32_t>(a.b[2 * i]) *
                                         static_cast<int8_t>(b.b[2 * i]);
                            int32_t hi = static_cast<int32_t>(a.b[2 * i + 1]) *
                                         static_cast<int8_t>(b.b[2 * i + 1]);
                            r.w[i] = sat_sw(lo + hi);
                        }
                        break;
                    case 0x08:  // PSIGNB
                    case 0x09:  // PSIGNW
                    case 0x0A:  // PSIGND
                        // The source's sign decides: negate, zero, or leave alone.
                        if (op3 == 0x08)
                            for (int i = 0; i < 16; ++i) {
                                int8_t s = static_cast<int8_t>(b.b[i]);
                                r.b[i] = s < 0 ? static_cast<uint8_t>(-static_cast<int8_t>(a.b[i]))
                                               : (s == 0 ? 0 : a.b[i]);
                            }
                        else if (op3 == 0x09)
                            for (int i = 0; i < 8; ++i) {
                                int16_t s = sw(b.w[i]);
                                r.w[i] = s < 0 ? static_cast<uint16_t>(-sw(a.w[i]))
                                               : (s == 0 ? 0 : a.w[i]);
                            }
                        else
                            for (int i = 0; i < 4; ++i) {
                                int32_t s = static_cast<int32_t>(b.d[i]);
                                r.d[i] = s < 0 ? static_cast<uint32_t>(-static_cast<int32_t>(a.d[i]))
                                               : (s == 0 ? 0 : a.d[i]);
                            }
                        break;
                    case 0x0B:  // PMULHRSW: multiply, keep the top, round to nearest
                        for (int i = 0; i < 8; ++i) {
                            int32_t p = sw(a.w[i]) * sw(b.w[i]);
                            r.w[i] = static_cast<uint16_t>(((p >> 14) + 1) >> 1);
                        }
                        break;
                    case 0x1C:  // PABSB - the source is the operand, not the destination
                        for (int i = 0; i < 16; ++i) {
                            int8_t v = static_cast<int8_t>(b.b[i]);
                            r.b[i] = static_cast<uint8_t>(v < 0 ? -v : v);
                        }
                        break;
                    case 0x1D:  // PABSW
                        for (int i = 0; i < 8; ++i) {
                            int16_t v = sw(b.w[i]);
                            r.w[i] = static_cast<uint16_t>(v < 0 ? -v : v);
                        }
                        break;
                    default:  // 0x1E, PABSD
                        for (int i = 0; i < 4; ++i) {
                            int32_t v = static_cast<int32_t>(b.d[i]);
                            r.d[i] = static_cast<uint32_t>(v < 0 ? -v : v);
                        }
                        break;
                }
                xmm[modrm_reg_] = r;
                return true;
            }
            if (sel == Sel::P66 && (op3 == 0x10 || op3 == 0x14 || op3 == 0x15)) {
                // PBLENDVB / BLENDVPS / BLENDVPD: the mask is xmm0, implicitly,
                // and only the top bit of each element of it is read.
                RM rm = decode_modrm();
                Xmm a = xmm[modrm_reg_], b = xmm_read(rm), m = xmm[0], r = a;
                if (op3 == 0x10)
                    for (int i = 0; i < 16; ++i) r.b[i] = (m.b[i] & 0x80) ? b.b[i] : a.b[i];
                else if (op3 == 0x14)
                    for (int i = 0; i < 4; ++i) r.d[i] = (m.d[i] & 0x80000000u) ? b.d[i] : a.d[i];
                else
                    for (int i = 0; i < 2; ++i)
                        r.q[i] = (m.q[i] & 0x8000000000000000ull) ? b.q[i] : a.q[i];
                xmm[modrm_reg_] = r;
                return true;
            }
            if (sel == Sel::P66 && ((op3 >= 0x20 && op3 <= 0x25) ||
                                    (op3 >= 0x30 && op3 <= 0x35))) {
                // PMOVSX / PMOVZX: widen the low part of the source.  The two
                // families differ only in what fills the new high bits.
                RM rm = decode_modrm();
                Xmm b = xmm_read(rm), r{};
                bool zero = op3 >= 0x30;
                switch (op3 & 0x0F) {
                    case 0x0:  // byte -> word
                        for (int i = 0; i < 8; ++i)
                            r.w[i] = zero ? b.b[i]
                                          : static_cast<uint16_t>(static_cast<int8_t>(b.b[i]));
                        break;
                    case 0x1:  // byte -> dword
                        for (int i = 0; i < 4; ++i)
                            r.d[i] = zero ? b.b[i]
                                          : static_cast<uint32_t>(static_cast<int8_t>(b.b[i]));
                        break;
                    case 0x2:  // byte -> qword
                        for (int i = 0; i < 2; ++i)
                            r.q[i] = zero ? b.b[i]
                                          : static_cast<uint64_t>(static_cast<int8_t>(b.b[i]));
                        break;
                    case 0x3:  // word -> dword
                        for (int i = 0; i < 4; ++i)
                            r.d[i] = zero ? b.w[i]
                                          : static_cast<uint32_t>(static_cast<int16_t>(b.w[i]));
                        break;
                    case 0x4:  // word -> qword
                        for (int i = 0; i < 2; ++i)
                            r.q[i] = zero ? b.w[i]
                                          : static_cast<uint64_t>(static_cast<int16_t>(b.w[i]));
                        break;
                    default:  // 0x5, dword -> qword
                        for (int i = 0; i < 2; ++i)
                            r.q[i] = zero ? b.d[i]
                                          : static_cast<uint64_t>(static_cast<int32_t>(b.d[i]));
                        break;
                }
                xmm[modrm_reg_] = r;
                return true;
            }
            if (sel == Sel::P66 && (op3 == 0x28 || op3 == 0x29 || op3 == 0x2B ||
                                    op3 == 0x37 || (op3 >= 0x38 && op3 <= 0x41))) {
                RM rm = decode_modrm();
                Xmm a = xmm[modrm_reg_], b = xmm_read(rm), r{};
                auto sd = [](uint32_t v) { return static_cast<int32_t>(v); };
                switch (op3) {
                    case 0x28:  // PMULDQ: the even dwords, signed, to qwords
                        for (int i = 0; i < 2; ++i)
                            r.q[i] = static_cast<uint64_t>(static_cast<int64_t>(sd(a.d[2 * i])) *
                                                           sd(b.d[2 * i]));
                        break;
                    case 0x29:  // PCMPEQQ
                        for (int i = 0; i < 2; ++i) r.q[i] = a.q[i] == b.q[i] ? ~0ull : 0;
                        break;
                    case 0x2B: {  // PACKUSDW: signed dwords -> unsigned words
                        auto sat = [](int32_t v) -> uint16_t {
                            return v < 0 ? 0 : v > 65535 ? 0xFFFF : static_cast<uint16_t>(v);
                        };
                        for (int i = 0; i < 4; ++i) r.w[i] = sat(sd(a.d[i]));
                        for (int i = 0; i < 4; ++i) r.w[4 + i] = sat(sd(b.d[i]));
                        break;
                    }
                    case 0x37:  // PCMPGTQ (SSE4.2)
                        for (int i = 0; i < 2; ++i)
                            r.q[i] = static_cast<int64_t>(a.q[i]) > static_cast<int64_t>(b.q[i])
                                         ? ~0ull
                                         : 0;
                        break;
                    case 0x38:  // PMINSB
                    case 0x3C:  // PMAXSB
                        for (int i = 0; i < 16; ++i) {
                            int8_t x = static_cast<int8_t>(a.b[i]), y = static_cast<int8_t>(b.b[i]);
                            r.b[i] = static_cast<uint8_t>(op3 == 0x38 ? (x < y ? x : y)
                                                                     : (x > y ? x : y));
                        }
                        break;
                    case 0x39:  // PMINSD
                    case 0x3D:  // PMAXSD
                        for (int i = 0; i < 4; ++i) {
                            int32_t x = sd(a.d[i]), y = sd(b.d[i]);
                            r.d[i] = static_cast<uint32_t>(op3 == 0x39 ? (x < y ? x : y)
                                                                      : (x > y ? x : y));
                        }
                        break;
                    case 0x3A:  // PMINUW
                    case 0x3E:  // PMAXUW
                        for (int i = 0; i < 8; ++i)
                            r.w[i] = op3 == 0x3A ? (a.w[i] < b.w[i] ? a.w[i] : b.w[i])
                                                 : (a.w[i] > b.w[i] ? a.w[i] : b.w[i]);
                        break;
                    case 0x3B:  // PMINUD
                    case 0x3F:  // PMAXUD
                        for (int i = 0; i < 4; ++i)
                            r.d[i] = op3 == 0x3B ? (a.d[i] < b.d[i] ? a.d[i] : b.d[i])
                                                 : (a.d[i] > b.d[i] ? a.d[i] : b.d[i]);
                        break;
                    case 0x40:  // PMULLD: the low half of the signed product
                        for (int i = 0; i < 4; ++i)
                            r.d[i] = static_cast<uint32_t>(sd(a.d[i]) * sd(b.d[i]));
                        break;
                    default: {  // 0x41, PHMINPOSUW: the smallest word, and where it was
                        int at = 0;
                        uint16_t best = b.w[0];
                        for (int i = 1; i < 8; ++i)
                            if (b.w[i] < best) {
                                best = b.w[i];
                                at = i;
                            }
                        r.w[0] = best;
                        r.w[1] = static_cast<uint16_t>(at);
                        break;
                    }
                }
                xmm[modrm_reg_] = r;
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
            if (sel == Sel::P66 && (op3 == 0x08 || op3 == 0x09)) {  // ROUNDPS / ROUNDPD
                RM rm = decode_modrm(1);
                Xmm s = xmm_read(rm), r{};
                uint8_t imm = fetch8();
                // Bit 2 says "use MXCSR"; otherwise bits 1:0 name the mode.
                auto round = [&](double v) {
                    if (imm & 4) return round_by_mxcsr(mxcsr, v);
                    switch (imm & 3) {
                        case 0: return std::nearbyint(v);
                        case 1: return std::floor(v);
                        case 2: return std::ceil(v);
                        default: return std::trunc(v);
                    }
                };
                if (op3 == 0x09)
                    for (int i = 0; i < 2; ++i) r.f64[i] = round(s.f64[i]);
                else
                    for (int i = 0; i < 4; ++i)
                        r.f32[i] = static_cast<float>(round(s.f32[i]));
                xmm[modrm_reg_] = r;
                return true;
            }
            if (sel == Sel::P66 && (op3 == 0x0C || op3 == 0x0D || op3 == 0x0E)) {
                // BLENDPS / BLENDPD / PBLENDW: one immediate bit per element.
                RM rm = decode_modrm(1);
                Xmm a = xmm[modrm_reg_], b = xmm_read(rm), r = a;
                uint8_t imm = fetch8();
                if (op3 == 0x0C)
                    for (int i = 0; i < 4; ++i) r.d[i] = (imm >> i) & 1 ? b.d[i] : a.d[i];
                else if (op3 == 0x0D)
                    for (int i = 0; i < 2; ++i) r.q[i] = (imm >> i) & 1 ? b.q[i] : a.q[i];
                else
                    for (int i = 0; i < 8; ++i) r.w[i] = (imm >> i) & 1 ? b.w[i] : a.w[i];
                xmm[modrm_reg_] = r;
                return true;
            }
            if (sel == Sel::P66 && op3 == 0x21) {  // INSERTPS
                RM rm = decode_modrm(1);
                Xmm s = xmm_read(rm);
                uint8_t imm = fetch8();
                // imm[7:6] picks the source dword (register form only), imm[5:4]
                // the destination one, and imm[3:0] then zeroes whichever
                // elements it names - including the one just written.
                uint32_t v = rm.is_reg ? s.d[(imm >> 6) & 3] : s.d[0];
                Xmm& d = xmm[modrm_reg_];
                d.d[(imm >> 4) & 3] = v;
                for (int i = 0; i < 4; ++i)
                    if ((imm >> i) & 1) d.d[i] = 0;
                return true;
            }
            if (sel == Sel::P66 && (op3 == 0x14 || op3 == 0x15 || op3 == 0x16 || op3 == 0x17)) {
                // PEXTRB / PEXTRW / PEXTRD / PEXTRQ / EXTRACTPS.  The register
                // form zero-extends into the whole general register; the memory
                // form writes exactly the element's width.
                RM rm = decode_modrm(1);
                Xmm s = xmm[modrm_reg_];
                uint8_t imm = fetch8();
                uint64_t v;
                int width;
                if (op3 == 0x14) {
                    v = s.b[imm & 15];
                    width = 1;
                } else if (op3 == 0x15) {
                    v = s.w[imm & 7];
                    width = 2;
                } else if (op3 == 0x17) {
                    v = s.d[imm & 3];
                    width = 4;
                } else if (pfx_.rex_w) {
                    v = s.q[imm & 1];
                    width = 8;
                } else {
                    v = s.d[imm & 3];
                    width = 4;
                }
                if (rm.is_reg)
                    reg_write(rm.reg, width == 8 ? 8 : 4, v);
                else
                    mem_.write_sized(rm.addr, width, v);
                return true;
            }
            if (sel == Sel::P66 && (op3 == 0x20 || op3 == 0x22)) {
                // PINSRB / PINSRD / PINSRQ, from a general register or memory.
                RM rm = decode_modrm(1);
                int width = op3 == 0x20 ? 1 : (pfx_.rex_w ? 8 : 4);
                uint64_t v = rm.is_reg ? reg_read(rm.reg, width == 8 ? 8 : 4)
                                       : mem_.read_sized(rm.addr, width);
                uint8_t imm = fetch8();
                Xmm& d = xmm[modrm_reg_];
                if (width == 1)
                    d.b[imm & 15] = static_cast<uint8_t>(v);
                else if (width == 4)
                    d.d[imm & 3] = static_cast<uint32_t>(v);
                else
                    d.q[imm & 1] = v;
                return true;
            }
            if (op3 == 0xDF && sel == Sel::P66) {  // AESKEYGENASSIST
                RM rm = decode_modrm(1);
                Xmm s = xmm_read(rm);
                uint8_t rcon = fetch8();
                auto sub_word = [](uint32_t w) {
                    uint32_t r = 0;
                    for (int i = 0; i < 4; ++i)
                        r |= static_cast<uint32_t>(kAesSbox[(w >> (i * 8)) & 0xFF]) << (i * 8);
                    return r;
                };
                auto rot_word = [](uint32_t w) { return (w >> 8) | (w << 24); };
                Xmm r{};
                r.d[0] = sub_word(s.d[1]);
                r.d[1] = rot_word(sub_word(s.d[1])) ^ rcon;
                r.d[2] = sub_word(s.d[3]);
                r.d[3] = rot_word(sub_word(s.d[3])) ^ rcon;
                ++g_aes.keygen;
                xmm[modrm_reg_] = r;
                return true;
            }
            if (op3 == 0x44 && sel == Sel::P66) {  // PCLMULQDQ
                RM rm = decode_modrm(1);
                Xmm s = xmm_read(rm), d = xmm[modrm_reg_];
                uint8_t imm = fetch8();
                uint64_t a = d.q[(imm & 0x01) ? 1 : 0], b = s.q[(imm & 0x10) ? 1 : 0];
                // Carry-less: the same shift-and-add as a multiply, with XOR
                // standing in for the add, so nothing ever carries.
                uint64_t lo = 0, hi = 0;
                for (int i = 0; i < 64; ++i) {
                    if ((a >> i) & 1) {
                        lo ^= b << i;
                        if (i) hi ^= b >> (64 - i);
                    }
                }
                Xmm r{};
                r.q[0] = lo;
                r.q[1] = hi;
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
