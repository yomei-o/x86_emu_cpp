// The x87 floating-point unit.
//
// Even code that does all its arithmetic in SSE still touches x87: a 32-bit CRT
// resets the FPU during startup, the 32-bit Windows ABI returns doubles in
// ST(0), and gcc uses the register stack for `long double`.
//
// The register stack holds host doubles instead of true 80-bit extended values.
// Loads and stores of an 80-bit memory operand convert, so the encoding works,
// but a computation carried out entirely in extended precision on real hardware
// may differ from this in its last bits.
#include <cmath>
#include <cstring>

#include "cpu.h"

namespace x86emu {
namespace {

// Status word bits: C0/C1/C2/C3 report comparison results.
enum : uint16_t {
    SW_C0 = 1u << 8,
    SW_C1 = 1u << 9,
    SW_C2 = 1u << 10,
    SW_C3 = 1u << 14,
};

// x87 80-bit extended format: 64-bit mantissa with an explicit leading bit, a
// 15-bit exponent biased by 16383, and a sign.
double from_extended(const uint8_t raw[10]) {
    uint64_t mantissa;
    std::memcpy(&mantissa, raw, 8);
    uint16_t se;
    std::memcpy(&se, raw + 8, 2);
    int exponent = se & 0x7FFF;
    bool negative = (se & 0x8000) != 0;

    double value;
    if (exponent == 0x7FFF) {
        value = (mantissa << 1) == 0 ? HUGE_VAL : NAN;
    } else if (exponent == 0 && mantissa == 0) {
        value = 0.0;
    } else {
        // ldexp puts the mantissa (as a fraction) back at the right magnitude.
        value = std::ldexp(static_cast<double>(mantissa), exponent - 16383 - 63);
    }
    return negative ? -value : value;
}

void to_extended(double v, uint8_t raw[10]) {
    std::memset(raw, 0, 10);
    bool negative = std::signbit(v);
    v = std::fabs(v);
    uint16_t se = negative ? 0x8000 : 0;
    uint64_t mantissa = 0;

    if (std::isnan(v)) {
        se |= 0x7FFF;
        mantissa = 0xC000000000000000ull;
    } else if (std::isinf(v)) {
        se |= 0x7FFF;
        mantissa = 0x8000000000000000ull;
    } else if (v != 0.0) {
        int exponent;
        double frac = std::frexp(v, &exponent);  // frac in [0.5, 1)
        mantissa = static_cast<uint64_t>(std::ldexp(frac, 64));
        se |= static_cast<uint16_t>(exponent - 1 + 16383);
    }
    std::memcpy(raw, &mantissa, 8);
    std::memcpy(raw + 8, &se, 2);
}

// The control word's RC field selects the rounding mode, and a C runtime really
// does switch it: it sets "round down" or "truncate" around FRNDINT and FISTP to
// get a floor or a cast.  Ignoring it silently changes the answer.
double round_by(uint16_t control, double v) {
    switch ((control >> 10) & 3) {
        case 1: return std::floor(v);
        case 2: return std::ceil(v);
        case 3: return std::trunc(v);
        default: return std::nearbyint(v);
    }
}

}  // namespace

void Cpu::fpu_push(double v) {
    st_top = (st_top - 1) & 7;
    st[st_top] = v;
    st_used[st_top] = true;
}

double Cpu::fpu_pop() {
    double v = st[st_top];
    st_used[st_top] = false;
    st_top = (st_top + 1) & 7;
    return v;
}

double& Cpu::fpu_reg(int i) { return st[(st_top + i) & 7]; }

void Cpu::execute_x87(uint8_t op) {
    const uint64_t start = rip - 1;
    // Peek at the ModRM byte: the "no operand" forms are encoded as mod == 3
    // with a fixed register field, and each opcode splits differently.
    uint8_t modrm = mem_.read8(rip);
    bool has_memory_operand = (modrm >> 6) != 3;
    int sub = (modrm >> 3) & 7;

    auto clear_cc = [&] { fpu_status &= ~(SW_C0 | SW_C1 | SW_C2 | SW_C3); };
    // Sets C3/C2/C0 the way FCOM does: equal, unordered, or less than.
    auto set_compare = [&](double a, double b) {
        clear_cc();
        if (std::isnan(a) || std::isnan(b))
            fpu_status |= SW_C0 | SW_C2 | SW_C3;
        else if (a > b)
            ;  // all three clear
        else if (a < b)
            fpu_status |= SW_C0;
        else
            fpu_status |= SW_C3;
    };
    // The FCOMI family reports into the integer flags instead.
    auto set_compare_flags = [&](double a, double b) {
        bool unordered = std::isnan(a) || std::isnan(b);
        set_flag(FLAG_OF, false);
        set_flag(FLAG_AF, false);
        set_flag(FLAG_SF, false);
        set_flag(FLAG_ZF, unordered || a == b);
        set_flag(FLAG_PF, unordered);
        set_flag(FLAG_CF, unordered || a < b);
    };
    auto arith = [&](int which, double a, double b) {
        switch (which) {
            case 0: return a + b;               // FADD
            case 1: return a * b;               // FMUL
            case 4: return a - b;               // FSUB
            case 5: return b - a;               // FSUBR
            case 6: return a / b;               // FDIV
            default: return b / a;              // FDIVR (7)
        }
    };

    if (has_memory_operand) {
        RM rm = decode_modrm();
        uint64_t addr = rm.addr;
        switch (op) {
            case 0xD9:  // 32-bit float, plus the control-word transfers
                switch (sub) {
                    case 0: {  // FLD m32
                        uint32_t bits = mem_.read32(addr);
                        float f;
                        std::memcpy(&f, &bits, 4);
                        fpu_push(f);
                        return;
                    }
                    case 2:
                    case 3: {  // FST / FSTP m32
                        float f = static_cast<float>(st[st_top]);
                        uint32_t bits;
                        std::memcpy(&bits, &f, 4);
                        mem_.write32(addr, bits);
                        if (sub == 3) fpu_pop();
                        return;
                    }
                    case 4:  // FLDENV - only the control word matters here
                        fpu_control = mem_.read16(addr);
                        return;
                    case 5:  // FLDCW
                        fpu_control = mem_.read16(addr);
                        return;
                    case 6:  // FNSTENV
                        mem_.write16(addr, fpu_control);
                        mem_.write16(addr + 4, fpu_status);
                        return;
                    case 7:  // FNSTCW
                        mem_.write16(addr, fpu_control);
                        return;
                    default:
                        unsupported("x87 D9 sub-opcode", static_cast<uint8_t>(sub), start);
                }
            case 0xDB:  // 32-bit integer, and 80-bit float
                switch (sub) {
                    case 0:  // FILD m32
                        fpu_push(static_cast<int32_t>(mem_.read32(addr)));
                        return;
                    case 1:
                    case 2:
                    case 3: {  // FISTTP / FIST / FISTP m32
                        double v = st[st_top];
                        int32_t i = to_int32_x86(
                            sub == 1 ? std::trunc(v) : round_by(fpu_control, v));
                        mem_.write32(addr, static_cast<uint32_t>(i));
                        if (sub != 2) fpu_pop();
                        return;
                    }
                    case 5: {  // FLD m80
                        uint8_t raw[10];
                        mem_.read(addr, raw, 10);
                        fpu_push(from_extended(raw));
                        return;
                    }
                    case 7: {  // FSTP m80
                        uint8_t raw[10];
                        to_extended(fpu_pop(), raw);
                        mem_.write(addr, raw, 10);
                        return;
                    }
                    default:
                        unsupported("x87 DB sub-opcode", static_cast<uint8_t>(sub), start);
                }
            case 0xD8:
            case 0xDC: {  // arithmetic against a memory operand
                double b;
                if (op == 0xD8) {
                    uint32_t bits = mem_.read32(addr);
                    float f;
                    std::memcpy(&f, &bits, 4);
                    b = f;
                } else {
                    b = 0;
                    uint64_t bits = mem_.read64(addr);
                    std::memcpy(&b, &bits, 8);
                }
                if (sub == 2 || sub == 3) {  // FCOM / FCOMP
                    set_compare(st[st_top], b);
                    if (sub == 3) fpu_pop();
                    return;
                }
                st[st_top] = arith(sub, st[st_top], b);
                return;
            }
            case 0xDD:  // 64-bit float
                switch (sub) {
                    case 0: {  // FLD m64
                        uint64_t bits = mem_.read64(addr);
                        double d;
                        std::memcpy(&d, &bits, 8);
                        fpu_push(d);
                        return;
                    }
                    case 2:
                    case 3: {  // FST / FSTP m64
                        uint64_t bits;
                        double d = st[st_top];
                        std::memcpy(&bits, &d, 8);
                        mem_.write64(addr, bits);
                        if (sub == 3) fpu_pop();
                        return;
                    }
                    case 7:  // FNSTSW m16
                        mem_.write16(addr, static_cast<uint16_t>(fpu_status |
                                                                 ((st_top & 7) << 11)));
                        return;
                    default:
                        unsupported("x87 DD sub-opcode", static_cast<uint8_t>(sub), start);
                }
            case 0xDE: {  // arithmetic against a 16-bit integer
                double b = static_cast<int16_t>(mem_.read16(addr));
                if (sub == 2 || sub == 3) {
                    set_compare(st[st_top], b);
                    if (sub == 3) fpu_pop();
                    return;
                }
                st[st_top] = arith(sub, st[st_top], b);
                return;
            }
            case 0xDF:  // 16- and 64-bit integers
                switch (sub) {
                    case 0:  // FILD m16
                        fpu_push(static_cast<int16_t>(mem_.read16(addr)));
                        return;
                    case 2:
                    case 3: {  // FIST / FISTP m16
                        int16_t i = to_int16_x86(round_by(fpu_control, st[st_top]));
                        mem_.write16(addr, static_cast<uint16_t>(i));
                        if (sub == 3) fpu_pop();
                        return;
                    }
                    case 5:  // FILD m64
                        fpu_push(static_cast<double>(static_cast<int64_t>(mem_.read64(addr))));
                        return;
                    case 7: {  // FISTP m64
                        int64_t i = to_int64_x86(round_by(fpu_control, fpu_pop()));
                        mem_.write64(addr, static_cast<uint64_t>(i));
                        return;
                    }
                    default:
                        unsupported("x87 DF sub-opcode", static_cast<uint8_t>(sub), start);
                }
            default:
                unsupported("x87 opcode with memory operand", op, start);
        }
    }

    // From here on the operand is a stack register, so consume the ModRM byte.
    ++rip;
    int reg = modrm & 7;

    switch (op) {
        case 0xD8:  // FADD/FMUL/FCOM/FSUB/... ST(0), ST(i)
            if (sub == 2 || sub == 3) {
                set_compare(st[st_top], fpu_reg(reg));
                if (sub == 3) fpu_pop();
                return;
            }
            st[st_top] = arith(sub, st[st_top], fpu_reg(reg));
            return;

        case 0xD9:
            switch (modrm) {
                case 0xD0: return;                       // FNOP
                case 0xE0: st[st_top] = -st[st_top]; return;              // FCHS
                case 0xE1: st[st_top] = std::fabs(st[st_top]); return;    // FABS
                case 0xE4: set_compare(st[st_top], 0.0); return;          // FTST
                case 0xE5:  // FXAM
                    clear_cc();
                    if (std::isnan(st[st_top])) fpu_status |= SW_C0;
                    else if (st[st_top] == 0.0) fpu_status |= SW_C3;
                    else fpu_status |= SW_C2;
                    if (std::signbit(st[st_top])) fpu_status |= SW_C1;
                    return;
                case 0xE8: fpu_push(1.0); return;                         // FLD1
                case 0xE9: fpu_push(3.321928094887362348); return;        // FLDL2T
                case 0xEA: fpu_push(1.442695040888963407); return;        // FLDL2E
                case 0xEB: fpu_push(3.141592653589793239); return;        // FLDPI
                case 0xEC: fpu_push(0.301029995663981195); return;        // FLDLG2
                case 0xED: fpu_push(0.693147180559945309); return;        // FLDLN2
                case 0xEE: fpu_push(0.0); return;                         // FLDZ
                case 0xF0: st[st_top] = std::exp2(st[st_top]) - 1.0; return;  // F2XM1
                case 0xF1: {  // FYL2X: ST(1) * log2(ST(0)), popping
                    double x = fpu_pop();
                    st[st_top] *= std::log2(x);
                    return;
                }
                case 0xF2: {  // FPTAN
                    double t = std::tan(st[st_top]);
                    st[st_top] = t;
                    fpu_push(1.0);
                    return;
                }
                case 0xF3: {  // FPATAN: atan(ST(1)/ST(0)), popping
                    double x = fpu_pop();
                    st[st_top] = std::atan2(st[st_top], x);
                    return;
                }
                case 0xF8: {  // FPREM
                    double b = fpu_reg(1);
                    st[st_top] = std::fmod(st[st_top], b);
                    clear_cc();
                    return;
                }
                case 0xFA: st[st_top] = std::sqrt(st[st_top]); return;    // FSQRT
                case 0xFB: {  // FSINCOS
                    double v = st[st_top];
                    st[st_top] = std::sin(v);
                    fpu_push(std::cos(v));
                    return;
                }
                case 0xFC: st[st_top] = round_by(fpu_control, st[st_top]); return;  // FRNDINT
                case 0xFD: {  // FSCALE: ST(0) * 2^trunc(ST(1))
                    st[st_top] = std::ldexp(st[st_top],
                                            static_cast<int>(std::trunc(fpu_reg(1))));
                    return;
                }
                case 0xFE: st[st_top] = std::sin(st[st_top]); return;     // FSIN
                case 0xFF: st[st_top] = std::cos(st[st_top]); return;     // FCOS
                default:
                    if (sub == 0) {  // FLD ST(i)
                        fpu_push(fpu_reg(reg));
                        return;
                    }
                    if (sub == 1) {  // FXCH
                        std::swap(st[st_top], fpu_reg(reg));
                        return;
                    }
                    unsupported("x87 D9 register form", modrm, start);
            }

        case 0xDA:
            if (modrm == 0xE9) {  // FUCOMPP
                double a = fpu_pop(), b = fpu_pop();
                set_compare(a, b);
                return;
            }
            // FCMOVcc: conditional moves driven by the integer flags.
            switch (sub) {
                case 0: if (flag(FLAG_CF)) st[st_top] = fpu_reg(reg); return;
                case 1: if (flag(FLAG_ZF)) st[st_top] = fpu_reg(reg); return;
                case 2: if (flag(FLAG_CF) || flag(FLAG_ZF)) st[st_top] = fpu_reg(reg); return;
                case 3: if (flag(FLAG_PF)) st[st_top] = fpu_reg(reg); return;
                default: unsupported("x87 DA register form", modrm, start);
            }

        case 0xDB:
            switch (modrm) {
                case 0xE2: fpu_status = 0; return;  // FNCLEX
                case 0xE3:                          // FNINIT
                    fpu_control = 0x037F;
                    fpu_status = 0;
                    st_top = 0;
                    for (int i = 0; i < 8; ++i) {
                        st[i] = 0.0;
                        st_used[i] = false;
                    }
                    return;
                default:
                    if (sub == 5) {  // FUCOMI
                        set_compare_flags(st[st_top], fpu_reg(reg));
                        return;
                    }
                    if (sub == 6) {  // FCOMI
                        set_compare_flags(st[st_top], fpu_reg(reg));
                        return;
                    }
                    if (sub <= 3) {  // FCMOVNcc
                        bool take = sub == 0 ? !flag(FLAG_CF)
                                  : sub == 1 ? !flag(FLAG_ZF)
                                  : sub == 2 ? !(flag(FLAG_CF) || flag(FLAG_ZF))
                                             : !flag(FLAG_PF);
                        if (take) st[st_top] = fpu_reg(reg);
                        return;
                    }
                    unsupported("x87 DB register form", modrm, start);
            }

        case 0xDC:  // arithmetic with ST(i) as the destination
            if (sub == 2 || sub == 3) {
                set_compare(fpu_reg(reg), st[st_top]);
                if (sub == 3) fpu_pop();
                return;
            }
            // The reversed sub-opcodes swap meaning in this direction.
            fpu_reg(reg) = arith(sub == 4 ? 5 : sub == 5 ? 4 : sub == 6 ? 7 : sub == 7 ? 6 : sub,
                                 fpu_reg(reg), st[st_top]);
            return;

        case 0xDD:
            switch (sub) {
                case 0: st_used[(st_top + reg) & 7] = false; return;  // FFREE
                case 1:                                               // FXCH (alias)
                    std::swap(st[st_top], fpu_reg(reg));
                    return;
                case 2: fpu_reg(reg) = st[st_top]; return;            // FST ST(i)
                case 3:                                               // FSTP ST(i)
                    fpu_reg(reg) = st[st_top];
                    fpu_pop();
                    return;
                case 4:                                               // FUCOM
                case 5:                                               // FUCOMP
                    set_compare(st[st_top], fpu_reg(reg));
                    if (sub == 5) fpu_pop();
                    return;
                default: unsupported("x87 DD register form", modrm, start);
            }

        case 0xDE:
            if (modrm == 0xD9) {  // FCOMPP
                double a = fpu_pop(), b = fpu_pop();
                set_compare(a, b);
                return;
            }
            // FADDP/FMULP/FSUBP/... : operate into ST(i), then pop.
            fpu_reg(reg) = arith(sub == 4 ? 5 : sub == 5 ? 4 : sub == 6 ? 7 : sub == 7 ? 6 : sub,
                                 fpu_reg(reg), st[st_top]);
            fpu_pop();
            return;

        case 0xDF:
            if (modrm == 0xE0) {  // FNSTSW AX
                reg_write(RAX, 2, static_cast<uint16_t>(fpu_status | ((st_top & 7) << 11)));
                return;
            }
            if (sub == 5 || sub == 6) {  // FUCOMIP / FCOMIP: compare, then pop
                double a = st[st_top], b = fpu_reg(reg);
                set_compare_flags(a, b);
                fpu_pop();
                return;
            }
            unsupported("x87 DF register form", modrm, start);

        default:
            unsupported("x87 opcode", op, start);
    }
}

}  // namespace x86emu
