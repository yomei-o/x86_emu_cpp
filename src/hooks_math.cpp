// The math library.
//
// Every one of these is a pure function of its arguments, so handing them to the
// host's libm is both the simplest implementation and the most accurate one
// available - the emulated x87 stack only carries double precision, so a guest
// computing sin() itself would be less exact than this is.
//
// The interesting part is not the functions but the plumbing: where a floating
// point argument lives and where the result goes differs completely between the
// three ABIs, and `float` versus `double` versions of the same function differ
// again.  Emulator::Args and set_result_double handle that.
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>

#include "emulator.h"

namespace x86emu {

void Emulator::install_math_hooks() {
    // Math is cdecl in every configuration the emulator supports.
    auto add = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };

    // Registers `name`, plus the `f` (float) and `l` (long double) spellings and
    // the underscore-prefixed one msvcrt uses.  Long double is treated as double,
    // which is exactly right for MSVC and loses precision for mingw.
    auto unary = [&](const char* name, double (*fn)(double)) {
        std::string base = name;
        add(name, [fn](Emulator& e) {
            Args a(e);
            e.set_result_double(fn(a.next_double_param()));
        });
        add(("_" + base).c_str(), [fn](Emulator& e) {
            Args a(e);
            e.set_result_double(fn(a.next_double_param()));
        });
        add((base + "f").c_str(), [fn](Emulator& e) {
            Args a(e);
            e.set_result_float(static_cast<float>(fn(a.next_float_param())));
        });
        add((base + "l").c_str(), [fn](Emulator& e) {
            Args a(e);
            e.set_result_double(fn(a.next_double_param()));
        });
    };
    auto binary = [&](const char* name, double (*fn)(double, double)) {
        std::string base = name;
        add(name, [fn](Emulator& e) {
            Args a(e);
            double x = a.next_double_param();
            double y = a.next_double_param();
            e.set_result_double(fn(x, y));
        });
        add(("_" + base).c_str(), [fn](Emulator& e) {
            Args a(e);
            double x = a.next_double_param();
            double y = a.next_double_param();
            e.set_result_double(fn(x, y));
        });
        add((base + "f").c_str(), [fn](Emulator& e) {
            Args a(e);
            float x = a.next_float_param();
            float y = a.next_float_param();
            e.set_result_float(static_cast<float>(fn(x, y)));
        });
        add((base + "l").c_str(), [fn](Emulator& e) {
            Args a(e);
            double x = a.next_double_param();
            double y = a.next_double_param();
            e.set_result_double(fn(x, y));
        });
    };

    // ---- one argument ------------------------------------------------------
    unary("sin", [](double x) { return std::sin(x); });
    unary("cos", [](double x) { return std::cos(x); });
    unary("tan", [](double x) { return std::tan(x); });
    unary("asin", [](double x) { return std::asin(x); });
    unary("acos", [](double x) { return std::acos(x); });
    unary("atan", [](double x) { return std::atan(x); });
    unary("sinh", [](double x) { return std::sinh(x); });
    unary("cosh", [](double x) { return std::cosh(x); });
    unary("tanh", [](double x) { return std::tanh(x); });
    unary("asinh", [](double x) { return std::asinh(x); });
    unary("acosh", [](double x) { return std::acosh(x); });
    unary("atanh", [](double x) { return std::atanh(x); });
    unary("exp", [](double x) { return std::exp(x); });
    unary("exp2", [](double x) { return std::exp2(x); });
    unary("expm1", [](double x) { return std::expm1(x); });
    unary("log", [](double x) { return std::log(x); });
    unary("log2", [](double x) { return std::log2(x); });
    unary("log10", [](double x) { return std::log10(x); });
    unary("log1p", [](double x) { return std::log1p(x); });
    unary("logb", [](double x) { return std::logb(x); });
    unary("sqrt", [](double x) { return std::sqrt(x); });
    unary("cbrt", [](double x) { return std::cbrt(x); });
    unary("fabs", [](double x) { return std::fabs(x); });
    unary("ceil", [](double x) { return std::ceil(x); });
    unary("floor", [](double x) { return std::floor(x); });
    unary("trunc", [](double x) { return std::trunc(x); });
    unary("round", [](double x) { return std::round(x); });
    unary("nearbyint", [](double x) { return std::nearbyint(x); });
    unary("rint", [](double x) { return std::rint(x); });
    unary("tgamma", [](double x) { return std::tgamma(x); });
    unary("lgamma", [](double x) { return std::lgamma(x); });
    unary("erf", [](double x) { return std::erf(x); });
    unary("erfc", [](double x) { return std::erfc(x); });

    // ---- two arguments -----------------------------------------------------
    binary("atan2", [](double y, double x) { return std::atan2(y, x); });
    binary("pow", [](double x, double y) { return std::pow(x, y); });
    binary("fmod", [](double x, double y) { return std::fmod(x, y); });
    binary("hypot", [](double x, double y) { return std::hypot(x, y); });
    binary("fdim", [](double x, double y) { return std::fdim(x, y); });
    binary("fmax", [](double x, double y) { return std::fmax(x, y); });
    binary("fmin", [](double x, double y) { return std::fmin(x, y); });
    binary("copysign", [](double x, double y) { return std::copysign(x, y); });
    binary("remainder", [](double x, double y) { return std::remainder(x, y); });
    binary("nextafter", [](double x, double y) { return std::nextafter(x, y); });

    // ---- mixed signatures ---------------------------------------------------
    add("ldexp", [](Emulator& e) {
        Args a(e);
        double x = a.next_double_param();
        int n = static_cast<int>(static_cast<int32_t>(a.next_int(4)));
        e.set_result_double(std::ldexp(x, n));
    });
    add("scalbn", [](Emulator& e) {
        Args a(e);
        double x = a.next_double_param();
        int n = static_cast<int>(static_cast<int32_t>(a.next_int(4)));
        e.set_result_double(std::scalbn(x, n));
    });
    add("frexp", [](Emulator& e) {
        Args a(e);
        double x = a.next_double_param();
        uint64_t out = a.next_ptr();
        int exponent = 0;
        double r = std::frexp(x, &exponent);
        if (out) e.mem.write32(out, static_cast<uint32_t>(exponent));
        e.set_result_double(r);
    });
    add("modf", [](Emulator& e) {
        Args a(e);
        double x = a.next_double_param();
        uint64_t out = a.next_ptr();
        double integral = 0;
        double r = std::modf(x, &integral);
        if (out) {
            uint64_t bits;
            std::memcpy(&bits, &integral, sizeof bits);
            e.mem.write64(out, bits);
        }
        e.set_result_double(r);
    });
    add("fma", [](Emulator& e) {
        Args a(e);
        double x = a.next_double_param();
        double y = a.next_double_param();
        double z = a.next_double_param();
        e.set_result_double(std::fma(x, y, z));
    });

    // ---- classification (integer results, so no FP return path) -------------
    auto predicate = [&](const char* name, int (*fn)(double)) {
        add(name, [fn](Emulator& e) {
            Args a(e);
            e.set_result(static_cast<uint64_t>(fn(a.next_double_param())));
        });
    };
    predicate("isnan", [](double x) { return std::isnan(x) ? 1 : 0; });
    predicate("_isnan", [](double x) { return std::isnan(x) ? 1 : 0; });
    predicate("isinf", [](double x) { return std::isinf(x) ? 1 : 0; });
    predicate("finite", [](double x) { return std::isfinite(x) ? 1 : 0; });
    predicate("_finite", [](double x) { return std::isfinite(x) ? 1 : 0; });
    predicate("signbit", [](double x) { return std::signbit(x) ? 1 : 0; });
    predicate("ilogb", [](double x) { return std::ilogb(x); });
    // msvcrt's _fpclass and glibc's fpclassify report the same categories with
    // different constants; the C ones are what a portable guest expects.
    predicate("fpclassify", [](double x) {
        switch (std::fpclassify(x)) {
            case FP_NAN: return 0;
            case FP_INFINITE: return 1;
            case FP_ZERO: return 2;
            case FP_SUBNORMAL: return 3;
            default: return 4;  // FP_NORMAL
        }
    });

    // The UCRT's own classification helpers, which is how fpclassify and isnan
    // are actually implemented there.  Its constants are not the ones other
    // libcs use, so they are spelled out rather than passed through.
    enum : int32_t {
        kFpInfinite = 1,
        kFpNan = 2,
        kFpNormal = -1,
        kFpSubnormal = -2,
        kFpZero = 0,
    };
    auto classify_double = [](double v) -> int32_t {
        switch (std::fpclassify(v)) {
            case FP_NAN: return kFpNan;
            case FP_INFINITE: return kFpInfinite;
            case FP_ZERO: return kFpZero;
            case FP_SUBNORMAL: return kFpSubnormal;
            default: return kFpNormal;
        }
    };
    add("_dclass", [classify_double](Emulator& e) {
        Args a(e);
        e.set_result(static_cast<uint64_t>(
            static_cast<int64_t>(classify_double(a.next_double_param()))));
    });
    add("_ldclass", [classify_double](Emulator& e) {
        Args a(e);
        e.set_result(static_cast<uint64_t>(
            static_cast<int64_t>(classify_double(a.next_double_param()))));
    });
    add("_fdclass", [classify_double](Emulator& e) {
        Args a(e);
        e.set_result(static_cast<uint64_t>(
            static_cast<int64_t>(classify_double(a.next_float_param()))));
    });
    // The _dtest family takes a pointer to the value instead of the value.
    add("_dtest", [classify_double](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        double v = 0;
        if (p) {
            uint64_t bits = e.mem.read64(p);
            std::memcpy(&v, &bits, sizeof v);
        }
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(classify_double(v))));
    });
    add("_fdtest", [classify_double](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        float v = 0;
        if (p) {
            uint32_t bits = e.mem.read32(p);
            std::memcpy(&v, &bits, sizeof v);
        }
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(classify_double(v))));
    });
    add("_dsign", [](Emulator& e) {
        Args a(e);
        e.set_result(std::signbit(a.next_double_param()) ? 0x8000u : 0u);
    });
    add("_fdsign", [](Emulator& e) {
        Args a(e);
        e.set_result(std::signbit(a.next_float_param()) ? 0x8000u : 0u);
    });
    add("_ldsign", [](Emulator& e) {
        Args a(e);
        e.set_result(std::signbit(a.next_double_param()) ? 0x8000u : 0u);
    });

    // msvcrt spells a few of these differently.
    add("_chgsign", [](Emulator& e) {
        Args a(e);
        e.set_result_double(-a.next_double_param());
    });
}

}  // namespace x86emu
