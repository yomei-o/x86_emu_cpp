// Floating-point formatting through a real Microsoft C runtime.
//
// With /MT the conversion runs inside the guest, and the 32-bit build does it on
// the x87 stack while switching the rounding mode around FRNDINT and FISTP - so
// this is the test that catches an emulator ignoring the control word.
#include <cstdio>

int main() {
    const double values[] = {1.0,     1.5,      2.0,   9.0,   10.0,     12.0,
                             99.0,    100.0,    0.25,  0.125, 3.14159,  98765.4,
                             1e-7,    1e20,     -2.5,  0.0,   1.0 / 3.0};
    for (double v : values)
        printf("%-14f %-14.3e %-12g %-8.2f %+.1f\n", v, v, v, v, v);

    // Integer and pointer-sized formats through the same runtime.
    printf("%d %u %x %o %lld %llu\n", -42, 42u, 0xABCDEF, 64, -1234567890123LL,
           12345678901234567890ULL);
    printf("[%10s][%-10s][%.4s][%c]\n", "abc", "abc", "abcdefgh", 'Z');

    // A little arithmetic so the FPU/SSE paths are exercised, not just printing.
    double acc = 0.0;
    for (int i = 1; i <= 10; ++i) acc += 1.0 / i;
    printf("harmonic(10) = %.10f\n", acc);
    return 0;
}
