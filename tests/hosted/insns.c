// Exercises the instruction forms a compiler uses that simpler guests do not:
// backward string moves, bit-test on memory with out-of-word offsets, 64-bit
// bit scans, SETcc, sign extension and a few SSE2 integer forms.  Every result
// is printed so emulated output can be diffed against native execution.
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static uint64_t bits[8];

static void show(const char* what, uint64_t v) { printf("%-24s %016llx\n", what, (unsigned long long)v); }

int main(void) {
    // ---- backward rep movsb (what a libc memmove does for overlap) ----
    char buf[64];
    for (int i = 0; i < 64; ++i) buf[i] = (char)('A' + i % 26);
    void* dst = buf + 8;
    void* src = buf;
    size_t n = 40;
    __asm__ volatile(
        "lea -1(%0,%2), %%rsi\n\t"
        "lea -1(%1,%2), %%rdi\n\t"
        "std\n\t"
        "rep movsb\n\t"
        "cld\n\t"
        : : "r"(src), "r"(dst), "r"(n) : "rsi", "rdi", "rcx", "memory");
    // rep movsb needs rcx: set it explicitly instead.
    for (int i = 0; i < 64; ++i) buf[i] = (char)('A' + i % 26);
    {
        register void* s asm("rsi") = (char*)buf + n - 1;
        register void* d asm("rdi") = (char*)buf + 8 + n - 1;
        register size_t c asm("rcx") = n;
        __asm__ volatile("std; rep movsb; cld" : "+r"(s), "+r"(d), "+r"(c) : : "memory");
    }
    buf[63] = 0;
    printf("backward movsb        %s\n", buf);

    // ---- backward stosq ----
    uint64_t fill[8] = {0};
    {
        register void* d asm("rdi") = &fill[7];
        register size_t c asm("rcx") = 8;
        register uint64_t a asm("rax") = 0x1122334455667788ull;
        __asm__ volatile("std; rep stosq; cld" : "+r"(d), "+r"(c) : "r"(a) : "memory");
    }
    show("backward stosq[0]", fill[0]);
    show("backward stosq[7]", fill[7]);

    // ---- bt/bts/btr/btc on memory, offsets past one word and negative ----
    memset(bits, 0, sizeof bits);
    uint64_t off = 100, cf = 0;
    __asm__ volatile("bts %2, %0" : "+m"(bits[0]) : "m"(bits[0]), "r"(off) : "cc");
    show("bts +100 word1", bits[1]);
    show("bts +100 word0", bits[0]);
    off = 200;
    __asm__ volatile("bts %1, %0" : "+m"(bits[0]) : "r"(off) : "cc");
    show("bts +200 word3", bits[3]);
    off = 100;
    __asm__ volatile("bt %2, %1\n\tsetc %b0" : "=q"(cf) : "m"(bits[0]), "r"(off) : "cc");
    show("bt +100 carry", cf & 1);
    off = 200;
    __asm__ volatile("btr %1, %0" : "+m"(bits[0]) : "r"(off) : "cc");
    show("btr +200 word3", bits[3]);
    // A negative offset reaches backwards from the addressed word.
    memset(bits, 0, sizeof bits);
    {
        int64_t neg = -64;
        __asm__ volatile("bts %1, %0" : "+m"(bits[4]) : "r"(neg) : "cc");
    }
    show("bts -64 from w4", bits[3]);
    memset(bits, 0, sizeof bits);
    {
        int64_t neg = -1;
        __asm__ volatile("btc %1, %0" : "+m"(bits[4]) : "r"(neg) : "cc");
    }
    show("btc -1 from w4", bits[3]);

    // ---- 64-bit bit scans ----
    uint64_t v = 0x0000800000000100ull, r = 0;
    __asm__ volatile("bsf %1, %0" : "=r"(r) : "r"(v));
    show("bsf", r);
    __asm__ volatile("bsr %1, %0" : "=r"(r) : "r"(v));
    show("bsr", r);

    // ---- setcc / movsx ----
    int32_t a32 = -5, b32 = 7;
    uint64_t ge = 0, le = 0;
    __asm__ volatile("cmp %2, %1\n\tsetge %b0" : "=q"(ge) : "r"(a32), "r"(b32) : "cc");
    __asm__ volatile("cmp %2, %1\n\tsetle %b0" : "=q"(le) : "r"(a32), "r"(b32) : "cc");
    show("setge(-5,7)", ge & 1);
    show("setle(-5,7)", le & 1);
    int16_t s16 = -1234;
    int64_t wide = 0;
    __asm__ volatile("movswq %1, %0" : "=r"(wide) : "m"(s16));
    show("movsx16->64", (uint64_t)wide);

    // ---- SSE2 integer forms ----
    uint32_t four[4] = {1, 2, 3, 4}, out4[4] = {0};
    __asm__ volatile(
        "movdqu %1, %%xmm0\n\t"
        "pshufd $0x1b, %%xmm0, %%xmm1\n\t"
        "paddd %%xmm0, %%xmm1\n\t"
        "movdqu %%xmm1, %0"
        : "=m"(out4) : "m"(four) : "xmm0", "xmm1");
    printf("pshufd+paddd         %u %u %u %u\n", out4[0], out4[1], out4[2], out4[3]);
    uint64_t q = 0xfeedfacecafebeefull, qout = 0;
    __asm__ volatile("movq %1, %%xmm2\n\tmovq %%xmm2, %0" : "=m"(qout) : "m"(q) : "xmm2");
    show("movq xmm roundtrip", qout);
    return 0;
}
