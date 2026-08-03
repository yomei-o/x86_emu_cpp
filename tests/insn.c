// Instruction-level tests.
//
// The arithmetic tests reach the interpreter through whatever a compiler happens
// to emit, which leaves the less common instructions untested.  These use inline
// assembly to name the instruction directly, so a run under the emulator diffed
// against a native run pins down exactly which one is wrong.
int printf(const char *fmt, ...);
void exit(int code);

#if defined(__x86_64__)
#define WORD_T unsigned long long
#define REG "q"
#else
#define WORD_T unsigned int
#define REG "l"
#endif

static void shifts_double(void) {
    // SHLD/SHRD feed bits from a second operand into the shifted-out end; they
    // are the backbone of multi-precision shifting inside a C runtime.
    unsigned d, s, r;
    int n;
    for (n = 1; n < 32; n += 7) {
        d = 0x12345678u; s = 0x9ABCDEF0u;
        __asm__("shldl %%cl, %1, %0" : "+r"(d) : "r"(s), "c"(n));
        r = d;
        d = 0x12345678u;
        __asm__("shrdl %%cl, %1, %0" : "+r"(d) : "r"(s), "c"(n));
        printf("shld/shrd %2d : %08X %08X\n", n, r, d);
    }
    d = 0x12345678u; s = 0x9ABCDEF0u;
    __asm__("shldl $5, %1, %0" : "+r"(d) : "r"(s));
    r = d;
    d = 0x12345678u;
    __asm__("shrdl $5, %1, %0" : "+r"(d) : "r"(s));
    printf("shld/shrd imm: %08X %08X\n", r, d);
}

static void rotates(void) {
    unsigned v;
    int n;
    for (n = 1; n < 32; n += 9) {
        v = 0xDEADBEEFu;
        __asm__("roll %%cl, %0" : "+r"(v) : "c"(n));
        printf("rol %2d : %08X ", n, v);
        v = 0xDEADBEEFu;
        __asm__("rorl %%cl, %0" : "+r"(v) : "c"(n));
        printf("ror: %08X\n", v);
    }
}

static void bitscan(void) {
    unsigned v[] = {1u, 0x80000000u, 0x00FF0000u, 0x12345678u};
    int i;
    for (i = 0; i < 4; i++) {
        unsigned f = 0, r = 0;
        __asm__("bsfl %1, %0" : "=r"(f) : "r"(v[i]));
        __asm__("bsrl %1, %0" : "=r"(r) : "r"(v[i]));
        printf("bsf/bsr %08X : %u %u\n", v[i], f, r);
    }
}

static void carry_chain(void) {
    // ADC/SBB across a pair of words: gets the carry flag wrong and the sums go
    // wrong only in the upper half, which is easy to miss without a test.
    unsigned lo_a = 0xFFFFFFF0u, hi_a = 0x00000001u;
    unsigned lo_b = 0x00000020u, hi_b = 0x00000002u;
    unsigned lo = lo_a, hi = hi_a;
    __asm__("addl %2, %0\n\tadcl %3, %1"
            : "+r"(lo), "+r"(hi) : "r"(lo_b), "r"(hi_b) : "cc");
    printf("add/adc : %08X%08X\n", hi, lo);
    lo = lo_a; hi = hi_a;
    __asm__("subl %2, %0\n\tsbbl %3, %1"
            : "+r"(lo), "+r"(hi) : "r"(lo_b), "r"(hi_b) : "cc");
    printf("sub/sbb : %08X%08X\n", hi, lo);
}

static void setcc_all(void) {
    // Every condition code, evaluated from one comparison.
    int a = -5, b = 3;
    unsigned char out[16];
    int i;
    __asm__("cmpl %1, %2\n\t"
            "seto  0(%0)\n\tsetno 1(%0)\n\tsetb  2(%0)\n\tsetae 3(%0)\n\t"
            "sete  4(%0)\n\tsetne 5(%0)\n\tsetbe 6(%0)\n\tseta  7(%0)\n\t"
            "sets  8(%0)\n\tsetns 9(%0)\n\tsetp 10(%0)\n\tsetnp 11(%0)\n\t"
            "setl 12(%0)\n\tsetge 13(%0)\n\tsetle 14(%0)\n\tsetg 15(%0)"
            : : "r"(out), "r"(b), "r"(a) : "cc", "memory");
    printf("setcc   : ");
    for (i = 0; i < 16; i++) printf("%d", out[i]);
    printf("\n");
}

static void mul_div_wide(void) {
    unsigned a = 0xFEDCBA98u, b = 0x76543210u, lo, hi;
    __asm__("mull %3" : "=a"(lo), "=d"(hi) : "a"(a), "r"(b) : "cc");
    printf("mul     : %08X%08X\n", hi, lo);
    __asm__("imull %3" : "=a"(lo), "=d"(hi) : "a"(a), "r"(b) : "cc");
    printf("imul    : %08X%08X\n", hi, lo);
    {
        unsigned q, r, nlo = 0x89ABCDEFu, nhi = 0x00000123u, d = 0xFEDCu;
        __asm__("divl %4" : "=a"(q), "=d"(r) : "a"(nlo), "d"(nhi), "r"(d) : "cc");
        printf("div     : %08X %08X\n", q, r);
    }
    {
        int q, r, nlo = -1234567, nhi = -1, d = 9876;
        __asm__("idivl %4" : "=a"(q), "=d"(r) : "a"(nlo), "d"(nhi), "r"(d) : "cc");
        printf("idiv    : %d %d\n", q, r);
    }
}

static void exchange(void) {
    unsigned dst = 100, src = 7, acc = 100;
    // CMPXCHG succeeds when the accumulator matches, XADD returns the old value.
    __asm__("cmpxchgl %2, %0" : "+m"(dst), "+a"(acc) : "r"(src) : "cc");
    printf("cmpxchg : %u %u\n", dst, acc);
    dst = 40; src = 2;
    __asm__("xaddl %1, %0" : "+m"(dst), "+r"(src) : : "cc");
    printf("xadd    : %u %u\n", dst, src);
    dst = 1; src = 2;
    __asm__("xchgl %1, %0" : "+r"(dst), "+r"(src));
    printf("xchg    : %u %u\n", dst, src);
}

static void bit_ops(void) {
    unsigned v = 0x00000100u;
    unsigned char c = 0;
    __asm__("btl $8, %1\n\tsetc %0" : "=r"(c) : "r"(v) : "cc");
    printf("bt      : %d ", c);
    __asm__("btsl $3, %0" : "+r"(v) : : "cc");
    __asm__("btrl $8, %0" : "+r"(v) : : "cc");
    __asm__("btcl $4, %0" : "+r"(v) : : "cc");
    printf("bts/btr/btc: %08X\n", v);
}

static void extend(void) {
    signed char b = -3;
    short s = -300;
    unsigned r1, r2, r3, r4;
    __asm__("movsbl %1, %0" : "=r"(r1) : "m"(b));
    __asm__("movzbl %1, %0" : "=r"(r2) : "m"(b));
    __asm__("movswl %1, %0" : "=r"(r3) : "m"(s));
    __asm__("movzwl %1, %0" : "=r"(r4) : "m"(s));
    printf("movsx/zx: %08X %08X %08X %08X\n", r1, r2, r3, r4);
}

static void string_ops(void) {
    // REP MOVSB / STOSB / SCASB, including the direction flag.
    char src[16] = "abcdefghijklmno";
    char dst[16];
    int i;
    unsigned long count = 16;
    void *d = dst, *s = src;
    __asm__ volatile("cld\n\trep movsb"
                     : "+D"(d), "+S"(s), "+c"(count) : : "memory");
    printf("rep movsb: %s\n", dst);
    d = dst; count = 5;
    __asm__ volatile("cld\n\trep stosb" : "+D"(d), "+c"(count) : "a"('Z') : "memory");
    printf("rep stosb: %s\n", dst);
    d = dst; count = 16;
    __asm__ volatile("cld\n\trepne scasb"
                     : "+D"(d), "+c"(count) : "a"('h') : "cc");
    printf("repne scasb: remaining %d\n", (int)count);
    (void)i;
}

static int run(void) {
    shifts_double();
    rotates();
    bitscan();
    carry_chain();
    setcc_all();
    mul_div_wide();
    exchange();
    bit_ops();
    extend();
    string_ops();
    return 0;
}

void start_(void) { exit(run()); }
