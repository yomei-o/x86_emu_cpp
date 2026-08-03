// Exercises the arithmetic paths of the interpreter: the results are printed so
// that a run under the emulator can be diffed against a native run.  Anything
// the interpreter gets wrong in flags, sign extension, division or shifting
// shows up as a differing line.
int printf(const char *fmt, ...);
void exit(int code);
unsigned long strlen(const char *s);
void *memset(void *p, int c, unsigned long n);
void *malloc(unsigned long n);
void free(void *p);

static void divide(void) {
    int a = -1234567, b = 89;
    unsigned ua = 4000000000u, ub = 7;
    printf("idiv     : %d %d\n", a / b, a % b);
    printf("div      : %u %u\n", ua / ub, ua % ub);
    printf("neg/abs  : %d %d\n", -a, a < 0 ? -a : a);
}

static void shifts(void) {
    unsigned x = 0x12345678u;
    int s = -1000;
    int i;
    for (i = 0; i < 4; i++)
        printf("shift %d  : %08X %08X %d\n", i * 7, x << (i * 7), x >> (i * 7), s >> (i * 7));
}

static void widths(void) {
    signed char c = -5;
    unsigned char uc = 250;
    short s = -30000;
    unsigned short us = 60000;
    printf("bytes    : %d %u %d %u\n", c, uc, s, us);
    printf("promote  : %d %d %d\n", c * 3, s + 40000, (unsigned char)(uc + 10));
    printf("compare  : %d %d %d %d\n", c < 0, uc > 200, s < c, us > (unsigned short)s);
}

static void wide(void) {
    // 64-bit arithmetic, printed as two 32-bit halves so the format string stays
    // portable across C runtimes.
    long long a = 123456789012345LL, b = -98765LL;
    long long m = a * b, d = a / b, r = a % b;
    printf("mul64    : %08X%08X\n", (unsigned)(m >> 32), (unsigned)m);
    printf("div64    : %08X%08X %08X%08X\n", (unsigned)(d >> 32), (unsigned)d,
           (unsigned)(r >> 32), (unsigned)r);
    unsigned long long u = 0xFEDCBA9876543210ULL;
    printf("shift64  : %08X%08X %08X%08X\n", (unsigned)(u >> 40), (unsigned)(u >> 8),
           (unsigned)((u << 12) >> 32), (unsigned)(u << 12));
}

static void bits(void) {
    unsigned x = 0xF0F0F0F0u, y = 0x0FF00FF0u;
    printf("bitops   : %08X %08X %08X %08X\n", x & y, x | y, x ^ y, ~x);
    printf("imul     : %d %d\n", 12345 * 6789, -12345 * 6789);
}

static void memfns(void) {
    char *p = (char *)malloc(64);
    if (!p) {
        printf("malloc failed\n");
        return;
    }
    memset(p, 'A', 16);
    p[16] = 0;
    printf("heap     : [%s] %u\n", p, (unsigned)strlen(p));
    free(p);
}

static int run(void) {
    divide();
    shifts();
    widths();
    wide();
    bits();
    memfns();
    return 0;
}

void start_(void) { exit(run()); }
