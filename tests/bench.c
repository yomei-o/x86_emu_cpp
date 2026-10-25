// Compute-heavy guest: recursion, sieve, crc, sort, matrix, 64-bit math.
// Prints checksums so a run under any execution engine can be diffed.
int printf(const char *fmt, ...);
void *malloc(unsigned long n);

static int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

static unsigned crc(unsigned c, const unsigned char *p, int n) {
    int i, k;
    for (i = 0; i < n; i++) {
        c ^= p[i];
        for (k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return c;
}

static unsigned long long lcg(unsigned long long x) { return x * 6364136223846793005ULL + 1442695040888963407ULL; }

static int run(void) {
    int i, j, k, n = 0;
    printf("fib %d\n", fib(27));

    unsigned char *s = malloc(200000);
    for (i = 0; i < 200000; i++) s[i] = 1;
    for (i = 2; i < 450; i++) if (s[i]) for (j = i * i; j < 200000; j += i) s[j] = 0;
    for (i = 2; i < 200000; i++) n += s[i];
    printf("primes %d\n", n);

    for (i = 0; i < 20000; i++) s[i] = (unsigned char)(i * 31 + (i >> 3));
    printf("crc %08X\n", crc(0xFFFFFFFFu, s, 20000));

    int *a = malloc(4 * 2000);
    unsigned long long r = 12345;
    for (i = 0; i < 2000; i++) { r = lcg(r); a[i] = (int)(r >> 33); }
    for (i = 0; i < 2000; i++)
        for (j = 0; j < 1999 - i; j++)
            if (a[j] > a[j + 1]) { int t = a[j]; a[j] = a[j + 1]; a[j + 1] = t; }
    printf("sort %d %d %d\n", a[0], a[1000], a[1999]);

    int *m = malloc(4 * 3 * 80 * 80);
    for (i = 0; i < 80 * 80; i++) { m[i] = i % 7 - 3; m[6400 + i] = i % 5 - 2; }
    for (i = 0; i < 80; i++)
        for (j = 0; j < 80; j++) {
            int acc = 0;
            for (k = 0; k < 80; k++) acc += m[i * 80 + k] * m[6400 + k * 80 + j];
            m[12800 + i * 80 + j] = acc;
        }
    long long sum = 0;
    for (i = 0; i < 6400; i++) sum += m[12800 + i];
    printf("mat %lld\n", sum);

    unsigned long long h = 1;
#ifdef __x86_64__
    for (i = 1; i < 30000; i++) { h = lcg(h) ^ (h / (unsigned)i) ^ (unsigned long long)((long long)h % (i + 3)); }
#else
    for (i = 1; i < 30000; i++) { h = lcg(h) ^ (unsigned)h / (unsigned)i; }
#endif
    printf("h %llu\n", h);
    return 0;
}
void exit(int);
void start_(void) { exit(run()); }
