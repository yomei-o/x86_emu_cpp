// Math library results, printed so a run under the emulator can be diffed
// against a native run.
//
// The point of the test is the plumbing rather than the functions: a floating
// point argument travels in XMM registers in 64-bit code and on the stack in
// 32-bit code, and the result comes back in XMM0 or on the x87 stack depending
// on the same thing.  Getting either wrong shows up here immediately.
int printf(const char *fmt, ...);
void exit(int code);

double sin(double), cos(double), tan(double);
double asin(double), acos(double), atan(double), atan2(double, double);
double exp(double), log(double), log10(double), pow(double, double), sqrt(double);
double sinh(double), cosh(double), tanh(double);
double fabs(double), ceil(double), floor(double), fmod(double, double);
double ldexp(double, int), frexp(double, int *), modf(double, double *);

static void trig(void) {
    static const double angles[] = {0.0, 0.5, 1.0, -1.25, 3.14159265358979, 100.0};
    int i;
    for (i = 0; i < 6; i++) {
        double a = angles[i];
        printf("sin %-18.15f cos %-18.15f tan %-18.12f\n", sin(a), cos(a), tan(a));
    }
    printf("asin %.15f acos %.15f atan %.15f\n", asin(0.75), acos(0.75), atan(0.75));
    printf("atan2 %.15f %.15f\n", atan2(1.0, 2.0), atan2(-3.0, -4.0));
}

static void exponentials(void) {
    printf("exp   %.12f %.12f %.12f\n", exp(0.0), exp(1.0), exp(-2.5));
    printf("log   %.12f %.12f\n", log(1.0), log(100.0));
    printf("log10 %.12f %.12f\n", log10(1000.0), log10(0.001));
    printf("pow   %.12f %.12f %.12f\n", pow(2.0, 10.0), pow(2.0, 0.5), pow(-8.0, 3.0));
    printf("sqrt  %.15f %.15f\n", sqrt(2.0), sqrt(1e6));
    printf("hyp   %.12f %.12f %.12f\n", sinh(1.0), cosh(1.0), tanh(1.0));
}

static void rounding(void) {
    static const double values[] = {2.5, -2.5, 0.49999, 1e10 + 0.5, -0.0};
    int i;
    for (i = 0; i < 5; i++) {
        double v = values[i];
        printf("%-14g fabs %-14g ceil %-14g floor %-14g\n", v, fabs(v), ceil(v), floor(v));
    }
    printf("fmod  %.12f %.12f\n", fmod(10.0, 3.0), fmod(-10.0, 3.0));
}

static void decompose(void) {
    int e = 0;
    double m = frexp(1234.5, &e);
    printf("frexp %.15f %d\n", m, e);
    printf("ldexp %.12f %.12f\n", ldexp(1.0, 10), ldexp(0.75, -3));
    double integral = 0;
    double frac = modf(-3.75, &integral);
    printf("modf  %.12f %.12f\n", integral, frac);
}

/* A little arithmetic done by the guest itself, so the emulated SSE2 path is
   compared against the host too, not just the hooked functions. */
static void guest_arithmetic(void) {
    double acc = 0.0, x = 1.0;
    int i;
    for (i = 1; i <= 20; i++) {
        x = x * 1.5 - 0.25;
        acc += x / i;
    }
    printf("guest %.12f %.12f\n", x, acc);
    float f = 1.0f;
    for (i = 0; i < 10; i++) f = f * 1.1f + 0.01f;
    printf("float %.6f\n", (double)f);
}

static int run(void) {
    trig();
    exponentials();
    rounding();
    decompose();
    guest_arithmetic();
    return 0;
}

void start_(void) { exit(run()); }
