// isatest.c - the same instructions, three CPUs, one checksum each.
//
// The model will not decrypt, and everything around it is ruled out: the bytes
// arriving are right, the allocator is right, the syscalls are right, AES-NI is
// never executed.  What is left is that some instruction returns the wrong
// answer.  Rather than diff a multi-gigabyte trace to find where, run the
// instructions themselves and diff the answers.
//
// Each group runs one instruction over a fixed set of operands chosen to hit
// the edges - zeroes, all-ones, sign bits, denormals, NaNs, shift counts at and
// past the width - and folds every result and every flag into one FNV-1a.  Run
// it natively, under qemu-x86_64 and under x86emu; the groups that disagree name
// the instruction.
//
//     gcc -O2 -o isatest isatest.c        # natively, and under qemu
//     x86emu --sysroot sysroot .../isatest
//
// Nothing here is voicevox-specific: this is an x86-64 emulator conformance
// test and belongs upstream in x86_emu_cpp.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------

static uint64_t fnv(const void* p, size_t n, uint64_t h) {
    const unsigned char* b = p;
    for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 1099511628211ull;
    return h;
}
#define FNV_INIT 1469598103934665603ull
static uint64_t fnv64(uint64_t v, uint64_t h) { return fnv(&v, 8, h); }

static int groups = 0;
static void report(const char* name, uint64_t h) {
    printf("%-14s %016llx\n", name, (unsigned long long)h);
    groups++;
}

// The flags the tests compare: CF PF AF ZF SF OF.  Anything else is either
// fixed or none of an emulator's business.
//
// Which of the six an instruction actually defines varies, and comparing an
// undefined one compares nothing: a real CPU and qemu disagree about the SF of
// an IMUL or the OF of a multi-bit shift, and both are right.  Every group
// therefore names the bits the manual says it defines, and only those are
// folded in.  With the masks right, native and qemu agree exactly - which is
// what makes a third answer meaningful.
#define F_CF 0x001ull
#define F_PF 0x004ull
#define F_AF 0x010ull
#define F_ZF 0x040ull
#define F_SF 0x080ull
#define F_OF 0x800ull
#define FLAGMASK (F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF)
#define M_ARITH FLAGMASK                                 // ADD, SUB, CMP, INC...
#define M_LOGIC (F_CF | F_PF | F_ZF | F_SF | F_OF)       // AND, OR, XOR: AF undefined
#define M_MUL (F_CF | F_OF)                              // the rest undefined
#define M_SHIFT (F_CF | F_PF | F_ZF | F_SF)              // AF and OF undefined
#define M_ROT F_CF                                       // OF defined only for count 1
#define M_BT F_CF
#define M_BS F_ZF                                        // and the result is undefined at 0
#define M_NONE 0ull

// ---- operands -------------------------------------------------------------

typedef struct {
    uint8_t b[16];
} v128 __attribute__((aligned(16)));

#define NV 12
static v128 V[NV];

#define NG 14
static uint64_t G[NG];

static void init_operands(void) {
    static const uint64_t g[NG] = {
        0x0000000000000000ull, 0x0000000000000001ull, 0x00000000ffffffffull,
        0xffffffffffffffffull, 0x8000000000000000ull, 0x7fffffffffffffffull,
        0x0123456789abcdefull, 0xfedcba9876543210ull, 0x00000000000000ffull,
        0x000000000000ff00ull, 0x5555555555555555ull, 0xaaaaaaaaaaaaaaaaull,
        0x000000007fffffffull, 0x0000000080000000ull,
    };
    memcpy(G, g, sizeof g);

    // Byte patterns first, then bit patterns that matter to the float ops:
    // +0/-0, 1.0, denormals, infinities, a quiet NaN and a signalling one.
    static const uint64_t vq[NV][2] = {
        {0x0000000000000000ull, 0x0000000000000000ull},
        {0xffffffffffffffffull, 0xffffffffffffffffull},
        {0x0123456789abcdefull, 0xfedcba9876543210ull},
        {0x8000800080008000ull, 0x0080008000800080ull},
        {0x7f7f7f7f7f7f7f7full, 0x8080808080808080ull},
        {0x0102040810204080ull, 0xff00ff00ff00ff00ull},
        {0x3ff0000000000000ull, 0xbff0000000000000ull},  //  1.0, -1.0
        {0x0000000000000000ull, 0x8000000000000000ull},  // +0.0, -0.0
        {0x7ff0000000000000ull, 0xfff0000000000000ull},  // +inf, -inf
        {0x7ff8000000000001ull, 0x7ff0000000000001ull},  // qNaN, sNaN
        {0x0000000000000001ull, 0x000fffffffffffffull},  // denormals
        {0x3f80000041200000ull, 0xc0490fdb7fc00000ull},  // floats: 1.0 10.0 -pi qNaN
    };
    for (int i = 0; i < NV; i++) memcpy(V[i].b, vq[i], 16);
}

// ---- SSE: register-to-register, no immediate ------------------------------
// xmm0 gets the destination, xmm1 the source, and the 16-byte result folds in.

#define SSE_RR(name, mnem)                                                        \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NV; i++)                                              \
            for (int j = 0; j < NV; j++) {                                        \
                v128 r;                                                           \
                __asm__ volatile("movdqu %1, %%xmm0\n\t"                          \
                                 "movdqu %2, %%xmm1\n\t" mnem                     \
                                 " %%xmm1, %%xmm0\n\t"                            \
                                 "movdqu %%xmm0, %0"                              \
                                 : "=m"(r)                                        \
                                 : "m"(V[i]), "m"(V[j])                           \
                                 : "xmm0", "xmm1", "memory");                     \
                h = fnv(&r, 16, h);                                               \
            }                                                                     \
        report(name, h);                                                          \
    } while (0)

// The float *arithmetic* groups run over operands with no NaN in them.  How a
// NaN payload comes out of an ADDPS is a place a real CPU and qemu already
// disagree, so comparing it compares nothing; infinities, signed zeroes and
// denormals stay, because those are defined.  The NaN cases still get run, in
// their own group at the end, where a three-way disagreement is expected.
#define NF 9
static const int FIN[NF] = {0, 2, 3, 4, 5, 6, 7, 8, 10};

#define SSE_RRF(name, mnem)                                                       \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int ii = 0; ii < NF; ii++)                                           \
            for (int jj = 0; jj < NF; jj++) {                                     \
                v128 r;                                                           \
                __asm__ volatile("movdqu %1, %%xmm0\n\t"                          \
                                 "movdqu %2, %%xmm1\n\t" mnem                     \
                                 " %%xmm1, %%xmm0\n\t"                            \
                                 "movdqu %%xmm0, %0"                              \
                                 : "=m"(r)                                        \
                                 : "m"(V[FIN[ii]]), "m"(V[FIN[jj]])               \
                                 : "xmm0", "xmm1", "memory");                     \
                h = fnv(&r, 16, h);                                               \
            }                                                                     \
        report(name, h);                                                          \
    } while (0)

// ---- SSE with an 8-bit immediate ------------------------------------------

#define SSE_RRI(name, mnem, imm)                                                  \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NV; i++)                                              \
            for (int j = 0; j < NV; j++) {                                        \
                v128 r;                                                           \
                __asm__ volatile("movdqu %1, %%xmm0\n\t"                          \
                                 "movdqu %2, %%xmm1\n\t" mnem " $" #imm           \
                                 ", %%xmm1, %%xmm0\n\t"                           \
                                 "movdqu %%xmm0, %0"                              \
                                 : "=m"(r)                                        \
                                 : "m"(V[i]), "m"(V[j])                           \
                                 : "xmm0", "xmm1", "memory");                     \
                h = fnv(&r, 16, h);                                               \
            }                                                                     \
        report(name, h);                                                          \
    } while (0)

// ---- SSE shifts by immediate, including counts past the element width ------

#define SSE_SHIFT_I(name, mnem)                                                   \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NV; i++) {                                            \
            v128 r;                                                               \
            __asm__ volatile("movdqu %1, %%xmm0\n\t" mnem                         \
                             " $0, %%xmm0\n\t"                                    \
                             "movdqu %%xmm0, %0"                                  \
                             : "=m"(r) : "m"(V[i]) : "xmm0", "memory");           \
            h = fnv(&r, 16, h);                                                   \
            __asm__ volatile("movdqu %1, %%xmm0\n\t" mnem                         \
                             " $1, %%xmm0\n\t"                                    \
                             "movdqu %%xmm0, %0"                                  \
                             : "=m"(r) : "m"(V[i]) : "xmm0", "memory");           \
            h = fnv(&r, 16, h);                                                   \
            __asm__ volatile("movdqu %1, %%xmm0\n\t" mnem                         \
                             " $7, %%xmm0\n\t"                                    \
                             "movdqu %%xmm0, %0"                                  \
                             : "=m"(r) : "m"(V[i]) : "xmm0", "memory");           \
            h = fnv(&r, 16, h);                                                   \
            __asm__ volatile("movdqu %1, %%xmm0\n\t" mnem                         \
                             " $15, %%xmm0\n\t"                                   \
                             "movdqu %%xmm0, %0"                                  \
                             : "=m"(r) : "m"(V[i]) : "xmm0", "memory");           \
            h = fnv(&r, 16, h);                                                   \
            __asm__ volatile("movdqu %1, %%xmm0\n\t" mnem                         \
                             " $31, %%xmm0\n\t"                                   \
                             "movdqu %%xmm0, %0"                                  \
                             : "=m"(r) : "m"(V[i]) : "xmm0", "memory");           \
            h = fnv(&r, 16, h);                                                   \
            __asm__ volatile("movdqu %1, %%xmm0\n\t" mnem                         \
                             " $64, %%xmm0\n\t"                                   \
                             "movdqu %%xmm0, %0"                                  \
                             : "=m"(r) : "m"(V[i]) : "xmm0", "memory");           \
            h = fnv(&r, 16, h);                                                   \
            __asm__ volatile("movdqu %1, %%xmm0\n\t" mnem                         \
                             " $255, %%xmm0\n\t"                                  \
                             "movdqu %%xmm0, %0"                                  \
                             : "=m"(r) : "m"(V[i]) : "xmm0", "memory");           \
            h = fnv(&r, 16, h);                                                   \
        }                                                                         \
        report(name, h);                                                          \
    } while (0)

// ---- SSE shifts by a whole xmm register -----------------------------------
// The count is the low 64 bits of the source, and a count of 64 or more zeroes
// the destination rather than wrapping - a classic thing to get wrong.

#define SSE_SHIFT_R(name, mnem)                                                   \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NV; i++)                                              \
            for (int j = 0; j < NV; j++) {                                        \
                v128 r;                                                           \
                __asm__ volatile("movdqu %1, %%xmm0\n\t"                          \
                                 "movdqu %2, %%xmm1\n\t" mnem                     \
                                 " %%xmm1, %%xmm0\n\t"                            \
                                 "movdqu %%xmm0, %0"                              \
                                 : "=m"(r)                                        \
                                 : "m"(V[i]), "m"(V[j])                           \
                                 : "xmm0", "xmm1", "memory");                     \
                h = fnv(&r, 16, h);                                               \
            }                                                                     \
        report(name, h);                                                          \
    } while (0)

// ---- SSE producing a GPR --------------------------------------------------

#define SSE_TO_GPR(name, mnem)                                                    \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NV; i++) {                                            \
            uint64_t r = 0;                                                       \
            __asm__ volatile("movdqu %1, %%xmm1\n\t" mnem " %%xmm1, %0"           \
                             : "=r"(r) : "m"(V[i]) : "xmm1");                     \
            h = fnv64(r, h);                                                      \
        }                                                                         \
        report(name, h);                                                          \
    } while (0)

// ---- SSE comparisons that set the flags -----------------------------------

#define SSE_CMP_FLAGS(name, mnem)                                                 \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NV; i++)                                              \
            for (int j = 0; j < NV; j++) {                                        \
                uint64_t f;                                                       \
                __asm__ volatile("movdqu %1, %%xmm0\n\t"                          \
                                 "movdqu %2, %%xmm1\n\t" mnem                     \
                                 " %%xmm1, %%xmm0\n\t"                            \
                                 "pushfq\n\t"                                     \
                                 "popq %0"                                        \
                                 : "=r"(f)                                        \
                                 : "m"(V[i]), "m"(V[j])                           \
                                 : "xmm0", "xmm1", "cc");                         \
                h = fnv64(f & FLAGMASK, h);                                       \
            }                                                                     \
        report(name, h);                                                          \
    } while (0)

// ---- general purpose, two operands, result and flags ----------------------
// Flags go in known before every execution, both with and without CF, because
// ADC and SBB read one.

#define GP2(name, insn, mask)                                                     \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NG; i++)                                              \
            for (int j = 0; j < NG; j++)                                          \
                for (int c = 0; c < 2; c++) {                                     \
                    uint64_t a = G[i], f, in = c ? 0x8D5ull : 0x002ull;           \
                    __asm__ volatile("pushq %4\n\t"                               \
                                     "popfq\n\t" insn                             \
                                     "\n\t"                                       \
                                     "pushfq\n\t"                                 \
                                     "popq %1"                                    \
                                     : "+r"(a), "=&r"(f)                          \
                                     : "0"(a), "r"(G[j]), "r"(in)                 \
                                     : "cc");                                     \
                    h = fnv64(a, h);                                              \
                    h = fnv64(f & (mask), h);                                     \
                }                                                                 \
        report(name, h);                                                          \
    } while (0)

// BSF and BSR leave the destination *unchanged and undefined* when the source
// is zero, so that case contributes only its ZF.
#define GP_BITSCAN(name, insn)                                                    \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NG; i++)                                              \
            for (int j = 0; j < NG; j++) {                                        \
                uint64_t a = G[i], f;                                             \
                __asm__ volatile("pushq $2\n\t"                                   \
                                 "popfq\n\t" insn                                 \
                                 "\n\t"                                           \
                                 "pushfq\n\t"                                     \
                                 "popq %1"                                        \
                                 : "+r"(a), "=&r"(f)                              \
                                 : "0"(a), "r"(G[j])                              \
                                 : "cc");                                         \
                h = fnv64(f & M_BS, h);                                           \
                if (!(f & F_ZF)) h = fnv64(a, h);                                 \
            }                                                                     \
        report(name, h);                                                          \
    } while (0)

// One operand, in place.
#define GP1(name, insn, mask)                                                     \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NG; i++)                                              \
            for (int c = 0; c < 2; c++) {                                         \
                uint64_t a = G[i], f, in = c ? 0x8D5ull : 0x002ull;               \
                __asm__ volatile("pushq %3\n\t"                                   \
                                 "popfq\n\t" insn                                 \
                                 "\n\t"                                           \
                                 "pushfq\n\t"                                     \
                                 "popq %1"                                        \
                                 : "+r"(a), "=&r"(f)                              \
                                 : "0"(a), "r"(in)                                \
                                 : "cc");                                         \
                h = fnv64(a, h);                                                  \
                h = fnv64(f & (mask), h);                                         \
            }                                                                     \
        report(name, h);                                                          \
    } while (0)

// Shifts and rotates, by CL, over every count from 0 to 71 - the counts that
// are masked, the ones that are not, and the boundary in between.
// A count of zero leaves every flag alone, which is defined and worth checking;
// any other count leaves OF and AF undefined.
#define GP_SHIFT(name, insn, mask)                                                \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NG; i++)                                              \
            for (int n = 0; n < 72; n++)                                          \
                for (int c = 0; c < 2; c++) {                                     \
                    uint64_t a = G[i], f, in = c ? 0x8D5ull : 0x002ull;           \
                    uint64_t cnt = (uint64_t)n;                                   \
                    __asm__ volatile("movq %4, %%rcx\n\t"                         \
                                     "pushq %3\n\t"                               \
                                     "popfq\n\t" insn                             \
                                     "\n\t"                                       \
                                     "pushfq\n\t"                                 \
                                     "popq %1"                                    \
                                     : "+r"(a), "=&r"(f)                          \
                                     : "0"(a), "r"(in), "r"(cnt)                  \
                                     : "cc", "rcx");                              \
                    h = fnv64(a, h);                                              \
                    h = fnv64(f & ((n & 63) == 0 ? FLAGMASK : (mask)), h);        \
                }                                                                 \
        report(name, h);                                                          \
    } while (0)

// SHLD/SHRD: two sources and a count, and the count semantics are their own.
#define GP_DSHIFT(name, insn)                                                     \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NG; i++)                                              \
            for (int j = 0; j < NG; j++)                                          \
                for (int n = 0; n < 72; n += 3) {                                 \
                    uint64_t a = G[i], f, cnt = (uint64_t)n;                      \
                    __asm__ volatile("movq %5, %%rcx\n\t"                         \
                                     "pushq $2\n\t"                               \
                                     "popfq\n\t" insn                             \
                                     "\n\t"                                       \
                                     "pushfq\n\t"                                 \
                                     "popq %1"                                    \
                                     : "+r"(a), "=&r"(f)                          \
                                     : "0"(a), "r"(G[j]), "r"(cnt), "r"(cnt)      \
                                     : "cc", "rcx");                              \
                    h = fnv64(a, h);                                              \
                    h = fnv64(f & ((n & 63) == 0 ? FLAGMASK : M_SHIFT), h);       \
                }                                                                 \
        report(name, h);                                                          \
    } while (0)

// ---------------------------------------------------------------------------

static void sse_integer(void) {
    printf("# SSE2 integer\n");
    SSE_RR("paddb", "paddb");
    SSE_RR("paddw", "paddw");
    SSE_RR("paddd", "paddd");
    SSE_RR("paddq", "paddq");
    SSE_RR("psubb", "psubb");
    SSE_RR("psubw", "psubw");
    SSE_RR("psubd", "psubd");
    SSE_RR("psubq", "psubq");
    SSE_RR("paddsb", "paddsb");
    SSE_RR("paddsw", "paddsw");
    SSE_RR("paddusb", "paddusb");
    SSE_RR("paddusw", "paddusw");
    SSE_RR("psubsb", "psubsb");
    SSE_RR("psubsw", "psubsw");
    SSE_RR("psubusb", "psubusb");
    SSE_RR("psubusw", "psubusw");
    SSE_RR("pmullw", "pmullw");
    SSE_RR("pmulhw", "pmulhw");
    SSE_RR("pmulhuw", "pmulhuw");
    SSE_RR("pmuludq", "pmuludq");
    SSE_RR("pmaddwd", "pmaddwd");
    SSE_RR("pand", "pand");
    SSE_RR("pandn", "pandn");
    SSE_RR("por", "por");
    SSE_RR("pxor", "pxor");
    SSE_RR("pcmpeqb", "pcmpeqb");
    SSE_RR("pcmpeqw", "pcmpeqw");
    SSE_RR("pcmpeqd", "pcmpeqd");
    SSE_RR("pcmpgtb", "pcmpgtb");
    SSE_RR("pcmpgtw", "pcmpgtw");
    SSE_RR("pcmpgtd", "pcmpgtd");
    SSE_RR("packsswb", "packsswb");
    SSE_RR("packssdw", "packssdw");
    SSE_RR("packuswb", "packuswb");
    SSE_RR("punpcklbw", "punpcklbw");
    SSE_RR("punpcklwd", "punpcklwd");
    SSE_RR("punpckldq", "punpckldq");
    SSE_RR("punpcklqdq", "punpcklqdq");
    SSE_RR("punpckhbw", "punpckhbw");
    SSE_RR("punpckhwd", "punpckhwd");
    SSE_RR("punpckhdq", "punpckhdq");
    SSE_RR("punpckhqdq", "punpckhqdq");
    SSE_RR("pavgb", "pavgb");
    SSE_RR("pavgw", "pavgw");
    SSE_RR("pmaxub", "pmaxub");
    SSE_RR("pmaxsw", "pmaxsw");
    SSE_RR("pminub", "pminub");
    SSE_RR("pminsw", "pminsw");
    SSE_RR("psadbw", "psadbw");
    SSE_TO_GPR("pmovmskb", "pmovmskb");
}

static void sse_shifts(void) {
    printf("# SSE2 shifts\n");
    SSE_SHIFT_I("psllw.i", "psllw");
    SSE_SHIFT_I("pslld.i", "pslld");
    SSE_SHIFT_I("psllq.i", "psllq");
    SSE_SHIFT_I("psrlw.i", "psrlw");
    SSE_SHIFT_I("psrld.i", "psrld");
    SSE_SHIFT_I("psrlq.i", "psrlq");
    SSE_SHIFT_I("psraw.i", "psraw");
    SSE_SHIFT_I("psrad.i", "psrad");
    SSE_SHIFT_I("pslldq.i", "pslldq");
    SSE_SHIFT_I("psrldq.i", "psrldq");
    SSE_SHIFT_R("psllw.r", "psllw");
    SSE_SHIFT_R("pslld.r", "pslld");
    SSE_SHIFT_R("psllq.r", "psllq");
    SSE_SHIFT_R("psrlw.r", "psrlw");
    SSE_SHIFT_R("psrld.r", "psrld");
    SSE_SHIFT_R("psrlq.r", "psrlq");
    SSE_SHIFT_R("psraw.r", "psraw");
    SSE_SHIFT_R("psrad.r", "psrad");
}

static void sse_shuffle(void) {
    printf("# SSE2 shuffles and moves\n");
    SSE_RRI("pshufd.1b", "pshufd", 0x1b);
    SSE_RRI("pshufd.00", "pshufd", 0x00);
    SSE_RRI("pshufd.e4", "pshufd", 0xe4);
    SSE_RRI("pshufd.a5", "pshufd", 0xa5);
    SSE_RRI("pshuflw.1b", "pshuflw", 0x1b);
    SSE_RRI("pshuflw.c9", "pshuflw", 0xc9);
    SSE_RRI("pshufhw.1b", "pshufhw", 0x1b);
    SSE_RRI("pshufhw.c9", "pshufhw", 0xc9);
    SSE_RRI("shufps.1b", "shufps", 0x1b);
    SSE_RRI("shufps.4e", "shufps", 0x4e);
    SSE_RRI("shufpd.0", "shufpd", 0);
    SSE_RRI("shufpd.1", "shufpd", 1);
    SSE_RRI("shufpd.2", "shufpd", 2);
    SSE_RRI("shufpd.3", "shufpd", 3);
    SSE_RR("movhlps", "movhlps");
    SSE_RR("movlhps", "movlhps");
    SSE_RR("unpcklps", "unpcklps");
    SSE_RR("unpckhps", "unpckhps");
    SSE_RR("unpcklpd", "unpcklpd");
    SSE_RR("unpckhpd", "unpckhpd");
    SSE_RR("movsd.rr", "movsd");
    SSE_RR("movss.rr", "movss");
    SSE_RR("movapd", "movapd");
    SSE_RR("movq.rr", "movq");
    SSE_TO_GPR("movmskps", "movmskps");
    SSE_TO_GPR("movmskpd", "movmskpd");
}

// ---- SSSE3 and SSE4.1 -----------------------------------------------------
// Not advertised by the emulator's CPUID today, which is exactly why they are
// worth testing: the reason the bits are off is that the instructions were
// missing, and turning them on is what would let ONNX Runtime stop using its
// slowest kernels.  Getting them right first, against an oracle, is the
// difference between that being a one-line change and a silent wrong answer.
//
// BLENDVPS/BLENDVPD/PBLENDVB read their mask from xmm0, so they cannot use the
// macros above - those put the destination there.

#define SSE_BLENDV(name, mnem)                                                    \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NV; i++)                                              \
            for (int j = 0; j < NV; j++)                                          \
                for (int k = 0; k < NV; k += 3) {                                 \
                    v128 r;                                                       \
                    __asm__ volatile("movdqu %1, %%xmm2\n\t"                      \
                                     "movdqu %2, %%xmm1\n\t"                      \
                                     "movdqu %3, %%xmm0\n\t" mnem                 \
                                     " %%xmm1, %%xmm2\n\t"                        \
                                     "movdqu %%xmm2, %0"                          \
                                     : "=m"(r)                                    \
                                     : "m"(V[i]), "m"(V[j]), "m"(V[k])            \
                                     : "xmm0", "xmm1", "xmm2", "memory");         \
                    h = fnv(&r, 16, h);                                           \
                }                                                                 \
        report(name, h);                                                          \
    } while (0)

// PEXTR* and EXTRACTPS write a general register, and the width of that register
// is part of the encoding - so the operand has to be named at the right size.
#define SSE_EXTRACT(name, insn)                                                   \
    do {                                                                          \
        uint64_t h = FNV_INIT;                                                    \
        for (int i = 0; i < NV; i++) {                                            \
            uint64_t r = 0;                                                       \
            __asm__ volatile("movdqu %1, %%xmm1\n\t" insn                         \
                             : "=r"(r)                                            \
                             : "m"(V[i])                                          \
                             : "xmm1");                                           \
            h = fnv64(r, h);                                                      \
        }                                                                         \
        report(name, h);                                                          \
    } while (0)

static void ssse3(void) {
    printf("# SSSE3\n");
    SSE_RR("pshufb", "pshufb");
    SSE_RR("phaddw", "phaddw");
    SSE_RR("phaddd", "phaddd");
    SSE_RR("phaddsw", "phaddsw");
    SSE_RR("phsubw", "phsubw");
    SSE_RR("phsubd", "phsubd");
    SSE_RR("phsubsw", "phsubsw");
    SSE_RR("pmaddubsw", "pmaddubsw");
    SSE_RR("pmulhrsw", "pmulhrsw");
    SSE_RR("psignb", "psignb");
    SSE_RR("psignw", "psignw");
    SSE_RR("psignd", "psignd");
    SSE_RR("pabsb", "pabsb");
    SSE_RR("pabsw", "pabsw");
    SSE_RR("pabsd", "pabsd");
    SSE_RRI("palignr.3", "palignr", 3);
    SSE_RRI("palignr.11", "palignr", 11);
    SSE_RRI("palignr.20", "palignr", 20);
}

static void sse41(void) {
    printf("# SSE4.1\n");
    // The sign- and zero-extending moves read only the low half (or less) of
    // the source, so the operand set still covers every interesting byte.
    SSE_RR("pmovsxbw", "pmovsxbw");
    SSE_RR("pmovsxbd", "pmovsxbd");
    SSE_RR("pmovsxbq", "pmovsxbq");
    SSE_RR("pmovsxwd", "pmovsxwd");
    SSE_RR("pmovsxwq", "pmovsxwq");
    SSE_RR("pmovsxdq", "pmovsxdq");
    SSE_RR("pmovzxbw", "pmovzxbw");
    SSE_RR("pmovzxbd", "pmovzxbd");
    SSE_RR("pmovzxbq", "pmovzxbq");
    SSE_RR("pmovzxwd", "pmovzxwd");
    SSE_RR("pmovzxwq", "pmovzxwq");
    SSE_RR("pmovzxdq", "pmovzxdq");
    SSE_RR("pmuldq", "pmuldq");
    SSE_RR("pmulld", "pmulld");
    SSE_RR("pcmpeqq", "pcmpeqq");
    SSE_RR("packusdw", "packusdw");
    SSE_RR("pminsb", "pminsb");
    SSE_RR("pminsd", "pminsd");
    SSE_RR("pminuw", "pminuw");
    SSE_RR("pminud", "pminud");
    SSE_RR("pmaxsb", "pmaxsb");
    SSE_RR("pmaxsd", "pmaxsd");
    SSE_RR("pmaxuw", "pmaxuw");
    SSE_RR("pmaxud", "pmaxud");
    SSE_RR("phminposuw", "phminposuw");
    SSE_RR("pcmpgtq", "pcmpgtq");  // SSE4.2, but the same shape
    SSE_RRF("roundps.0", "roundps $0,");
    SSE_RRF("roundps.1", "roundps $1,");
    SSE_RRF("roundps.2", "roundps $2,");
    SSE_RRF("roundps.3", "roundps $3,");
    SSE_RRF("roundpd.0", "roundpd $0,");
    SSE_RRF("roundpd.3", "roundpd $3,");
    SSE_RRI("blendps.5", "blendps", 5);
    SSE_RRI("blendpd.2", "blendpd", 2);
    SSE_RRI("pblendw.a5", "pblendw", 0xa5);
    SSE_RRI("insertps.4e", "insertps", 0x4e);
    SSE_RRI("insertps.09", "insertps", 0x09);
    SSE_BLENDV("blendvps", "blendvps");
    SSE_BLENDV("blendvpd", "blendvpd");
    SSE_BLENDV("pblendvb", "pblendvb");
    SSE_EXTRACT("pextrb.3", "pextrb $3, %%xmm1, %k0");
    SSE_EXTRACT("pextrw.5", "pextrw $5, %%xmm1, %k0");
    SSE_EXTRACT("pextrd.2", "pextrd $2, %%xmm1, %k0");
    SSE_EXTRACT("pextrq.1", "pextrq $1, %%xmm1, %0");
    SSE_EXTRACT("extractps.2", "extractps $2, %%xmm1, %k0");
}

static void sse_float(void) {
    printf("# SSE/SSE2 floating point\n");
    SSE_RRF("addps", "addps");
    SSE_RRF("subps", "subps");
    SSE_RRF("mulps", "mulps");
    SSE_RRF("divps", "divps");
    SSE_RRF("minps", "minps");
    SSE_RRF("maxps", "maxps");
    SSE_RRF("sqrtps", "sqrtps");
    SSE_RRF("addpd", "addpd");
    SSE_RRF("subpd", "subpd");
    SSE_RRF("mulpd", "mulpd");
    SSE_RRF("divpd", "divpd");
    SSE_RRF("minpd", "minpd");
    SSE_RRF("maxpd", "maxpd");
    SSE_RRF("sqrtpd", "sqrtpd");
    SSE_RRF("addss", "addss");
    SSE_RRF("mulss", "mulss");
    SSE_RRF("divss", "divss");
    SSE_RRF("addsd", "addsd");
    SSE_RRF("mulsd", "mulsd");
    SSE_RRF("divsd", "divsd");
    SSE_RR("andps", "andps");
    SSE_RR("andnps", "andnps");
    SSE_RR("orps", "orps");
    SSE_RR("xorps", "xorps");
    SSE_RR("andpd", "andpd");
    SSE_RR("andnpd", "andnpd");
    SSE_RR("orpd", "orpd");
    SSE_RR("xorpd", "xorpd");
    SSE_RRI("cmpps.eq", "cmpps", 0);
    SSE_RRI("cmpps.lt", "cmpps", 1);
    SSE_RRI("cmpps.le", "cmpps", 2);
    SSE_RRI("cmpps.un", "cmpps", 3);
    SSE_RRI("cmpps.neq", "cmpps", 4);
    SSE_RRI("cmpps.nlt", "cmpps", 5);
    SSE_RRI("cmppd.eq", "cmppd", 0);
    SSE_RRI("cmppd.lt", "cmppd", 1);
    SSE_RRI("cmppd.un", "cmppd", 3);
    SSE_RRI("cmppd.ord", "cmppd", 7);
    SSE_RRI("cmpsd.lt", "cmpsd", 1);
    SSE_RRI("cmpss.lt", "cmpss", 1);
    SSE_CMP_FLAGS("comisd", "comisd");
    SSE_CMP_FLAGS("ucomisd", "ucomisd");
    SSE_CMP_FLAGS("comiss", "comiss");
    SSE_CMP_FLAGS("ucomiss", "ucomiss");
    printf("# conversions\n");
    SSE_RRF("cvtps2pd", "cvtps2pd");
    SSE_RRF("cvtpd2ps", "cvtpd2ps");
    SSE_RRF("cvtdq2ps", "cvtdq2ps");
    SSE_RRF("cvtdq2pd", "cvtdq2pd");
    SSE_RRF("cvtps2dq", "cvtps2dq");
    SSE_RRF("cvttps2dq", "cvttps2dq");
    SSE_RRF("cvtpd2dq", "cvtpd2dq");
    SSE_RRF("cvttpd2dq", "cvttpd2dq");
    SSE_RRF("cvtss2sd", "cvtss2sd");
    SSE_RRF("cvtsd2ss", "cvtsd2ss");
    SSE_TO_GPR("cvtsd2si", "cvtsd2si");
    SSE_TO_GPR("cvttsd2si", "cvttsd2si");
    SSE_TO_GPR("cvtss2si", "cvtss2si");
    SSE_TO_GPR("cvttss2si", "cvttss2si");
    SSE_TO_GPR("movq.tor", "movq");
}

static void gp(void) {
    printf("# general purpose\n");
    GP2("add", "addq %3, %0", M_ARITH);
    GP2("adc", "adcq %3, %0", M_ARITH);
    GP2("sub", "subq %3, %0", M_ARITH);
    GP2("sbb", "sbbq %3, %0", M_ARITH);
    GP2("and", "andq %3, %0", M_LOGIC);
    GP2("or", "orq %3, %0", M_LOGIC);
    GP2("xor", "xorq %3, %0", M_LOGIC);
    GP2("cmp", "cmpq %3, %0", M_ARITH);
    GP2("test", "testq %3, %0", M_LOGIC);
    GP2("add32", "addl %k3, %k0", M_ARITH);
    GP2("adc32", "adcl %k3, %k0", M_ARITH);
    GP2("sub32", "subl %k3, %k0", M_ARITH);
    GP2("add16", "addw %w3, %w0", M_ARITH);
    GP2("add8", "addb %b3, %b0", M_ARITH);
    GP2("adc8", "adcb %b3, %b0", M_ARITH);
    GP2("imul2", "imulq %3, %0", M_MUL);
    GP2("imul2.32", "imull %k3, %k0", M_MUL);
    GP2("bt", "btq %3, %0", M_BT);
    GP2("bts", "btsq %3, %0", M_BT);
    GP2("btr", "btrq %3, %0", M_BT);
    GP2("btc", "btcq %3, %0", M_BT);
    GP_BITSCAN("bsf", "bsfq %3, %0");
    GP_BITSCAN("bsr", "bsrq %3, %0");
    GP_BITSCAN("bsf32", "bsfl %k3, %k0");
    GP_BITSCAN("bsr32", "bsrl %k3, %k0");
    GP2("xadd", "xaddq %3, %0", M_ARITH);
    GP2("cmovz", "cmovzq %3, %0", FLAGMASK);
    GP2("cmovs", "cmovsq %3, %0", FLAGMASK);
    GP2("cmovc", "cmovcq %3, %0", FLAGMASK);
    GP2("cmovo", "cmovoq %3, %0", FLAGMASK);
    GP2("cmovp", "cmovpq %3, %0", FLAGMASK);
    GP2("cmovl", "cmovlq %3, %0", FLAGMASK);
    GP2("cmovle", "cmovleq %3, %0", FLAGMASK);
    GP2("cmova", "cmovaq %3, %0", FLAGMASK);
    GP1("inc", "incq %0", M_ARITH & ~F_CF);  // INC and DEC leave CF alone
    GP1("dec", "decq %0", M_ARITH & ~F_CF);
    GP1("neg", "negq %0", M_ARITH);
    GP1("not", "notq %0", FLAGMASK);  // NOT touches no flag
    GP1("inc32", "incl %k0", M_ARITH & ~F_CF);
    GP1("neg8", "negb %b0", M_ARITH);
    GP1("bswap", "bswapq %0", FLAGMASK);
    GP1("bswap32", "bswapl %k0", FLAGMASK);
    GP1("movzbq", "movzbq %b0, %0", FLAGMASK);
    GP1("movzwq", "movzwq %w0, %0", FLAGMASK);
    GP1("movsbq", "movsbq %b0, %0", FLAGMASK);
    GP1("movswq", "movswq %w0, %0", FLAGMASK);
    GP1("movslq", "movslq %k0, %0", FLAGMASK);
    GP1("seta", "seta %b0", FLAGMASK);
    GP1("setb", "setb %b0", FLAGMASK);
    GP1("setl", "setl %b0", FLAGMASK);
    GP1("setle", "setle %b0", FLAGMASK);
    GP1("setp", "setp %b0", FLAGMASK);
    GP1("seto", "seto %b0", FLAGMASK);
    printf("# shifts and rotates\n");
    GP_SHIFT("shl", "shlq %%cl, %0", M_SHIFT);
    GP_SHIFT("shr", "shrq %%cl, %0", M_SHIFT);
    GP_SHIFT("sar", "sarq %%cl, %0", M_SHIFT);
    GP_SHIFT("rol", "rolq %%cl, %0", M_ROT);
    GP_SHIFT("ror", "rorq %%cl, %0", M_ROT);
    GP_SHIFT("rcl", "rclq %%cl, %0", M_ROT);
    GP_SHIFT("rcr", "rcrq %%cl, %0", M_ROT);
    GP_SHIFT("shl32", "shll %%cl, %k0", M_SHIFT);
    GP_SHIFT("shr32", "shrl %%cl, %k0", M_SHIFT);
    GP_SHIFT("sar32", "sarl %%cl, %k0", M_SHIFT);
    GP_SHIFT("rol32", "roll %%cl, %k0", M_ROT);
    GP_SHIFT("ror32", "rorl %%cl, %k0", M_ROT);
    GP_SHIFT("shl16", "shlw %%cl, %w0", M_SHIFT);
    GP_SHIFT("shr16", "shrw %%cl, %w0", M_SHIFT);
    GP_SHIFT("rol16", "rolw %%cl, %w0", M_ROT);
    GP_SHIFT("shl8", "shlb %%cl, %b0", M_SHIFT);
    GP_SHIFT("rol8", "rolb %%cl, %b0", M_ROT);
    GP_SHIFT("ror8", "rorb %%cl, %b0", M_ROT);
    GP_DSHIFT("shld", "shldq %%cl, %3, %0");
    GP_DSHIFT("shrd", "shrdq %%cl, %3, %0");
    GP_DSHIFT("shld32", "shldl %%cl, %k3, %k0");
    GP_DSHIFT("shrd32", "shrdl %%cl, %k3, %k0");
}

// mul, imul and div write fixed registers and cannot go through the macros.
static void gp_muldiv(void) {
    printf("# mul and div\n");
    uint64_t h = FNV_INIT;
    for (int i = 0; i < NG; i++)
        for (int j = 0; j < NG; j++) {
            uint64_t lo = G[i], hi, f;
            __asm__ volatile("pushq $2\n\t"
                             "popfq\n\t"
                             "mulq %3\n\t"
                             "pushfq\n\t"
                             "popq %2"
                             : "+a"(lo), "=d"(hi), "=r"(f)
                             : "r"(G[j])
                             : "cc");
            h = fnv64(lo, h);
            h = fnv64(hi, h);
            h = fnv64(f & M_MUL, h);
        }
    report("mul", h);

    h = FNV_INIT;
    for (int i = 0; i < NG; i++)
        for (int j = 0; j < NG; j++) {
            uint64_t lo = G[i], hi, f;
            __asm__ volatile("pushq $2\n\t"
                             "popfq\n\t"
                             "imulq %3\n\t"
                             "pushfq\n\t"
                             "popq %2"
                             : "+a"(lo), "=d"(hi), "=r"(f)
                             : "r"(G[j])
                             : "cc");
            h = fnv64(lo, h);
            h = fnv64(hi, h);
            h = fnv64(f & M_MUL, h);
        }
    report("imul1", h);

    // Divisors chosen so the quotient always fits: dividend high half is zero.
    h = FNV_INIT;
    for (int i = 0; i < NG; i++)
        for (int j = 0; j < NG; j++) {
            if (G[j] == 0) continue;
            uint64_t lo = G[i], hi = 0, f;
            __asm__ volatile("pushq $2\n\t"
                             "popfq\n\t"
                             "divq %4\n\t"
                             "pushfq\n\t"
                             "popq %2"
                             : "+a"(lo), "+d"(hi), "=r"(f)
                             : "0"(lo), "r"(G[j])
                             : "cc");
            h = fnv64(lo, h);
            h = fnv64(hi, h);
        }
    report("div", h);

    // idiv: keep the dividend a sign-extended 64-bit value so INT64_MIN / -1
    // - the one case that faults - never arises.
    h = FNV_INIT;
    for (int i = 0; i < NG; i++)
        for (int j = 0; j < NG; j++) {
            int64_t d = (int64_t)G[j];
            if (d == 0) continue;
            int64_t n = (int64_t)G[i] >> 1;  // halved, so |n| < 2^62
            uint64_t lo = (uint64_t)n, hi = (uint64_t)(n >> 63), f;
            __asm__ volatile("pushq $2\n\t"
                             "popfq\n\t"
                             "idivq %4\n\t"
                             "pushfq\n\t"
                             "popq %2"
                             : "+a"(lo), "+d"(hi), "=r"(f)
                             : "0"(lo), "r"((uint64_t)d)
                             : "cc");
            h = fnv64(lo, h);
            h = fnv64(hi, h);
        }
    report("idiv", h);
}

// The string instructions, which memcpy and memcmp are made of.
static void strings(void) {
    printf("# string ops\n");
    static unsigned char src[512], dst[512];
    for (int i = 0; i < 512; i++) src[i] = (unsigned char)(i * 7 + 3);
    uint64_t h = FNV_INIT;

    for (int n = 0; n < 40; n++) {
        memset(dst, 0xcc, sizeof dst);
        __asm__ volatile("cld\n\t rep movsb"
                         :
                         : "D"(dst), "S"(src), "c"((uint64_t)n)
                         : "memory");
        h = fnv(dst, 64, h);
    }
    report("rep.movsb", h);

    h = FNV_INIT;
    for (int n = 0; n < 40; n++) {
        memset(dst, 0xcc, sizeof dst);
        __asm__ volatile("cld\n\t rep movsq"
                         :
                         : "D"(dst), "S"(src), "c"((uint64_t)n)
                         : "memory");
        h = fnv(dst, 384, h);
    }
    report("rep.movsq", h);

    h = FNV_INIT;
    for (int n = 0; n < 40; n++) {
        memset(dst, 0xcc, sizeof dst);
        __asm__ volatile("cld\n\t rep stosq"
                         :
                         : "D"(dst), "a"(0x0123456789abcdefull), "c"((uint64_t)n)
                         : "memory");
        h = fnv(dst, 384, h);
    }
    report("rep.stosq", h);

    h = FNV_INIT;
    for (int n = 0; n < 40; n++) {
        memcpy(dst, src, sizeof dst);
        if (n < 512) dst[n] ^= 0x80;
        uint64_t f, cnt = 200;
        const void *p = dst, *q = src;
        __asm__ volatile("cld\n\t"
                         "pushq $2\n\t"
                         "popfq\n\t"
                         "repe cmpsb\n\t"
                         "pushfq\n\t"
                         "popq %0"
                         : "=r"(f), "+D"(p), "+S"(q), "+c"(cnt)
                         :
                         : "cc");
        h = fnv64(f & FLAGMASK, h);
        h = fnv64(cnt, h);
    }
    report("repe.cmpsb", h);

    h = FNV_INIT;
    for (int n = 0; n < 40; n++) {
        memset(dst, 0x11, sizeof dst);
        dst[n] = 0x99;
        uint64_t f, cnt = 300;
        const void* p = dst;
        __asm__ volatile("cld\n\t"
                         "pushq $2\n\t"
                         "popfq\n\t"
                         "repne scasb\n\t"
                         "pushfq\n\t"
                         "popq %0"
                         : "=r"(f), "+D"(p), "+c"(cnt)
                         : "a"((uint64_t)0x99)
                         : "cc");
        h = fnv64(f & FLAGMASK, h);
        h = fnv64(cnt, h);
    }
    report("repne.scasb", h);
}

// The locked forms, which a C++ runtime's reference counts are made of.
static void atomics(void) {
    printf("# locked\n");
    uint64_t h = FNV_INIT;
    for (int i = 0; i < NG; i++)
        for (int j = 0; j < NG; j++) {
            volatile uint64_t m = G[i];
            uint64_t a = G[j], f;
            __asm__ volatile("pushq $2\n\t"
                             "popfq\n\t"
                             "lock xaddq %2, %0\n\t"
                             "pushfq\n\t"
                             "popq %1"
                             : "+m"(m), "=&r"(f), "+r"(a)
                             :
                             : "cc", "memory");
            h = fnv64(m, h);
            h = fnv64(a, h);
            h = fnv64(f & FLAGMASK, h);
        }
    report("lock.xadd", h);

    h = FNV_INIT;
    for (int i = 0; i < NG; i++)
        for (int j = 0; j < NG; j++) {
            volatile uint64_t m = G[i];
            uint64_t want = G[j], newv = G[(j + 1) % NG], f;
            __asm__ volatile("pushq $2\n\t"
                             "popfq\n\t"
                             "lock cmpxchgq %3, %0\n\t"
                             "pushfq\n\t"
                             "popq %1"
                             : "+m"(m), "=&r"(f), "+a"(want)
                             : "r"(newv)
                             : "cc", "memory");
            h = fnv64(m, h);
            h = fnv64(want, h);
            h = fnv64(f & FLAGMASK, h);
        }
    report("lock.cmpxchg", h);

    h = FNV_INIT;
    for (int i = 0; i < NG; i++) {
        volatile uint64_t m = G[i];
        uint64_t a = 0x1234;
        __asm__ volatile("xchgq %1, %0" : "+m"(m), "+r"(a) : : "memory");
        h = fnv64(m, h);
        h = fnv64(a, h);
    }
    report("xchg", h);
}

int main(void) {
    init_operands();
    sse_integer();
    ssse3();
    sse41();
    sse_shifts();
    sse_shuffle();
    sse_float();
    gp();
    gp_muldiv();
    strings();
    atomics();
    printf("# %d groups\n", groups);
    printf("ISATEST DONE\n");
    return 0;
}
