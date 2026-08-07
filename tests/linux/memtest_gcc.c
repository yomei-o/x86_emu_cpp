// memtest.c - does a large buffer survive the emulator's allocator?
//
// The model that will not decrypt is 58 MB, and the trace shows glibc's realloc
// reaching for mremap on it, getting ENOSYS, and falling back to
// mmap + memcpy + munmap.  That fallback is the emulator's mmap and munmap on a
// 58 MB region, which nothing else here exercises.  If it drops or duplicates a
// page the bytes ORT parses are wrong and the failure looks exactly like a
// decrypt that produced garbage.
//
// So: build the same shape of buffer the same way and check it byte for byte.
// Nothing here touches the model's contents - it reads the file the guest can
// already read and compares a checksum against the one the file has on the host.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t fnv1a(const unsigned char* p, size_t n, uint64_t h) {
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 1099511628211ull;
    return h;
}
#define FNV_INIT 1469598103934665603ull

static int fails = 0;

static void check(const char* what, int ok) {
    printf("%-52s %s\n", what, ok ? "ok" : "FAIL");
    fflush(stdout);
    if (!ok) fails++;
}

// A cheap deterministic byte at index i - not a pattern the allocator could
// accidentally reproduce, and computable without keeping a second copy.
static unsigned char pat(size_t i) {
    uint64_t x = i * 0x9E3779B97F4A7C15ull;
    x ^= x >> 29;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 32;
    return (unsigned char)x;
}

static int verify(const unsigned char* p, size_t n, size_t* first_bad) {
    for (size_t i = 0; i < n; i++)
        if (p[i] != pat(i)) {
            *first_bad = i;
            return 0;
        }
    return 1;
}

// Grow a buffer the way a reader that does not know the length does: double it
// and copy.  Above mmap_threshold every one of these is an mmap chunk, so every
// realloc is the mremap-or-fall-back path.
static void grow_test(size_t start, size_t end) {
    char what[96];
    size_t cap = start;
    unsigned char* p = malloc(cap);
    if (!p) {
        printf("malloc(%zu) failed\n", cap);
        fails++;
        return;
    }
    for (size_t i = 0; i < cap; i++) p[i] = pat(i);

    while (cap < end) {
        size_t want = cap * 2 > end ? end : cap * 2;
        unsigned char* q = realloc(p, want);
        if (!q) {
            printf("realloc(%zu) failed\n", want);
            fails++;
            free(p);
            return;
        }
        p = q;
        size_t bad = 0;
        int ok = verify(p, cap, &bad);
        snprintf(what, sizeof what, "realloc %zu -> %zu keeps the first %zu bytes",
                 cap, want, cap);
        check(what, ok);
        if (!ok) {
            printf("      first wrong byte at %zu: got %02x want %02x\n", bad, p[bad],
                   pat(bad));
            free(p);
            return;
        }
        for (size_t i = cap; i < want; i++) p[i] = pat(i);
        cap = want;
    }
    size_t bad = 0;
    snprintf(what, sizeof what, "the whole %zu byte buffer is intact", cap);
    check(what, verify(p, cap, &bad));
    free(p);
}

int main(int argc, char** argv) {
    // A large file to read, if the caller names one.  The allocator bug this
    // was written to look for showed up on a 58 MB read, so reading a real file
    // of that order is part of the test - but there is no such file to point at
    // by default, and inventing a path only produces a recorded expectation
    // full of "cannot open".
    const char* vvm = argc > 1 ? argv[1] : NULL;

    printf("== a large buffer grown by realloc, which is the model's shape\n");
    grow_test(64 * 1024, 64u * 1024 * 1024);

    printf("\n== one big allocation, written and read back\n");
    {
        size_t n = 58u * 1024 * 1024;
        unsigned char* p = malloc(n);
        if (!p) {
            printf("malloc(%zu) failed\n", n);
            fails++;
        } else {
            for (size_t i = 0; i < n; i++) p[i] = pat(i);
            size_t bad = 0;
            int ok = verify(p, n, &bad);
            check("58 MB written then read back", ok);
            if (!ok)
                printf("      first wrong byte at %zu: got %02x want %02x\n", bad, p[bad],
                       pat(bad));
            free(p);
        }
    }

    printf("\n== many mmap-sized chunks alive at once, then freed in a shuffled order\n");
    {
        enum { N = 64 };
        unsigned char* v[N];
        size_t sz[N];
        int ok = 1;
        for (int i = 0; i < N; i++) {
            sz[i] = (size_t)(256 + i * 37) * 1024;  // all above mmap_threshold
            v[i] = malloc(sz[i]);
            if (!v[i]) { ok = 0; break; }
            memset(v[i], i, sz[i]);
        }
        for (int i = 0; i < N && ok; i++)
            for (size_t j = 0; j < sz[i]; j += 4093)
                if (v[i][j] != (unsigned char)i) { ok = 0; break; }
        check("64 mmap chunks keep their own bytes", ok);
        for (int i = 0; i < N; i++) free(v[(i * 37) % N]);
    }

    printf("\n== a large file, read into a buffer grown by realloc\n");
    {
        FILE* f = vvm ? fopen(vvm, "rb") : NULL;
        if (!f) {
            printf("no file given - skipping (name one as the first argument)\n");
        } else {
            size_t cap = 64 * 1024, len = 0;
            unsigned char* p = malloc(cap);
            for (;;) {
                if (len == cap) {
                    cap *= 2;
                    unsigned char* q = realloc(p, cap);
                    if (!q) { free(p); p = NULL; break; }
                    p = q;
                }
                size_t got = fread(p + len, 1, cap - len, f);
                if (got == 0) break;
                len += got;
            }
            fclose(f);
            if (!p) {
                printf("out of memory\n");
                fails++;
            } else {
                printf("      %zu bytes, fnv1a %016llx\n", len,
                       (unsigned long long)fnv1a(p, len, FNV_INIT));
                printf("      (the file streamed 64 KB at a time reads fbd5370b3d46e74d)\n");
                check("the realloc-grown copy has the file's checksum",
                      fnv1a(p, len, FNV_INIT) == 0xfbd5370b3d46e74dull &&
                          len == 58214379);
                free(p);
            }
        }
    }

    printf("\n%s\n", fails ? "MEMTEST FAILED" : "MEMTEST OK");
    return fails ? 1 : 0;
}
