/* An ordinary C program built by gcc against a real glibc, linked statically.
 *
 * Unlike the hand-assembled ELF tests, everything here runs inside the guest:
 * glibc's own startup, its stdio with its own buffering, its SSE2 string
 * routines, and its floating-point conversion.  The emulator only provides the
 * kernel interface underneath. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    printf("hello from static glibc\n");
    printf("argc=%d argv0=%s\n", argc, argv[0] ? argv[0] : "(null)");

    for (int i = 0; i < 3; i++)
        printf("i=%d  half=%.3f  sq=%d\n", i, i * 1.5, i * i);

    char *buf = malloc(64);
    if (!buf) return 1;
    strcpy(buf, "heap string");
    printf("strlen(%s)=%zu\n", buf, strlen(buf));
    free(buf);

    /* Enough floating point to reach glibc's own conversion code. */
    double acc = 0;
    for (int i = 1; i <= 10; i++) acc += 1.0 / i;
    printf("harmonic(10)=%.10f\n", acc);

    fputs("done\n", stdout);
    return 3;
}
