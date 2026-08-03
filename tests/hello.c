// The first milestone: reach printf through the import table and print text.
//
// Built freestanding, so `start_` stands in for the CRT entry point and the
// only imports are the ones this file names.
int printf(const char *fmt, ...);
void exit(int code);

static int run(void) {
    int i;
    printf("hello from the guest!\n");
    printf("integers : %d %u %05d %+d %x %X\n", -42, 3000000000u, 7, 7, 0xBEEF, 0xBEEF);
    printf("strings  : [%s] [%10s] [%-10s] [%.3s]\n", "abc", "abc", "abc", "abcdef");
    printf("chars    : %c%c%c\n", 'x', '8', '6');
    for (i = 0; i < 3; i++) printf("loop %d of 3\n", i + 1);
    return 0;
}

void start_(void) { exit(run()); }
