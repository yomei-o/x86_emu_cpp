// File I/O through C stdio, exercising the guest's descriptor table end to end:
// create, write, seek, read back, append, stat by size, and delete.
//
// The test creates and removes its own file, so a run under the emulator and a
// native run produce identical output only if every step really happened.
int printf(const char *fmt, ...);
void exit(int code);
unsigned long strlen(const char *s);

typedef void FILE;
FILE *fopen(const char *path, const char *mode);
int fclose(FILE *f);
unsigned long fwrite(const void *p, unsigned long size, unsigned long n, FILE *f);
unsigned long fread(void *p, unsigned long size, unsigned long n, FILE *f);
int fseek(FILE *f, long off, int whence);
long ftell(FILE *f);
int fputs(const char *s, FILE *f);
char *fgets(char *s, int n, FILE *f);
int feof(FILE *f);
int remove(const char *path);
int rename(const char *from, const char *to);

#define PATH "x86emu_io_test.tmp"
#define PATH2 "x86emu_io_test2.tmp"

static int write_phase(void) {
    FILE *f = fopen(PATH, "wb");
    if (!f) {
        printf("fopen for write failed\n");
        return 1;
    }
    const char *text = "line one\nline two\nline three\n";
    unsigned long n = fwrite(text, 1, strlen(text), f);
    printf("wrote %lu bytes, ftell %ld\n", n, ftell(f));
    fputs("line four\n", f);
    printf("after fputs ftell %ld\n", ftell(f));
    fclose(f);
    return 0;
}

static int read_phase(void) {
    FILE *f = fopen(PATH, "rb");
    if (!f) {
        printf("fopen for read failed\n");
        return 1;
    }
    char buf[64];
    int line = 0;
    while (fgets(buf, sizeof buf, f)) {
        /* Trim the newline so the output does not depend on line endings. */
        unsigned long len = strlen(buf);
        while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) buf[--len] = 0;
        printf("  line %d: [%s]\n", ++line, buf);
    }
    printf("eof %d, ftell %ld\n", feof(f) ? 1 : 0, ftell(f));

    /* Seek back to a known offset and read a fixed slice. */
    fseek(f, 9, 0);
    char slice[9];
    unsigned long got = fread(slice, 1, 8, f);
    slice[got] = 0;
    printf("slice at 9: [%s] (%lu)\n", slice, got);

    fseek(f, -10, 2); /* SEEK_END */
    printf("ftell from end: %ld\n", ftell(f));
    fclose(f);
    return 0;
}

static int append_phase(void) {
    FILE *f = fopen(PATH, "ab");
    if (!f) {
        printf("fopen for append failed\n");
        return 1;
    }
    fputs("appended\n", f);
    fclose(f);

    f = fopen(PATH, "rb");
    fseek(f, 0, 2);
    printf("size after append: %ld\n", ftell(f));
    fclose(f);
    return 0;
}

static int rename_phase(void) {
    printf("rename %d\n", rename(PATH, PATH2));
    FILE *f = fopen(PATH2, "rb");
    printf("reopened after rename: %s\n", f ? "yes" : "no");
    if (f) fclose(f);
    printf("remove old %d, remove new %d\n", remove(PATH), remove(PATH2));
    f = fopen(PATH2, "rb");
    printf("exists after remove: %s\n", f ? "yes" : "no");
    if (f) fclose(f);
    return 0;
}

static int run(void) {
    if (write_phase()) return 1;
    if (read_phase()) return 1;
    if (append_phase()) return 1;
    if (rename_phase()) return 1;
    printf("file io ok\n");
    return 0;
}

void start_(void) { exit(run()); }
