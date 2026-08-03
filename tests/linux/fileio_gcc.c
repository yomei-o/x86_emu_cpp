/* File I/O on Linux, through both layers a program can use: glibc's stdio and
 * the raw open/read/write/lseek syscalls underneath it. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PATH "x86emu_linux_io.tmp"

static int stdio_phase(void) {
    FILE *f = fopen(PATH, "wb");
    if (!f) {
        printf("fopen failed\n");
        return 1;
    }
    const char *text = "alpha\nbeta\ngamma\n";
    printf("fwrite %zu\n", fwrite(text, 1, strlen(text), f));
    fclose(f);

    f = fopen(PATH, "rb");
    char line[64];
    int n = 0;
    while (fgets(line, sizeof line, f)) {
        size_t len = strlen(line);
        while (len && line[len - 1] == '\n') line[--len] = 0;
        printf("  %d: %s\n", ++n, line);
    }
    fseek(f, 6, SEEK_SET);
    char slice[5];
    size_t got = fread(slice, 1, 4, f);
    slice[got] = 0;
    printf("slice [%s]\n", slice);
    fclose(f);
    return 0;
}

static int syscall_phase(void) {
    int fd = open(PATH, O_RDWR | O_APPEND);
    if (fd < 0) {
        printf("open failed\n");
        return 1;
    }
    const char *more = "delta\n";
    printf("write %zd\n", write(fd, more, strlen(more)));
    off_t end = lseek(fd, 0, SEEK_END);
    printf("size %lld\n", (long long)end);

    struct stat st;
    if (fstat(fd, &st) == 0) printf("fstat size %lld\n", (long long)st.st_size);
    close(fd);

    fd = open(PATH, O_RDONLY);
    char buf[64];
    ssize_t r = read(fd, buf, sizeof buf - 1);
    buf[r > 0 ? r : 0] = 0;
    /* Print with newlines escaped so the layout is obvious. */
    printf("read %zd: ", r);
    for (ssize_t i = 0; i < r; i++) putchar(buf[i] == '\n' ? '|' : buf[i]);
    putchar('\n');
    close(fd);

    if (stat(PATH, &st) == 0) printf("stat size %lld\n", (long long)st.st_size);
    printf("unlink %d\n", unlink(PATH));
    printf("access after unlink %d\n", access(PATH, F_OK));
    return 0;
}

int main(void) {
    if (stdio_phase()) return 1;
    if (syscall_phase()) return 1;
    printf("linux file io ok\n");
    return 5;
}
