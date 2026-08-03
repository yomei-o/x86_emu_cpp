// File I/O through the Win32 API rather than C stdio.
//
// CreateFile/ReadFile/WriteFile and fopen/fread/fwrite are two spellings of the
// same operations, and both land on the emulator's one descriptor table - so a
// HANDLE here is a descriptor in disguise, and this test and tests/fileio.c
// exercise the same machinery from opposite ends.
int printf(const char *fmt, ...);
void exit(int code);
unsigned long strlen(const char *s);

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

HANDLE __stdcall CreateFileA(const char *name, DWORD access, DWORD share, void *sa,
                             DWORD disposition, DWORD flags, HANDLE templ);
BOOL __stdcall WriteFile(HANDLE h, const void *buf, DWORD n, DWORD *written, void *ov);
BOOL __stdcall ReadFile(HANDLE h, void *buf, DWORD n, DWORD *read, void *ov);
BOOL __stdcall SetFilePointerEx(HANDLE h, long long distance, long long *newpos, DWORD method);
BOOL __stdcall GetFileSizeEx(HANDLE h, long long *size);
BOOL __stdcall CloseHandle(HANDLE h);
BOOL __stdcall DeleteFileA(const char *name);
DWORD __stdcall GetFileAttributesA(const char *name);
DWORD __stdcall GetLastError(void);
DWORD __stdcall GetFileType(HANDLE h);
HANDLE __stdcall GetStdHandle(DWORD which);

#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define INVALID_HANDLE ((HANDLE)(long long)-1)
#define PATH "x86emu_win_io.tmp"

static int write_phase(void) {
    HANDLE h = CreateFileA(PATH, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (h == INVALID_HANDLE) {
        printf("CreateFileA for write failed\n");
        return 1;
    }
    const char *text = "win32 line one\nwin32 line two\n";
    DWORD written = 0;
    WriteFile(h, text, (DWORD)strlen(text), &written, 0);
    printf("wrote %lu\n", (unsigned long)written);

    long long size = 0;
    GetFileSizeEx(h, &size);
    printf("size while open %lld\n", size);
    CloseHandle(h);
    return 0;
}

static int read_phase(void) {
    HANDLE h = CreateFileA(PATH, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
    if (h == INVALID_HANDLE) {
        printf("CreateFileA for read failed\n");
        return 1;
    }
    char buf[128];
    DWORD got = 0;
    ReadFile(h, buf, 15, &got, 0);
    buf[got] = 0;
    /* Show the newline as a bar so the output does not depend on line endings. */
    for (DWORD i = 0; i < got; i++)
        if (buf[i] == '\n') buf[i] = '|';
    printf("read %lu [%s]\n", (unsigned long)got, buf);

    long long pos = 0;
    SetFilePointerEx(h, 6, &pos, 0 /* FILE_BEGIN */);
    printf("seek to %lld\n", pos);
    got = 0;
    ReadFile(h, buf, 4, &got, 0);
    buf[got] = 0;
    printf("slice [%s]\n", buf);

    SetFilePointerEx(h, 0, &pos, 2 /* FILE_END */);
    printf("end at %lld\n", pos);
    CloseHandle(h);
    return 0;
}

static int attribute_phase(void) {
    DWORD attrs = GetFileAttributesA(PATH);
    printf("attributes present: %d\n", attrs != 0xFFFFFFFFu);
    printf("missing file: %d\n", GetFileAttributesA("no_such_file_here") == 0xFFFFFFFFu);

    HANDLE missing = CreateFileA("no_such_file_here", GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
    printf("open missing invalid: %d\n", missing == INVALID_HANDLE);

    printf("delete %d\n", DeleteFileA(PATH) != 0);
    printf("gone: %d\n", GetFileAttributesA(PATH) == 0xFFFFFFFFu);
    return 0;
}

static int console_phase(void) {
    /* The standard handles go through the same table, so writing to one is the
       same operation as writing to a file. */
    HANDLE out = GetStdHandle((DWORD)-11);
    const char *msg = "via WriteFile to stdout\n";
    DWORD written = 0;
    WriteFile(out, msg, (DWORD)strlen(msg), &written, 0);
    printf("stdout handle type %lu, wrote %lu\n", (unsigned long)GetFileType(out),
           (unsigned long)written);
    return 0;
}

static int run(void) {
    if (write_phase()) return 1;
    if (read_phase()) return 1;
    if (attribute_phase()) return 1;
    if (console_phase()) return 1;
    printf("win32 file io ok\n");
    return 0;
}

void start_(void) { exit(run()); }
