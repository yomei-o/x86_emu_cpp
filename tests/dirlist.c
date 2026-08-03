// Directory enumeration and file metadata through the Win32 API.
//
// The test creates its own files so the expected result does not depend on what
// happens to be in the directory, and sorts the names itself so the output does
// not depend on the order the filesystem hands them back.
int printf(const char *fmt, ...);
void exit(int code);
unsigned long strlen(const char *s);
int strcmp(const char *a, const char *b);
char *strcpy(char *d, const char *s);

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

HANDLE __stdcall CreateFileA(const char *name, DWORD access, DWORD share, void *sa,
                             DWORD disposition, DWORD flags, HANDLE templ);
BOOL __stdcall WriteFile(HANDLE h, const void *buf, DWORD n, DWORD *written, void *ov);
BOOL __stdcall CloseHandle(HANDLE h);
BOOL __stdcall DeleteFileA(const char *name);
DWORD __stdcall GetFileAttributesA(const char *name);
BOOL __stdcall CreateDirectoryA(const char *name, void *sa);
BOOL __stdcall RemoveDirectoryA(const char *name);
HANDLE __stdcall FindFirstFileA(const char *pattern, void *data);
/* Windows' wchar_t is 16 bits; spelling it out avoids needing <stddef.h> in a
   freestanding test. */
typedef unsigned short WCHAR;
HANDLE __stdcall FindFirstFileW(const WCHAR *pattern, void *data);
BOOL __stdcall FindNextFileW(HANDLE h, void *data);
DWORD __stdcall GetLastError(void);
DWORD __stdcall SetLastError(DWORD code);
BOOL __stdcall FindNextFileA(HANDLE h, void *data);
BOOL __stdcall FindClose(HANDLE h);

#define GENERIC_WRITE 0x40000000u
#define CREATE_ALWAYS 2
#define INVALID_HANDLE ((HANDLE)(long long)-1)
#define FILE_ATTRIBUTE_DIRECTORY 0x10

/* WIN32_FIND_DATAA: attributes, three FILETIMEs, size, two reserved words, then
   a 260-byte name and a 14-byte 8.3 name. */
struct find_data {
    DWORD attributes;
    unsigned char times[24];
    DWORD size_high;
    DWORD size_low;
    DWORD reserved0;
    DWORD reserved1;
    char name[260];
    char alternate[14];
};

#define DIR "x86emu_dir_test"
#define MAX_NAMES 16

/* The wide form of the same structure: the fixed part is identical, but both
   name arrays are twice as wide. */
struct find_dataw {
    DWORD attributes;
    unsigned char times[24];
    DWORD size_high;
    DWORD size_low;
    DWORD reserved0;
    DWORD reserved1;
    WCHAR name[260];
    WCHAR alternate[14];
};

/* Exactly the sequence a libc's listdir uses on Windows, including the
   GetLastError contract that says the loop ended because there was nothing left
   rather than because something failed. */
static void enumerate_wide(void) {
    struct find_dataw data;
    int count = 0;
    int saw_beta = 0;
    HANDLE h;

    /* The pattern, spelled out so no wide string literal or locale conversion is
       involved: "x86emu_dir_test\*.*". */
    static const WCHAR pattern[] = {'x', '8', '6', 'e', 'm', 'u', '_', 'd', 'i',
                                    'r', '_', 't', 'e', 's', 't', '\\', '*', '.',
                                    '*', 0};

    SetLastError(0);
    h = FindFirstFileW(pattern, &data);
    if (h == INVALID_HANDLE) {
        printf("wide: FindFirstFileW failed\n");
        return;
    }
    do {
        if (data.name[0] == '.' && (data.name[1] == 0 ||
                                    (data.name[1] == '.' && data.name[2] == 0)))
            continue;
        count++;
        /* Compare against a wide literal, the way real code would. */
        if (data.name[0] == 'b' && data.name[1] == 'e' && data.name[2] == 't' &&
            data.name[3] == 'a' && data.name[4] == '.' && data.name[5] == 't' &&
            data.name[6] == 'x' && data.name[7] == 't' && data.name[8] == 0)
            saw_beta = 1;
    } while (FindNextFileW(h, &data));
    DWORD err = GetLastError();
    FindClose(h);
    printf("wide: %d entries, beta seen %d, last error %lu\n", count, saw_beta,
           (unsigned long)err);
}

static char g_names[MAX_NAMES][64];
static int g_count;

static int make_file(const char *path, const char *contents) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    DWORD written = 0;
    if (h == INVALID_HANDLE) return 1;
    WriteFile(h, contents, (DWORD)strlen(contents), &written, 0);
    CloseHandle(h);
    return 0;
}

static void collect(const char *pattern) {
    struct find_data data;
    HANDLE h = FindFirstFileA(pattern, &data);
    g_count = 0;
    if (h == INVALID_HANDLE) return;
    do {
        /* Skip the "." and ".." entries some filesystems report. */
        if (data.name[0] == '.' && (data.name[1] == 0 ||
                                    (data.name[1] == '.' && data.name[2] == 0)))
            continue;
        if (g_count < MAX_NAMES) {
            strcpy(g_names[g_count], data.name);
            g_count++;
        }
    } while (FindNextFileA(h, &data));
    FindClose(h);

    /* Sort so the output is independent of enumeration order. */
    for (int i = 1; i < g_count; i++) {
        char tmp[64];
        int j = i;
        strcpy(tmp, g_names[i]);
        while (j > 0 && strcmp(g_names[j - 1], tmp) > 0) {
            strcpy(g_names[j], g_names[j - 1]);
            j--;
        }
        strcpy(g_names[j], tmp);
    }
}

static int run(void) {
    char path[128];

    CreateDirectoryA(DIR, 0);
    printf("dir created: %d\n",
           (GetFileAttributesA(DIR) & FILE_ATTRIBUTE_DIRECTORY) != 0);

    strcpy(path, DIR "/alpha.txt");
    if (make_file(path, "aaa")) { printf("create failed\n"); return 1; }
    strcpy(path, DIR "/beta.txt");
    if (make_file(path, "bbbbb")) { printf("create failed\n"); return 1; }
    strcpy(path, DIR "/gamma.dat");
    if (make_file(path, "ccccccc")) { printf("create failed\n"); return 1; }

    collect(DIR "/*");
    printf("all entries: %d\n", g_count);
    for (int i = 0; i < g_count; i++) printf("  %s\n", g_names[i]);

    collect(DIR "/*.txt");
    printf("txt entries: %d\n", g_count);
    for (int i = 0; i < g_count; i++) printf("  %s\n", g_names[i]);

    collect(DIR "/nothing_matches_*");
    printf("no matches: %d\n", g_count);

    enumerate_wide();

    /* Sizes come back in the find data too. */
    struct find_data data;
    HANDLE h = FindFirstFileA(DIR "/beta.txt", &data);
    if (h != INVALID_HANDLE) {
        printf("beta size %lu dir %d\n", (unsigned long)data.size_low,
               (data.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
        FindClose(h);
    }

    strcpy(path, DIR "/alpha.txt");
    DeleteFileA(path);
    strcpy(path, DIR "/beta.txt");
    DeleteFileA(path);
    strcpy(path, DIR "/gamma.dat");
    DeleteFileA(path);
    printf("removed dir: %d\n", RemoveDirectoryA(DIR) != 0);
    printf("dir gone: %d\n", GetFileAttributesA(DIR) == 0xFFFFFFFFu);

    printf("dirlist ok\n");
    return 0;
}

void start_(void) { exit(run()); }
