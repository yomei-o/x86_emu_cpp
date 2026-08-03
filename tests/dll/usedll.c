// Uses the test DLL both ways a Windows program can: linked against its import
// library, and looked up at runtime through LoadLibrary/GetProcAddress.
int printf(const char *fmt, ...);
void exit(int code);

__declspec(dllimport) int lib_add(int a, int b);
__declspec(dllimport) const char *lib_name(void);
__declspec(dllimport) int lib_counter;          /* exported *data* */
__declspec(dllimport) const char *lib_greeting; /* a relocated pointer */
__declspec(dllimport) int lib_call_back(int (*fn)(int), int value);
__declspec(dllimport) double lib_scale(double x);

/* Declared the way windows.h would, without pulling in the header. */
void *__stdcall LoadLibraryA(const char *name);
void *__stdcall GetProcAddress(void *module, const char *name);
int __stdcall FreeLibrary(void *module);

static int triple(int v) { return v * 3; }

static int implicit_phase(void) {
    printf("add        %d\n", lib_add(20, 22));
    printf("name       %s\n", lib_name());
    printf("data       %d\n", lib_counter);
    printf("greeting   %s\n", lib_greeting);
    printf("callback   %d\n", lib_call_back(triple, 7));
    printf("scale      %.3f\n", lib_scale(1.5));
    lib_counter = 500;
    printf("data write %d\n", lib_counter);
    return 0;
}

static int runtime_phase(void) {
    void *module = LoadLibraryA("testlib.dll");
    if (!module) {
        printf("LoadLibrary failed\n");
        return 1;
    }
    int (*add)(int, int) = (int (*)(int, int))GetProcAddress(module, "lib_add");
    const char *(*name)(void) = (const char *(*)(void))GetProcAddress(module, "lib_name");
    void *missing = GetProcAddress(module, "no_such_symbol");
    printf("runtime    %d %s missing=%s\n", add ? add(1, 2) : -1, name ? name() : "?",
           missing ? "found" : "null");
    /* The already-loaded module must come back as the same handle. */
    printf("same handle %s\n", LoadLibraryA("testlib.dll") == module ? "yes" : "no");
    FreeLibrary(module);
    return 0;
}

static int run(void) {
    if (implicit_phase()) return 1;
    if (runtime_phase()) return 1;
    printf("dll test ok\n");
    return 0;
}

void start_(void) { exit(run()); }
