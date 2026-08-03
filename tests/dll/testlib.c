// A DLL for the emulator to load for real.
//
// It has everything the loader has to get right: exported functions and exported
// *data*, a global with a non-trivial initial value (so relocations matter), a
// DllMain that runs before anything else, and an import of its own.
__declspec(dllexport) int lib_add(int a, int b);
__declspec(dllexport) const char *lib_name(void);
__declspec(dllexport) int lib_counter;
__declspec(dllexport) const char *lib_greeting;
__declspec(dllexport) int lib_call_back(int (*fn)(int), int value);
__declspec(dllexport) double lib_scale(double x);

int printf(const char *fmt, ...);

/* A pointer initialised to another global's address: the loader has to relocate
   it, and getting that wrong shows up as a garbage string. */
static const char kGreeting[] = "greetings from the dll";
const char *lib_greeting = kGreeting;
int lib_counter = 100;

int lib_add(int a, int b) { return a + b; }
const char *lib_name(void) { return "testlib"; }
int lib_call_back(int (*fn)(int), int value) { return fn(value) * 2; }
double lib_scale(double x) { return x * 2.5; }

int __stdcall DllMain(void *instance, unsigned long reason, void *reserved) {
    (void)instance;
    (void)reserved;
    if (reason == 1) { /* DLL_PROCESS_ATTACH */
        lib_counter += 11;
        printf("dllmain attach, counter now %d\n", lib_counter);
    }
    return 1;
}
