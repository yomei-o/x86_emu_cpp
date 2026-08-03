// Threads, exercising what the scheduler and the per-thread state have to get
// right: independent stacks, per-thread storage, a lock that actually excludes,
// an event one thread waits on and another sets, and joining with exit codes.
//
// Nothing is printed from a worker thread, and every ordering question is
// answered by a synchronisation object rather than by timing - so the output is
// identical every run, and can be diffed against native execution.
int printf(const char *fmt, ...);
void exit(int code);

typedef void *HANDLE;
typedef unsigned long DWORD;

HANDLE __stdcall CreateThread(void *sa, unsigned long stack,
                              DWORD(__stdcall *start)(void *), void *arg,
                              DWORD flags, DWORD *id);
DWORD __stdcall WaitForSingleObject(HANDLE h, DWORD ms);
int __stdcall CloseHandle(HANDLE h);
DWORD __stdcall GetCurrentThreadId(void);
HANDLE __stdcall CreateEventA(void *sa, int manual, int initial, const char *name);
int __stdcall SetEvent(HANDLE h);
void __stdcall InitializeCriticalSection(void *cs);
void __stdcall EnterCriticalSection(void *cs);
void __stdcall LeaveCriticalSection(void *cs);
void __stdcall Sleep(DWORD ms);
int __stdcall GetExitCodeThread(HANDLE h, DWORD *code);
DWORD __stdcall TlsAlloc(void);
void *__stdcall TlsGetValue(DWORD index);
int __stdcall TlsSetValue(DWORD index, void *value);

#define WORKERS 4
#define ITERATIONS 1000

/* A critical section is opaque; give it more room than any version needs. */
static char g_lock[128];
static int g_counter;
static HANDLE g_ready;
static int g_waiter_ran;

/* Thread-local storage through the API, so each thread must see its own value.
   (__declspec(thread) needs a CRT to set up the TLS directory, and these tests
   are deliberately freestanding.) */
static DWORD g_tls;

/* Each worker records what it observed, for the main thread to print in order. */
static int g_tls_seen[WORKERS + 1];
static int g_ids_differ = 1;
static DWORD g_main_id;

static DWORD __stdcall counter_thread(void *arg) {
    int n = (int)(long long)arg;
    int i;
    TlsSetValue(g_tls, (void *)(long long)(n * 100));

    for (i = 0; i < ITERATIONS; i++) {
        EnterCriticalSection(g_lock);
        g_counter++;
        LeaveCriticalSection(g_lock);
    }
    /* If the slot were shared, another worker's value would show up here. */
    g_tls_seen[n] = (int)(long long)TlsGetValue(g_tls);
    if (GetCurrentThreadId() == g_main_id) g_ids_differ = 0;
    return (DWORD)(n * 7);
}

static DWORD __stdcall waiter_thread(void *arg) {
    (void)arg;
    /* Blocks until the main thread signals; with a single-threaded scheduler this
       only completes if waiting really yields to the other thread. */
    WaitForSingleObject(g_ready, 0xFFFFFFFF);
    g_waiter_ran = 1;
    return 0;
}

static int run(void) {
    HANDLE threads[WORKERS];
    DWORD code;
    int i;

    InitializeCriticalSection(g_lock);
    g_main_id = GetCurrentThreadId();
    g_tls = TlsAlloc();
    TlsSetValue(g_tls, (void *)(long long)-1);

    for (i = 0; i < WORKERS; i++)
        threads[i] = CreateThread(0, 0, counter_thread, (void *)(long long)(i + 1), 0, 0);
    for (i = 0; i < WORKERS; i++) {
        WaitForSingleObject(threads[i], 0xFFFFFFFF);
        code = 0;
        GetExitCodeThread(threads[i], &code);
        printf("joined %d exit %lu tls %d\n", i + 1, (unsigned long)code, g_tls_seen[i + 1]);
        CloseHandle(threads[i]);
    }
    printf("counter %d (expected %d)\n", g_counter, WORKERS * ITERATIONS);
    printf("main tls %d\n", (int)(long long)TlsGetValue(g_tls));
    printf("thread ids distinct: %d\n", g_ids_differ);

    g_ready = CreateEventA(0, 1, 0, 0);
    HANDLE w = CreateThread(0, 0, waiter_thread, 0, 0, 0);
    Sleep(1); /* let the waiter reach its wait */
    SetEvent(g_ready);
    WaitForSingleObject(w, 0xFFFFFFFF);
    CloseHandle(w);
    printf("waiter woken: %d\n", g_waiter_ran);

    printf("threads ok\n");
    return 0;
}

void start_(void) { exit(run()); }
