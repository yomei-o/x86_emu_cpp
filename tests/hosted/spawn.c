// Exercises CreateProcess + CreatePipe: run as parent (no args) it spawns
// itself twice - once capturing the child's stdout through a pipe, once letting
// it inherit the console - then reports the exit codes.
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        // The pid itself cannot be printed: it differs between a native run and
        // an emulated one, and this test is checked by diffing the two.  That it
        // is *some* distinct process is what matters.
        printf("child says: hello, my pid differs from 0: %d\n",
               GetCurrentProcessId() != 0);
        // Both streams reach the same pipe, and stdout is block-buffered there
        // while stderr is not; flushing makes the order of the two lines the
        // child's choice rather than the C runtime's.
        fflush(stdout);
        fprintf(stderr, "child stderr line\n");
        return 42;
    }
    if (argc > 1 && strcmp(argv[1], "echo") == 0) {
        // Copy stdin to stdout, proving the child can read a pipe.
        char buf[128];
        DWORD got = 0;
        HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
        while (ReadFile(in, buf, sizeof buf, &got, NULL) && got > 0) {
            fwrite(buf, 1, got, stdout);
        }
        return 7;
    }

    // ---- child with stdout captured by a pipe ----
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE rd, wr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        printf("CreatePipe failed\n");
        return 1;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    // Both of the child's output streams go into the pipe.  Sending its stderr
    // to the console instead would test the same redirection but leave the order
    // of the two processes' output undefined, which no diff can check.
    si.hStdOutput = wr;
    si.hStdError = wr;
    char cmd[512];
    snprintf(cmd, sizeof cmd, "\"%s\" child", argv[0]);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed, error %lu\n", GetLastError());
        return 1;
    }
    CloseHandle(wr);  // or the read below never sees EOF
    // Nothing is printed until the child has finished.  Interleaving two
    // processes' output is not something either a real OS or a cooperative
    // scheduler promises, so a test that diffs the two must not depend on it.
    char collected[1024];
    size_t total = 0;
    char buf[256];
    DWORD got = 0;
    while (total < sizeof collected - 1 &&
           ReadFile(rd, buf, sizeof buf - 1, &got, NULL) && got > 0) {
        if (got > sizeof collected - 1 - total) got = (DWORD)(sizeof collected - 1 - total);
        memcpy(collected + total, buf, got);
        total += got;
    }
    collected[total] = 0;
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    printf("parent got: %s", collected);
    printf("child exited with %lu\n", code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // ---- child reading a pipe on stdin ----
    HANDLE in_rd, in_wr;
    CreatePipe(&in_rd, &in_wr, &sa, 0);
    SetHandleInformation(in_wr, HANDLE_FLAG_INHERIT, 0);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_rd;
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    snprintf(cmd, sizeof cmd, "\"%s\" echo", argv[0]);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess(echo) failed, error %lu\n", GetLastError());
        return 1;
    }
    DWORD put = 0;
    WriteFile(in_wr, "pipe payload\n", 13, &put, NULL);
    CloseHandle(in_wr);
    CloseHandle(in_rd);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    printf("echo child exited with %lu\n", code);

    printf("parent done\n");
    return 0;
}
