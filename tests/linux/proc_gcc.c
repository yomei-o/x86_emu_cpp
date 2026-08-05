// fork + pipe + execve + waitpid, self-contained: run with "child" to be the
// child, so the test needs no second binary.
//
// The recorded expectation in tests/expected/ is written by hand rather than
// captured from a reference run, because there is no reference available on this
// host: WSL here is aarch64, and qemu-user cannot execve() an x86-64 image (the
// host kernel rejects it), which is precisely the call this test is about.  What
// the output must be is not in doubt - the child's getpid()/getppid() are both
// positive, it exits 42, and the parent reads its bytes through the pipe.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        printf("child pid=%d ppid ok=%d\n", getpid() > 0, getppid() > 0);
        fflush(stdout);
        return 42;
    }
    int fds[2];
    if (pipe(fds) != 0) { printf("pipe failed\n"); return 1; }
    pid_t pid = fork();
    if (pid < 0) { printf("fork failed\n"); return 1; }
    if (pid == 0) {
        dup2(fds[1], 1);
        close(fds[0]);
        close(fds[1]);
        char* args[] = {argv[0], "child", NULL};
        execv(argv[0], args);
        fprintf(stderr, "exec failed\n");
        _exit(127);
    }
    close(fds[1]);
    char buf[256];
    int total = 0, n;
    while ((n = read(fds[0], buf + total, sizeof buf - 1 - total)) > 0) total += n;
    buf[total] = 0;
    printf("parent got: %s", buf);
    int status = 0;
    waitpid(pid, &status, 0);
    printf("child exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    printf("parent done\n");
    return 0;
}
