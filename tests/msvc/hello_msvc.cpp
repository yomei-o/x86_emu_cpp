// An ordinary C++ program built by a normal Visual Studio toolchain: the CRT
// startup runs before main, so this exercises far more of the Windows surface
// than the freestanding tests do.
#include <cstdio>

int main() {
    printf("hello\n");
    printf("%d %s %c %05.2f\n", 42, "world", '!', 3.14159);
    return 0;
}
