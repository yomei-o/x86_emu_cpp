// Exceptions through a mingw-w64 toolchain, which on x86-64 uses the same SEH
// machinery Microsoft's does - the unwind tables in .pdata and a language
// handler of its own - so this checks the emulator's unwinder against a second,
// independent implementation of the language half.
#include <cstdio>
#include <stdexcept>
#include <string>

struct Noisy {
    const char* name;
    explicit Noisy(const char* n) : name(n) { std::printf("construct %s\n", name); }
    ~Noisy() { std::printf("destroy %s\n", name); }
};

static int depth_three() {
    Noisy inner("inner");
    throw std::runtime_error("from depth three");
}

static int depth_two() {
    Noisy middle("middle");
    return depth_three();
}

static int depth_one() {
    Noisy outer("outer");
    return depth_two();
}

int main() {
    try {
        depth_one();
    } catch (const std::exception& e) {
        std::printf("caught: %s\n", e.what());
    }

    // A second throw, caught by type, with the object copied out.
    try {
        throw std::string("a string by value");
    } catch (const std::string& s) {
        std::printf("caught string: %s\n", s.c_str());
    }

    // Rethrow from a nested handler.
    try {
        try {
            throw 7;
        } catch (int v) {
            std::printf("inner caught %d, rethrowing\n", v);
            throw;
        }
    } catch (int v) {
        std::printf("outer caught %d\n", v);
    }

    // An exception that no handler matches by type, caught by the catch-all.
    try {
        throw 3.5;
    } catch (const char*) {
        std::printf("wrong handler\n");
    } catch (...) {
        std::printf("caught by ellipsis\n");
    }
    std::printf("done\n");
    return 0;
}
