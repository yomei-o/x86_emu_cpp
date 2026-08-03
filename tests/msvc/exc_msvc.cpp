// C++ exceptions, which the emulator does not support yet: throwing needs a real
// unwinder walking the .pdata/.xdata tables (x64) or the SEH chain (x86).
//
// Kept as its own file so that the rest of the C++ coverage can pass, and so the
// day unwinding lands there is already a test for it.  Excluded from the default
// run by tests/run_tests.sh.
#include <iostream>
#include <stdexcept>

int main() {
    try {
        throw std::runtime_error("thrown and caught");
    } catch (const std::exception& e) {
        std::cout << "caught: " << e.what() << '\n';
    }
    try {
        throw 42;
    } catch (int v) {
        std::cout << "caught int: " << v << '\n';
    }
    return 0;
}
