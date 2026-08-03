// Idiomatic C++ rather than C: iostreams, containers, static constructors and
// exceptions.  This is what a "hello world in C++" actually drags in, and it
// reaches parts of a C runtime that printf never touches.
#include <algorithm>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

// A namespace-scope object with a constructor: it runs before main, through the
// initialiser table the CRT walks.
struct Banner {
    Banner() { std::cout << "static constructor ran\n"; }
    ~Banner() { std::cout << "static destructor ran\n"; }
};
static Banner banner;

int main() {
    std::cout << "hello from C++\n";

    std::string s = "abc";
    s += "def";
    std::cout << "string: " << s << " (" << s.size() << ")\n";

    std::vector<int> v{5, 3, 9, 1, 7};
    std::sort(v.begin(), v.end());
    std::cout << "sorted:";
    for (int x : v) std::cout << ' ' << x;
    std::cout << '\n';

    std::map<std::string, int> m{{"one", 1}, {"two", 2}, {"three", 3}};
    for (const auto& [k, val] : m) std::cout << "  " << k << " => " << val << '\n';

    std::cout << "float: " << 3.14159 << " " << 1.0 / 3.0 << '\n';

    // Throwing is deliberately left out: it needs a real unwinder, which the
    // emulator does not have.  tests/msvc/exc_msvc.cpp covers that separately so
    // this file can keep passing.
    return 0;
}
