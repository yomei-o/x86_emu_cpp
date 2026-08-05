// The rest of the C runtime: locale, errno, character classification, the wide
// string family, conversions, sorting and time.
//
// None of it is interesting individually - each is a few lines over the host's
// own libc - but a real language runtime touches most of it during startup, so
// the breadth is the point.
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "emulator.h"
#include "guest_printf.h"

namespace x86emu {
namespace {

// Reads a NUL-terminated UTF-16 string from the guest.
std::u16string read_wide(Emulator& e, uint64_t ptr, int64_t max_units = -1) {
    std::u16string s;
    if (!ptr) return s;
    for (int64_t i = 0; max_units < 0 || i < max_units; ++i) {
        uint16_t c = e.mem.read16(ptr + static_cast<uint64_t>(i) * 2);
        if (!c) break;
        s += static_cast<char16_t>(c);
    }
    return s;
}

void write_wide(Emulator& e, uint64_t ptr, const std::u16string& s) {
    for (size_t i = 0; i < s.size(); ++i) e.mem.write16(ptr + i * 2, s[i]);
    e.mem.write16(ptr + s.size() * 2, 0);
}

int compare_sign(int v) { return v < 0 ? -1 : (v > 0 ? 1 : 0); }

}  // namespace

void Emulator::install_libc_hooks() {
    auto libc = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };
    auto libc2 = [&](const char* name, std::function<void(Emulator&)> fn) {
        libc(name, fn);
        libc(("_" + std::string(name)).c_str(), fn);
    };

    // ---- errno ---------------------------------------------------------------
    // errno is a variable, so what a guest calls is a function returning its
    // address.  One shared slot is right: there is one thread.
    libc("_errno", [](Emulator& e) { e.set_result(e.errno_address()); });
    libc("__errno_location", [](Emulator& e) { e.set_result(e.errno_address()); });
    libc("__doserrno", [](Emulator& e) { e.set_result(e.errno_address()); });
    libc("_set_errno", [](Emulator& e) {
        e.set_guest_errno(static_cast<int>(e.arg_slot(0)));
        e.set_result(0);
    });
    libc("_get_errno", [](Emulator& e) {
        if (e.arg_slot(0)) e.mem.write32(e.arg_slot(0), e.mem.read32(e.errno_address()));
        e.set_result(0);
    });
    libc("strerror", [](Emulator& e) {
        e.set_result(e.alloc_guest_string(std::strerror(static_cast<int>(e.arg_slot(0)))));
    });
    libc("perror", [](Emulator& e) {
        std::string prefix = e.arg_slot(0) ? e.mem.read_cstring(e.arg_slot(0)) : "";
        e.write_text(2, prefix.empty() ? "error\n" : prefix + ": error\n");
        e.set_result(0);
    });

    // ---- locale ---------------------------------------------------------------
    // Only the "C" locale exists here, which is what a guest gets if it asks for
    // anything else and does not check.
    libc("setlocale", [](Emulator& e) { e.set_result(e.alloc_guest_string("C")); });
    libc("_wsetlocale", [](Emulator& e) {
        const uint8_t c_locale[4] = {'C', 0, 0, 0};
        e.set_result(e.alloc_guest_data(c_locale, sizeof c_locale));
    });
    // These hand out a `_locale_t`, and there is nothing honest to hand out: it
    // points at the UCRT's own `__crt_locale_data`, whose layout a C++ runtime
    // reads *directly* rather than through functions, so inventing one would mean
    // committing to an undocumented structure.  NULL is the closest available
    // answer - "no locale could be made" - and a guest that does not check it
    // will fault on the NULL later, which the log line is there to explain.
    auto no_locale = [](Emulator& e) {
        e.log_call("a _locale_t was asked for; NULL is the only honest answer, and a "
                   "guest that stores it without checking will fault on it later");
        e.set_result(0);
    };
    libc("_create_locale", no_locale);
    libc("_wcreate_locale", no_locale);
    libc("_get_current_locale", no_locale);
    libc("_free_locale", [](Emulator& e) { e.set_result(0); });
    libc("localeconv", [this](Emulator& e) {
        // struct lconv, with the C locale's values: "." for the decimal point and
        // empty strings everywhere else.
        if (!lconv_address_) {
            int ps = e.pointer_size();
            uint64_t dot = e.alloc_guest_string(".");
            uint64_t empty = e.alloc_guest_string("");
            std::vector<uint8_t> block(static_cast<size_t>(ps) * 16 + 16, 0);
            lconv_address_ = e.alloc_guest_data(block.data(), block.size());
            // The first three members are decimal_point, thousands_sep, grouping.
            e.mem.write_sized(lconv_address_, ps, dot);
            e.mem.write_sized(lconv_address_ + ps, ps, empty);
            e.mem.write_sized(lconv_address_ + ps * 2, ps, empty);
            for (int i = 3; i < 16; ++i)
                e.mem.write_sized(lconv_address_ + ps * i, ps, empty);
        }
        e.set_result(lconv_address_);
    });

    // ---- character classification ---------------------------------------------
    auto classify = [&](const char* name, int (*fn)(int)) {
        libc(name, [fn](Emulator& e) {
            int c = static_cast<int>(static_cast<int32_t>(e.arg_slot(0)));
            // The C functions are only defined for EOF and unsigned char values.
            e.set_result(c >= -1 && c < 256 ? static_cast<uint64_t>(fn(c)) : 0);
        });
    };
    classify("isalpha", [](int c) { return std::isalpha(c) ? 1 : 0; });
    classify("isdigit", [](int c) { return std::isdigit(c) ? 1 : 0; });
    classify("isalnum", [](int c) { return std::isalnum(c) ? 1 : 0; });
    classify("isspace", [](int c) { return std::isspace(c) ? 1 : 0; });
    classify("isupper", [](int c) { return std::isupper(c) ? 1 : 0; });
    classify("islower", [](int c) { return std::islower(c) ? 1 : 0; });
    classify("ispunct", [](int c) { return std::ispunct(c) ? 1 : 0; });
    classify("isxdigit", [](int c) { return std::isxdigit(c) ? 1 : 0; });
    classify("isprint", [](int c) { return std::isprint(c) ? 1 : 0; });
    classify("iscntrl", [](int c) { return std::iscntrl(c) ? 1 : 0; });
    classify("isgraph", [](int c) { return std::isgraph(c) ? 1 : 0; });
    classify("toupper", [](int c) { return std::toupper(c); });
    classify("tolower", [](int c) { return std::tolower(c); });
    classify("_toupper", [](int c) { return std::toupper(c); });
    classify("_tolower", [](int c) { return std::tolower(c); });

    // ---- narrow strings ---------------------------------------------------------
    libc("strncat", [](Emulator& e) {
        uint64_t dst = e.arg_slot(0);
        std::string a = e.mem.read_cstring(dst), b = e.mem.read_cstring(e.arg_slot(1));
        uint64_t n = e.arg_slot(2);
        if (b.size() > n) b.resize(static_cast<size_t>(n));
        e.mem.write_cstring(dst, a + b);
        e.set_result(dst);
    });
    libc("strrchr", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        std::string s = e.mem.read_cstring(p);
        char c = static_cast<char>(e.arg_slot(1));
        // As with strchr, searching for the terminator finds it.
        size_t pos = c ? s.rfind(c) : s.size();
        e.set_result(pos == std::string::npos ? 0 : p + pos);
    });
    libc("memchr", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        uint8_t c = static_cast<uint8_t>(e.arg_slot(1));
        uint64_t n = e.arg_slot(2);
        for (uint64_t i = 0; i < n; ++i)
            if (e.mem.read8(p + i) == c) {
                e.set_result(p + i);
                return;
            }
        e.set_result(0);
    });
    libc("strcspn", [](Emulator& e) {
        std::string s = e.mem.read_cstring(e.arg_slot(0));
        std::string reject = e.mem.read_cstring(e.arg_slot(1));
        size_t pos = s.find_first_of(reject);
        e.set_result(pos == std::string::npos ? s.size() : pos);
    });
    libc("strspn", [](Emulator& e) {
        std::string s = e.mem.read_cstring(e.arg_slot(0));
        std::string accept = e.mem.read_cstring(e.arg_slot(1));
        size_t pos = s.find_first_not_of(accept);
        e.set_result(pos == std::string::npos ? s.size() : pos);
    });
    libc("strpbrk", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        std::string s = e.mem.read_cstring(p);
        size_t pos = s.find_first_of(e.mem.read_cstring(e.arg_slot(1)));
        e.set_result(pos == std::string::npos ? 0 : p + pos);
    });
    libc2("strdup", [](Emulator& e) {
        std::string s = e.mem.read_cstring(e.arg_slot(0));
        uint64_t p = e.heap_alloc(s.size() + 1);
        if (p) e.mem.write_cstring(p, s);
        e.set_result(p);
    });
    libc("strcoll", [](Emulator& e) {
        std::string a = e.mem.read_cstring(e.arg_slot(0)), b = e.mem.read_cstring(e.arg_slot(1));
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(compare_sign(a.compare(b)))));
    });
    auto case_insensitive_compare = [](Emulator& e, bool bounded) {
        std::string a = e.mem.read_cstring(e.arg_slot(0)), b = e.mem.read_cstring(e.arg_slot(1));
        size_t n = bounded ? static_cast<size_t>(e.arg_slot(2)) : std::string::npos;
        for (size_t i = 0; i < n; ++i) {
            int ca = i < a.size() ? std::tolower(static_cast<unsigned char>(a[i])) : 0;
            int cb = i < b.size() ? std::tolower(static_cast<unsigned char>(b[i])) : 0;
            if (ca != cb) {
                e.set_result(static_cast<uint64_t>(static_cast<int64_t>(ca < cb ? -1 : 1)));
                return;
            }
            if (!ca) break;
        }
        e.set_result(0);
    };
    libc("_stricmp", [case_insensitive_compare](Emulator& e) { case_insensitive_compare(e, false); });
    libc("strcasecmp", [case_insensitive_compare](Emulator& e) { case_insensitive_compare(e, false); });
    libc("_strnicmp", [case_insensitive_compare](Emulator& e) { case_insensitive_compare(e, true); });
    libc("strncasecmp", [case_insensitive_compare](Emulator& e) { case_insensitive_compare(e, true); });

    // ---- wide strings -----------------------------------------------------------
    libc("wcslen", [](Emulator& e) {
        size_t n = read_wide(e, e.arg_slot(0)).size();
        e.log_call("wcslen(0x%llX) = %zu", (unsigned long long)e.arg_slot(0), n);
        e.set_result(n);
    });
    libc("wcscpy", [](Emulator& e) {
        uint64_t dst = e.arg_slot(0);
        write_wide(e, dst, read_wide(e, e.arg_slot(1)));
        e.set_result(dst);
    });
    libc("wcsncpy", [](Emulator& e) {
        uint64_t dst = e.arg_slot(0);
        std::u16string s = read_wide(e, e.arg_slot(1));
        uint64_t n = e.arg_slot(2);
        for (uint64_t i = 0; i < n; ++i)
            e.mem.write16(dst + i * 2, i < s.size() ? s[i] : 0);
        e.set_result(dst);
    });
    libc("wcscat", [](Emulator& e) {
        uint64_t dst = e.arg_slot(0);
        write_wide(e, dst, read_wide(e, dst) + read_wide(e, e.arg_slot(1)));
        e.set_result(dst);
    });
    libc("wcscmp", [](Emulator& e) {
        std::u16string a = read_wide(e, e.arg_slot(0)), b = read_wide(e, e.arg_slot(1));
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(compare_sign(a.compare(b)))));
    });
    libc("wcsncmp", [](Emulator& e) {
        uint64_t n = e.arg_slot(2);
        std::u16string a = read_wide(e, e.arg_slot(0), static_cast<int64_t>(n));
        std::u16string b = read_wide(e, e.arg_slot(1), static_cast<int64_t>(n));
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(compare_sign(a.compare(b)))));
    });
    libc("wcschr", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        std::u16string s = read_wide(e, p);
        auto c = static_cast<char16_t>(e.arg_slot(1));
        size_t pos = c ? s.find(c) : s.size();
        e.set_result(pos == std::u16string::npos ? 0 : p + pos * 2);
    });
    libc("wcsrchr", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        std::u16string s = read_wide(e, p);
        auto c = static_cast<char16_t>(e.arg_slot(1));
        size_t pos = c ? s.rfind(c) : s.size();
        e.set_result(pos == std::u16string::npos ? 0 : p + pos * 2);
    });
    libc("wcsstr", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        std::u16string s = read_wide(e, p), t = read_wide(e, e.arg_slot(1));
        size_t pos = s.find(t);
        e.set_result(pos == std::u16string::npos ? 0 : p + pos * 2);
    });
    libc2("wcsdup", [](Emulator& e) {
        std::u16string s = read_wide(e, e.arg_slot(0));
        uint64_t p = e.heap_alloc((s.size() + 1) * 2);
        if (p) write_wide(e, p, s);
        e.set_result(p);
    });
    libc("_wcsicmp", [](Emulator& e) {
        std::u16string a = read_wide(e, e.arg_slot(0)), b = read_wide(e, e.arg_slot(1));
        for (size_t i = 0;; ++i) {
            char16_t ca = i < a.size() ? a[i] : 0, cb = i < b.size() ? b[i] : 0;
            if (ca < 128) ca = static_cast<char16_t>(std::tolower(ca));
            if (cb < 128) cb = static_cast<char16_t>(std::tolower(cb));
            if (ca != cb) {
                e.set_result(static_cast<uint64_t>(static_cast<int64_t>(ca < cb ? -1 : 1)));
                return;
            }
            if (!ca) break;
        }
        e.set_result(0);
    });

    // ---- conversions --------------------------------------------------------------
    libc("atol", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(
            static_cast<int64_t>(std::atol(e.mem.read_cstring(e.arg_slot(0)).c_str()))));
    });
    libc2("atoi64", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(
            std::strtoll(e.mem.read_cstring(e.arg_slot(0)).c_str(), nullptr, 10)));
    });
    // strtol and friends must report where they stopped, which means finding the
    // end pointer in the guest's own string rather than the host copy.
    auto string_to_integer = [](Emulator& e, bool is_signed, int bytes) {
        uint64_t start = e.arg_slot(0);
        std::string s = e.mem.read_cstring(start);
        uint64_t end_out = e.arg_slot(1);
        int radix = static_cast<int>(static_cast<int32_t>(e.arg_slot(2)));
        const char* begin = s.c_str();
        char* end = nullptr;
        uint64_t value;
        if (is_signed)
            value = static_cast<uint64_t>(std::strtoll(begin, &end, radix));
        else
            value = std::strtoull(begin, &end, radix);
        if (end_out)
            e.mem.write_sized(end_out, e.pointer_size(),
                              start + static_cast<uint64_t>(end - begin));
        if (bytes == 4)
            value = is_signed ? static_cast<uint64_t>(static_cast<int64_t>(
                                    static_cast<int32_t>(value)))
                              : (value & 0xFFFFFFFFull);
        e.set_result(value);
    };
    libc("strtol", [string_to_integer](Emulator& e) { string_to_integer(e, true, 4); });
    libc("strtoul", [string_to_integer](Emulator& e) { string_to_integer(e, false, 4); });
    libc("strtoll", [string_to_integer](Emulator& e) { string_to_integer(e, true, 8); });
    libc("strtoull", [string_to_integer](Emulator& e) { string_to_integer(e, false, 8); });
    libc("_strtoi64", [string_to_integer](Emulator& e) { string_to_integer(e, true, 8); });
    libc("_strtoui64", [string_to_integer](Emulator& e) { string_to_integer(e, false, 8); });
    libc("strtod", [](Emulator& e) {
        uint64_t start = e.arg_slot(0);
        std::string s = e.mem.read_cstring(start);
        char* end = nullptr;
        double v = std::strtod(s.c_str(), &end);
        if (e.arg_slot(1))
            e.mem.write_sized(e.arg_slot(1), e.pointer_size(),
                              start + static_cast<uint64_t>(end - s.c_str()));
        e.set_result_double(v);
    });
    libc("atof", [](Emulator& e) {
        e.set_result_double(std::atof(e.mem.read_cstring(e.arg_slot(0)).c_str()));
    });
    libc("abs", [](Emulator& e) {
        int32_t v = static_cast<int32_t>(e.arg_slot(0));
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(v < 0 ? -v : v)));
    });
    libc("labs", [](Emulator& e) {
        int32_t v = static_cast<int32_t>(e.arg_slot(0));
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(v < 0 ? -v : v)));
    });
    libc("llabs", [](Emulator& e) {
        Args a(e);
        int64_t v = static_cast<int64_t>(a.next_int(8));
        e.set_result(static_cast<uint64_t>(v < 0 ? -v : v));
    });
    libc("mbstowcs", [](Emulator& e) {
        std::string s = e.mem.read_cstring(e.arg_slot(1));
        std::u16string w = utf8_to_utf16(s);
        uint64_t dst = e.arg_slot(0), n = e.arg_slot(2);
        if (!dst) {
            e.set_result(w.size());
            return;
        }
        size_t count = w.size() < n ? w.size() : static_cast<size_t>(n);
        for (size_t i = 0; i < count; ++i) e.mem.write16(dst + i * 2, w[i]);
        if (count < n) e.mem.write16(dst + count * 2, 0);
        e.set_result(count);
    });
    libc("wcstombs", [](Emulator& e) {
        std::string s = utf16_to_utf8(e, e.arg_slot(1), -1);
        uint64_t dst = e.arg_slot(0), n = e.arg_slot(2);
        if (!dst) {
            e.set_result(s.size());
            return;
        }
        size_t count = s.size() < n ? s.size() : static_cast<size_t>(n);
        if (count) e.mem.write(dst, s.data(), count);
        if (count < n) e.mem.write8(dst + count, 0);
        e.set_result(count);
    });

    // ---- sorting and searching ------------------------------------------------------
    // These take a comparison function in the guest, so the hook calls back into
    // guest code for every comparison.
    libc("qsort", [](Emulator& e) {
        uint64_t base = e.arg_slot(0), count = e.arg_slot(1), size = e.arg_slot(2);
        uint64_t compare = e.arg_slot(3);
        if (!count || !size || !compare) {
            e.set_result(0);
            return;
        }
        // Read the array out, sort it here, write it back: sorting in guest
        // memory would mean a guest call per swap as well as per comparison.
        std::vector<std::vector<uint8_t>> items;
        items.reserve(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) {
            std::vector<uint8_t> item(static_cast<size_t>(size));
            e.mem.read(base + i * size, item.data(), size);
            items.push_back(std::move(item));
        }
        uint64_t scratch_a = e.heap_alloc(size), scratch_b = e.heap_alloc(size);
        std::stable_sort(items.begin(), items.end(),
                         [&](const std::vector<uint8_t>& x, const std::vector<uint8_t>& y) {
                             e.mem.write(scratch_a, x.data(), size);
                             e.mem.write(scratch_b, y.data(), size);
                             int64_t r = static_cast<int32_t>(
                                 e.call_guest(compare, {scratch_a, scratch_b}));
                             return r < 0;
                         });
        for (uint64_t i = 0; i < count; ++i) e.mem.write(base + i * size, items[i].data(), size);
        e.heap_free(scratch_a);
        e.heap_free(scratch_b);
        e.set_result(0);
    });
    libc("bsearch", [](Emulator& e) {
        uint64_t key = e.arg_slot(0), base = e.arg_slot(1), count = e.arg_slot(2);
        uint64_t size = e.arg_slot(3), compare = e.arg_slot(4);
        uint64_t low = 0, high = count;
        while (low < high) {
            uint64_t mid = low + (high - low) / 2;
            int64_t r = static_cast<int32_t>(e.call_guest(compare, {key, base + mid * size}));
            if (r == 0) {
                e.set_result(base + mid * size);
                return;
            }
            if (r < 0)
                high = mid;
            else
                low = mid + 1;
        }
        e.set_result(0);
    });

    // ---- time -----------------------------------------------------------------------
    libc("_time64", [](Emulator& e) {
        auto now = static_cast<uint64_t>(std::time(nullptr));
        if (e.arg_slot(0)) e.mem.write64(e.arg_slot(0), now);
        e.set_result(now);
    });
    // struct tm is nine ints in the same order on every platform of interest.
    auto write_tm = [](Emulator& e, uint64_t out, const std::tm& tm) {
        const int fields[9] = {tm.tm_sec,  tm.tm_min,  tm.tm_hour,
                               tm.tm_mday, tm.tm_mon,  tm.tm_year,
                               tm.tm_wday, tm.tm_yday, tm.tm_isdst};
        for (int i = 0; i < 9; ++i)
            e.mem.write32(out + static_cast<uint64_t>(i) * 4, static_cast<uint32_t>(fields[i]));
    };
    auto convert_time = [write_tm](Emulator& e, bool local, bool has_out_param) {
        // Either (time_t*) returning a static tm, or (tm*, time_t*) returning 0.
        Args a(e);
        uint64_t out = has_out_param ? a.next_ptr() : 0;
        uint64_t time_ptr = a.next_ptr();
        std::time_t t = time_ptr ? static_cast<std::time_t>(e.mem.read64(time_ptr)) : 0;
        std::tm tm{};
#if defined(_WIN32)
        if (local)
            localtime_s(&tm, &t);
        else
            gmtime_s(&tm, &t);
#else
        if (local)
            localtime_r(&t, &tm);
        else
            gmtime_r(&t, &tm);
#endif
        if (!has_out_param) {
            std::vector<uint8_t> zeros(36, 0);
            out = e.alloc_guest_data(zeros.data(), zeros.size());
        }
        write_tm(e, out, tm);
        e.set_result(has_out_param ? 0 : out);
    };
    libc("_localtime64", [convert_time](Emulator& e) { convert_time(e, true, false); });
    libc("_gmtime64", [convert_time](Emulator& e) { convert_time(e, false, false); });
    libc("_localtime64_s", [convert_time](Emulator& e) { convert_time(e, true, true); });
    libc("_gmtime64_s", [convert_time](Emulator& e) { convert_time(e, false, true); });
    libc("localtime", [convert_time](Emulator& e) { convert_time(e, true, false); });
    libc("gmtime", [convert_time](Emulator& e) { convert_time(e, false, false); });
}

}  // namespace x86emu
