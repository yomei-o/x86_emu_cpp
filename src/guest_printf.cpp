// The printf engine and the string conversions the stdio hooks share.
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "guest_printf.h"

namespace x86emu {
namespace {

int64_t sign_extend(uint64_t v, int bytes) {
    switch (bytes) {
        case 1: return static_cast<int8_t>(v);
        case 2: return static_cast<int16_t>(v);
        case 4: return static_cast<int32_t>(v);
        default: return static_cast<int64_t>(v);
    }
}

// Rewrites the exponent of a formatted %e/%g result to a fixed minimum number of
// digits.  Two things make this necessary: the old msvcrt prints three digits
// where C99 prints two, and host C runtimes do not all agree either - doing it
// here keeps guest output identical whatever the emulator was built with.
void normalise_exponent(std::string& s, int min_digits) {
    size_t e = s.find_last_of("eE");
    if (e == std::string::npos || e + 2 >= s.size()) return;
    size_t p = e + 1;
    if (s[p] == '+' || s[p] == '-') ++p;
    size_t start = p;
    while (p < s.size() && s[p] >= '0' && s[p] <= '9') ++p;
    if (p == start) return;

    std::string digits = s.substr(start, p - start);
    // Strip leading zeroes, then pad back up to the requested width.
    size_t first = digits.find_first_not_of('0');
    digits = first == std::string::npos ? "0" : digits.substr(first);
    while (static_cast<int>(digits.size()) < min_digits) digits.insert(digits.begin(), '0');
    s.replace(start, p - start, digits);
}

std::string pad(const std::string& s, int width, bool left_align) {
    if (width <= 0 || static_cast<int>(s.size()) >= width) return s;
    std::string fill(static_cast<size_t>(width) - s.size(), ' ');
    return left_align ? s + fill : fill + s;
}

// Formats a guest format string, pulling the variadic arguments through `va`.
// Conversions are handed to the host's snprintf so that padding, precision and
// rounding match a real libc.
}  // namespace

std::string format_guest(Emulator& e, uint64_t fmt_ptr, Emulator::Args& va, bool wide) {
    if (fmt_ptr == 0) return "(null)";
    const std::string fmt = wide ? utf16_to_utf8(e, fmt_ptr, -1) : e.mem.read_cstring(fmt_ptr);
    // In the wide family %s is a wchar_t* and %hs is a char*; in the narrow one
    // it is the other way round.  `wide_string` tracks which this conversion is.
    bool default_wide_strings = wide;
    std::string out;

    size_t i = 0;
    while (i < fmt.size()) {
        if (fmt[i] != '%') {
            out += fmt[i++];
            continue;
        }
        ++i;
        if (i < fmt.size() && fmt[i] == '%') {
            out += '%';
            ++i;
            continue;
        }

        std::string flags;
        while (i < fmt.size() && std::strchr("-+ #0", fmt[i])) {
            flags += fmt[i++];
        }

        bool has_width = false;
        int width = 0;
        if (i < fmt.size() && fmt[i] == '*') {
            ++i;
            width = static_cast<int>(sign_extend(va.next_int(4), 4));
            has_width = true;
            if (width < 0) {  // a negative * width means left alignment
                flags += '-';
                width = -width;
            }
        } else {
            std::string digits;
            while (i < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[i])))
                digits += fmt[i++];
            if (!digits.empty()) {
                width = std::atoi(digits.c_str());
                has_width = true;
            }
        }

        bool has_prec = false;
        int prec = 0;
        if (i < fmt.size() && fmt[i] == '.') {
            ++i;
            has_prec = true;
            if (i < fmt.size() && fmt[i] == '*') {
                ++i;
                prec = static_cast<int>(sign_extend(va.next_int(4), 4));
                if (prec < 0) has_prec = false;
            } else {
                std::string digits;
                while (i < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[i])))
                    digits += fmt[i++];
                prec = digits.empty() ? 0 : std::atoi(digits.c_str());
            }
        }

        // Length modifiers.  `long` is 4 bytes everywhere except 64-bit Linux.
        int int_bytes = 4;
        bool wide_string = default_wide_strings;
        for (bool more = true; more && i < fmt.size();) {
            if (fmt.compare(i, 2, "hh") == 0) {
                i += 2;
            } else if (fmt.compare(i, 2, "ll") == 0) {
                i += 2;
                int_bytes = 8;
            } else if (fmt.compare(i, 3, "I64") == 0) {
                i += 3;
                int_bytes = 8;
            } else if (fmt.compare(i, 3, "I32") == 0) {
                i += 3;
                int_bytes = 4;
            } else if (fmt[i] == 'h') {
                ++i;
                wide_string = false;  // %hs is narrow even in a wide format
            } else if (fmt[i] == 'l' || fmt[i] == 'w') {
                ++i;
                wide_string = true;   // %ls and %ws are wide even in a narrow one
                int_bytes = (e.is64() && e.os() == Os::Linux) ? 8 : 4;
            } else if (fmt[i] == 'j' || fmt[i] == 'z' || fmt[i] == 't' || fmt[i] == 'I') {
                ++i;
                int_bytes = e.pointer_size();
            } else if (fmt[i] == 'L' || fmt[i] == 'q') {
                ++i;
                int_bytes = 8;
            } else {
                more = false;
            }
        }
        if (i >= fmt.size()) break;
        char conv = fmt[i++];

        // Rebuilds the conversion spec for the host, forcing a `ll` length so
        // that one code path covers every guest integer width.
        auto host_spec = [&](const char* length, char cv) {
            std::string s = "%" + flags;
            if (has_width) s += std::to_string(width);
            if (has_prec) s += "." + std::to_string(prec);
            s += length;
            s += cv;
            return s;
        };
        std::vector<char> buf(static_cast<size_t>(64 + (has_width ? width : 0) +
                                                  (has_prec ? prec : 0)));

        switch (conv) {
            case 'd':
            case 'i': {
                long long v = static_cast<long long>(sign_extend(va.next_int(int_bytes), int_bytes));
                std::snprintf(buf.data(), buf.size(), host_spec("ll", 'd').c_str(), v);
                out += buf.data();
                break;
            }
            case 'u':
            case 'o':
            case 'x':
            case 'X': {
                unsigned long long v = va.next_int(int_bytes);
                if (int_bytes == 4) v &= 0xFFFFFFFFull;
                std::snprintf(buf.data(), buf.size(), host_spec("ll", conv).c_str(), v);
                out += buf.data();
                break;
            }
            case 'c': {
                uint32_t code = static_cast<uint32_t>(va.next_int(4));
                std::string ch;
                if (wide_string && code > 0x7F) {
                    // A wide character has to come back as UTF-8, not one byte.
                    std::u16string one(1, static_cast<char16_t>(code));
                    for (char16_t u : one) {
                        if (u < 0x80) {
                            ch += static_cast<char>(u);
                        } else if (u < 0x800) {
                            ch += static_cast<char>(0xC0 | (u >> 6));
                            ch += static_cast<char>(0x80 | (u & 0x3F));
                        } else {
                            ch += static_cast<char>(0xE0 | (u >> 12));
                            ch += static_cast<char>(0x80 | ((u >> 6) & 0x3F));
                            ch += static_cast<char>(0x80 | (u & 0x3F));
                        }
                    }
                } else {
                    ch = std::string(1, static_cast<char>(code));
                }
                out += pad(ch, has_width ? width : 0, flags.find('-') != std::string::npos);
                break;
            }
            case 's': {
                uint64_t p = va.next_ptr();
                std::string s = !p ? std::string("(null)")
                              : wide_string ? utf16_to_utf8(e, p, -1)
                                            : e.mem.read_cstring(p);
                if (has_prec && static_cast<int>(s.size()) > prec)
                    s.resize(static_cast<size_t>(prec));
                out += pad(s, has_width ? width : 0, flags.find('-') != std::string::npos);
                break;
            }
            case 'p': {
                uint64_t p = va.next_ptr();
                // msvcrt prints bare uppercase hex; glibc prints 0x-prefixed.
                if (e.os() == Os::Windows)
                    std::snprintf(buf.data(), buf.size(), e.is64() ? "%016llX" : "%08llX",
                                  static_cast<unsigned long long>(p));
                else
                    std::snprintf(buf.data(), buf.size(), "0x%llx",
                                  static_cast<unsigned long long>(p));
                out += buf.data();
                break;
            }
            case 'f':
            case 'F':
            case 'e':
            case 'E':
            case 'g':
            case 'G':
            case 'a':
            case 'A': {
                double d = va.next_double();
                buf.resize(buf.size() + 512);  // %f of a huge value is long
                bool has_exponent = conv != 'f' && conv != 'F';
                if (!has_exponent) {
                    std::snprintf(buf.data(), buf.size(), host_spec("", conv).c_str(), d);
                    out += buf.data();
                    break;
                }
                // Rewriting the exponent changes the length, so the field width
                // has to be applied afterwards rather than by the host.
                int saved_width = width;
                bool saved_has_width = has_width;
                has_width = false;
                std::snprintf(buf.data(), buf.size(), host_spec("", conv).c_str(), d);
                has_width = saved_has_width;
                width = saved_width;

                std::string text = buf.data();
                normalise_exponent(text, e.three_digit_exponents() ? 3 : 2);
                if (has_width && static_cast<int>(text.size()) < width) {
                    bool left = flags.find('-') != std::string::npos;
                    if (!left && flags.find('0') != std::string::npos) {
                        // Zero padding goes after the sign, not before it.
                        size_t at = (!text.empty() && (text[0] == '-' || text[0] == '+')) ? 1 : 0;
                        text.insert(at, static_cast<size_t>(width) - text.size(), '0');
                    } else {
                        text = pad(text, width, left);
                    }
                }
                out += text;
                break;
            }
            case 'n': {
                uint64_t p = va.next_ptr();
                if (p) e.mem.write32(p, static_cast<uint32_t>(out.size()));
                break;
            }
            default:
                // Unknown conversion: reproduce it literally, like most libcs.
                out += '%';
                out += conv;
                break;
        }
    }
    return out;
}



// ---------------------------------------------------------------------------
// UTF-16 <-> UTF-8, for the wide Win32 entry points.  Surrogate pairs are
// decoded, but nothing beyond that: the guests we care about print ASCII, and a
// wrong answer here would be a silently mangled string rather than a crash.
// ---------------------------------------------------------------------------

std::string utf16_to_utf8(Emulator& e, uint64_t ptr, int units) {
    std::string out;
    if (!ptr) return out;
    for (int i = 0; units < 0 || i < units; ++i) {
        uint32_t c = e.mem.read16(ptr + static_cast<uint64_t>(i) * 2);
        if (c == 0 && units < 0) break;
        if (c >= 0xD800 && c < 0xDC00) {  // high surrogate
            uint32_t lo = e.mem.read16(ptr + static_cast<uint64_t>(i + 1) * 2);
            if (lo >= 0xDC00 && lo < 0xE000) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            }
        }
        if (c < 0x80) {
            out += static_cast<char>(c);
        } else if (c < 0x800) {
            out += static_cast<char>(0xC0 | (c >> 6));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            out += static_cast<char>(0xE0 | (c >> 12));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (c >> 18));
            out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        }
    }
    return out;
}

std::string utf16_string_to_utf8(const std::u16string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        uint32_t c = s[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < s.size() &&
            s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000)
            c = 0x10000 + ((c - 0xD800) << 10) + (s[++i] - 0xDC00);
        if (c < 0x80) {
            out += static_cast<char>(c);
        } else if (c < 0x800) {
            out += static_cast<char>(0xC0 | (c >> 6));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            out += static_cast<char>(0xE0 | (c >> 12));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (c >> 18));
            out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        }
    }
    return out;
}

std::u16string utf8_to_utf16(const std::string& s) {
    std::u16string out;
    size_t i = 0;
    while (i < s.size()) {
        auto b = static_cast<unsigned char>(s[i]);
        uint32_t c;
        int extra;
        if (b < 0x80) { c = b; extra = 0; }
        else if ((b & 0xE0) == 0xC0) { c = b & 0x1F; extra = 1; }
        else if ((b & 0xF0) == 0xE0) { c = b & 0x0F; extra = 2; }
        else if ((b & 0xF8) == 0xF0) { c = b & 0x07; extra = 3; }
        else { c = 0xFFFD; extra = 0; }
        ++i;
        for (int k = 0; k < extra && i < s.size(); ++k, ++i)
            c = (c << 6) | (static_cast<unsigned char>(s[i]) & 0x3F);
        if (c >= 0x10000) {
            c -= 0x10000;
            out += static_cast<char16_t>(0xD800 + (c >> 10));
            out += static_cast<char16_t>(0xDC00 + (c & 0x3FF));
        } else {
            out += static_cast<char16_t>(c);
        }
    }
    return out;
}

}  // namespace x86emu
