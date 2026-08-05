// The scanf engine, the counterpart to guest_printf.cpp.
//
// Formatting could be delegated to the host's snprintf one conversion at a time,
// because printf's job is to turn one value into text.  Scanning cannot be:
// the interesting part is *how much of the input each conversion consumed*, and
// the host's sscanf will not tell you that without a %n the caller did not
// write.  So the scanner is here in full - which is also the only way to get
// `%[^,]`, assignment suppression and the width limits right, all of which a
// real program uses and all of which decide where the next conversion starts.
//
// Input is a string rather than a stream: the guests that need this call the
// sscanf family, and a stream would have to be able to push a character back.
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "guest_printf.h"

namespace x86emu {
namespace {

// The length modifiers, reduced to the size they ask for.  `L` and `ll` are the
// same 8 bytes here; `h` is 2 and `hh` is 1.
struct Length {
    int int_bytes = 4;
    bool long_double = false;  // a double target rather than a float one
    bool is_float_target = false;
    bool wide_target = false;
    bool narrow_target = false;
};

bool is_space(int c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }

void store_int(Emulator& e, uint64_t dst, int bytes, uint64_t value) {
    if (!dst) return;
    switch (bytes) {
        case 1: e.mem.write8(dst, static_cast<uint8_t>(value)); break;
        case 2: e.mem.write16(dst, static_cast<uint16_t>(value)); break;
        case 8: e.mem.write64(dst, value); break;
        default: e.mem.write32(dst, static_cast<uint32_t>(value)); break;
    }
}

// Writes one scanned character into the target, in whichever width the
// conversion asked for.
void store_char(Emulator& e, uint64_t dst, uint64_t index, uint32_t c, bool wide) {
    if (wide)
        e.mem.write16(dst + index * 2, static_cast<uint16_t>(c));
    else
        e.mem.write8(dst + index, static_cast<uint8_t>(c));
}

}  // namespace

int scan_guest(Emulator& e, const std::string& input, uint64_t fmt_ptr, Emulator::Args& va,
               bool wide) {
    std::string fmt = wide ? utf16_to_utf8(e, fmt_ptr, -1) : e.mem.read_cstring(fmt_ptr);
    size_t in = 0;          // cursor into the input
    size_t assigned = 0;    // what the return value counts
    bool any_conversion = false;

    for (size_t f = 0; f < fmt.size(); ++f) {
        char c = fmt[f];
        if (is_space(static_cast<unsigned char>(c))) {
            // Whitespace in the format matches any amount of it, including none.
            while (in < input.size() && is_space(static_cast<unsigned char>(input[in]))) ++in;
            continue;
        }
        if (c != '%') {
            if (in >= input.size() || input[in] != c)
                return any_conversion ? static_cast<int>(assigned) : -1;
            ++in;
            continue;
        }

        ++f;
        if (f >= fmt.size()) break;
        if (fmt[f] == '%') {
            while (in < input.size() && is_space(static_cast<unsigned char>(input[in]))) ++in;
            if (in >= input.size() || input[in] != '%')
                return any_conversion ? static_cast<int>(assigned) : -1;
            ++in;
            continue;
        }

        bool suppress = false;
        if (fmt[f] == '*') {
            suppress = true;
            ++f;
        }
        size_t width = 0;
        while (f < fmt.size() && fmt[f] >= '0' && fmt[f] <= '9')
            width = width * 10 + static_cast<size_t>(fmt[f++] - '0');

        Length len;
        // A wide format's default target is wide; a narrow one's is narrow.
        len.wide_target = wide;
        for (bool more = true; more && f < fmt.size();) {
            switch (fmt[f]) {
                case 'h':
                    len.int_bytes = fmt[f + 1] == 'h' ? 1 : 2;
                    if (fmt[f + 1] == 'h') ++f;
                    len.wide_target = false;
                    ++f;
                    break;
                case 'l':
                    if (fmt[f + 1] == 'l') {
                        len.int_bytes = 8;
                        ++f;
                    } else {
                        len.int_bytes = 4;  // long is 4 bytes on both Windows ABIs
                        len.wide_target = true;
                        len.is_float_target = false;
                    }
                    len.long_double = true;
                    ++f;
                    break;
                case 'j':
                case 'z':
                case 't':
                    len.int_bytes = e.pointer_size();
                    ++f;
                    break;
                case 'L':
                    len.int_bytes = 8;
                    len.long_double = true;
                    ++f;
                    break;
                case 'I':
                    // Microsoft's I64/I32, and a bare I meaning pointer-sized.
                    if (fmt.compare(f, 3, "I64") == 0) {
                        len.int_bytes = 8;
                        f += 3;
                    } else if (fmt.compare(f, 3, "I32") == 0) {
                        len.int_bytes = 4;
                        f += 3;
                    } else {
                        len.int_bytes = e.pointer_size();
                        ++f;
                    }
                    break;
                default: more = false; break;
            }
        }
        if (f >= fmt.size()) break;
        char conv = fmt[f];

        // %c, %[ and %n are the three that do not skip leading whitespace.
        if (conv != 'c' && conv != '[' && conv != 'n')
            while (in < input.size() && is_space(static_cast<unsigned char>(input[in]))) ++in;

        uint64_t dst = suppress ? 0 : va.next_ptr();

        if (conv == 'n') {
            // Not a conversion: it reports progress and does not count towards
            // the return value.
            store_int(e, dst, len.int_bytes, in);
            continue;
        }

        if (in >= input.size()) return any_conversion ? static_cast<int>(assigned) : -1;

        switch (conv) {
            case 'd':
            case 'i':
            case 'u':
            case 'o':
            case 'x':
            case 'X':
            case 'p': {
                int base = conv == 'o' ? 8 : (conv == 'x' || conv == 'X' || conv == 'p') ? 16
                           : conv == 'i'                                                 ? 0
                                                                                         : 10;
                size_t limit = width ? std::min(input.size(), in + width) : input.size();
                std::string chunk = input.substr(in, limit - in);
                const char* begin = chunk.c_str();
                char* end = nullptr;
                bool is_signed = conv == 'd' || conv == 'i';
                uint64_t value = is_signed
                                     ? static_cast<uint64_t>(std::strtoll(begin, &end, base))
                                     : std::strtoull(begin, &end, base);
                if (end == begin) return any_conversion ? static_cast<int>(assigned) : -1;
                in += static_cast<size_t>(end - begin);
                any_conversion = true;
                if (!suppress) {
                    store_int(e, dst, conv == 'p' ? e.pointer_size() : len.int_bytes, value);
                    ++assigned;
                }
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
                size_t limit = width ? std::min(input.size(), in + width) : input.size();
                std::string chunk = input.substr(in, limit - in);
                const char* begin = chunk.c_str();
                char* end = nullptr;
                double value = std::strtod(begin, &end);
                if (end == begin) return any_conversion ? static_cast<int>(assigned) : -1;
                in += static_cast<size_t>(end - begin);
                any_conversion = true;
                if (!suppress) {
                    // `l` or `L` asks for a double; a bare conversion is a float.
                    if (len.long_double) {
                        uint64_t bits;
                        std::memcpy(&bits, &value, 8);
                        e.mem.write64(dst, bits);
                    } else {
                        float single = static_cast<float>(value);
                        uint32_t bits;
                        std::memcpy(&bits, &single, 4);
                        e.mem.write32(dst, bits);
                    }
                    ++assigned;
                }
                break;
            }
            case 'c': {
                size_t count = width ? width : 1;
                if (input.size() - in < count)
                    return any_conversion ? static_cast<int>(assigned) : -1;
                for (size_t i = 0; i < count; ++i)
                    if (!suppress)
                        store_char(e, dst, i, static_cast<unsigned char>(input[in + i]),
                                   len.wide_target);
                in += count;
                any_conversion = true;
                if (!suppress) ++assigned;
                break;
            }
            case 's': {
                size_t start = in;
                while (in < input.size() && !is_space(static_cast<unsigned char>(input[in])) &&
                       (!width || in - start < width))
                    ++in;
                if (in == start) return any_conversion ? static_cast<int>(assigned) : -1;
                if (!suppress) {
                    for (size_t i = 0; i < in - start; ++i)
                        store_char(e, dst, i, static_cast<unsigned char>(input[start + i]),
                                   len.wide_target);
                    store_char(e, dst, in - start, 0, len.wide_target);
                    ++assigned;
                }
                any_conversion = true;
                break;
            }
            case '[': {
                // A scanset: `^` negates, a `]` first is a literal, and `a-z`
                // inside is a range.
                ++f;
                bool negate = false;
                if (f < fmt.size() && fmt[f] == '^') {
                    negate = true;
                    ++f;
                }
                bool set[256] = {};
                bool first = true;
                for (; f < fmt.size() && (fmt[f] != ']' || first); ++f, first = false) {
                    unsigned char ch = static_cast<unsigned char>(fmt[f]);
                    if (!first && ch == '-' && f + 1 < fmt.size() && fmt[f + 1] != ']') {
                        unsigned char lo = static_cast<unsigned char>(fmt[f - 1]);
                        unsigned char hi = static_cast<unsigned char>(fmt[f + 1]);
                        for (int v = lo; v <= hi; ++v) set[v] = true;
                        ++f;
                        continue;
                    }
                    set[ch] = true;
                }
                size_t start = in;
                while (in < input.size() && (!width || in - start < width) &&
                       set[static_cast<unsigned char>(input[in])] != negate)
                    ++in;
                if (in == start) return any_conversion ? static_cast<int>(assigned) : -1;
                if (!suppress) {
                    for (size_t i = 0; i < in - start; ++i)
                        store_char(e, dst, i, static_cast<unsigned char>(input[start + i]),
                                   len.wide_target);
                    store_char(e, dst, in - start, 0, len.wide_target);
                    ++assigned;
                }
                any_conversion = true;
                break;
            }
            default:
                // An unknown conversion: stop rather than guess how much of the
                // input it would have eaten.
                return static_cast<int>(assigned);
        }
    }
    return static_cast<int>(assigned);
}

}  // namespace x86emu
