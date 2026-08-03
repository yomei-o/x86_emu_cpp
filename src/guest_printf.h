// The printf engine shared by every stdio hook.
#pragma once

#include <cstdint>
#include <string>

#include "emulator.h"

namespace x86emu {

// Formats a guest format string, pulling the variadic arguments through `va`.
// Conversions are handed to the host's snprintf so that padding, precision and
// rounding match a real libc.
// `wide` selects the wprintf family: the format string is UTF-16, and a bare %s
// means a wide string rather than a narrow one.  The result is UTF-8 either way;
// the caller converts back if it needs wide output.
std::string format_guest(Emulator& e, uint64_t fmt_ptr, Emulator::Args& va, bool wide = false);

// UTF-16 <-> UTF-8 for the wide Win32 entry points (BMP only).
std::string utf16_to_utf8(Emulator& e, uint64_t ptr, int units);
std::u16string utf8_to_utf16(const std::string& s);

}  // namespace x86emu
