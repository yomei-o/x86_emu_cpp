// The printf engine shared by every stdio hook.
#pragma once

#include <cstdint>
#include <string>

#include "emulator.h"

namespace x86emu {

// Formats a guest format string, pulling the variadic arguments through `va`.
// Conversions are handed to the host's snprintf so that padding, precision and
// rounding match a real libc.
std::string format_guest(Emulator& e, uint64_t fmt_ptr, Emulator::Args& va);

// UTF-16 <-> UTF-8 for the wide Win32 entry points (BMP only).
std::string utf16_to_utf8(Emulator& e, uint64_t ptr, int units);
std::u16string utf8_to_utf16(const std::string& s);

}  // namespace x86emu
