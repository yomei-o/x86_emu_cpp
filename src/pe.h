// PE mapping, for executables and DLLs alike.
//
// The loader's job stops at "the image is in memory and here is what it needs":
// it reports the imports rather than resolving them, because only the emulator
// knows whether a given DLL should be hooked or actually loaded, and that
// decision is what makes dynamic loading work.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "cpu.h"
#include "memory.h"

namespace x86emu {

struct PeImage {
    Mode mode = Mode::X86_32;
    std::string format;      // "PE32" or "PE32+"
    uint64_t base = 0;       // where it actually landed
    uint64_t preferred = 0;  // where it wanted to be
    uint64_t size = 0;
    uint64_t entry = 0;      // 0 if the image has no entry point
    bool is_dll = false;
    bool relocated = false;

    // One slot in an import address table, waiting to be filled in.
    struct Import {
        std::string dll;
        std::string symbol;   // empty when imported by ordinal
        uint32_t ordinal = 0;
        uint64_t slot = 0;    // address of the IAT entry to write
    };
    std::vector<Import> imports;

    // What this image offers others.  A forwarder names another DLL's symbol
    // instead of an address ("api-ms-win-crt-math-l1-1-0.sin" style), so it has
    // to be followed at resolution time.
    std::unordered_map<std::string, uint64_t> exports;
    std::unordered_map<uint32_t, uint64_t> exports_by_ordinal;
    std::unordered_map<std::string, std::string> forwarders;

    // TLS callbacks the guest expects to run at load time.
    std::vector<uint64_t> tls_callbacks;
    uint64_t tls_index_address = 0;
};

// Reads just enough of the headers to know the CPU mode; throws LoadError if the
// file is not a PE at all.
void peek_pe(const std::vector<uint8_t>& file, Mode& mode, std::string& format, bool& is_dll);

// Maps an image.  load_base of 0 means "wherever it prefers"; anything else
// relocates it there, which requires a relocation directory unless the addresses
// happen to match.
PeImage map_pe(const std::vector<uint8_t>& file, Memory& mem, uint64_t load_base);

}  // namespace x86emu
