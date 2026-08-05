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

    // Static thread-local storage.  The image carries a template that the loader
    // copies into a per-thread block, and stores that block's slot number where
    // the code expects to find it - which is how `__declspec(thread)` compiles
    // down to gs:[0x58] plus an index.
    std::vector<uint64_t> tls_callbacks;
    uint64_t tls_index_address = 0;  // where to write the slot number
    uint64_t tls_raw_start = 0;      // the template's bounds, as addresses
    uint64_t tls_raw_end = 0;
    uint64_t tls_zero_fill = 0;      // extra zeroed bytes after the template

    // The x64 exception directory: a sorted array of RUNTIME_FUNCTION, three
    // RVAs each, describing how to unwind every function in the image.  This is
    // what makes throwing possible - on x64 there is no frame-pointer chain to
    // walk, only this table.
    uint64_t exception_table = 0;    // as an address, not an RVA
    uint32_t exception_table_size = 0;

    // The resource directory, a three-level tree of type -> name -> language.
    // A localised program keeps its strings in a resource-only DLL and cannot
    // print anything at all until that DLL's resources can be found.
    uint64_t resource_table = 0;     // as an address
    uint32_t resource_table_size = 0;
};

// Reads just enough of the headers to know the CPU mode; throws LoadError if the
// file is not a PE at all.
void peek_pe(const std::vector<uint8_t>& file, Mode& mode, std::string& format, bool& is_dll);

// The one address an image can be loaded at, or 0 if it can go anywhere.  Only
// an image with no relocation directory - a resource-only DLL, say - is fixed,
// and honouring that is what lets one load; every other DLL is deliberately
// left to be relocated, because *where* a module lands changes which code paths
// a guest takes and moving them all would be a needless change.
uint64_t fixed_base_of(const std::vector<uint8_t>& file);

// Maps an image.  load_base of 0 means "wherever it prefers"; anything else
// relocates it there, which requires a relocation directory unless the addresses
// happen to match.
PeImage map_pe(const std::vector<uint8_t>& file, Memory& mem, uint64_t load_base);

}  // namespace x86emu
