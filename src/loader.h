// Executable loaders.  Each loader maps an image into guest memory and reports
// what the CPU needs to start running it.
#pragma once

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include "cpu.h"
#include "memory.h"

namespace x86emu {

struct LoadError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

enum class Os { Windows, Linux };

struct LoadedImage {
    Mode mode = Mode::X86_32;
    Os os = Os::Windows;
    std::string format;       // "PE32", "PE32+", "ELF32", "ELF64"
    uint64_t entry = 0;
    uint64_t image_base = 0;
    uint64_t image_size = 0;

    // ELF only, needed to build the initial auxiliary vector.
    uint64_t phdr_addr = 0;
    uint64_t phent_size = 0;
    uint64_t phnum = 0;
    // Highest mapped address, i.e. where the heap can start.
    uint64_t brk = 0;
};

// Called for every import the loader finds.  Returns the guest address that
// should be written into the import slot.
using ImportBinder = std::function<uint64_t(const std::string& dll, const std::string& symbol)>;

std::vector<uint8_t> read_file(const std::string& path);

// Reads just enough of the headers to know which CPU mode and OS personality
// the image needs.  The emulator has to know that before it can lay out guest
// memory and install hooks, which happens before the full load.
void peek_image(const std::vector<uint8_t>& file, Mode& mode, Os& os, std::string& format);

// PE images go through map_pe() in pe.h, because the emulator binds their imports
// itself: whether a DLL should be hooked or actually loaded is its decision.
LoadedImage load_elf(const std::vector<uint8_t>& file, Memory& mem);

}  // namespace x86emu
