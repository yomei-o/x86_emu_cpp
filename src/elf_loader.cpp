// ELF32 / ELF64 loader for statically linked Linux executables.
//
// Only ET_EXEC with PT_LOAD segments is handled: dynamic linking would mean
// emulating ld.so plus a real libc, whereas static binaries reach the kernel
// interface directly, which the emulator implements as syscall hooks.
#include <cstdio>
#include <cstring>

#include "loader.h"

namespace x86emu {
namespace {

template <typename T>
T rd(const std::vector<uint8_t>& f, size_t off) {
    if (off + sizeof(T) > f.size()) throw LoadError("truncated ELF file");
    T v;
    std::memcpy(&v, f.data() + off, sizeof(T));
    return v;
}

constexpr uint16_t kEmI386 = 3;
constexpr uint16_t kEmX8664 = 62;
constexpr uint32_t kPtLoad = 1;
constexpr uint32_t kPtInterp = 3;

}  // namespace

LoadedImage load_elf(const std::vector<uint8_t>& f, Memory& mem, uint64_t load_base) {
    if (f.size() < 64 || f[0] != 0x7F || f[1] != 'E' || f[2] != 'L' || f[3] != 'F')
        throw LoadError("not an ELF image");

    uint8_t cls = f[4];        // 1 = ELF32, 2 = ELF64
    uint8_t endian = f[5];     // 1 = little
    if (endian != 1) throw LoadError("big-endian ELF not supported");

    LoadedImage img;
    img.os = Os::Linux;

    uint16_t type = rd<uint16_t>(f, 16);
    uint16_t machine = rd<uint16_t>(f, 18);
    bool is64;
    if (cls == 2 && machine == kEmX8664) {
        is64 = true;
        img.mode = Mode::X86_64;
        img.format = "ELF64";
    } else if (cls == 1 && machine == kEmI386) {
        is64 = false;
        img.mode = Mode::X86_32;
        img.format = "ELF32";
    } else {
        char buf[96];
        std::snprintf(buf, sizeof buf, "unsupported ELF (class=%u machine=%u)", cls, machine);
        throw LoadError(buf);
    }
    // ET_EXEC (2) loads at its own absolute vaddrs; ET_DYN (3, PIE / shared
    // object) is position-independent and loads at a bias the caller chooses.
    if (type != 2 && type != 3) throw LoadError("unsupported ELF type (not ET_EXEC or ET_DYN)");
    const uint64_t bias = (type == 3) ? load_base : 0;
    img.is_dynamic = (type == 3);
    img.load_bias = bias;

    uint64_t phoff, entry;
    uint16_t phentsize, phnum;
    if (is64) {
        entry = rd<uint64_t>(f, 24);
        phoff = rd<uint64_t>(f, 32);
        phentsize = rd<uint16_t>(f, 54);
        phnum = rd<uint16_t>(f, 56);
    } else {
        entry = rd<uint32_t>(f, 24);
        phoff = rd<uint32_t>(f, 28);
        phentsize = rd<uint16_t>(f, 42);
        phnum = rd<uint16_t>(f, 44);
    }
    img.entry = entry + bias;
    img.phent_size = phentsize;
    img.phnum = phnum;

    uint64_t lowest = ~0ull;
    for (uint16_t i = 0; i < phnum; ++i) {
        size_t p = static_cast<size_t>(phoff) + i * phentsize;
        uint32_t p_type = rd<uint32_t>(f, p);

        if (p_type == kPtInterp) {  // path of the dynamic loader (ld.so)
            uint64_t off = is64 ? rd<uint64_t>(f, p + 8) : rd<uint32_t>(f, p + 4);
            uint64_t sz = is64 ? rd<uint64_t>(f, p + 32) : rd<uint32_t>(f, p + 16);
            if (off + sz <= f.size()) {
                const char* s = reinterpret_cast<const char*>(f.data() + off);
                img.interp.assign(s, strnlen(s, static_cast<size_t>(sz)));
            }
            continue;
        }
        if (p_type != kPtLoad) continue;

        uint64_t offset, vaddr, filesz, memsz;
        if (is64) {
            offset = rd<uint64_t>(f, p + 8);
            vaddr = rd<uint64_t>(f, p + 16) + bias;
            filesz = rd<uint64_t>(f, p + 32);
            memsz = rd<uint64_t>(f, p + 40);
        } else {
            offset = rd<uint32_t>(f, p + 4);
            vaddr = rd<uint32_t>(f, p + 8) + bias;
            filesz = rd<uint32_t>(f, p + 16);
            memsz = rd<uint32_t>(f, p + 20);
        }

        // .bss lives in the memsz beyond filesz; map() zero fills it for us.
        mem.map(vaddr, memsz ? memsz : 1, "PT_LOAD");
        if (filesz) {
            if (offset + filesz > f.size()) throw LoadError("PT_LOAD extends past end of file");
            mem.write(vaddr, f.data() + offset, filesz);
        }
        if (vaddr < lowest) lowest = vaddr;
        uint64_t end = vaddr + memsz;
        if (end > img.brk) img.brk = end;

        // The program headers are normally inside the first PT_LOAD; the guest
        // finds them through AT_PHDR.
        if (phoff >= offset && phoff < offset + filesz)
            img.phdr_addr = vaddr + (phoff - offset);
    }
    if (lowest == ~0ull) throw LoadError("no PT_LOAD segments");
    img.image_base = lowest;
    img.image_size = img.brk - lowest;
    // Dynamic linking is signalled by PT_INTERP, not by ET_DYN: a distro
    // toolchain ships ET_EXEC binaries that still need ld.so (non-PIE, fixed
    // addresses, PLT relocations).  Entering one directly jumps through an
    // unrelocated PLT into address zero.
    if (!img.interp.empty()) img.is_dynamic = true;
    return img;
}

}  // namespace x86emu
