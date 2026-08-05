// Guest linear memory for the emulator.
//
// Addresses are 64-bit so the same class serves both x86-32 and x86-64 guests.
// The space is sparse, so memory is a hash map of 4 KiB pages created on demand
// by map().  Touching an address that was never mapped raises MemoryFault
// instead of silently reading zeroes: a wild pointer in the guest is almost
// always something we want to see, not paper over.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace x86emu {

// Diagnostics: X86EMU_WATCH=hexaddr logs every guest write covering that
// address, with the guest rip that made it (g_watch_rip, kept current by
// Cpu::step).  Zero cost when the variable is unset.
extern uint64_t g_watch_addr;
extern bool g_watch_on;
extern uint64_t g_watch_rip;
void watch_init();
void watch_report(uint64_t addr, uint64_t len, const void* bytes);

struct MemoryFault : std::runtime_error {
    uint64_t addr;
    bool is_write;
    MemoryFault(uint64_t a, bool w, const std::string& what)
        : std::runtime_error(what), addr(a), is_write(w) {}
};

class Memory {
public:
    static constexpr uint64_t kPageBits = 12;
    static constexpr uint64_t kPageSize = 1ull << kPageBits;  // 4096
    static constexpr uint64_t kPageMask = kPageSize - 1;

    // Region bookkeeping, purely informational (used by the memory map dump).
    struct Region {
        uint64_t base;
        uint64_t size;
        std::string name;
    };

    // Makes [addr, addr+size) readable/writable, zero filled.  Pages that are
    // already present are left untouched, so overlapping maps are harmless.
    void map(uint64_t addr, uint64_t size, const std::string& name = "");

    bool is_mapped(uint64_t addr) const {
        return pages_.find(addr >> kPageBits) != pages_.end();
    }

    // Drops the pages covering [addr, addr+size), releasing their memory.  A
    // later map() of the same range gets fresh zero-filled pages, which is what
    // munmap() followed by mmap() means.
    void unmap(uint64_t addr, uint64_t size);

    void read(uint64_t addr, void* dst, uint64_t len) const;
    void write(uint64_t addr, const void* src, uint64_t len);

    uint8_t read8(uint64_t addr) const { return *host_ptr(addr, false); }
    uint16_t read16(uint64_t addr) const { return read_int<uint16_t>(addr); }
    uint32_t read32(uint64_t addr) const { return read_int<uint32_t>(addr); }
    uint64_t read64(uint64_t addr) const { return read_int<uint64_t>(addr); }

    void write8(uint64_t addr, uint8_t v) {
        if (g_watch_on && addr == g_watch_addr) watch_report(addr, 1, &v);
        *host_ptr(addr, true) = v;
    }
    void write16(uint64_t addr, uint16_t v) { write_int(addr, v); }
    void write32(uint64_t addr, uint32_t v) { write_int(addr, v); }
    void write64(uint64_t addr, uint64_t v) { write_int(addr, v); }

    // Reads sized 1/2/4/8 generically; used by the interpreter's operand paths.
    uint64_t read_sized(uint64_t addr, int size) const {
        switch (size) {
            case 1: return read8(addr);
            case 2: return read16(addr);
            case 4: return read32(addr);
            default: return read64(addr);
        }
    }
    void write_sized(uint64_t addr, int size, uint64_t v) {
        switch (size) {
            case 1: write8(addr, static_cast<uint8_t>(v)); break;
            case 2: write16(addr, static_cast<uint16_t>(v)); break;
            case 4: write32(addr, static_cast<uint32_t>(v)); break;
            default: write64(addr, v); break;
        }
    }

    // Reads a NUL terminated string.  Stops at max_len so that a corrupt
    // pointer cannot walk the whole address space.
    std::string read_cstring(uint64_t addr, uint64_t max_len = 1ull << 20) const;
    void write_cstring(uint64_t addr, const std::string& s);

    // Replaces this memory with a page-for-page copy of another - the whole of
    // what fork() means for an address space.
    void clone_from(const Memory& other) {
        pages_.clear();
        for (const auto& [index, page] : other.pages_)
            pages_[index] = std::make_unique<Page>(*page);
        regions_ = other.regions_;
    }

    const std::vector<Region>& regions() const { return regions_; }

private:
    using Page = std::array<uint8_t, kPageSize>;

    uint8_t* host_ptr(uint64_t addr, bool for_write) const;

    template <typename T>
    T read_int(uint64_t addr) const {
        // Fast path: the access does not straddle a page boundary.
        if ((addr & kPageMask) + sizeof(T) <= kPageSize) {
            T v;
            std::memcpy(&v, host_ptr(addr, false), sizeof(T));
            return v;
        }
        T v{};
        read(addr, &v, sizeof(T));
        return v;
    }

    template <typename T>
    void write_int(uint64_t addr, T v) {
        if (g_watch_on && addr <= g_watch_addr && g_watch_addr < addr + sizeof(T))
            watch_report(addr, sizeof(T), &v);
        if ((addr & kPageMask) + sizeof(T) <= kPageSize) {
            std::memcpy(host_ptr(addr, true), &v, sizeof(T));
            return;
        }
        write(addr, &v, sizeof(T));
    }

    mutable std::unordered_map<uint64_t, std::unique_ptr<Page>> pages_;
    std::vector<Region> regions_;
};

}  // namespace x86emu
