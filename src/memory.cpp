#include "memory.h"

#include <cstdio>
#include <cstdlib>

namespace x86emu {

uint64_t g_watch_addr = 0;
bool g_watch_on = false;
uint64_t g_watch_rip = 0;

// Reads X86EMU_WATCH once, before main() runs.
static const bool g_watch_initialized = [] {
    if (const char* w = std::getenv("X86EMU_WATCH")) {
        g_watch_addr = std::strtoull(w, nullptr, 16);
        g_watch_on = g_watch_addr != 0;
    }
    return true;
}();

void watch_report(uint64_t addr, uint64_t len, const void* bytes) {
    uint64_t v = 0;
    std::memcpy(&v, bytes, len > 8 ? 8 : len);
    std::fprintf(stderr, "[watch] write %llu bytes at %llX (value %llX) rip=%llX\n",
                 (unsigned long long)len, (unsigned long long)addr,
                 (unsigned long long)v, (unsigned long long)g_watch_rip);
}

void Memory::map(uint64_t addr, uint64_t size, const std::string& name) {
    if (size == 0) return;
    uint64_t first = addr >> kPageBits;
    uint64_t last = (addr + size - 1) >> kPageBits;
    for (uint64_t p = first; p <= last; ++p) {
        auto& slot = pages_[p];
        if (!slot) slot = std::make_unique<Page>();
    }
    if (!name.empty()) regions_.push_back({addr, size, name});
}

void Memory::unmap(uint64_t addr, uint64_t size) {
    if (size == 0) return;
    uint64_t first = addr >> kPageBits;
    uint64_t last = (addr + size - 1) >> kPageBits;
    for (uint64_t p = first; p <= last; ++p) pages_.erase(p);
}

uint8_t* Memory::host_ptr(uint64_t addr, bool for_write) const {
    auto it = pages_.find(addr >> kPageBits);
    if (it == pages_.end()) {
        char buf[128];
        std::snprintf(buf, sizeof buf, "unmapped memory %s at 0x%016llX",
                      for_write ? "write" : "read",
                      static_cast<unsigned long long>(addr));
        throw MemoryFault(addr, for_write, buf);
    }
    return it->second->data() + (addr & kPageMask);
}

void Memory::read(uint64_t addr, void* dst, uint64_t len) const {
    auto* out = static_cast<uint8_t*>(dst);
    while (len > 0) {
        uint64_t off = addr & kPageMask;
        uint64_t n = kPageSize - off;
        if (n > len) n = len;
        std::memcpy(out, host_ptr(addr, false), n);
        out += n;
        addr += n;
        len -= n;
    }
}

void Memory::write(uint64_t addr, const void* src, uint64_t len) {
    const auto* in = static_cast<const uint8_t*>(src);
    if (g_watch_on && addr <= g_watch_addr && g_watch_addr < addr + len)
        watch_report(addr, len, in + (g_watch_addr - addr));
    while (len > 0) {
        uint64_t off = addr & kPageMask;
        uint64_t n = kPageSize - off;
        if (n > len) n = len;
        std::memcpy(host_ptr(addr, true), in, n);
        in += n;
        addr += n;
        len -= n;
    }
}

std::string Memory::read_cstring(uint64_t addr, uint64_t max_len) const {
    std::string s;
    for (uint64_t i = 0; i < max_len; ++i) {
        uint8_t c = read8(addr + i);
        if (c == 0) break;
        s.push_back(static_cast<char>(c));
    }
    return s;
}

void Memory::write_cstring(uint64_t addr, const std::string& s) {
    write(addr, s.data(), s.size());
    write8(addr + s.size(), 0);
}

}  // namespace x86emu
