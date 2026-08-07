#include "memory.h"

#include <algorithm>
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
    // Reserve, do not allocate.  operator[] default-constructs a null
    // unique_ptr, which is exactly the "reserved" state; a page that already
    // has memory behind it keeps it.
    for (uint64_t p = first; p <= last; ++p) pages_[p];
    if (!name.empty()) regions_.push_back({addr, size, name});
}

void Memory::unmap(uint64_t addr, uint64_t size) {
    if (size == 0) return;
    // A contiguous mapping is dropped whole: it is one allocation, and half of
    // one is not a thing this can represent.  Nothing maps over part of one.
    for (size_t i = spans_.size(); i-- > 0;) {
        const Span& s = spans_[i];
        if (addr < s.base + s.size && s.base < addr + size) {
            tlb_flush();
            spans_.erase(spans_.begin() + static_cast<long>(i));
        }
    }
    uint64_t first = addr >> kPageBits;
    uint64_t last = (addr + size - 1) >> kPageBits;
    for (uint64_t p = first; p <= last; ++p) {
        pages_.erase(p);
        // The freed page may be in the cache, and a stale entry there is a
        // pointer into released memory.  Clearing only the slot it could
        // occupy keeps a large munmap from costing the whole cache.
        TlbEntry& e = tlb_[p & (kTlbSize - 1)];
        if (e.page == p) {
            e.page = kTlbNone;
            e.host = nullptr;
        }
    }
}

void Memory::map_contiguous(uint64_t addr, uint64_t size, const std::string& name) {
    if (size == 0) return;
    // Whole pages, so that a span and the page table never disagree about who
    // owns a page.
    uint64_t base = addr & ~kPageMask;
    uint64_t end = (addr + size + kPageMask) & ~kPageMask;
    unmap(base, end - base);
    Span s;
    s.base = base;
    s.size = end - base;
    s.data.reset(new uint8_t[s.size]());
    spans_.push_back(std::move(s));
    if (!name.empty()) regions_.push_back({base, end - base, name, std::string(), 0, true});
}

uint8_t* Memory::host_span(uint64_t addr, uint64_t size) const {
    const Span* s = span_for(addr);
    if (!s || addr + size > s->base + s->size) return nullptr;
    return s->data.get() + (addr - s->base);
}

uint8_t* Memory::host_ptr_slow(uint64_t addr, bool for_write) const {
    uint64_t page = addr >> kPageBits;
    // A contiguous mapping answers before the page table, and caches into the
    // TLB exactly like a page does, so the fast path never learns the
    // difference.
    if (const Span* s = span_for(addr)) {
        uint8_t* base = s->data.get() + ((page << kPageBits) - s->base);
        TlbEntry& e = tlb_[page & (kTlbSize - 1)];
        e.page = page;
        e.host = base;
        return base + (addr & kPageMask);
    }
    auto it = pages_.find(page);
    if (it == pages_.end()) {
        char buf[128];
        std::snprintf(buf, sizeof buf, "unmapped memory %s at 0x%016llX",
                      for_write ? "write" : "read",
                      static_cast<unsigned long long>(addr));
        throw MemoryFault(addr, for_write, buf);
    }
    // Reserved but never touched: the memory appears now, zero filled, which is
    // what the guest was promised when it mapped the range.  Reading is as good
    // a reason as writing - a fresh page reads as zero either way.
    if (!it->second) it->second = std::make_unique<Page>();
    uint8_t* base = it->second->data();
    TlbEntry& e = tlb_[page & (kTlbSize - 1)];
    e.page = page;
    e.host = base;
    return base + (addr & kPageMask);
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
        // A whole page of zeros over a page that has never been touched is a
        // no-op, and skipping it leaves the page unbacked.  That is not a
        // micro-optimisation: a loader mapping a library whose 419 MB of device
        // code the emulator never runs writes exactly this, page after page.
        bool all_zero = n == kPageSize && unbacked(addr);
        for (uint64_t i = 0; all_zero && i < n; ++i)
            if (in[i]) all_zero = false;
        if (!all_zero) std::memcpy(host_ptr(addr, true), in, n);
        in += n;
        addr += n;
        len -= n;
    }
}

void Memory::set_region_file(uint64_t base, std::string path, uint64_t offset) {
    // The most recent region with this base: mmap appends one per call, and a
    // MAP_FIXED drop into a reservation makes several with the same name.
    for (auto it = regions_.rbegin(); it != regions_.rend(); ++it)
        if (it->base == base) {
            it->file = std::move(path);
            it->file_offset = offset;
            return;
        }
}

std::vector<uint64_t> Memory::live_pages() const {
    std::vector<uint64_t> out;
    out.reserve(pages_.size());
    for (const auto& [index, page] : pages_)
        if (page) out.push_back(index);
    // A contiguous mapping is guest memory like any other, and anything
    // capturing this address space has to capture it - otherwise a snapshot
    // silently loses whatever lives there.
    for (const auto& s : spans_)
        for (uint64_t a = s.base; a < s.base + s.size; a += kPageSize)
            out.push_back(a >> kPageBits);
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<uint64_t> Memory::mapped_pages() const {
    std::vector<uint64_t> out;
    out.reserve(pages_.size());
    for (const auto& [index, page] : pages_) {
        (void)page;  // reserved and live alike: what is being asked is existence
        out.push_back(index);
    }
    for (const auto& s : spans_)
        for (uint64_t a = s.base; a < s.base + s.size; a += kPageSize)
            out.push_back(a >> kPageBits);
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

const uint8_t* Memory::page_data(uint64_t index) const {
    uint64_t addr = index << kPageBits;
    if (const Span* s = span_for(addr)) return s->data.get() + (addr - s->base);
    auto it = pages_.find(index);
    return (it == pages_.end() || !it->second) ? nullptr : it->second->data();
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
