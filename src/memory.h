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
        // For a file mapping, where the bytes came from.  Anything capturing
        // this address space can then leave out the pages that still match the
        // file and read them back instead - which for a guest that has mapped a
        // 98 MB dictionary is most of what it would otherwise carry.
        std::string file;
        uint64_t file_offset = 0;
        // Whether this came from map_contiguous.  Anything rebuilding an
        // address space has to put it back the same way: a caller outside the
        // emulator is holding a host pointer into it, and ordinary pages cannot
        // give one.
        bool contiguous = false;
    };

    // Makes [addr, addr+size) readable/writable, zero filled.  Pages that are
    // already present are left untouched, so overlapping maps are harmless.
    //
    // The pages are *reserved*, not allocated: the table gets an empty slot for
    // each and the 4 KiB behind it appears on the first access.  A slot is
    // about fifty bytes against the page's four thousand, which is the
    // difference between a guest that maps a 460 MB library and one that can.
    // Most of that library is device code the emulator never runs; a segment of
    // it that is never touched now costs nothing.
    void map(uint64_t addr, uint64_t size, const std::string& name = "");

    bool is_mapped(uint64_t addr) const {
        return pages_.find(addr >> kPageBits) != pages_.end() || span_for(addr);
    }

    // Drops the pages covering [addr, addr+size), releasing their memory.  A
    // later map() of the same range gets fresh zero-filled pages, which is what
    // munmap() followed by mmap() means.
    void unmap(uint64_t addr, uint64_t size);

    // Every guest memory access ends up in host_ptr, so what host_ptr costs is
    // multiplied by billions.  A hash lookup per byte is far more than the work
    // it is finding, and a guest with a gigabyte live has a quarter of a
    // million pages for the table to spread over.
    //
    // So: a direct-mapped cache of resolved pages, the smallest thing that
    // works.  Code and stack and the array being walked land in different slots
    // and all stay resident, which is the case that matters; a conflict costs
    // one hash lookup, which is what every access used to cost.
    //
    // A cached entry can only go stale when a page is freed, so unmap() and
    // clone_from() clear it and nothing else has to.  map() never replaces a
    // page that exists, and a miss is never cached, so neither can invalidate
    // anything.  The pages themselves are separately allocated, so the table
    // rehashing does not move them.  A reserved-but-unbacked page is never
    // cached either - host_ptr_slow allocates it first.
    static constexpr int kTlbBits = 10;
    static constexpr int kTlbSize = 1 << kTlbBits;
    static constexpr uint64_t kTlbNone = ~0ull;

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

    // One contiguous mapping.  Kept apart from pages_ rather than threaded
    // through it: a Page is separately owned, and a span's pages are not.
    struct Span {
        uint64_t base = 0;
        uint64_t size = 0;
        std::unique_ptr<uint8_t[]> data;
    };
    const Span* span_for(uint64_t addr) const {
        for (const auto& s : spans_)
            if (addr >= s.base && addr < s.base + s.size) return &s;
        return nullptr;
    }

    // Replaces this memory with a page-for-page copy of another - the whole of
    // what fork() means for an address space.
    void clone_from(const Memory& other) {
        pages_.clear();
        spans_.clear();
        tlb_flush();
        for (const auto& [index, page] : other.pages_)
            pages_[index] = page ? std::make_unique<Page>(*page) : nullptr;
        // Contiguous mappings are copied like everything else: fork() gives the
        // child its own memory, and a span that both halves pointed at would be
        // shared memory, which is a different thing entirely.
        for (const auto& s : other.spans_) {
            Span copy;
            copy.base = s.base;
            copy.size = s.size;
            copy.data.reset(new uint8_t[s.size]);
            std::memcpy(copy.data.get(), s.data.get(), s.size);
            spans_.push_back(std::move(copy));
        }
        regions_ = other.regions_;
    }

    // Empties the address space.  Restoring a saved state rebuilds the map from
    // what was written down rather than merging into whatever loading the
    // program laid out, so that a restored guest sees its own memory and
    // nothing left over from the one it displaced.
    void reset() {
        pages_.clear();
        spans_.clear();
        regions_.clear();
        tlb_flush();
    }

    const std::vector<Region>& regions() const { return regions_; }

    // Records what a mapping was read from.  Separate from map() because the
    // syscall knows the file and the allocator does not.
    void set_region_file(uint64_t base, std::string path, uint64_t offset);

    // Maps [addr, addr+size) backed by one contiguous host allocation.
    //
    // Ordinary pages are separate 4 KiB blocks, which is right for a sparse
    // address space and wrong for anything outside the emulator that wants to
    // work on a guest buffer in place - a host library handed a guest pointer
    // needs the bytes to actually be consecutive.
    //
    // The point is not speed but *addressing*: with this, such a caller can
    // keep guest addresses everywhere and translate one to a host pointer with
    // a subtraction.  Keeping host pointers in guest memory instead works until
    // the two have different widths, or until the state is saved on one host
    // and restored on another - both of which stop being possible the moment a
    // host address is written into the guest's memory.
    void map_contiguous(uint64_t addr, uint64_t size, const std::string& name = "");

    // The host address of a guest range, or nullptr if the range is not inside
    // one contiguous mapping.  Never true of ordinary pages.
    uint8_t* host_span(uint64_t addr, uint64_t size) const;

    // The pages that have memory behind them, and the bytes of one.  Reserved
    // but untouched pages are not listed: they read as zero, so anything
    // capturing this address space can leave them out and get them back for
    // free.  Sorted, so a capture is reproducible.
    std::vector<uint64_t> live_pages() const;
    const uint8_t* page_data(uint64_t index) const;

    // Every page the guest may touch, whether or not anything is behind it yet.
    //
    // Reserved-but-untouched pages read as zero, so a capture can leave their
    // *contents* out - but not their existence.  A guest whose heap has grown
    // by another megabyte has a megabyte of pages that are mapped, empty, and
    // outside any named region; rebuilding the address space from the regions
    // and the live pages alone loses them, and the first write into the grown
    // heap faults.
    std::vector<uint64_t> mapped_pages() const;

private:
    using Page = std::array<uint8_t, kPageSize>;

    struct TlbEntry {
        uint64_t page = kTlbNone;
        uint8_t* host = nullptr;
    };

    uint8_t* host_ptr(uint64_t addr, bool for_write) const {
        uint64_t page = addr >> kPageBits;
        const TlbEntry& e = tlb_[page & (kTlbSize - 1)];
        if (e.page == page) return e.host + (addr & kPageMask);
        return host_ptr_slow(addr, for_write);
    }

    uint8_t* host_ptr_slow(uint64_t addr, bool for_write) const;

    void tlb_flush() {
        for (auto& e : tlb_) {
            e.page = kTlbNone;
            e.host = nullptr;
        }
    }

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

    // Whether a page is reserved but has never been touched.  Such a page
    // reads as zero, so writing zeros over the whole of one is a no-op - which
    // is what keeps a library's 419 MB of unused device code from being copied
    // into memory it will never be read from.
    bool unbacked(uint64_t addr) const {
        auto it = pages_.find(addr >> kPageBits);
        return it != pages_.end() && !it->second;
    }

    // A null slot means reserved; the Page appears on first access.
    mutable std::unordered_map<uint64_t, std::unique_ptr<Page>> pages_;
    std::vector<Span> spans_;
    mutable TlbEntry tlb_[kTlbSize];
    std::vector<Region> regions_;
};

}  // namespace x86emu
