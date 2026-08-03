// PE32 / PE32+ loader.
//
// The image is mapped at its preferred ImageBase (so no relocation processing
// is needed) and every import slot in the IAT is overwritten with the guest
// address of a host hook.  That is the whole trick behind intercepting calls
// like printf: the guest still executes its own `call [__imp_printf]` thunk,
// but the address it lands on belongs to the emulator, not to real code.
#include <cstdio>
#include <cstring>

#include "loader.h"

namespace x86emu {
namespace {

// Little-endian scalar reads with bounds checking against the file image.
template <typename T>
T rd(const std::vector<uint8_t>& f, size_t off) {
    if (off + sizeof(T) > f.size()) throw LoadError("truncated PE file");
    T v;
    std::memcpy(&v, f.data() + off, sizeof(T));
    return v;
}

constexpr uint16_t kMachineI386 = 0x014C;
constexpr uint16_t kMachineAmd64 = 0x8664;
constexpr uint16_t kMagicPe32 = 0x010B;
constexpr uint16_t kMagicPe32Plus = 0x020B;

struct Section {
    std::string name;
    uint32_t virtual_size;
    uint32_t virtual_addr;
    uint32_t raw_size;
    uint32_t raw_ptr;
};

}  // namespace

LoadedImage load_pe(const std::vector<uint8_t>& f, Memory& mem, const ImportBinder& bind) {
    if (f.size() < 0x40 || f[0] != 'M' || f[1] != 'Z') throw LoadError("not an MZ image");
    uint32_t pe_off = rd<uint32_t>(f, 0x3C);
    if (rd<uint32_t>(f, pe_off) != 0x00004550u) throw LoadError("missing PE signature");

    size_t fh = pe_off + 4;  // IMAGE_FILE_HEADER
    uint16_t machine = rd<uint16_t>(f, fh + 0);
    uint16_t num_sections = rd<uint16_t>(f, fh + 2);
    uint16_t opt_size = rd<uint16_t>(f, fh + 16);
    size_t oh = fh + 20;  // IMAGE_OPTIONAL_HEADER

    uint16_t magic = rd<uint16_t>(f, oh + 0);
    LoadedImage img;
    img.os = Os::Windows;

    bool plus;
    if (magic == kMagicPe32Plus && machine == kMachineAmd64) {
        plus = true;
        img.mode = Mode::X86_64;
        img.format = "PE32+";
    } else if (magic == kMagicPe32 && machine == kMachineI386) {
        plus = false;
        img.mode = Mode::X86_32;
        img.format = "PE32";
    } else {
        char buf[96];
        std::snprintf(buf, sizeof buf, "unsupported PE (machine=0x%04X magic=0x%04X)", machine,
                      magic);
        throw LoadError(buf);
    }

    uint32_t entry_rva = rd<uint32_t>(f, oh + 16);
    // ImageBase is 4 bytes at +28 in PE32 and 8 bytes at +24 in PE32+.
    img.image_base = plus ? rd<uint64_t>(f, oh + 24) : rd<uint32_t>(f, oh + 28);
    img.image_size = rd<uint32_t>(f, oh + 56);
    uint32_t headers_size = rd<uint32_t>(f, oh + 60);
    size_t dd = oh + (plus ? 112 : 96);  // DataDirectory[]
    uint32_t num_dd = rd<uint32_t>(f, oh + (plus ? 108 : 92));

    img.entry = img.image_base + entry_rva;

    // Reserve the whole image up front so that section gaps are readable.
    mem.map(img.image_base, img.image_size ? img.image_size : 0x10000, "image");

    // The headers themselves stay visible at the image base; some code reads
    // its own PE header (e.g. to find resources).
    uint32_t hdr_copy = static_cast<uint32_t>(
        headers_size && headers_size <= f.size() ? headers_size : f.size());
    mem.write(img.image_base, f.data(), hdr_copy);

    size_t sh = oh + opt_size;
    std::vector<Section> sections;
    for (uint16_t i = 0; i < num_sections; ++i) {
        size_t p = sh + i * 40;
        Section s;
        char name[9] = {};
        std::memcpy(name, f.data() + p, 8);
        s.name = name;
        s.virtual_size = rd<uint32_t>(f, p + 8);
        s.virtual_addr = rd<uint32_t>(f, p + 12);
        s.raw_size = rd<uint32_t>(f, p + 16);
        s.raw_ptr = rd<uint32_t>(f, p + 20);
        sections.push_back(s);

        uint64_t va = img.image_base + s.virtual_addr;
        uint32_t span = s.virtual_size > s.raw_size ? s.virtual_size : s.raw_size;
        mem.map(va, span ? span : 1, ".. " + s.name);
        if (s.raw_size > 0 && s.raw_ptr + s.raw_size <= f.size())
            mem.write(va, f.data() + s.raw_ptr, s.raw_size);

        uint64_t end = va + span;
        if (end > img.brk) img.brk = end;
    }
    if (img.brk < img.image_base + img.image_size) img.brk = img.image_base + img.image_size;

    // ---- imports ----------------------------------------------------------
    if (num_dd > 1) {
        uint32_t imp_rva = rd<uint32_t>(f, dd + 8);
        uint32_t imp_size = rd<uint32_t>(f, dd + 12);
        if (imp_rva && imp_size) {
            for (uint32_t off = 0;; off += 20) {
                uint64_t desc = img.image_base + imp_rva + off;
                uint32_t orig_thunk = mem.read32(desc + 0);
                uint32_t name_rva = mem.read32(desc + 12);
                uint32_t first_thunk = mem.read32(desc + 16);
                if (orig_thunk == 0 && name_rva == 0 && first_thunk == 0) break;

                std::string dll = mem.read_cstring(img.image_base + name_rva, 256);
                // The name table (if present) survives binding; the address
                // table is what the guest actually calls through.
                uint32_t names = orig_thunk ? orig_thunk : first_thunk;
                int slot_size = plus ? 8 : 4;
                for (uint32_t i = 0;; ++i) {
                    uint64_t name_slot = img.image_base + names + i * slot_size;
                    uint64_t iat_slot = img.image_base + first_thunk + i * slot_size;
                    uint64_t ent = plus ? mem.read64(name_slot) : mem.read32(name_slot);
                    if (ent == 0) break;

                    std::string symbol;
                    uint64_t ordinal_bit = plus ? (1ull << 63) : (1ull << 31);
                    if (ent & ordinal_bit) {
                        char buf[32];
                        std::snprintf(buf, sizeof buf, "#%u",
                                      static_cast<unsigned>(ent & 0xFFFF));
                        symbol = buf;
                    } else {
                        // IMAGE_IMPORT_BY_NAME: 2-byte hint, then the name.
                        symbol = mem.read_cstring(img.image_base + (ent & 0x7FFFFFFFull) + 2, 256);
                    }

                    uint64_t target = bind(dll, symbol);
                    if (plus)
                        mem.write64(iat_slot, target);
                    else
                        mem.write32(iat_slot, static_cast<uint32_t>(target));
                }
            }
        }
    }

    return img;
}

}  // namespace x86emu
