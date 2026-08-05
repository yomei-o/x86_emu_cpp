// PE32 / PE32+ mapping.
//
// An executable is mapped at its preferred ImageBase, so it needs no relocation
// processing.  A DLL usually cannot have its preferred base - something else is
// already there - so this also applies the relocation directory, which is what
// makes loading several modules into one address space possible.
#include <cstdio>
#include <cstring>

#include "loader.h"
#include "pe.h"

namespace x86emu {
namespace {

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

// Offsets into the file that every path here needs.
struct Headers {
    size_t file_header;
    size_t optional_header;
    size_t data_directory;
    size_t section_table;
    uint16_t machine;
    uint16_t magic;
    uint16_t num_sections;
    uint32_t num_directories;
    bool plus;
};

Headers read_headers(const std::vector<uint8_t>& f) {
    if (f.size() < 0x40 || f[0] != 'M' || f[1] != 'Z') throw LoadError("not an MZ image");
    uint32_t pe_off = rd<uint32_t>(f, 0x3C);
    if (rd<uint32_t>(f, pe_off) != 0x00004550u) throw LoadError("missing PE signature");

    Headers h{};
    h.file_header = pe_off + 4;
    h.machine = rd<uint16_t>(f, h.file_header + 0);
    h.num_sections = rd<uint16_t>(f, h.file_header + 2);
    uint16_t opt_size = rd<uint16_t>(f, h.file_header + 16);
    h.optional_header = h.file_header + 20;
    h.magic = rd<uint16_t>(f, h.optional_header);
    h.plus = h.magic == kMagicPe32Plus;
    h.data_directory = h.optional_header + (h.plus ? 112 : 96);
    h.num_directories = rd<uint32_t>(f, h.optional_header + (h.plus ? 108 : 92));
    h.section_table = h.optional_header + opt_size;
    return h;
}

uint32_t directory_rva(const std::vector<uint8_t>& f, const Headers& h, int index) {
    if (static_cast<uint32_t>(index) >= h.num_directories) return 0;
    return rd<uint32_t>(f, h.data_directory + static_cast<size_t>(index) * 8);
}
uint32_t directory_size(const std::vector<uint8_t>& f, const Headers& h, int index) {
    if (static_cast<uint32_t>(index) >= h.num_directories) return 0;
    return rd<uint32_t>(f, h.data_directory + static_cast<size_t>(index) * 8 + 4);
}

// Walks the relocation directory, adding `delta` to every listed address.
void apply_relocations(Memory& mem, uint64_t base, uint32_t reloc_rva, uint32_t reloc_size,
                       int64_t delta, bool plus) {
    if (!reloc_rva || !reloc_size || delta == 0) return;
    uint64_t p = base + reloc_rva;
    uint64_t end = p + reloc_size;
    while (p + 8 <= end) {
        uint32_t page_rva = mem.read32(p);
        uint32_t block_size = mem.read32(p + 4);
        if (block_size < 8) break;
        uint64_t entries = (block_size - 8) / 2;
        for (uint64_t i = 0; i < entries; ++i) {
            uint16_t entry = mem.read16(p + 8 + i * 2);
            uint32_t type = entry >> 12;
            uint64_t at = base + page_rva + (entry & 0x0FFF);
            switch (type) {
                case 0:  // ABSOLUTE: padding, nothing to do
                    break;
                case 3:  // HIGHLOW: a 32-bit address
                    mem.write32(at, static_cast<uint32_t>(mem.read32(at) +
                                                          static_cast<uint32_t>(delta)));
                    break;
                case 10:  // DIR64: a 64-bit address
                    mem.write64(at, mem.read64(at) + static_cast<uint64_t>(delta));
                    break;
                default: {
                    char buf[64];
                    std::snprintf(buf, sizeof buf, "unsupported relocation type %u", type);
                    throw LoadError(buf);
                }
            }
        }
        (void)plus;
        p += block_size;
    }
}

void read_imports(Memory& mem, const std::vector<uint8_t>& f, const Headers& h, PeImage& img) {
    uint32_t rva = directory_rva(f, h, 1);
    if (!rva) return;
    const int slot_size = h.plus ? 8 : 4;
    const uint64_t ordinal_bit = h.plus ? (1ull << 63) : (1ull << 31);

    for (uint32_t off = 0;; off += 20) {
        uint64_t desc = img.base + rva + off;
        uint32_t orig_thunk = mem.read32(desc + 0);
        uint32_t name_rva = mem.read32(desc + 12);
        uint32_t first_thunk = mem.read32(desc + 16);
        if (orig_thunk == 0 && name_rva == 0 && first_thunk == 0) break;

        std::string dll = mem.read_cstring(img.base + name_rva, 256);
        // The name table survives binding; the address table is what the guest
        // actually calls through.
        uint32_t names = orig_thunk ? orig_thunk : first_thunk;
        for (uint32_t i = 0;; ++i) {
            uint64_t name_slot = img.base + names + i * slot_size;
            uint64_t iat_slot = img.base + first_thunk + i * slot_size;
            uint64_t ent = h.plus ? mem.read64(name_slot) : mem.read32(name_slot);
            if (ent == 0) break;

            PeImage::Import imp;
            imp.dll = dll;
            imp.slot = iat_slot;
            if (ent & ordinal_bit) {
                imp.ordinal = static_cast<uint32_t>(ent & 0xFFFF);
            } else {
                // IMAGE_IMPORT_BY_NAME: a 2-byte hint, then the name.
                imp.symbol = mem.read_cstring(img.base + (ent & 0x7FFFFFFFull) + 2, 512);
            }
            img.imports.push_back(std::move(imp));
        }
    }
}

void read_exports(Memory& mem, const std::vector<uint8_t>& f, const Headers& h, PeImage& img) {
    uint32_t rva = directory_rva(f, h, 0);
    uint32_t size = directory_size(f, h, 0);
    if (!rva) return;
    uint64_t dir = img.base + rva;

    uint32_t ordinal_base = mem.read32(dir + 16);
    uint32_t num_functions = mem.read32(dir + 20);
    uint32_t num_names = mem.read32(dir + 24);
    uint32_t functions_rva = mem.read32(dir + 28);
    uint32_t names_rva = mem.read32(dir + 32);
    uint32_t ordinals_rva = mem.read32(dir + 36);

    // Addresses first, by ordinal.
    std::vector<uint32_t> function_rvas(num_functions);
    for (uint32_t i = 0; i < num_functions; ++i)
        function_rvas[i] = mem.read32(img.base + functions_rva + i * 4);

    auto record = [&](const std::string& name, uint32_t function_rva, uint32_t ordinal) {
        // An address that points back inside the export directory is not code but
        // a string naming another DLL's symbol - a forwarder.
        if (function_rva >= rva && function_rva < rva + size) {
            std::string target = mem.read_cstring(img.base + function_rva, 256);
            if (!name.empty()) img.forwarders[name] = target;
            return;
        }
        uint64_t addr = img.base + function_rva;
        if (!name.empty()) img.exports[name] = addr;
        img.exports_by_ordinal[ordinal] = addr;
    };

    for (uint32_t i = 0; i < num_names; ++i) {
        uint32_t name_rva = mem.read32(img.base + names_rva + i * 4);
        uint16_t ordinal_index = mem.read16(img.base + ordinals_rva + i * 2);
        if (ordinal_index >= num_functions) continue;
        std::string name = mem.read_cstring(img.base + name_rva, 512);
        record(name, function_rvas[ordinal_index], ordinal_base + ordinal_index);
    }
    // Ordinal-only exports have no entry in the name table.
    for (uint32_t i = 0; i < num_functions; ++i) {
        uint32_t ordinal = ordinal_base + i;
        if (function_rvas[i] == 0) continue;
        if (img.exports_by_ordinal.find(ordinal) == img.exports_by_ordinal.end())
            record({}, function_rvas[i], ordinal);
    }
}

void read_tls(Memory& mem, const std::vector<uint8_t>& f, const Headers& h, PeImage& img) {
    uint32_t rva = directory_rva(f, h, 9);
    if (!rva) return;
    uint64_t dir = img.base + rva;
    int ps = h.plus ? 8 : 4;
    // IMAGE_TLS_DIRECTORY: raw data start and end, index address, callbacks
    // array, then the zero-fill size.  The first four are addresses, not RVAs,
    // and have already been relocated along with everything else.
    img.tls_raw_start = mem.read_sized(dir, ps);
    img.tls_raw_end = mem.read_sized(dir + static_cast<uint64_t>(ps), ps);
    img.tls_index_address = mem.read_sized(dir + static_cast<uint64_t>(ps) * 2, ps);
    uint64_t callbacks = mem.read_sized(dir + static_cast<uint64_t>(ps) * 3, ps);
    img.tls_zero_fill = mem.read32(dir + static_cast<uint64_t>(ps) * 4);
    if (!callbacks) return;
    for (int i = 0; i < 64; ++i) {
        uint64_t fn = mem.read_sized(callbacks + static_cast<uint64_t>(i) * ps, ps);
        if (!fn) break;
        img.tls_callbacks.push_back(fn);
    }
}

}  // namespace

void peek_pe(const std::vector<uint8_t>& f, Mode& mode, std::string& format, bool& is_dll) {
    Headers h = read_headers(f);
    if (h.magic == kMagicPe32Plus && h.machine == kMachineAmd64) {
        mode = Mode::X86_64;
        format = "PE32+";
    } else if (h.magic == kMagicPe32 && h.machine == kMachineI386) {
        mode = Mode::X86_32;
        format = "PE32";
    } else {
        char buf[96];
        std::snprintf(buf, sizeof buf, "unsupported PE (machine=0x%04X magic=0x%04X)", h.machine,
                      h.magic);
        throw LoadError(buf);
    }
    // IMAGE_FILE_DLL
    is_dll = (rd<uint16_t>(f, h.file_header + 18) & 0x2000) != 0;
}

uint64_t fixed_base_of(const std::vector<uint8_t>& f) {
    Headers h = read_headers(f);
    if (directory_rva(f, h, 5)) return 0;  // it has relocations: put it anywhere
    return h.plus ? rd<uint64_t>(f, h.optional_header + 24)
                  : rd<uint32_t>(f, h.optional_header + 28);
}

PeImage map_pe(const std::vector<uint8_t>& f, Memory& mem, uint64_t load_base) {
    Headers h = read_headers(f);
    PeImage img;
    peek_pe(f, img.mode, img.format, img.is_dll);

    img.preferred = h.plus ? rd<uint64_t>(f, h.optional_header + 24)
                           : rd<uint32_t>(f, h.optional_header + 28);
    img.base = load_base ? load_base : img.preferred;
    img.size = rd<uint32_t>(f, h.optional_header + 56);
    uint32_t entry_rva = rd<uint32_t>(f, h.optional_header + 16);
    uint32_t headers_size = rd<uint32_t>(f, h.optional_header + 60);
    if (img.size == 0) img.size = 0x10000;

    // Reserve the whole image so that gaps between sections are readable.
    mem.map(img.base, img.size, img.is_dll ? "dll" : "image");

    // Keep the headers visible: code does read its own PE header.
    uint32_t hdr_copy = headers_size && headers_size <= f.size()
                            ? headers_size
                            : static_cast<uint32_t>(f.size());
    mem.write(img.base, f.data(), hdr_copy);

    uint64_t highest = img.base + img.size;
    for (uint16_t i = 0; i < h.num_sections; ++i) {
        size_t p = h.section_table + static_cast<size_t>(i) * 40;
        char name[9] = {};
        std::memcpy(name, f.data() + p, 8);
        uint32_t virtual_size = rd<uint32_t>(f, p + 8);
        uint32_t virtual_addr = rd<uint32_t>(f, p + 12);
        uint32_t raw_size = rd<uint32_t>(f, p + 16);
        uint32_t raw_ptr = rd<uint32_t>(f, p + 20);

        uint64_t va = img.base + virtual_addr;
        uint32_t span = virtual_size > raw_size ? virtual_size : raw_size;
        mem.map(va, span ? span : 1, std::string(".. ") + name);
        if (raw_size > 0 && raw_ptr + raw_size <= f.size())
            mem.write(va, f.data() + raw_ptr, raw_size);
        if (va + span > highest) highest = va + span;
    }
    img.size = highest - img.base;

    // Relocate before reading any directory, so every address is already correct.
    int64_t delta = static_cast<int64_t>(img.base) - static_cast<int64_t>(img.preferred);
    if (delta != 0) {
        uint32_t reloc_rva = directory_rva(f, h, 5);
        uint32_t reloc_size = directory_size(f, h, 5);
        // An image with nothing to relocate can be mapped anywhere: a
        // resource-only DLL - the localised message strings a toolchain prints -
        // has no entry point and no imports, so no absolute address inside it is
        // ever used.  Its resources are found by RVA from wherever it landed.
        bool resource_only = entry_rva == 0 && directory_rva(f, h, 1) == 0;
        if (!reloc_rva && !resource_only) {
            char buf[176];
            std::snprintf(buf, sizeof buf,
                          "image has no relocation directory, so it can only load at its "
                          "preferred base 0x%llX, but it was asked for 0x%llX",
                          (unsigned long long)img.preferred, (unsigned long long)img.base);
            throw LoadError(buf);
        }
        // With no relocation directory there is nothing to fix up: the mapping
        // above was the whole job.
        if (reloc_rva) apply_relocations(mem, img.base, reloc_rva, reloc_size, delta, h.plus);
        img.relocated = true;
    }

    if (entry_rva) img.entry = img.base + entry_rva;
    // Directory 3 is IMAGE_DIRECTORY_ENTRY_EXCEPTION; only x64 images have one.
    if (uint32_t pdata_rva = directory_rva(f, h, 3)) {
        img.exception_table = img.base + pdata_rva;
        img.exception_table_size = directory_size(f, h, 3);
    }
    // Directory 2 is IMAGE_DIRECTORY_ENTRY_RESOURCE.
    if (uint32_t rsrc_rva = directory_rva(f, h, 2)) {
        img.resource_table = img.base + rsrc_rva;
        img.resource_table_size = directory_size(f, h, 2);
    }
    read_imports(mem, f, h, img);
    read_exports(mem, f, h, img);
    read_tls(mem, f, h, img);
    return img;
}

}  // namespace x86emu
