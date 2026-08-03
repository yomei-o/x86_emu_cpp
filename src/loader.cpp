#include <cstdio>
#include <cstring>

#include "loader.h"

namespace x86emu {

std::vector<uint8_t> read_file(const std::string& path) {
    std::FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) throw LoadError("cannot open " + path);
    std::fseek(fp, 0, SEEK_END);
    long size = std::ftell(fp);
    std::fseek(fp, 0, SEEK_SET);
    if (size < 0) {
        std::fclose(fp);
        throw LoadError("cannot determine size of " + path);
    }
    std::vector<uint8_t> data(static_cast<size_t>(size));
    size_t got = data.empty() ? 0 : std::fread(data.data(), 1, data.size(), fp);
    std::fclose(fp);
    if (got != data.size()) throw LoadError("short read on " + path);
    return data;
}

void peek_image(const std::vector<uint8_t>& f, Mode& mode, Os& os, std::string& format) {
    auto u16 = [&](size_t o) -> uint16_t {
        if (o + 2 > f.size()) throw LoadError("truncated image header");
        return static_cast<uint16_t>(f[o] | (f[o + 1] << 8));
    };
    auto u32 = [&](size_t o) -> uint32_t {
        if (o + 4 > f.size()) throw LoadError("truncated image header");
        return static_cast<uint32_t>(f[o]) | (static_cast<uint32_t>(f[o + 1]) << 8) |
               (static_cast<uint32_t>(f[o + 2]) << 16) | (static_cast<uint32_t>(f[o + 3]) << 24);
    };

    if (f.size() > 4 && f[0] == 0x7F && f[1] == 'E' && f[2] == 'L' && f[3] == 'F') {
        os = Os::Linux;
        bool is64 = f[4] == 2;
        mode = is64 ? Mode::X86_64 : Mode::X86_32;
        format = is64 ? "ELF64" : "ELF32";
        return;
    }
    if (f.size() > 0x40 && f[0] == 'M' && f[1] == 'Z') {
        os = Os::Windows;
        uint32_t pe = u32(0x3C);
        if (u32(pe) != 0x00004550u) throw LoadError("MZ image without a PE header");
        uint16_t machine = u16(pe + 4);
        bool is64 = machine == 0x8664;
        mode = is64 ? Mode::X86_64 : Mode::X86_32;
        format = is64 ? "PE32+" : "PE32";
        return;
    }
    throw LoadError("unrecognised executable format (expected PE or ELF)");
}

}  // namespace x86emu
