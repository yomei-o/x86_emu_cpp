// Generates the ELF test binaries for the emulator.
//
// A cross toolchain that targets Linux is not always at hand (and is overkill
// for a hello world), so the machine code here is assembled by hand.  The
// programs are statically linked in the strictest sense: they contain nothing
// but their own instructions and talk to the kernel through raw syscalls, which
// is exactly the path the emulator implements in syscalls.cpp.
//
//   build: g++ -std=c++17 -O1 -o gen_elf_tests tools/gen_elf_tests.cpp
//   run:   ./gen_elf_tests tests/bin
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct Buf {
    std::vector<uint8_t> b;

    void u8(uint8_t v) { b.push_back(v); }
    void u16(uint16_t v) {
        for (int i = 0; i < 2; ++i) b.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
    void bytes(const void* p, size_t n) {
        const auto* q = static_cast<const uint8_t*>(p);
        b.insert(b.end(), q, q + n);
    }
    void str(const std::string& s) { bytes(s.data(), s.size()); }
    size_t size() const { return b.size(); }
    void patch32(size_t at, uint32_t v) {
        for (int i = 0; i < 4; ++i) b[at + i] = static_cast<uint8_t>(v >> (i * 8));
    }
    void patch64(size_t at, uint64_t v) {
        for (int i = 0; i < 8; ++i) b[at + i] = static_cast<uint8_t>(v >> (i * 8));
    }
};

const std::string kMsg1 = "hello from the ELF guest!\n";
const std::string kMsg2 = "count = 0\n";  // the digit gets rewritten each pass
const size_t kDigitOffset = 8;            // index of that digit inside kMsg2

bool write_file(const std::string& path, const Buf& buf) {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) {
        std::fprintf(stderr, "cannot write %s\n", path.c_str());
        return false;
    }
    std::fwrite(buf.b.data(), 1, buf.b.size(), f);
    std::fclose(f);
    std::printf("   %s (%zu bytes)\n", path.c_str(), buf.b.size());
    return true;
}

// ---------------------------------------------------------------------------
// i386: syscalls through int 0x80, arguments in EBX/ECX/EDX
// ---------------------------------------------------------------------------
Buf build_elf32() {
    constexpr uint32_t kBase = 0x08048000;
    constexpr uint32_t kEhdrSize = 52, kPhdrSize = 32;
    const uint32_t code_off = kEhdrSize + kPhdrSize;

    Buf code;
    std::vector<std::pair<size_t, int>> fixups;  // patch site -> which message
    auto imm32_msg = [&](int which) {
        fixups.emplace_back(code.size(), which);
        code.u32(0);
    };

    // write(1, msg1, len1)
    code.u8(0xB8); code.u32(4);              // mov eax, 4 (SYS_write)
    code.u8(0xBB); code.u32(1);              // mov ebx, 1 (stdout)
    code.u8(0xB9); imm32_msg(1);             // mov ecx, msg1
    code.u8(0xBA); code.u32(static_cast<uint32_t>(kMsg1.size()));  // mov edx, len
    code.u8(0xCD); code.u8(0x80);            // int 0x80

    code.u8(0xBF); code.u32('1');            // mov edi, '1'  (loop counter)
    size_t loop_start = code.size();
    code.u8(0x89); code.u8(0xF8);            // mov eax, edi
    code.u8(0xA2); imm32_msg(3);             // mov [digit], al
    code.u8(0xB8); code.u32(4);              // mov eax, 4
    code.u8(0xBB); code.u32(1);              // mov ebx, 1
    code.u8(0xB9); imm32_msg(2);             // mov ecx, msg2
    code.u8(0xBA); code.u32(static_cast<uint32_t>(kMsg2.size()));
    code.u8(0xCD); code.u8(0x80);            // int 0x80
    code.u8(0x47);                           // inc edi
    code.u8(0x83); code.u8(0xFF); code.u8('4');  // cmp edi, '4'
    code.u8(0x75);                           // jne loop_start
    code.u8(static_cast<uint8_t>(static_cast<int8_t>(
        static_cast<long>(loop_start) - static_cast<long>(code.size() + 1))));

    // exit(7)
    code.u8(0xB8); code.u32(1);              // mov eax, 1 (SYS_exit)
    code.u8(0xBB); code.u32(7);              // mov ebx, 7
    code.u8(0xCD); code.u8(0x80);

    const uint32_t data_off = code_off + static_cast<uint32_t>(code.size());
    const uint32_t msg1_addr = kBase + data_off;
    const uint32_t msg2_addr = msg1_addr + static_cast<uint32_t>(kMsg1.size());
    for (auto& [at, which] : fixups) {
        uint32_t v = which == 1 ? msg1_addr
                   : which == 2 ? msg2_addr
                                : msg2_addr + static_cast<uint32_t>(kDigitOffset);
        code.patch32(at, v);
    }

    const uint32_t total = data_off + static_cast<uint32_t>(kMsg1.size() + kMsg2.size());
    Buf out;
    // ELF header
    out.u8(0x7F); out.str("ELF");
    out.u8(1); out.u8(1); out.u8(1); out.u8(0);  // 32-bit, little endian, v1, SysV
    for (int i = 0; i < 8; ++i) out.u8(0);
    out.u16(2);                    // ET_EXEC
    out.u16(3);                    // EM_386
    out.u32(1);
    out.u32(kBase + code_off);     // e_entry
    out.u32(kEhdrSize);            // e_phoff
    out.u32(0);                    // e_shoff
    out.u32(0);                    // e_flags
    out.u16(kEhdrSize);
    out.u16(kPhdrSize);
    out.u16(1);                    // one program header
    out.u16(40); out.u16(0); out.u16(0);
    // Program header: map the whole file, read/write/execute (the guest patches
    // a byte of its own data).
    out.u32(1);                    // PT_LOAD
    out.u32(0);                    // p_offset
    out.u32(kBase);                // p_vaddr
    out.u32(kBase);                // p_paddr
    out.u32(total);                // p_filesz
    out.u32(total);                // p_memsz
    out.u32(7);                    // RWX
    out.u32(0x1000);
    out.bytes(code.b.data(), code.b.size());
    out.str(kMsg1);
    out.str(kMsg2);
    return out;
}

// ---------------------------------------------------------------------------
// x86-64: the `syscall` instruction, arguments in RDI/RSI/RDX
// ---------------------------------------------------------------------------
Buf build_elf64() {
    constexpr uint64_t kBase = 0x400000;
    constexpr uint64_t kEhdrSize = 64, kPhdrSize = 56;
    const uint64_t code_off = kEhdrSize + kPhdrSize;

    Buf code;
    std::vector<std::pair<size_t, int>> abs64;  // mov rsi, imm64 sites
    std::vector<size_t> riprel;                 // rip-relative store to the digit

    auto mov_rsi_msg = [&](int which) {
        code.u8(0x48); code.u8(0xBE);  // mov rsi, imm64
        abs64.emplace_back(code.size(), which);
        code.u64(0);
    };

    // write(1, msg1, len1)
    code.u8(0xB8); code.u32(1);      // mov eax, 1 (SYS_write)
    code.u8(0xBF); code.u32(1);      // mov edi, 1
    mov_rsi_msg(1);
    code.u8(0xBA); code.u32(static_cast<uint32_t>(kMsg1.size()));  // mov edx, len
    code.u8(0x0F); code.u8(0x05);    // syscall

    code.u8(0x41); code.u8(0xB4); code.u8('1');  // mov r12b, '1'
    size_t loop_start = code.size();
    // mov [rip+disp32], r12b - exercises RIP-relative addressing with REX.R
    code.u8(0x44); code.u8(0x88); code.u8(0x25);
    riprel.push_back(code.size());
    code.u32(0);
    code.u8(0xB8); code.u32(1);      // mov eax, 1
    code.u8(0xBF); code.u32(1);      // mov edi, 1
    mov_rsi_msg(2);
    code.u8(0xBA); code.u32(static_cast<uint32_t>(kMsg2.size()));
    code.u8(0x0F); code.u8(0x05);    // syscall
    code.u8(0x41); code.u8(0xFE); code.u8(0xC4);          // inc r12b
    code.u8(0x41); code.u8(0x80); code.u8(0xFC); code.u8('4');  // cmp r12b, '4'
    code.u8(0x75);                                        // jne loop_start
    code.u8(static_cast<uint8_t>(static_cast<int8_t>(
        static_cast<long>(loop_start) - static_cast<long>(code.size() + 1))));

    // exit(7)
    code.u8(0xB8); code.u32(60);     // mov eax, 60 (SYS_exit)
    code.u8(0xBF); code.u32(7);      // mov edi, 7
    code.u8(0x0F); code.u8(0x05);

    const uint64_t data_off = code_off + code.size();
    const uint64_t msg1_addr = kBase + data_off;
    const uint64_t msg2_addr = msg1_addr + kMsg1.size();
    const uint64_t digit_addr = msg2_addr + kDigitOffset;
    for (auto& [at, which] : abs64) code.patch64(at, which == 1 ? msg1_addr : msg2_addr);
    for (size_t at : riprel) {
        // The displacement is relative to the end of the instruction, which is
        // right after the 4 displacement bytes.
        uint64_t next_insn = kBase + code_off + at + 4;
        code.patch32(at, static_cast<uint32_t>(digit_addr - next_insn));
    }

    const uint64_t total = data_off + kMsg1.size() + kMsg2.size();
    Buf out;
    out.u8(0x7F); out.str("ELF");
    out.u8(2); out.u8(1); out.u8(1); out.u8(0);  // 64-bit, little endian, v1, SysV
    for (int i = 0; i < 8; ++i) out.u8(0);
    out.u16(2);                    // ET_EXEC
    out.u16(62);                   // EM_X86_64
    out.u32(1);
    out.u64(kBase + code_off);     // e_entry
    out.u64(kEhdrSize);            // e_phoff
    out.u64(0);                    // e_shoff
    out.u32(0);                    // e_flags
    out.u16(kEhdrSize);
    out.u16(kPhdrSize);
    out.u16(1);
    out.u16(64); out.u16(0); out.u16(0);
    out.u32(1);                    // PT_LOAD
    out.u32(7);                    // RWX
    out.u64(0);                    // p_offset
    out.u64(kBase);                // p_vaddr
    out.u64(kBase);                // p_paddr
    out.u64(total);                // p_filesz
    out.u64(total);                // p_memsz
    out.u64(0x1000);
    out.bytes(code.b.data(), code.b.size());
    out.str(kMsg1);
    out.str(kMsg2);
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    std::string dir = argc > 1 ? argv[1] : ".";
    std::printf("== generating ELF test programs\n");
    bool ok = write_file(dir + "/hello_elf32", build_elf32()) &&
              write_file(dir + "/hello_elf64", build_elf64());
    return ok ? 0 : 1;
}
