// The Visual C++ toolchain's surface: what cl.exe, its compiler DLLs
// (c1.dll, c1xx.dll, c2.dll) and link.exe need beyond the API the earlier
// guests already exercised.  Almost all of it is the UCRT's wide-character
// dialect plus a few kernel32 corners (thread pools, file mappings).
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include "emulator.h"
#include "guest_printf.h"
#include "processes.h"

#if defined(_WIN32)
#include <direct.h>
#else
#include <unistd.h>
#endif

namespace x86emu {
namespace {

// Writes a UTF-16 string with NUL, returning units written including the NUL.
int put_wide(Emulator& e, uint64_t dst, const std::string& s, uint64_t capacity_units) {
    std::u16string w = utf8_to_utf16(s);
    if (!dst || w.size() + 1 > capacity_units) return -static_cast<int>(w.size() + 1);
    for (size_t i = 0; i <= w.size(); ++i)
        e.mem.write16(dst + i * 2, i < w.size() ? w[i] : 0);
    return static_cast<int>(w.size() + 1);
}

std::string wide_arg(Emulator& e, uint64_t ptr) {
    return ptr ? utf16_to_utf8(e, ptr, -1) : std::string();
}

#if defined(_WIN32)
// Declared here rather than by including <windows.h>, which would drag the whole
// Win32 namespace into a file that defines its own CONTEXT-shaped things.
extern "C" __declspec(dllimport) unsigned short __stdcall GetUserDefaultUILanguage(void);
#endif

// The language a guest with localised resources should be told to look for.
// Taking it from the host is what makes a real toolchain find its message DLL:
// a Japanese Visual Studio ships only 1041, an English one only 1033, and a
// guest that asks for the wrong one has nothing to print its errors with.
uint32_t host_ui_language() {
#if defined(_WIN32)
    unsigned short id = GetUserDefaultUILanguage();
    if (id) return id;
#endif
    return 0x0409;  // en-US
}

// LANGID -> the RFC-style name Windows uses for the same language.  Only the
// languages a toolchain is actually shipped in are worth listing; anything else
// falls back to English, which every localised program also carries.
std::string language_name(uint32_t langid) {
    switch (langid & 0x3FF) {
        case 0x11: return "ja-JP";
        case 0x04: return "zh-CN";
        case 0x07: return "de-DE";
        case 0x0A: return "es-ES";
        case 0x0C: return "fr-FR";
        case 0x10: return "it-IT";
        case 0x12: return "ko-KR";
        case 0x15: return "pl-PL";
        case 0x16: return "pt-BR";
        case 0x19: return "ru-RU";
        case 0x1F: return "tr-TR";
        case 0x0B: return "fi-FI";
        default: return "en-US";
    }
}

}  // namespace

void Emulator::install_cl_hooks() {
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, is64() ? 0 : nargs * 4, std::move(fn));
    };
    auto ucrt = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };
    auto ret0 = [&](const char* name, int nargs) {
        win32(name, nargs, [](Emulator& e) { e.set_result(0); });
    };
    auto ret1 = [&](const char* name, int nargs) {
        win32(name, nargs, [](Emulator& e) { e.set_result(1); });
    };

    // ---- advapi32: crypto and event tracing ---------------------------------------
    // (phProv, container, provider, type, flags).  Returning success is not
    // enough: the *handle* is the answer, and a caller that checks it - cl.exe
    // does, and reports an unknown error when it is zero - sees nothing.  An
    // out parameter left unwritten is the quietest way for a hook to lie.
    auto acquire_context = [](Emulator& e) {
        constexpr uint64_t kProviderHandle = 0xC0DE0001;
        if (e.arg_slot(0)) e.mem.write_sized(e.arg_slot(0), e.pointer_size(), kProviderHandle);
        e.set_result(1);
    };
    win32("CryptAcquireContextW", 5, acquire_context);
    win32("CryptAcquireContextA", 5, acquire_context);
    ret1("CryptReleaseContext", 2);
    win32("CryptGenRandom", 3, [](Emulator& e) {
        uint64_t len = e.arg_slot(1), buf = e.arg_slot(2);
        uint32_t state = 0xC0FFEE42u;
        for (uint64_t i = 0; i < len; ++i) {
            state = state * 1103515245u + 12345u;
            e.mem.write8(buf + i, static_cast<uint8_t>(state >> 16));
        }
        e.set_result(1);
    });
    // The hashing side of the crypto API, which a toolchain uses to derive a
    // name - for a temporary file, or a build key - from some bytes.  A real
    // digest is needed rather than a stub: the caller uses the *value*, and two
    // different inputs must not collide.  FNV-1a spread over the requested
    // length is not MD5, but it is a function of the input, which is what a name
    // needs; nothing here depends on the digest being cryptographic.
    {
        struct Hash {
            std::vector<uint8_t> data;
        };
        auto hashes = std::make_shared<std::unordered_map<uint64_t, Hash>>();
        auto next = std::make_shared<uint64_t>(0xC0DE1000);
        // (provider, algorithm, key, flags, out handle)
        win32("CryptCreateHash", 5, [hashes, next](Emulator& e) {
            uint64_t h = (*next += 16);
            (*hashes)[h] = Hash{};
            if (e.arg_slot(4)) e.mem.write_sized(e.arg_slot(4), e.pointer_size(), h);
            e.set_result(1);
        });
        // (hash, data, length, flags)
        win32("CryptHashData", 4, [hashes](Emulator& e) {
            auto it = hashes->find(e.arg_slot(0));
            if (it == hashes->end()) {
                e.set_result(0);
                return;
            }
            uint64_t len = e.arg_slot(2);
            size_t at = it->second.data.size();
            it->second.data.resize(at + static_cast<size_t>(len));
            if (len) e.mem.read(e.arg_slot(1), it->second.data.data() + at, len);
            e.set_result(1);
        });
        // (hash, param, buffer, *length, flags).  HP_HASHVAL is 2, HP_HASHSIZE 4.
        win32("CryptGetHashParam", 5, [hashes](Emulator& e) {
            auto it = hashes->find(e.arg_slot(0));
            if (it == hashes->end()) {
                e.set_result(0);
                return;
            }
            uint32_t param = static_cast<uint32_t>(e.arg_slot(1));
            uint64_t buf = e.arg_slot(2), len_ptr = e.arg_slot(3);
            constexpr uint32_t kHashVal = 2, kHashSize = 4;
            if (param == kHashSize) {
                if (buf) e.mem.write32(buf, 16);
                if (len_ptr) e.mem.write32(len_ptr, 4);
                e.set_result(1);
                return;
            }
            if (param != kHashVal) {
                e.set_result(0);
                return;
            }
            uint32_t want = len_ptr ? e.mem.read32(len_ptr) : 16;
            if (!buf) {
                if (len_ptr) e.mem.write32(len_ptr, 16);
                e.set_result(1);
                return;
            }
            if (want > 64) want = 64;
            // One FNV-1a per output byte, seeded by its index, so the whole
            // digest depends on the whole input.
            for (uint32_t i = 0; i < want; ++i) {
                uint64_t acc = 1469598103934665603ull + i;
                for (uint8_t b : it->second.data) {
                    acc ^= b;
                    acc *= 1099511628211ull;
                }
                e.mem.write8(buf + i, static_cast<uint8_t>(acc >> 24));
            }
            if (len_ptr) e.mem.write32(len_ptr, want);
            e.set_result(1);
        });
        win32("CryptDestroyHash", 1, [hashes](Emulator& e) {
            hashes->erase(e.arg_slot(0));
            e.set_result(1);
        });
    }
    ret0("EventRegister", 4);
    ret0("EventUnregister", 1);
    ret0("EventWriteTransfer", 7);
    ret0("EventSetInformation", 4);
    win32("RegOpenKeyExW", 5, [](Emulator& e) { e.set_result(2); });   // FILE_NOT_FOUND
    win32("RegGetValueW", 7, [](Emulator& e) { e.set_result(2); });
    win32("RegQueryValueExW", 6, [](Emulator& e) { e.set_result(2); });
    ret0("RegCloseKey", 1);

    // ---- kernel32 ------------------------------------------------------------------
    ret1("AreFileApisANSI", 0);
    win32("CompareStringEx", 9, [](Emulator& e) {
        // (locale, flags, s1, len1, s2, len2, ...); -1 lengths mean NUL-terminated.
        auto read = [&](uint64_t p, int64_t len) {
            return utf16_to_utf8(e, p, static_cast<int>(len));
        };
        std::string a = read(e.arg_slot(2), static_cast<int64_t>(e.arg_slot(3)));
        std::string b = read(e.arg_slot(4), static_cast<int64_t>(e.arg_slot(5)));
        constexpr uint64_t kIgnoreCase = 1;  // NORM_IGNORECASE / LINGUISTIC_IGNORECASE share bit 0
        if (e.arg_slot(1) & kIgnoreCase) {
            for (char& c : a) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char& c : b) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        int c = a.compare(b);
        e.set_result(c < 0 ? 1u : c > 0 ? 3u : 2u);  // CSTR_LESS_THAN/EQUAL/GREATER
    });
    win32("CopyFileW", 3, [](Emulator& e) {
        std::string from = FileTable::host_path(wide_arg(e, e.arg_slot(0)));
        std::string to = FileTable::host_path(wide_arg(e, e.arg_slot(1)));
        std::FILE* in = std::fopen(from.c_str(), "rb");
        if (!in) {
            e.set_last_error(2);
            e.set_result(0);
            return;
        }
        if (e.arg_slot(2)) {  // bFailIfExists
            if (std::FILE* probe = std::fopen(to.c_str(), "rb")) {
                std::fclose(probe);
                std::fclose(in);
                e.set_last_error(80);  // ERROR_FILE_EXISTS
                e.set_result(0);
                return;
            }
        }
        std::FILE* out = std::fopen(to.c_str(), "wb");
        if (!out) {
            std::fclose(in);
            e.set_last_error(5);
            e.set_result(0);
            return;
        }
        char buf[65536];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof buf, in)) > 0) std::fwrite(buf, 1, n, out);
        std::fclose(in);
        std::fclose(out);
        e.set_result(1);
    });
    ret0("CreateHardLinkW", 3);
    ret0("CreateSymbolicLinkW", 3);
    win32("CreateToolhelp32Snapshot", 2, [](Emulator& e) { e.set_result(~0ull); });
    ret0("Process32FirstW", 2);
    ret0("Process32NextW", 2);
    // ---- resources -----------------------------------------------------------------
    // The resource directory is a three-level tree: type, then name, then
    // language.  A localised program keeps every string it prints in a
    // resource-only DLL, so without this it cannot even report why it failed.
    // An HRSRC here is the address of the IMAGE_RESOURCE_DATA_ENTRY, which is
    // what real Windows hands out too.
    auto find_resource = [](Emulator& e, uint64_t module, uint64_t name, uint64_t type,
                            uint64_t language) -> uint64_t {
        Module* m = e.module_for(module ? module : e.image().image_base);
        if (!m || !m->image.resource_table) return 0;
        uint64_t root = m->image.resource_table;

        // One level of the tree: match by integer id or by name.
        auto find_entry = [&e](uint64_t dir, uint64_t key, uint64_t base) -> uint64_t {
            uint32_t named = e.mem.read16(dir + 12);
            uint32_t ids = e.mem.read16(dir + 14);
            bool by_name = key >= 0x10000;
            std::string wanted;
            if (by_name) {
                wanted = utf16_to_utf8(e, key, -1);
                for (char& c : wanted)
                    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            }
            for (uint32_t i = 0; i < named + ids; ++i) {
                uint64_t entry = dir + 16 + static_cast<uint64_t>(i) * 8;
                uint32_t id = e.mem.read32(entry);
                uint32_t offset = e.mem.read32(entry + 4);
                bool entry_named = (id & 0x80000000u) != 0;
                if (by_name != entry_named) continue;
                if (entry_named) {
                    uint64_t str = base + (id & 0x7FFFFFFFu);
                    uint32_t len = e.mem.read16(str);
                    std::string got;
                    for (uint32_t k = 0; k < len; ++k) {
                        uint16_t c = e.mem.read16(str + 2 + k * 2);
                        got += static_cast<char>(c < 128 ? std::toupper(static_cast<int>(c))
                                                         : '?');
                    }
                    if (got != wanted) continue;
                } else if (id != static_cast<uint32_t>(key)) {
                    continue;
                }
                // Every offset in the tree is measured from its base; the high
                // bit only says whether this points at a subdirectory or at a
                // leaf, and the caller already knows which level it is on.
                return base + (offset & 0x7FFFFFFFu);
            }
            return 0;
        };

        uint64_t by_type = find_entry(root, type, root);
        if (!by_type) return 0;
        uint64_t by_name = find_entry(by_type, name, root);
        if (!by_name) return 0;
        // The language level: take the requested one, else the first entry,
        // because a resource DLL usually holds exactly one language.
        uint64_t leaf = language ? find_entry(by_name, language, root) : 0;
        if (!leaf) {
            uint32_t count = e.mem.read16(by_name + 12) + e.mem.read16(by_name + 14);
            if (!count) return 0;
            leaf = root + (e.mem.read32(by_name + 16 + 4) & 0x7FFFFFFFu);
        }
        return leaf;
    };
    win32("FindResourceW", 3, [find_resource](Emulator& e) {
        uint64_t found = find_resource(e, e.arg_slot(0), e.arg_slot(1), e.arg_slot(2), 0);
        // Which resource a guest looked for, and whether it was there, is the
        // whole story when a localised program prints the wrong message.
        e.log_call("FindResource(module 0x%llX, type %llu, name %llu) = 0x%llX",
                   (unsigned long long)e.arg_slot(0), (unsigned long long)e.arg_slot(2),
                   (unsigned long long)e.arg_slot(1), (unsigned long long)found);
        if (const char* want = std::getenv("X86EMU_TRACE_RESOURCE")) {
            // Debugging aid for a guest that prints the wrong message: dumping
            // the instruction history at the moment it looks up a particular
            // string shows which code decided to print it.
            if (e.arg_slot(1) == static_cast<uint64_t>(std::atoi(want))) {
                std::fprintf(stderr, "[dbg] resource %s looked up from:\n%s", want,
                             e.stack_trace(24).c_str());
                for (uint64_t a : e.cpu().history())
                    std::fprintf(stderr, "    %012llX\n", (unsigned long long)a);
            }
        }
        e.set_result(found);
    });
    win32("FindResourceA", 3, [find_resource](Emulator& e) {
        e.set_result(find_resource(e, e.arg_slot(0), e.arg_slot(1), e.arg_slot(2), 0));
    });
    win32("FindResourceExW", 4, [find_resource](Emulator& e) {
        e.set_result(
            find_resource(e, e.arg_slot(0), e.arg_slot(2), e.arg_slot(1), e.arg_slot(3)));
    });
    win32("LoadResource", 2, [](Emulator& e) {
        uint64_t data_entry = e.arg_slot(1);
        Module* m = e.module_for(e.arg_slot(0) ? e.arg_slot(0) : e.image().image_base);
        if (!data_entry || !m) {
            e.set_result(0);
            return;
        }
        // OffsetToData is an RVA, unlike every other offset in the tree.
        e.set_result(m->image.base + e.mem.read32(data_entry));
    });
    win32("LockResource", 1, [](Emulator& e) { e.set_result(e.arg_slot(0)); });
    win32("FreeResource", 1, [](Emulator& e) { e.set_result(1); });
    win32("SizeofResource", 2, [](Emulator& e) {
        uint64_t data_entry = e.arg_slot(1);
        e.set_result(data_entry ? e.mem.read32(data_entry + 4) : 0);
    });
    ret0("FlushProcessWriteBuffers", 0);
    ret0("FreeLibraryWhenCallbackReturns", 2);

    // ntdll's UNICODE_STRING helpers: {Length, MaximumLength, Buffer}, with the
    // two lengths counted in *bytes* rather than characters.  A guest reaching
    // for these has usually already built the string; it wants the descriptor.
    win32("RtlInitUnicodeString", 2, [](Emulator& e) {
        uint64_t out = e.arg_slot(0), src = e.arg_slot(1);
        if (!out) {
            e.set_result(0);
            return;
        }
        uint64_t units = src ? utf8_to_utf16(wide_arg(e, src)).size() : 0;
        e.mem.write16(out, static_cast<uint16_t>(units * 2));
        e.mem.write16(out + 2, static_cast<uint16_t>((units + 1) * 2));
        e.mem.write_sized(out + 8, e.pointer_size(), src);
        e.set_result(0);
    });
    win32("RtlCreateUnicodeString", 2, [](Emulator& e) {
        // Unlike Init, this one *copies* the text into memory of its own.
        uint64_t out = e.arg_slot(0), src = e.arg_slot(1);
        if (!out || !src) {
            e.set_result(0);
            return;
        }
        std::u16string w = utf8_to_utf16(wide_arg(e, src));
        std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
        std::memcpy(raw.data(), w.data(), w.size() * 2);
        uint64_t buf = e.alloc_guest_data(raw.data(), raw.size());
        e.mem.write16(out, static_cast<uint16_t>(w.size() * 2));
        e.mem.write16(out + 2, static_cast<uint16_t>((w.size() + 1) * 2));
        e.mem.write_sized(out + 8, e.pointer_size(), buf);
        e.set_result(1);
    });
    ret0("RtlFreeUnicodeString", 1);

    // The native file interface.  A toolchain that opens files through ntdll
    // rather than kernel32 is asking for the same thing in a lower-level
    // spelling: the path arrives as a UNICODE_STRING inside OBJECT_ATTRIBUTES,
    // in NT namespace form ("\??\C:\dir\file"), and the answer is an NTSTATUS
    // plus a handle written through a pointer.
    auto nt_path = [](Emulator& e, uint64_t object_attributes) -> std::string {
        if (!object_attributes) return {};
        int ps = e.pointer_size();
        uint64_t name = e.mem.read_sized(object_attributes + 0x10, ps);
        if (!name) return {};
        uint32_t bytes = e.mem.read16(name);
        uint64_t buf = e.mem.read_sized(name + 8, ps);
        if (!buf) return {};
        std::string path = utf16_to_utf8(e, buf, static_cast<int>(bytes / 2));
        // "\??\" and "\DosDevices\" both introduce a drive-letter path.
        if (path.compare(0, 4, "\\??\\") == 0) path.erase(0, 4);
        else if (path.compare(0, 12, "\\DosDevices\\") == 0) path.erase(0, 12);

        // RootDirectory turns the name into a *relative* one - which is how a
        // guest opens a directory once and then the files inside it, and how
        // this call ends up looking like it was given only a directory name.
        uint64_t root = e.mem.read_sized(object_attributes + 8, ps);
        if (root) {
            int dir_fd = Emulator::fd_from_handle(root);
            FileTable::Entry* dir = dir_fd >= 0 ? e.files.get(dir_fd) : nullptr;
            if (dir && !dir->path.empty()) {
                std::string base = dir->path;
                char last = base.back();
                if (last != '\\' && last != '/') base += '\\';
                path = base + path;
            }
        }
        return path;
    };
    auto nt_open = [nt_path](Emulator& e, bool creating) {
        constexpr uint32_t kStatusSuccess = 0;
        constexpr uint32_t kStatusNotFound = 0xC0000034;   // OBJECT_NAME_NOT_FOUND
        constexpr uint32_t kStatusCollision = 0xC0000035;  // OBJECT_NAME_COLLISION
        uint64_t handle_out = e.arg_slot(0);
        // These are 32-bit parameters; the rest of the slot they arrive in holds
        // whatever was there before, so it has to be masked off.
        uint32_t access = static_cast<uint32_t>(e.arg_slot(1));
        std::string path = nt_path(e, e.arg_slot(2));
        uint64_t status_block = e.arg_slot(3);
        // NtCreateFile has AllocationSize/FileAttributes/ShareAccess before the
        // disposition; NtOpenFile has neither and no disposition at all.
        uint32_t disposition = creating ? static_cast<uint32_t>(e.arg_slot(7)) : 1 /* FILE_OPEN */;
        uint32_t options = static_cast<uint32_t>(e.arg_slot(creating ? 8 : 5));

        FileTable::OpenFlags f;
        constexpr uint64_t kReadData = 0x1, kWriteData = 0x2, kAppendData = 0x4;
        constexpr uint64_t kGenericRead = 0x80000000, kGenericWrite = 0x40000000;
        f.read = (access & (kReadData | kGenericRead)) != 0;
        f.write = (access & (kWriteData | kAppendData | kGenericWrite)) != 0;
        if (!f.read && !f.write) f.read = true;  // an attributes-only open
        switch (disposition) {
            case 2: f.create = f.exclusive = f.write = true; break;   // FILE_CREATE
            case 3: f.create = true; break;                           // FILE_OPEN_IF
            case 0: case 4: case 5:                                   // SUPERSEDE/OVERWRITE*
                f.create = f.truncate = f.write = true;
                break;
            default: break;                                           // FILE_OPEN
        }
        // A directory is opened by name too - FILE_DIRECTORY_FILE says so, and a
        // guest that asks for one then uses it as OBJECT_ATTRIBUTES.RootDirectory.
        constexpr uint32_t kDirectoryFile = 0x1;
        FileTable::Stat st;
        bool is_directory = (options & kDirectoryFile) != 0 ||
                            (FileTable::stat_path(path, st) == 0 && st.is_dir);
        int fd = is_directory ? e.files.open_directory(path) : e.files.open(path, f);
        e.log_call("NtCreateFile(%s%s, access 0x%X, disposition %u) = %d", path.c_str(),
                   is_directory ? " [directory]" : "", access, disposition, fd);
        uint32_t status = kStatusSuccess;
        if (fd < 0) status = fd == -17 ? kStatusCollision : kStatusNotFound;
        if (handle_out)
            e.mem.write_sized(handle_out, e.pointer_size(),
                              fd < 0 ? 0 : Emulator::handle_from_fd(fd));
        if (status_block) {
            e.mem.write32(status_block, status);
            // Information: which of the disposition's outcomes happened.  1 is
            // FILE_OPENED, 2 FILE_CREATED; nothing here inspects it closely.
            e.mem.write_sized(status_block + 8, e.pointer_size(), disposition == 2 ? 2 : 1);
        }
        e.set_result(status);
    };
    win32("NtCreateFile", 11, [nt_open](Emulator& e) { nt_open(e, true); });
    win32("ZwCreateFile", 11, [nt_open](Emulator& e) { nt_open(e, true); });
    win32("NtOpenFile", 6, [nt_open](Emulator& e) { nt_open(e, false); });
    win32("NtClose", 1, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        if (fd >= 3) e.files.close(fd);
        e.set_result(0);
    });
    // (handle, io status, buffer, length, class).  The classes a toolchain asks
    // about are the ones that decide whether a path is on a local disk and how
    // big its blocks are; both answers are the same for every file here.
    win32("NtQueryVolumeInformationFile", 5, [](Emulator& e) {
        uint64_t status_block = e.arg_slot(1), buf = e.arg_slot(2);
        uint32_t length = static_cast<uint32_t>(e.arg_slot(3));
        uint32_t info_class = static_cast<uint32_t>(e.arg_slot(4));
        constexpr uint32_t kFsDeviceInformation = 4;
        constexpr uint32_t kFsSizeInformation = 3;
        constexpr uint32_t kFsAttributeInformation = 5;
        std::vector<uint8_t> zeros(length, 0);
        if (buf && length) e.mem.write(buf, zeros.data(), zeros.size());
        uint64_t written = 0;
        if (buf && info_class == kFsDeviceInformation && length >= 8) {
            e.mem.write32(buf, 0x7);       // FILE_DEVICE_DISK
            e.mem.write32(buf + 4, 0x10);  // FILE_DEVICE_IS_MOUNTED
            written = 8;
        } else if (buf && info_class == kFsSizeInformation && length >= 24) {
            e.mem.write64(buf, 1ull << 24);       // TotalAllocationUnits
            e.mem.write64(buf + 8, 1ull << 23);   // AvailableAllocationUnits
            e.mem.write32(buf + 16, 8);           // SectorsPerAllocationUnit
            e.mem.write32(buf + 20, 512);         // BytesPerSector
            written = 24;
        } else if (buf && info_class == kFsAttributeInformation && length >= 16) {
            e.mem.write32(buf, 0x0000000F);       // case-sensitive search etc.
            e.mem.write32(buf + 4, 255);          // MaximumComponentNameLength
            e.mem.write32(buf + 8, 8);            // FileSystemNameLength ("NTFS")
            const char16_t ntfs[] = u"NTFS";
            for (int i = 0; i < 4; ++i) e.mem.write16(buf + 12 + i * 2, ntfs[i]);
            written = 20;
        }
        if (status_block) {
            e.mem.write32(status_block, 0);
            e.mem.write_sized(status_block + 8, e.pointer_size(), written);
        }
        e.set_result(0);
    });
    // (handle, io status, buffer, length, class): the per-file queries.  Only the
    // ones a toolchain uses to size a read are worth answering properly.
    win32("NtQueryInformationFile", 5, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        uint64_t status_block = e.arg_slot(1), buf = e.arg_slot(2);
        uint32_t length = static_cast<uint32_t>(e.arg_slot(3));
        uint32_t info_class = static_cast<uint32_t>(e.arg_slot(4));
        constexpr uint32_t kFileStandardInformation = 5;
        constexpr uint32_t kFilePositionInformation = 14;
        FileTable::Stat st;
        bool have = fd >= 0 && e.files.stat_fd(fd, st) == 0;
        std::vector<uint8_t> zeros(length, 0);
        if (buf && length) e.mem.write(buf, zeros.data(), zeros.size());
        uint64_t written = 0;
        if (buf && info_class == kFileStandardInformation && length >= 24 && have) {
            e.mem.write64(buf, st.size);           // AllocationSize
            e.mem.write64(buf + 8, st.size);       // EndOfFile
            e.mem.write32(buf + 16, 1);            // NumberOfLinks
            e.mem.write8(buf + 20, 0);             // DeletePending
            e.mem.write8(buf + 21, st.is_dir ? 1 : 0);
            written = 24;
        } else if (buf && info_class == kFilePositionInformation && length >= 8) {
            int64_t at = fd >= 0 ? e.files.tell(fd) : 0;
            e.mem.write64(buf, static_cast<uint64_t>(at < 0 ? 0 : at));
            written = 8;
        }
        if (status_block) {
            e.mem.write32(status_block, have || written ? 0 : 0xC0000008 /* INVALID_HANDLE */);
            e.mem.write_sized(status_block + 8, e.pointer_size(), written);
        }
        e.set_result(have || written ? 0 : 0xC0000008);
    });
    // (handle, event, apc, apc ctx, io status, buffer, length, offset, key)
    win32("NtReadFile", 9, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        uint64_t status_block = e.arg_slot(4), buf = e.arg_slot(5);
        uint64_t length = static_cast<uint32_t>(e.arg_slot(6));
        uint64_t offset_ptr = e.arg_slot(7);
        if (fd < 0) {
            e.set_result(0xC0000008);
            return;
        }
        int64_t saved = -1;
        if (offset_ptr) {
            int64_t want = static_cast<int64_t>(e.mem.read64(offset_ptr));
            // A negative offset means "use the current position".
            if (want >= 0) {
                saved = e.files.tell(fd);
                e.files.seek(fd, want, 0);
            }
        }
        std::vector<uint8_t> tmp(static_cast<size_t>(length));
        int64_t got = length ? e.files.read(fd, tmp.data(), length) : 0;
        if (got > 0) e.mem.write(buf, tmp.data(), static_cast<uint64_t>(got));
        if (saved >= 0) e.files.seek(fd, saved, 0);
        constexpr uint32_t kStatusEndOfFile = 0xC0000011;
        uint32_t status = got > 0 ? 0 : (got == 0 ? kStatusEndOfFile : 0xC0000022);
        if (status_block) {
            e.mem.write32(status_block, status);
            e.mem.write_sized(status_block + 8, e.pointer_size(),
                              got > 0 ? static_cast<uint64_t>(got) : 0);
        }
        e.set_result(status);
    });
    win32("NtWriteFile", 9, [](Emulator& e) {
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        uint64_t status_block = e.arg_slot(4), buf = e.arg_slot(5);
        uint64_t length = static_cast<uint32_t>(e.arg_slot(6));
        if (fd < 0) {
            e.set_result(0xC0000008);
            return;
        }
        std::vector<uint8_t> tmp(static_cast<size_t>(length));
        if (length) e.mem.read(buf, tmp.data(), length);
        int64_t put = length ? e.files.write(fd, tmp.data(), length) : 0;
        if (status_block) {
            e.mem.write32(status_block, put < 0 ? 0xC0000022 : 0);
            e.mem.write_sized(status_block + 8, e.pointer_size(),
                              put > 0 ? static_cast<uint64_t>(put) : 0);
        }
        e.set_result(put < 0 ? 0xC0000022 : 0);
    });
    // (handle, event, apc, apc ctx, io status, buffer, length, class,
    //  single entry, name filter, restart).  The directory walk in its native
    //  form: a toolchain looks for a source file this way, so the filter - which
    //  may be an exact name rather than a wildcard - has to be honoured.
    win32("NtQueryDirectoryFile", 11, [](Emulator& e) {
        constexpr uint32_t kStatusNoMoreFiles = 0x80000006;
        constexpr uint32_t kStatusInvalidHandle = 0xC0000008;
        constexpr uint32_t kStatusBufferOverflow = 0x80000005;
        int fd = Emulator::fd_from_handle(e.arg_slot(0));
        FileTable::Entry* dir = fd >= 0 ? e.files.get(fd) : nullptr;
        if (!dir || !dir->is_directory) {
            e.set_result(kStatusInvalidHandle);
            return;
        }
        uint64_t status_block = e.arg_slot(4), buf = e.arg_slot(5);
        uint32_t length = static_cast<uint32_t>(e.arg_slot(6));
        uint32_t info_class = static_cast<uint32_t>(e.arg_slot(7));
        bool single = (e.arg_slot(8) & 0xFF) != 0;
        uint64_t filter_ptr = e.arg_slot(9);
        bool restart = (e.arg_slot(10) & 0xFF) != 0;

        std::string filter;
        if (filter_ptr) {
            uint32_t bytes = e.mem.read16(filter_ptr);
            uint64_t text = e.mem.read_sized(filter_ptr + 8, e.pointer_size());
            if (text) filter = utf16_to_utf8(e, text, static_cast<int>(bytes / 2));
        }
        if (filter.empty()) filter = "*";

        // The listing is snapshotted on the first call and walked by a cursor,
        // the same state getdents64 uses.  A new filter or RestartScan starts over.
        if (restart || !dir->dir_loaded || dir->dir_filter != filter) {
            dir->dir_loaded = true;
            dir->dir_filter = filter;
            dir->dir_pos = 0;
            dir->dir_names.clear();
            dir->dir_types.clear();
            for (const auto& de : e.list_directory(dir->path + "/" + filter)) {
                dir->dir_names.push_back(de.name);
                dir->dir_types.push_back(de.is_dir ? 4 : 8);
            }
        }

        // Where the name sits, and the fixed part's size, depend on the class.
        uint32_t header = 0;
        switch (info_class) {
            case 1: header = 0x40; break;   // FileDirectoryInformation
            case 2: header = 0x44; break;   // FileFullDirectoryInformation
            case 3: header = 0x5E; break;   // FileBothDirectoryInformation
            case 12: header = 0x0C; break;  // FileNamesInformation
            case 37: header = 0x58; break;  // FileIdBothDirectoryInformation
            default: header = 0x40; break;
        }

        uint32_t written = 0;
        uint64_t last_entry = 0;
        while (dir->dir_pos < dir->dir_names.size()) {
            const std::string& name = dir->dir_names[dir->dir_pos];
            std::u16string wide = utf8_to_utf16(name);
            uint32_t need = header + static_cast<uint32_t>(wide.size() * 2);
            need = (need + 7) & ~7u;
            if (written + need > length) {
                if (!written) {
                    if (status_block) e.mem.write32(status_block, kStatusBufferOverflow);
                    e.set_result(kStatusBufferOverflow);
                    return;
                }
                break;
            }
            uint64_t entry = buf + written;
            std::vector<uint8_t> zeros(need, 0);
            e.mem.write(entry, zeros.data(), zeros.size());
            FileTable::Stat st;
            std::string full = dir->path + "/" + name;
            bool have = FileTable::stat_path(full, st) == 0;
            uint64_t ticks = have ? (static_cast<uint64_t>(st.mtime) + 11644473600ull) * 10000000ull
                                  : 0;
            e.mem.write32(entry + 4, static_cast<uint32_t>(dir->dir_pos));  // FileIndex
            if (info_class == 12) {
                e.mem.write32(entry + 8, static_cast<uint32_t>(wide.size() * 2));
            } else {
                e.mem.write64(entry + 0x08, ticks);
                e.mem.write64(entry + 0x10, ticks);
                e.mem.write64(entry + 0x18, ticks);
                e.mem.write64(entry + 0x20, ticks);
                e.mem.write64(entry + 0x28, have ? st.size : 0);
                e.mem.write64(entry + 0x30, have ? st.size : 0);
                e.mem.write32(entry + 0x38, dir->dir_types[dir->dir_pos] == 4 ? 0x10u : 0x80u);
                e.mem.write32(entry + 0x3C, static_cast<uint32_t>(wide.size() * 2));
            }
            for (size_t i = 0; i < wide.size(); ++i)
                e.mem.write16(entry + header + i * 2, wide[i]);
            if (last_entry) e.mem.write32(last_entry, static_cast<uint32_t>(entry - last_entry));
            last_entry = entry;
            written += need;
            ++dir->dir_pos;
            if (single) break;
        }
        if (last_entry) e.mem.write32(last_entry, 0);  // the list ends here

        uint32_t status = written ? 0 : kStatusNoMoreFiles;
        if (status_block) {
            e.mem.write32(status_block, status);
            e.mem.write_sized(status_block + 8, e.pointer_size(), written);
        }
        e.set_result(status);
    });

    // (attributes, out): the cheap "does this exist" query.
    win32("NtQueryAttributesFile", 2, [nt_path](Emulator& e) {
        std::string path = nt_path(e, e.arg_slot(0));
        FileTable::Stat st;
        if (FileTable::stat_path(path, st) != 0) {
            e.set_result(0xC0000034);  // OBJECT_NAME_NOT_FOUND
            return;
        }
        uint64_t out = e.arg_slot(1);
        if (out) {
            std::vector<uint8_t> zeros(56, 0);
            e.mem.write(out, zeros.data(), zeros.size());
            uint64_t ticks = (static_cast<uint64_t>(st.mtime) + 11644473600ull) * 10000000ull;
            e.mem.write64(out + 8, ticks);   // CreationTime
            e.mem.write64(out + 16, ticks);  // LastAccessTime
            e.mem.write64(out + 24, ticks);  // LastWriteTime
            e.mem.write64(out + 32, ticks);  // ChangeTime
            e.mem.write32(out + 40, st.is_dir ? 0x10u : 0x80u);
        }
        e.set_result(0);
    });

    // version.dll, which a toolchain *delay-loads* to read a file's version
    // resource.  Reporting "no version information" is a normal answer that
    // callers handle; not being there at all is not - the delay-load helper
    // raises 0xC06D007F for a missing procedure, and cl.exe turns that into an
    // internal compiler error naming nothing.
    win32("GetFileVersionInfoSizeW", 2, [](Emulator& e) {
        if (e.arg_slot(1)) e.mem.write32(e.arg_slot(1), 0);
        e.set_last_error(1813);  // ERROR_RESOURCE_TYPE_NOT_FOUND
        e.set_result(0);
    });
    win32("GetFileVersionInfoSizeA", 2, [](Emulator& e) {
        if (e.arg_slot(1)) e.mem.write32(e.arg_slot(1), 0);
        e.set_last_error(1813);
        e.set_result(0);
    });
    ret0("GetFileVersionInfoW", 4);
    ret0("GetFileVersionInfoA", 4);
    ret0("VerQueryValueW", 4);
    ret0("VerQueryValueA", 4);
    // The OS-version comparison pair.  VerSetConditionMask packs a condition per
    // type into a 64-bit mask (3 bits each), and VerifyVersionInfo evaluates the
    // request against what the emulator claims to be - Windows 10 build 19045.
    // Answering "yes" to everything would tell a guest it is on a newer Windows
    // than it is, so the comparison is done properly.
    win32("VerSetConditionMask", 3, [](Emulator& e) {
        uint64_t mask = e.arg_slot(0);
        uint32_t type_bit_mask = static_cast<uint32_t>(e.arg_slot(1));
        uint32_t condition = static_cast<uint32_t>(e.arg_slot(2)) & 0x7;
        // The type flags are single bits; each one owns three bits of the mask at
        // (index of that bit) * 3.
        for (int i = 0; i < 8; ++i) {
            if (!(type_bit_mask & (1u << i))) continue;
            mask &= ~(uint64_t{0x7} << (i * 3));
            mask |= static_cast<uint64_t>(condition) << (i * 3);
        }
        e.set_result(mask);
    });
    win32("VerifyVersionInfoW", 4, [](Emulator& e) {
        // (OSVERSIONINFOEX*, type mask, condition mask).  What the emulator is:
        constexpr uint32_t kMajor = 10, kMinor = 0, kBuild = 19045;
        uint64_t info = e.arg_slot(0);
        uint32_t types = static_cast<uint32_t>(e.arg_slot(1));
        uint64_t conditions = e.arg_slot(2);
        if (!info) {
            e.set_last_error(87);  // ERROR_INVALID_PARAMETER
            e.set_result(0);
            return;
        }
        // VER_MAJORVERSION 0x2 -> field at +4, MINORVERSION 0x1 -> +8,
        // BUILDNUMBER 0x4 -> +12, in the order the mask's bits are numbered.
        struct Check {
            uint32_t flag;
            uint64_t offset;
            uint32_t actual;
        } checks[] = {{0x1, 8, kMinor}, {0x2, 4, kMajor}, {0x4, 12, kBuild}};
        bool ok = true;
        for (const Check& c : checks) {
            if (!(types & c.flag)) continue;
            uint32_t wanted = e.mem.read32(info + c.offset);
            int bit = 0;
            for (int i = 0; i < 8; ++i)
                if (c.flag & (1u << i)) bit = i;
            uint32_t condition = static_cast<uint32_t>((conditions >> (bit * 3)) & 0x7);
            switch (condition) {
                case 1: ok = ok && c.actual == wanted; break;   // VER_EQUAL
                case 2: ok = ok && c.actual > wanted; break;    // VER_GREATER
                case 3: ok = ok && c.actual >= wanted; break;   // VER_GREATER_EQUAL
                case 4: ok = ok && c.actual < wanted; break;    // VER_LESS
                case 5: ok = ok && c.actual <= wanted; break;   // VER_LESS_EQUAL
                default: break;
            }
        }
        if (!ok) e.set_last_error(1150);  // ERROR_OLD_WIN_VERSION
        e.set_result(ok ? 1 : 0);
    });
    // Two more a modern toolchain probes for and can live without; naming them
    // here means GetProcAddress answers NULL rather than a delay-load failing.
    ret0("GetCurrentPackageId", 2);
    win32("GetTempPath2W", 2, [](Emulator& e) {
        // Windows 10+ spelling of GetTempPathW; the older one is implemented.
        if (uint64_t hook = e.existing_hook("GetTempPathW")) {
            e.cpu().rip = hook;
            e.retry_current_call();
            return;
        }
        e.set_result(0);
    });
    win32("GetDiskFreeSpaceExW", 4, [](Emulator& e) {
        for (int i = 1; i <= 3; ++i)
            if (e.arg_slot(i)) e.mem.write64(e.arg_slot(i), 64ull << 30);  // plenty
        e.set_result(1);
    });
    ret0("GetLocaleInfoEx", 4);
    // Same answer as GetSystemInfo: there is no WOW64 layer to differ about.
    win32("GetNativeSystemInfo", 1, [](Emulator& e) {
        if (uint64_t hook = e.existing_hook("GetSystemInfo")) {
            // Reuse the real implementation rather than keeping a second copy of
            // a structure whose zero fields a guest divides by.
            e.cpu().rip = hook;
            e.retry_current_call();
            return;
        }
        e.set_result(0);
    });
    // The preferred UI languages, which a program with localised resources uses
    // to decide which resource DLL to load.  A guest typically *sets* a
    // candidate and reads it back to see whether the system accepted it, so the
    // faithful implementation is to remember what it set: it then goes looking
    // for that language's resources and copes with their absence itself.
    {
        // {flags, the double-NUL-terminated list as the guest wrote it}, seeded
        // with the host's own UI language in both spellings a guest may ask for.
        uint32_t langid = host_ui_language();
        char id_text[8];
        std::snprintf(id_text, sizeof id_text, "%04X", langid);
        std::u16string default_id = utf8_to_utf16(id_text);
        default_id.push_back(0);
        std::u16string default_name = utf8_to_utf16(language_name(langid));
        default_name.push_back(0);
        auto stored = std::make_shared<std::pair<uint32_t, std::u16string>>(0u, default_name);
        // (flags, languages, *count)
        win32("SetThreadPreferredUILanguages", 3, [stored](Emulator& e) {
            uint32_t flags = static_cast<uint32_t>(e.arg_slot(0));
            uint64_t p = e.arg_slot(1);
            std::u16string list;
            if (p) {
                // Two NULs in a row end the list.
                for (uint64_t i = 0; i < 4096; ++i) {
                    uint16_t c = e.mem.read16(p + i * 2);
                    if (!c && (i == 0 || list.back() == 0)) break;
                    list.push_back(static_cast<char16_t>(c));
                }
            }
            if (!list.empty()) *stored = {flags, list};
            if (e.arg_slot(2)) {
                uint32_t n = 0;
                for (size_t i = 0; i < list.size(); ++i)
                    if (list[i] == 0 && i && list[i - 1] != 0) ++n;
                e.mem.write32(e.arg_slot(2), n);
            }
            e.set_result(1);
        });
        // (flags, *count, buffer, *size in characters)
        win32("GetThreadPreferredUILanguages", 4,
              [stored, default_id, default_name](Emulator& e) {
            uint32_t flags = static_cast<uint32_t>(e.arg_slot(0));
            constexpr uint32_t kLanguageId = 0x4, kLanguageName = 0x8;
            std::u16string list = stored->second;
            // If the guest wants a different spelling than the one it set, fall
            // back to a default in that spelling rather than handing back
            // something it cannot parse.
            bool stored_is_id = (stored->first & kLanguageId) != 0;
            bool want_id = (flags & kLanguageId) != 0;
            if ((flags & (kLanguageId | kLanguageName)) && want_id != stored_is_id)
                list = want_id ? default_id : default_name;
            list.push_back(0);  // the list's own terminator

            uint64_t count_out = e.arg_slot(1), buf = e.arg_slot(2), size_out = e.arg_slot(3);
            uint32_t languages = 0;
            for (size_t i = 0; i + 1 < list.size(); ++i)
                if (list[i] == 0 && i && list[i - 1] != 0) ++languages;
            if (count_out) e.mem.write32(count_out, languages);
            uint64_t have = size_out ? e.mem.read32(size_out) : 0;
            if (size_out) e.mem.write32(size_out, static_cast<uint32_t>(list.size()));
            if (!buf || have < list.size()) {
                // Reporting the size needed is success for the query form and
                // ERROR_INSUFFICIENT_BUFFER otherwise; both leave the buffer be.
                e.set_result(buf ? 0 : 1);
                if (buf) e.set_last_error(122);
                return;
            }
            for (size_t i = 0; i < list.size(); ++i)
                e.mem.write16(buf + i * 2, list[i]);
            e.set_result(1);
        });
    }
    win32("RtlCaptureStackBackTrace", 4, [](Emulator& e) { e.set_result(0); });
    win32("SearchPathW", 6, [](Emulator& e) {
        // (path, file, extension, buflen, buf, filepart)
        std::string file = wide_arg(e, e.arg_slot(1));
        std::string ext = wide_arg(e, e.arg_slot(2));
        auto exists = [](const std::string& p) {
            FileTable::Stat st;
            return FileTable::stat_path(p, st) == 0 && !st.is_dir;
        };
        auto try_dir = [&](std::string dir) -> std::string {
            if (!dir.empty() && dir.back() != '\\' && dir.back() != '/') dir += '\\';
            std::string full = dir + file;
            if (exists(full)) return full;
            if (!ext.empty() && exists(full + ext)) return full + ext;
            return {};
        };
        std::string found;
        if (e.arg_slot(0)) {
            found = try_dir(wide_arg(e, e.arg_slot(0)));
        } else {
            found = try_dir(".");
            if (found.empty()) {
                if (const std::string* pathv = e.getenv("PATH")) {
                    size_t start = 0;
                    while (found.empty() && start <= pathv->size()) {
                        size_t sep = pathv->find(';', start);
                        std::string dir = pathv->substr(
                            start, sep == std::string::npos ? std::string::npos : sep - start);
                        if (!dir.empty()) found = try_dir(dir);
                        if (sep == std::string::npos) break;
                        start = sep + 1;
                    }
                }
            }
        }
        if (found.empty()) {
            e.set_result(0);
            return;
        }
        int n = put_wide(e, e.arg_slot(4), found, e.arg_slot(3));
        e.set_result(n < 0 ? static_cast<uint64_t>(-n) : static_cast<uint64_t>(n - 1));
    });

    // Thread pools, driven synchronously: submitting a work item runs it on the
    // spot, so by the time anything waits for the pool it is already drained.
    {
        struct Work {
            uint64_t callback = 0, context = 0;
        };
        auto works = std::make_shared<std::unordered_map<uint64_t, Work>>();
        auto next = std::make_shared<uint64_t>(0xD0000000ull);
        win32("CreateThreadpoolWork", 3, [works, next](Emulator& e) {
            uint64_t h = (*next += 16);
            (*works)[h] = Work{e.arg_slot(0), e.arg_slot(1)};
            e.set_result(h);
        });
        win32("SubmitThreadpoolWork", 1, [works](Emulator& e) {
            auto it = works->find(e.arg_slot(0));
            if (it != works->end())
                e.call_guest(it->second.callback, {0, it->second.context, it->first});
            e.set_result(0);
        });
        ret0("WaitForThreadpoolWorkCallbacks", 2);
        win32("CloseThreadpoolWork", 1, [works](Emulator& e) {
            works->erase(e.arg_slot(0));
            e.set_result(0);
        });
        win32("CreateThreadpoolTimer", 3, [next](Emulator& e) { e.set_result(*next += 16); });
        ret0("SetThreadpoolTimer", 4);
        ret0("WaitForThreadpoolTimerCallbacks", 2);
        ret0("CloseThreadpoolTimer", 1);
        win32("CreateThreadpoolWait", 3, [next](Emulator& e) { e.set_result(*next += 16); });
        ret0("SetThreadpoolWait", 3);
        ret0("CloseThreadpoolWait", 1);
    }

    // One-time initialisation: the INIT_ONCE word itself records "has run".
    win32("InitOnceExecuteOnce", 4, [](Emulator& e) {
        uint64_t once = e.arg_slot(0);
        int ps = e.pointer_size();
        if (e.mem.read_sized(once, ps) == 0) {
            e.mem.write_sized(once, ps, 1);
            e.call_guest(e.arg_slot(1), {once, e.arg_slot(2), e.arg_slot(3)});
        }
        e.set_result(1);
    });

    // File mappings: a view is the file's bytes read into fresh guest pages.
    {
        struct Mapping {
            int fd = -1;
        };
        auto maps = std::make_shared<std::unordered_map<uint64_t, Mapping>>();
        auto next = std::make_shared<uint64_t>(0xE0000000ull);
        auto create_mapping = [maps, next](Emulator& e) {
            int fd = Emulator::fd_from_handle(e.arg_slot(0));
            if (fd < 0 || !e.files.valid(fd)) {
                e.set_result(0);
                return;
            }
            uint64_t h = (*next += 16);
            (*maps)[h] = Mapping{fd};
            e.set_result(h);
        };
        win32("CreateFileMappingA", 6, create_mapping);
        win32("CreateFileMappingW", 6, create_mapping);
        auto map_view = [maps](Emulator& e, uint64_t base) {
            auto it = maps->find(e.arg_slot(0));
            if (it == maps->end()) {
                e.set_result(0);
                return;
            }
            int fd = it->second.fd;
            uint64_t offset = (e.arg_slot(2) << 32) | (e.arg_slot(3) & 0xFFFFFFFFull);
            uint64_t size = e.arg_slot(4);
            if (!size) {
                int64_t file_size = e.files.size(fd);
                if (file_size < 0 || static_cast<uint64_t>(file_size) < offset) {
                    e.set_result(0);
                    return;
                }
                size = static_cast<uint64_t>(file_size) - offset;
            }
            uint64_t target;
            if (base) {
                e.mem.map(base, size, "file view");
                target = base;
            } else {
                target = e.alloc_pages(size);
            }
            int64_t saved = e.files.tell(fd);
            if (e.files.seek(fd, static_cast<int64_t>(offset), 0) >= 0) {
                std::vector<uint8_t> buf(static_cast<size_t>(size));
                int64_t got = e.files.read(fd, buf.data(), size);
                if (got > 0) e.mem.write(target, buf.data(), static_cast<uint64_t>(got));
            }
            if (saved >= 0) e.files.seek(fd, saved, 0);
            e.set_result(target);
        };
        win32("MapViewOfFile", 5, [map_view](Emulator& e) { map_view(e, 0); });
        win32("MapViewOfFileEx", 6, [map_view](Emulator& e) { map_view(e, e.arg_slot(5)); });
        ret1("UnmapViewOfFile", 1);
        ret1("FlushViewOfFile", 2);
    }

    // ---- vcruntime -----------------------------------------------------------------
    win32("__AdjustPointer", 2, [](Emulator& e) { e.set_result(e.arg_slot(0)); });
    ucrt("__std_exception_copy", [](Emulator& e) {
        // (const from*, to*): struct { char* what; bool do_free; }
        uint64_t from = e.arg_slot(0), to = e.arg_slot(1);
        int ps = e.pointer_size();
        uint64_t what = e.mem.read_sized(from, ps);
        if (what) what = e.alloc_guest_string(e.mem.read_cstring(what));
        e.mem.write_sized(to, ps, what);
        e.mem.write8(to + ps, what ? 1 : 0);
        e.set_result(0);
    });
    ucrt("__std_exception_destroy", [](Emulator& e) {
        int ps = e.pointer_size();
        e.mem.write_sized(e.arg_slot(0), ps, 0);
        e.set_result(0);
    });
    ucrt("__std_terminate", [](Emulator& e) {
        e.write_text(2, "terminate() called\n");
        e.exit_process(3);
    });
    ucrt("__uncaught_exception", [](Emulator& e) { e.set_result(0); });
    ucrt("__uncaught_exceptions", [](Emulator& e) { e.set_result(0); });

    // ---- UCRT: conversion ------------------------------------------------------------
    ucrt("_itow_s", [](Emulator& e) {
        char text[32];
        long long v = static_cast<int32_t>(e.arg_slot(0));
        int radix = static_cast<int>(e.arg_slot(3));
        std::snprintf(text, sizeof text, radix == 16 ? "%llx" : radix == 8 ? "%llo" : "%lld", v);
        put_wide(e, e.arg_slot(1), text, e.arg_slot(2));
        e.set_result(0);
    });
    // The bounded integer-to-string family.  (value, buffer, size, radix) for the
    // narrow ones; _i64toa_s and _ui64toa_s put the 64-bit value first, so the
    // buffer is one slot further along.
    auto int_to_string = [](Emulator& e, bool wide, bool wide_value, bool sign) {
        int slot = 0;
        int64_t value;
        if (wide_value)
            value = static_cast<int64_t>(e.arg_slot(slot++));
        else
            value = sign ? static_cast<int32_t>(e.arg_slot(slot++))
                         : static_cast<int64_t>(static_cast<uint32_t>(e.arg_slot(slot++)));
        uint64_t buf = e.arg_slot(slot++);
        uint64_t size = e.arg_slot(slot++);
        int radix = static_cast<int>(e.arg_slot(slot));
        if (radix < 2 || radix > 36) radix = 10;

        // Only base 10 is signed; every other base treats the value as unsigned,
        // which is what the CRT does and what a caller printing a bitmask wants.
        std::string text;
        bool negative = sign && radix == 10 && value < 0;
        uint64_t magnitude = negative ? ~static_cast<uint64_t>(value) + 1
                                      : static_cast<uint64_t>(value);
        if (!wide_value && !sign) magnitude &= 0xFFFFFFFFull;
        do {
            int digit = static_cast<int>(magnitude % static_cast<uint64_t>(radix));
            text += static_cast<char>(digit < 10 ? '0' + digit : 'a' + digit - 10);
            magnitude /= static_cast<uint64_t>(radix);
        } while (magnitude);
        if (negative) text += '-';
        std::reverse(text.begin(), text.end());

        if (!buf || text.size() + 1 > size) {
            e.set_result(34);  // ERANGE
            return;
        }
        if (wide)
            put_wide(e, buf, text, size);
        else
            e.mem.write_cstring(buf, text);
        e.set_result(0);
    };
    ucrt("_itoa_s", [int_to_string](Emulator& e) { int_to_string(e, false, false, true); });
    ucrt("_ltoa_s", [int_to_string](Emulator& e) { int_to_string(e, false, false, true); });
    ucrt("_ultoa_s", [int_to_string](Emulator& e) { int_to_string(e, false, false, false); });
    ucrt("_i64toa_s", [int_to_string](Emulator& e) { int_to_string(e, false, true, true); });
    ucrt("_ui64toa_s", [int_to_string](Emulator& e) { int_to_string(e, false, true, false); });
    ucrt("_ltow_s", [int_to_string](Emulator& e) { int_to_string(e, true, false, true); });
    ucrt("_ultow_s", [int_to_string](Emulator& e) { int_to_string(e, true, false, false); });
    ucrt("_i64tow_s", [int_to_string](Emulator& e) { int_to_string(e, true, true, true); });
    ucrt("_ui64tow_s", [int_to_string](Emulator& e) { int_to_string(e, true, true, false); });

    ucrt("_wtoi", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(
            std::strtol(wide_arg(e, e.arg_slot(0)).c_str(), nullptr, 10))));
    });
    ucrt("_wtoi64", [](Emulator& e) {
        e.set_result(static_cast<uint64_t>(
            std::strtoll(wide_arg(e, e.arg_slot(0)).c_str(), nullptr, 10)));
    });
    ucrt("btowc", [](Emulator& e) {
        uint64_t c = e.arg_slot(0);
        e.set_result(c <= 0x7F ? c : 0xFFFFFFFFull);  // WEOF outside ASCII
    });
    ucrt("strtof", [](Emulator& e) {
        std::string s = e.mem.read_cstring(e.arg_slot(0));
        char* end = nullptr;
        float v = std::strtof(s.c_str(), &end);
        if (e.arg_slot(1)) e.mem.write_sized(e.arg_slot(1), e.pointer_size(),
                                             e.arg_slot(0) + (end - s.c_str()));
        e.set_result_float(v);
    });
    ucrt("wcstoul", [](Emulator& e) {
        std::string s = wide_arg(e, e.arg_slot(0));
        char* end = nullptr;
        unsigned long v = std::strtoul(s.c_str(), &end, static_cast<int>(e.arg_slot(2)));
        if (e.arg_slot(1)) e.mem.write_sized(e.arg_slot(1), e.pointer_size(),
                                             e.arg_slot(0) + 2 * (end - s.c_str()));
        e.set_result(v);
    });

    // ---- UCRT: environment and filesystem, wide ---------------------------------------
    ucrt("_wgetenv_s", [](Emulator& e) {
        // (size_t* len, buf, bufsize, name)
        const std::string* v = e.getenv(wide_arg(e, e.arg_slot(3)));
        uint64_t len_out = e.arg_slot(0);
        if (!v) {
            if (len_out) e.mem.write_sized(len_out, e.pointer_size(), 0);
            e.set_result(0);
            return;
        }
        std::u16string w = utf8_to_utf16(*v);
        if (len_out) e.mem.write_sized(len_out, e.pointer_size(), w.size() + 1);
        if (e.arg_slot(1) && e.arg_slot(2) > w.size()) put_wide(e, e.arg_slot(1), *v, e.arg_slot(2));
        e.set_result(0);
    });
    ucrt("_lock_file", [](Emulator& e) { e.set_result(0); });
    ucrt("_unlock_file", [](Emulator& e) { e.set_result(0); });
    ucrt("_waccess_s", [](Emulator& e) {
        FileTable::Stat st;
        e.set_result(FileTable::stat_path(wide_arg(e, e.arg_slot(0)), st) == 0 ? 0 : 2);
    });
    ucrt("_waccess", [](Emulator& e) {
        FileTable::Stat st;
        int ok = FileTable::stat_path(wide_arg(e, e.arg_slot(0)), st) == 0 ? 0 : -1;
        if (ok != 0) e.set_guest_errno(2);
        e.set_result(static_cast<uint64_t>(static_cast<int64_t>(ok)));
    });
    ucrt("_wremove", [](Emulator& e) {
        e.set_result(FileTable::remove_file(wide_arg(e, e.arg_slot(0))) == 0 ? 0
                                                                             : static_cast<uint64_t>(-1));
    });
    ucrt("_wunlink", [](Emulator& e) {
        e.set_result(FileTable::remove_file(wide_arg(e, e.arg_slot(0))) == 0 ? 0
                                                                             : static_cast<uint64_t>(-1));
    });
    ucrt("_wrename", [](Emulator& e) {
        e.set_result(FileTable::rename_file(wide_arg(e, e.arg_slot(0)),
                                            wide_arg(e, e.arg_slot(1))) == 0
                         ? 0
                         : static_cast<uint64_t>(-1));
    });
    ucrt("_wsplitpath_s", [](Emulator& e) {
        // (path, drive, dsz, dir, dirsz, fname, fsz, ext, esz)
        std::string path = wide_arg(e, e.arg_slot(0));
        std::string drive, dir, fname, ext;
        size_t start = 0;
        if (path.size() >= 2 && path[1] == ':') {
            drive = path.substr(0, 2);
            start = 2;
        }
        size_t slash = path.find_last_of("/\\");
        size_t name_at = slash == std::string::npos ? start : slash + 1;
        if (slash != std::string::npos && slash >= start) dir = path.substr(start, slash + 1 - start);
        std::string base = path.substr(name_at);
        size_t dot = base.find_last_of('.');
        if (dot != std::string::npos) {
            ext = base.substr(dot);
            base = base.substr(0, dot);
        }
        fname = base;
        put_wide(e, e.arg_slot(1), drive, e.arg_slot(2));
        put_wide(e, e.arg_slot(3), dir, e.arg_slot(4));
        put_wide(e, e.arg_slot(5), fname, e.arg_slot(6));
        put_wide(e, e.arg_slot(7), ext, e.arg_slot(8));
        e.set_result(0);
    });
    ucrt("_wmakepath_s", [](Emulator& e) {
        // (buf, size, drive, dir, fname, ext)
        std::string drive = wide_arg(e, e.arg_slot(2));
        std::string dir = wide_arg(e, e.arg_slot(3));
        std::string fname = wide_arg(e, e.arg_slot(4));
        std::string ext = wide_arg(e, e.arg_slot(5));
        std::string path = drive;
        path += dir;
        if (!dir.empty() && dir.back() != '\\' && dir.back() != '/') path += '\\';
        path += fname;
        if (!ext.empty() && ext[0] != '.') path += '.';
        path += ext;
        put_wide(e, e.arg_slot(0), path, e.arg_slot(1));
        e.set_result(0);
    });
    ucrt("_callnewh", [](Emulator& e) { e.set_result(1); });
    // (buffer, size, errno): the message for an errno value, bounded.
    auto strerror_s = [](Emulator& e, bool wide) {
        uint64_t buf = e.arg_slot(0), size = e.arg_slot(1);
        const char* text = std::strerror(static_cast<int>(e.arg_slot(2)));
        std::string message = text ? text : "unknown error";
        if (!buf || size == 0) {
            e.set_result(22);  // EINVAL
            return;
        }
        if (wide) {
            if (put_wide(e, buf, message, size) < 0) {
                e.set_result(34);  // ERANGE
                return;
            }
        } else {
            if (message.size() + 1 > size) {
                e.set_result(34);
                return;
            }
            e.mem.write_cstring(buf, message);
        }
        e.set_result(0);
    };
    ucrt("strerror_s", [strerror_s](Emulator& e) { strerror_s(e, false); });
    ucrt("_strerror_s", [strerror_s](Emulator& e) { strerror_s(e, false); });
    ucrt("_wcserror_s", [strerror_s](Emulator& e) { strerror_s(e, true); });
    ucrt("__wcserror_s", [strerror_s](Emulator& e) { strerror_s(e, true); });
    ucrt("_wcserror", [](Emulator& e) {
        const char* text = std::strerror(static_cast<int>(e.arg_slot(0)));
        std::u16string w = utf8_to_utf16(text ? text : "unknown error");
        std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
        std::memcpy(raw.data(), w.data(), w.size() * 2);
        e.set_result(e.alloc_guest_data(raw.data(), raw.size()));
    });
    // (buffer, relative, size in characters); a NULL buffer means "allocate one".
    ucrt("_wfullpath", [](Emulator& e) {
        std::string in = wide_arg(e, e.arg_slot(1));
        bool absolute = (in.size() > 1 && in[1] == ':') ||
                        (!in.empty() && (in[0] == '\\' || in[0] == '/'));
        std::string full = in;
        if (!absolute) {
            char cwd[4096];
#if defined(_WIN32)
            if (_getcwd(cwd, sizeof cwd)) full = std::string(cwd) + "\\" + in;
#else
            if (getcwd(cwd, sizeof cwd)) full = std::string(cwd) + "/" + in;
#endif
        }
        for (char& c : full)
            if (c == '/') c = '\\';
        uint64_t buf = e.arg_slot(0);
        uint64_t size = e.arg_slot(2);
        if (!buf) {
            buf = e.heap_alloc((full.size() + 1) * 2);
            size = full.size() + 1;
        }
        if (put_wide(e, buf, full, size) < 0) {
            e.set_guest_errno(34);  // ERANGE
            e.set_result(0);
            return;
        }
        e.set_result(buf);
    });

    // ---- UCRT: locale tables -----------------------------------------------------------
    ucrt("_lock_locales", [](Emulator& e) { e.set_result(0); });
    ucrt("_unlock_locales", [](Emulator& e) { e.set_result(0); });
    ucrt("___lc_collate_cp_func", [](Emulator& e) { e.set_result(1252); });
    ucrt("___lc_locale_name_func", [](Emulator& e) {
        // wchar_t** indexed by LC_* category; all C locale, all NULL.
        static const uint64_t zeros[8] = {};
        e.set_result(e.alloc_guest_data(zeros, sizeof zeros));
    });
    ucrt("__pctype_func", [](Emulator& e) {
        // The 256-entry classification table isalpha() and friends index.
        uint16_t table[256] = {};
        for (int c = 0; c < 256; ++c) {
            uint16_t f = 0;
            if (c >= 'A' && c <= 'Z') f |= 0x0001;             // _UPPER
            if (c >= 'a' && c <= 'z') f |= 0x0002;             // _LOWER
            if (c >= '0' && c <= '9') f |= 0x0004;             // _DIGIT
            if (c == ' ' || (c >= 9 && c <= 13)) f |= 0x0008;  // _SPACE
            if (c < 32 || c == 127) f |= 0x0020;               // _CONTROL
            if (c == ' ' || c == '\t') f |= 0x0040;            // _BLANK
            if ((c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'))
                f |= 0x0080;                                   // _HEX
            if (c >= 33 && c <= 126 && !std::isalnum(c)) f |= 0x0010;  // _PUNCT
            if (f & 0x0003) f |= 0x0100;                       // _ALPHA
            table[c] = f;
        }
        e.set_result(e.alloc_guest_data(table, sizeof table));
    });

    // ---- UCRT: process -----------------------------------------------------------------
    ucrt("_wspawnv", [](Emulator& e) {
        // (mode, path, argv).  cl uses _P_WAIT (0) to run link.exe; the whole
        // child runs to completion inside this hook, driven by the System.
        int mode = static_cast<int>(e.arg_slot(0));
        std::string path = wide_arg(e, e.arg_slot(1));
        std::vector<std::string> argv;
        uint64_t vec = e.arg_slot(2);
        int ps = e.pointer_size();
        for (int i = 0; i < 1024; ++i) {
            uint64_t p = e.mem.read_sized(vec + static_cast<uint64_t>(i) * ps, ps);
            if (!p) break;
            argv.push_back(wide_arg(e, p));
        }
        if (argv.empty()) argv.push_back(path);
        System::SpawnRequest req;
        req.path = FileTable::host_path(path);
        req.argv = argv;
        req.env = e.environment();
        req.ppid = e.pid();
        for (int fd = 0; fd < 3; ++fd)
            if (FileTable::Entry* entry = e.files.get(fd)) req.handles.emplace_back(fd, *entry);
        int pid = e.system()->spawn(req);
        e.log_call("_wspawnv(%s) -> pid %d", path.c_str(), pid);
        if (pid < 0) {
            e.set_guest_errno(2);
            e.set_result(static_cast<uint64_t>(-1));
            return;
        }
        if (mode == 0 /* _P_WAIT */) {
            int code = e.system()->run_until_exit(pid, e.pid());
            e.set_result(static_cast<uint64_t>(static_cast<int64_t>(code)));
        } else {
            e.set_result(static_cast<uint64_t>(pid));
        }
    });
    ucrt("_wsystem", [](Emulator& e) {
        if (!e.arg_slot(0)) {
            e.set_result(1);  // "a shell exists"
            return;
        }
        e.log_call("_wsystem(%s) unsupported", wide_arg(e, e.arg_slot(0)).c_str());
        e.set_result(static_cast<uint64_t>(-1));
    });

    // ---- UCRT: runtime -------------------------------------------------------------------
    ucrt("__p__wpgmptr", [](Emulator& e) {
        std::string path = e.args().empty() ? "program.exe" : e.args()[0];
        for (char& c : path)
            if (c == '/') c = '\\';
        std::u16string w = utf8_to_utf16(path);
        std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
        std::memcpy(raw.data(), w.data(), w.size() * 2);
        uint64_t str = e.alloc_guest_data(raw.data(), raw.size());
        uint64_t var = e.alloc_guest_data(nullptr, 0);
        e.mem.write_sized(var, e.pointer_size(), str);
        e.set_result(var);
    });
    ucrt("_get_wpgmptr", [](Emulator& e) {
        std::string path = e.args().empty() ? "program.exe" : e.args()[0];
        for (char& c : path)
            if (c == '/') c = '\\';
        std::u16string w = utf8_to_utf16(path);
        std::vector<uint8_t> raw((w.size() + 1) * 2, 0);
        std::memcpy(raw.data(), w.data(), w.size() * 2);
        uint64_t str = e.alloc_guest_data(raw.data(), raw.size());
        if (e.arg_slot(0)) e.mem.write_sized(e.arg_slot(0), e.pointer_size(), str);
        e.set_result(0);
    });
    ucrt("_invalid_parameter_noinfo", [](Emulator& e) { e.set_result(0); });
    ucrt("_invalid_parameter_noinfo_noreturn", [](Emulator& e) {
        e.write_text(2, "invalid parameter\n");
        e.exit_process(3);
    });
    ucrt("_set_new_handler", [](Emulator& e) { e.set_result(0); });

    // ---- UCRT: stdio, wide ------------------------------------------------------------------
    ucrt("__stdio_common_vsnwprintf_s", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);                      // options
        uint64_t buf = a.next_ptr();
        uint64_t bufsize = a.next_ptr();    // in wide characters
        uint64_t count = a.next_ptr();
        uint64_t fmt = a.next_ptr();
        a.next_ptr();                       // locale
        uint64_t va = a.next_ptr();
        Args tail = Args::va_list_at(e, va);
        std::u16string s = utf8_to_utf16(format_guest(e, fmt, tail, true));
        uint64_t limit = count < bufsize ? count : (bufsize ? bufsize - 1 : 0);
        size_t n = s.size() < limit ? s.size() : static_cast<size_t>(limit);
        if (buf) {
            for (size_t i = 0; i < n; ++i) e.mem.write16(buf + i * 2, s[i]);
            e.mem.write16(buf + n * 2, 0);
        }
        e.set_result(s.size());
    });
    ucrt("__stdio_common_vsprintf_s", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);
        uint64_t buf = a.next_ptr();
        uint64_t bufsize = a.next_ptr();
        uint64_t fmt = a.next_ptr();
        a.next_ptr();
        uint64_t va = a.next_ptr();
        Args tail = Args::va_list_at(e, va);
        std::string s = format_guest(e, fmt, tail);
        if (buf && bufsize) {
            size_t n = s.size() < bufsize ? s.size() : static_cast<size_t>(bufsize - 1);
            e.mem.write(buf, s.data(), n);
            e.mem.write8(buf + n, 0);
        }
        e.set_result(s.size());
    });
    ucrt("__stdio_common_vswprintf_s", [](Emulator& e) {
        Args a(e, 0);
        a.next_int(8);
        uint64_t buf = a.next_ptr();
        uint64_t bufsize = a.next_ptr();
        uint64_t fmt = a.next_ptr();
        a.next_ptr();
        uint64_t va = a.next_ptr();
        Args tail = Args::va_list_at(e, va);
        std::u16string s = utf8_to_utf16(format_guest(e, fmt, tail, true));
        if (buf && bufsize) {
            size_t n = s.size() < bufsize ? s.size() : static_cast<size_t>(bufsize - 1);
            for (size_t i = 0; i < n; ++i) e.mem.write16(buf + i * 2, s[i]);
            e.mem.write16(buf + n * 2, 0);
        }
        e.set_result(s.size());
    });
    ucrt("_flushall", [](Emulator& e) {
        e.flush_guest_output();
        e.set_result(0);
    });
    auto fsopen = [](Emulator& e, bool wide) {
        std::string path = wide ? wide_arg(e, e.arg_slot(0)) : e.mem.read_cstring(e.arg_slot(0));
        std::string mode = wide ? wide_arg(e, e.arg_slot(1)) : e.mem.read_cstring(e.arg_slot(1));
        FileTable::OpenFlags f;
        f.binary = mode.find('b') != std::string::npos;
        if (mode.find('r') != std::string::npos) {
            f.read = true;
            if (mode.find('+') != std::string::npos) f.write = true;
        } else if (mode.find('w') != std::string::npos) {
            f.write = f.create = f.truncate = true;
            if (mode.find('+') != std::string::npos) f.read = true;
        } else {
            f.append = f.create = true;
        }
        int fd = e.files.open(path, f);
        if (fd < 0) {
            e.report_file_error(fd);
            e.set_result(0);
            return;
        }
        e.set_result(e.guest_file(fd));
    };
    // (fd out, path, oflag, shflag, pmode): the descriptor-level open, whose
    // flags are the POSIX ones rather than a mode string.
    auto sopen_s = [](Emulator& e, bool wide) {
        uint64_t fd_out = e.arg_slot(0);
        std::string path = wide ? wide_arg(e, e.arg_slot(1)) : e.mem.read_cstring(e.arg_slot(1));
        uint32_t oflag = static_cast<uint32_t>(e.arg_slot(2));
        constexpr uint32_t kRdOnly = 0x0000, kWrOnly = 0x0001, kRdWr = 0x0002;
        constexpr uint32_t kAppend = 0x0008, kCreat = 0x0100, kTrunc = 0x0200;
        constexpr uint32_t kExcl = 0x0400, kText = 0x4000;
        FileTable::OpenFlags f;
        uint32_t mode = oflag & 0x3;
        f.read = mode == kRdOnly || mode == kRdWr;
        f.write = mode == kWrOnly || mode == kRdWr;
        f.append = (oflag & kAppend) != 0;
        f.create = (oflag & kCreat) != 0;
        f.truncate = (oflag & kTrunc) != 0;
        f.exclusive = (oflag & kExcl) != 0;
        f.binary = (oflag & kText) == 0;
        int fd = e.files.open(path, f);
        e.log_call("_sopen_s(%s, oflag 0x%X) = %d", path.c_str(), oflag, fd);
        if (fd < 0) {
            e.report_file_error(fd);
            if (fd_out) e.mem.write32(fd_out, 0xFFFFFFFFu);
            e.set_result(static_cast<uint64_t>(-fd));  // the errno itself
            return;
        }
        if (fd_out) e.mem.write32(fd_out, static_cast<uint32_t>(fd));
        e.set_result(0);
    };
    ucrt("_sopen_s", [sopen_s](Emulator& e) { sopen_s(e, false); });
    ucrt("_wsopen_s", [sopen_s](Emulator& e) { sopen_s(e, true); });
    ucrt("_fsopen", [fsopen](Emulator& e) { fsopen(e, false); });
    ucrt("_wfsopen", [fsopen](Emulator& e) { fsopen(e, true); });
    ucrt("_wfopen_s", [fsopen](Emulator& e) {
        // (FILE** out, path, mode) - shift the arguments over and reuse.
        uint64_t out = e.arg_slot(0);
        std::string path = wide_arg(e, e.arg_slot(1));
        std::string mode = wide_arg(e, e.arg_slot(2));
        FileTable::OpenFlags f;
        f.binary = mode.find('b') != std::string::npos;
        if (mode.find('r') != std::string::npos) {
            f.read = true;
            if (mode.find('+') != std::string::npos) f.write = true;
        } else if (mode.find('w') != std::string::npos) {
            f.write = f.create = f.truncate = true;
            if (mode.find('+') != std::string::npos) f.read = true;
        } else {
            f.append = f.create = true;
        }
        int fd = e.files.open(path, f);
        if (out) e.mem.write_sized(out, e.pointer_size(), fd < 0 ? 0 : e.guest_file(fd));
        e.set_result(fd < 0 ? 2 : 0);
    });
    ucrt("_get_stream_buffer_pointers", [](Emulator& e) {
        for (int i = 1; i <= 3; ++i)
            if (e.arg_slot(i)) e.mem.write_sized(e.arg_slot(i), e.pointer_size(), 0);
        e.set_result(0);
    });
    ucrt("fputwc", [](Emulator& e) {
        uint32_t c = static_cast<uint16_t>(e.arg_slot(0));
        std::string out;
        if (c < 0x80) {
            out += static_cast<char>(c);
        } else if (c < 0x800) {
            out += static_cast<char>(0xC0 | (c >> 6));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            out += static_cast<char>(0xE0 | (c >> 12));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        }
        int fd = e.host_fd(e.arg_slot(1));
        e.write_text(fd == 2 ? 2 : 1, out);
        e.set_result(c);
    });
    ucrt("fputws", [](Emulator& e) {
        std::string s = wide_arg(e, e.arg_slot(0));
        int fd = e.host_fd(e.arg_slot(1));
        e.write_text(fd == 2 ? 2 : 1, s);
        e.set_result(0);
    });
    ucrt("fgetws", [](Emulator& e) {
        // (buf, n, stream): read a line, widen it.
        uint64_t buf = e.arg_slot(0);
        int64_t n = static_cast<int64_t>(e.arg_slot(1));
        int fd = e.host_fd(e.arg_slot(2));
        std::string line;
        while (static_cast<int64_t>(line.size()) < n - 1) {
            uint8_t b = 0;
            if (e.files.read(fd, &b, 1) != 1) break;
            line += static_cast<char>(b);
            if (b == '\n') break;
        }
        if (line.empty()) {
            e.set_result(0);
            return;
        }
        put_wide(e, buf, line, static_cast<uint64_t>(n));
        e.set_result(buf);
    });
    ucrt("getwchar", [](Emulator& e) {
        uint8_t b = 0;
        e.set_result(e.files.read(0, &b, 1) == 1 ? b : 0xFFFFull);
    });
    ucrt("ungetwc", [](Emulator& e) {
        int fd = e.host_fd(e.arg_slot(1));
        if (fd >= 0) e.files.seek(fd, -1, 1);
        e.set_result(e.arg_slot(0));
    });
    ucrt("_cputws", [](Emulator& e) {
        e.write_text(1, wide_arg(e, e.arg_slot(0)));
        e.set_result(0);
    });

    // ---- UCRT: string, wide ---------------------------------------------------------------
    ucrt("__strncnt", [](Emulator& e) {
        uint64_t p = e.arg_slot(0), max = e.arg_slot(1), n = 0;
        while (n < max && e.mem.read8(p + n) != 0) ++n;
        e.set_result(n);
    });
    auto wcs_case = [](Emulator& e, bool upper) {
        uint64_t p = e.arg_slot(0);
        for (uint64_t i = 0;; ++i) {
            uint16_t c = e.mem.read16(p + i * 2);
            if (!c) break;
            if (upper && c >= 'a' && c <= 'z') e.mem.write16(p + i * 2, c - 32);
            if (!upper && c >= 'A' && c <= 'Z') e.mem.write16(p + i * 2, c + 32);
        }
        e.set_result(0);
    };
    ucrt("_wcslwr_s", [wcs_case](Emulator& e) { wcs_case(e, false); });
    ucrt("_wcsupr_s", [wcs_case](Emulator& e) { wcs_case(e, true); });
    // The wide classification family.  Only ASCII is classified: a real answer
    // for the rest needs Unicode tables, and claiming one without them would be
    // a guess a guest cannot tell from the truth.  Characters above 127 are
    // reported as letters, which is what a compiler tokenising an identifier
    // needs and what MSVC's own "any non-ASCII is an identifier character"
    // behaviour amounts to.
    auto isw_class = [](Emulator& e, int (*fn)(int), bool letters_above_ascii) {
        uint32_t c = static_cast<uint32_t>(e.arg_slot(0));
        bool r;
        if (c < 128)
            r = fn(static_cast<int>(c)) != 0;
        else
            r = letters_above_ascii;
        e.set_result(r ? 1 : 0);
    };
    auto isw = [&](const char* name, int (*fn)(int), bool letters_above_ascii = false) {
        ucrt(name, [isw_class, fn, letters_above_ascii](Emulator& e) {
            isw_class(e, fn, letters_above_ascii);
        });
    };
    isw("iswalnum", [](int c) { return std::isalnum(c); }, true);
    isw("iswalpha", [](int c) { return std::isalpha(c); }, true);
    isw("iswdigit", [](int c) { return std::isdigit(c); });
    isw("iswspace", [](int c) { return std::isspace(c); });
    isw("iswxdigit", [](int c) { return std::isxdigit(c); });
    isw("iswprint", [](int c) { return std::isprint(c); }, true);
    isw("iswupper", [](int c) { return std::isupper(c); });
    isw("iswlower", [](int c) { return std::islower(c); });
    isw("iswpunct", [](int c) { return std::ispunct(c); });
    isw("iswcntrl", [](int c) { return std::iscntrl(c); });
    isw("iswgraph", [](int c) { return std::isgraph(c); }, true);
    isw("iswblank", [](int c) { return c == ' ' || c == '\t' ? 1 : 0; });
    isw("__iswcsymf", [](int c) { return std::isalpha(c) || c == '_' ? 1 : 0; }, true);
    isw("__iswcsym", [](int c) { return std::isalnum(c) || c == '_' ? 1 : 0; }, true);
    ucrt("towlower", [](Emulator& e) {
        uint64_t c = e.arg_slot(0);
        e.set_result(c >= 'A' && c <= 'Z' ? c + 32 : c);
    });
    ucrt("towupper", [](Emulator& e) {
        uint64_t c = e.arg_slot(0);
        e.set_result(c >= 'a' && c <= 'z' ? c - 32 : c);
    });
    auto wcs_copy = [](Emulator& e, bool cat, bool bounded) {
        // wcscpy_s(dst, size, src) / wcsncpy_s(dst, size, src, count)
        uint64_t dst = e.arg_slot(0);
        uint64_t src = e.arg_slot(2);
        uint64_t count = bounded ? e.arg_slot(3) : ~0ull;
        uint64_t at = 0;
        if (cat)
            while (e.mem.read16(dst + at * 2) != 0) ++at;
        for (uint64_t i = 0; i < count; ++i) {
            uint16_t c = e.mem.read16(src + i * 2);
            e.mem.write16(dst + (at + i) * 2, c);
            if (!c) {
                e.set_result(0);
                return;
            }
        }
        e.mem.write16(dst + (at + count) * 2, 0);
        e.set_result(0);
    };
    ucrt("wcscpy_s", [wcs_copy](Emulator& e) { wcs_copy(e, false, false); });
    ucrt("wcscat_s", [wcs_copy](Emulator& e) { wcs_copy(e, true, false); });
    ucrt("wcsncpy_s", [wcs_copy](Emulator& e) { wcs_copy(e, false, true); });
    ucrt("wcsncat_s", [wcs_copy](Emulator& e) { wcs_copy(e, true, true); });

    // The narrow bounded forms, same shape: (dst, dst size, src[, count]).  They
    // return 0 on success and ERANGE when the destination is too small, and a
    // caller that checks - this toolchain does - notices the difference.
    auto str_copy = [](Emulator& e, bool cat, bool bounded) {
        uint64_t dst = e.arg_slot(0);
        uint64_t capacity = e.arg_slot(1);
        std::string src = e.mem.read_cstring(e.arg_slot(2));
        if (bounded) {
            uint64_t count = e.arg_slot(3);
            if (src.size() > count) src.resize(static_cast<size_t>(count));
        }
        std::string result = cat ? e.mem.read_cstring(dst) + src : src;
        if (!dst || result.size() + 1 > capacity) {
            e.set_result(34);  // ERANGE
            return;
        }
        e.mem.write_cstring(dst, result);
        e.set_result(0);
    };
    ucrt("strcpy_s", [str_copy](Emulator& e) { str_copy(e, false, false); });
    ucrt("strcat_s", [str_copy](Emulator& e) { str_copy(e, true, false); });
    ucrt("strncpy_s", [str_copy](Emulator& e) { str_copy(e, false, true); });
    ucrt("strncat_s", [str_copy](Emulator& e) { str_copy(e, true, true); });
    // (dst, dst size, src, count)
    ucrt("memcpy_s", [](Emulator& e) {
        uint64_t dst = e.arg_slot(0), capacity = e.arg_slot(1);
        uint64_t src = e.arg_slot(2), count = e.arg_slot(3);
        if (!count) {
            e.set_result(0);
            return;
        }
        if (!dst || count > capacity) {
            e.set_result(34);  // ERANGE
            return;
        }
        std::vector<uint8_t> tmp(static_cast<size_t>(count));
        e.mem.read(src, tmp.data(), count);
        e.mem.write(dst, tmp.data(), count);
        e.set_result(0);
    });
    ucrt("memmove_s", [](Emulator& e) {
        uint64_t dst = e.arg_slot(0), capacity = e.arg_slot(1);
        uint64_t src = e.arg_slot(2), count = e.arg_slot(3);
        if (!count) {
            e.set_result(0);
            return;
        }
        if (!dst || count > capacity) {
            e.set_result(34);
            return;
        }
        std::vector<uint8_t> tmp(static_cast<size_t>(count));
        e.mem.read(src, tmp.data(), count);
        e.mem.write(dst, tmp.data(), count);
        e.set_result(0);
    });
    ucrt("wcspbrk", [](Emulator& e) {
        std::string set = wide_arg(e, e.arg_slot(1));
        uint64_t p = e.arg_slot(0);
        for (uint64_t i = 0;; ++i) {
            uint16_t c = e.mem.read16(p + i * 2);
            if (!c) break;
            if (c < 128 && set.find(static_cast<char>(c)) != std::string::npos) {
                e.set_result(p + i * 2);
                return;
            }
        }
        e.set_result(0);
    });
    ucrt("wcsspn", [](Emulator& e) {
        std::string set = wide_arg(e, e.arg_slot(1));
        uint64_t p = e.arg_slot(0), n = 0;
        while (true) {
            uint16_t c = e.mem.read16(p + n * 2);
            if (!c || c >= 128 || set.find(static_cast<char>(c)) == std::string::npos) break;
            ++n;
        }
        e.set_result(n);
    });

    // ---- UCRT: time -----------------------------------------------------------------------
    ucrt("_Getdays", [](Emulator& e) {
        e.set_result(e.alloc_guest_string(
            ":Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday"));
    });
    ucrt("_Getmonths", [](Emulator& e) {
        e.set_result(e.alloc_guest_string(
            ":Jan:January:Feb:February:Mar:March:Apr:April:May:May:Jun:June:Jul:July:Aug:August"
            ":Sep:September:Oct:October:Nov:November:Dec:December"));
    });
    ucrt("_Gettnames", [](Emulator& e) { e.set_result(0); });
    ucrt("_W_Getdays", [](Emulator& e) { e.set_result(0); });
    ucrt("_W_Getmonths", [](Emulator& e) { e.set_result(0); });
    ucrt("_W_Gettnames", [](Emulator& e) { e.set_result(0); });
    ucrt("_ftime64_s", [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) {
            e.mem.write64(p, static_cast<uint64_t>(std::time(nullptr)));  // time
            e.mem.write16(p + 8, 0);   // millitm
            e.mem.write16(p + 10, 0);  // timezone
            e.mem.write16(p + 12, 0);  // dstflag
        }
        e.set_result(0);
    });
    // (buffer, size, const __time64_t*): the bounded ctime, 26 characters
    // including the newline and the terminator.
    ucrt("_ctime64_s", [](Emulator& e) {
        uint64_t buf = e.arg_slot(0), size = e.arg_slot(1);
        if (!buf || size < 26) {
            e.set_result(22);  // EINVAL
            return;
        }
        auto t = static_cast<time_t>(e.mem.read64(e.arg_slot(2)));
        const char* s = std::ctime(&t);
        e.mem.write_cstring(buf, s ? s : "Thu Jan  1 00:00:00 1970\n");
        e.set_result(0);
    });
    ucrt("_localtime64_s", [](Emulator& e) {
        // (struct tm* out, const __time64_t* in)
        uint64_t out = e.arg_slot(0);
        auto t = static_cast<time_t>(e.mem.read64(e.arg_slot(1)));
        std::tm* tm = std::localtime(&t);
        if (!out || !tm) {
            e.set_result(22);
            return;
        }
        const int fields[9] = {tm->tm_sec,  tm->tm_min,  tm->tm_hour,
                               tm->tm_mday, tm->tm_mon,  tm->tm_year,
                               tm->tm_wday, tm->tm_yday, tm->tm_isdst};
        for (int i = 0; i < 9; ++i)
            e.mem.write32(out + static_cast<uint64_t>(i) * 4, static_cast<uint32_t>(fields[i]));
        e.set_result(0);
    });
    ucrt("rand_s", [](Emulator& e) {
        if (e.arg_slot(0)) e.mem.write32(e.arg_slot(0), 0x2A2A2A2Au);
        e.set_result(0);
    });

    // ---- ole32 -------------------------------------------------------------------------
    win32("CoCreateGuid", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        static uint32_t counter = 0;
        ++counter;
        if (p) {
            e.mem.write32(p, 0xE586A9E0u + counter);
            e.mem.write32(p + 4, 0x4D4D0000u);
            e.mem.write32(p + 8, 0x11EE0000u);
            e.mem.write32(p + 12, counter);
        }
        e.set_result(0);  // S_OK
    });
    win32("StringFromGUID2", 3, [](Emulator& e) {
        uint64_t g = e.arg_slot(0);
        char text[64];
        std::snprintf(text, sizeof text,
                      "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                      e.mem.read32(g), e.mem.read16(g + 4), e.mem.read16(g + 6),
                      e.mem.read8(g + 8), e.mem.read8(g + 9), e.mem.read8(g + 10),
                      e.mem.read8(g + 11), e.mem.read8(g + 12), e.mem.read8(g + 13),
                      e.mem.read8(g + 14), e.mem.read8(g + 15));
        int n = put_wide(e, e.arg_slot(1), text, e.arg_slot(2));
        e.set_result(n < 0 ? 0 : static_cast<uint64_t>(n));
    });
}

}  // namespace x86emu
