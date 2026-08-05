// Dynamic loading of real DLLs.
//
// Up to now every import was answered by a host hook.  That works for the C
// runtime and the Win32 API, whose behaviour the emulator can reproduce, but not
// for an application's own DLLs: their behaviour *is* the code inside them, and
// some of what they export is data rather than functions.  So those get mapped
// into guest memory for real - relocated, their own imports bound recursively,
// their TLS callbacks and DllMain run - and only the system libraries stay hooked.
#include <cstring>
#include <string>
#include <vector>

#include "emulator.h"

namespace x86emu {
namespace {

std::string lowercase(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out += static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
    return out;
}

// Splits a forwarder target ("KERNEL32.Sleep") into its two halves.
bool split_forwarder(const std::string& target, std::string& dll, std::string& symbol) {
    size_t dot = target.rfind('.');
    if (dot == std::string::npos) return false;
    dll = target.substr(0, dot) + ".dll";
    symbol = target.substr(dot + 1);
    return true;
}

// The libraries the emulator implements itself.  Loading a real copy of these
// would mean emulating the kernel underneath them, so they stay hooked even when
// the file happens to be sitting on disk.
bool is_system_library(const std::string& lower_name) {
    static const char* kPrefixes[] = {
        "kernel32", "kernelbase", "user32", "gdi32", "advapi32", "shell32", "ole32",
        "oleaut32", "ws2_32", "wsock32", "rpcrt4", "sechost", "shlwapi", "psapi",
        "version", "comdlg32", "comctl32", "winmm", "imm32", "setupapi", "crypt32",
        "bcrypt", "ncrypt", "userenv", "netapi32", "iphlpapi", "dbghelp",
        // Deliberately absent, because they export things no hook can stand in
        // for, so they have to be the real files when the guest can find them:
        //
        //   msvcp*      - exports std::cout as *data*
        //   vcruntime*  - owns the language half of exception handling;
        //                 __CxxFrameHandler4 is called by the unwinder itself
        //
        // Everything here stays hooked.  A guest that cannot find a non-listed
        // DLL falls back to hooks anyway, which is why this list is a policy
        // rather than a requirement - and also why adding to it is safer than
        // removing from it: a name taken off the list changes behaviour only on
        // the machines where that file happens to be findable.
        //
        // The UCRT (`ucrtbase` and the `api-ms-win-crt-*` forwarders) was tried
        // *off* this list, since its own imports are all `api-ms-win-core-*`,
        // which forward to kernel32 and land back on these hooks - so loading it
        // does not drag the NT layer in.  It does load and run: a /MD guest gets
        // through the real UCRT's initialisation, its lowio setup and its exit
        // path.  But **nothing it prints comes out** - no WriteFile, no
        // WriteConsole, no error - so the result is a silent program where the
        // hooks give a working one.  Until that is understood it stays hooked;
        // resume.md records how far it got and where to look.
        "msvcrt", "msvcr", "ucrtbase", "concrt",
        "api-ms-win-", "ext-ms-win-", "ntdll",
    };
    for (const char* p : kPrefixes)
        if (lower_name.compare(0, std::strlen(p), p) == 0) return true;
    return false;
}

std::string directory_of(const std::string& path) {
    size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? std::string(".") : path.substr(0, slash);
}

bool file_exists(const std::string& path) {
    FileTable::Stat st;
    return FileTable::stat_path(path, st) == 0 && !st.is_dir;
}

}  // namespace

std::string Emulator::find_library_file(const std::string& name) const {
    // A guest may name a library by full path - a localised program builds
    // "<its own directory>\<langid>\foo.dll" and loads that - in which case
    // there is nothing to search for.
    bool absolute = (name.size() > 1 && name[1] == ':') ||
                    (!name.empty() && (name[0] == '/' || name[0] == '\\'));
    if (absolute) return file_exists(name) ? name : std::string();

    std::vector<std::string> dirs;
    if (!args_.empty()) dirs.push_back(directory_of(args_[0]));
    // A module's own directory, for the modules it depends on: a Python
    // extension in DLLs\ finds the OpenSSL it links against beside itself, and
    // that is what LOAD_WITH_ALTERED_SEARCH_PATH and AddDllDirectory arrange for
    // on real Windows.
    for (const auto& m : modules_)
        if (!m->path.empty()) dirs.push_back(directory_of(m->path));
    dirs.push_back(".");
    for (const auto& d : opt_.library_paths) dirs.push_back(d);

    for (const auto& dir : dirs) {
        std::string candidate = dir + "/" + name;
        if (file_exists(candidate)) return candidate;
    }
    return {};
}

Emulator::Module* Emulator::module_by_name(const std::string& name) {
    std::string lower = lowercase(name);
    for (auto& m : modules_)
        if (m->name == lower) return m.get();
    return nullptr;
}

Emulator::Module* Emulator::module_for(uint64_t base) {
    for (auto& m : modules_)
        if (base >= m->image.base && base < m->image.base + m->image.size) return m.get();
    return nullptr;
}

uint64_t Emulator::load_library(const std::string& raw_name) {
    std::string name = lowercase(raw_name);
    if (name.find('.') == std::string::npos) name += ".dll";

    if (Module* existing = module_by_name(name)) return existing->image.base;
    if (is_system_library(name)) return 0;  // the hooks are the implementation

    // A cycle in DLL dependencies would otherwise recurse forever; the partially
    // loaded module is already registered by the time its imports are bound, so
    // this only catches a cycle *during* the map step.
    for (const auto& n : loading_)
        if (n == name) return 0;

    std::string path = find_library_file(name);
    if (path.empty()) {
        log_call("load_library(%s): not found", name.c_str());
        return 0;
    }

    std::vector<uint8_t> file;
    try {
        file = read_file(path);
    } catch (const LoadError& err) {
        log_call("load_library(%s): cannot read %s: %s", name.c_str(), path.c_str(), err.what());
        return 0;
    }

    // A DLL almost never gets its preferred base, so pick the next free slot in
    // the region set aside for them and let map_pe relocate.
    Mode mode;
    std::string format;
    bool is_dll = false;
    try {
        peek_pe(file, mode, format, is_dll);
    } catch (const LoadError& err) {
        log_call("load_library(%s): not a usable PE: %s", name.c_str(), err.what());
        return 0;
    }
    if (mode != image_.mode) {
        log_call("load_library(%s): wrong bitness, ignoring", name.c_str());
        return 0;
    }

    loading_.push_back(name);
    auto module = std::make_unique<Module>();
    module->name = name;
    module->path = path;
    // Normally a DLL is relocated into the region set aside for them, but a
    // resource-only DLL - the message strings a localised program prints - has
    // no relocation directory at all, so it can only be mapped where it asks to
    // be.  Where that address is taken, map_pe puts it elsewhere anyway: with no
    // entry point and no imports, nothing inside it uses an absolute address.
    uint64_t fixed = fixed_base_of(file);
    uint64_t base = dll_next_base_;
    if (fixed && !mem.is_mapped(fixed)) base = fixed;
    try {
        module->image = map_pe(file, mem, base);
    } catch (const LoadError& err) {
        loading_.pop_back();
        log_call("load_library(%s): %s", name.c_str(), err.what());
        return 0;
    }
    // Leave a gap so a module that grows its mapping cannot collide with the next.
    dll_next_base_ = (module->image.base + module->image.size + 0xFFFF) & ~0xFFFFull;

    Module* raw = module.get();
    modules_.push_back(std::move(module));
    log_call("load_library(%s) at 0x%llX from %s", name.c_str(),
             (unsigned long long)raw->image.base, path.c_str());

    bind_imports(raw->image);
    loading_.pop_back();

    // Only set up its thread-local storage and run its initialisers if the guest
    // environment is already up; during the initial load it is not, and
    // run_pending_module_init() catches up.  A library loaded *later* - which is
    // how a compiler driver loads its front and back ends - needs the same
    // treatment, and not giving it a TLS slot leaves it reading another module's.
    if (guest_env_ready_) {
        setup_static_tls(*raw);
        run_module_init(*raw);
    }
    return raw->image.base;
}

uint64_t Emulator::find_export(uint64_t module_base, const std::string& symbol) {
    Module* m = module_for(module_base);
    if (!m) return 0;
    auto it = m->image.exports.find(symbol);
    if (it != m->image.exports.end()) return it->second;

    auto fwd = m->image.forwarders.find(symbol);
    if (fwd != m->image.forwarders.end()) {
        std::string dll, target;
        if (split_forwarder(fwd->second, dll, target)) {
            uint64_t base = load_library(dll);
            // A forwarder into a system library lands back on the hook for it.
            if (base == 0) return resolve_import(dll, target);
            return find_export(base, target);
        }
    }
    return 0;
}

uint64_t Emulator::find_export_ordinal(uint64_t module_base, uint32_t ordinal) {
    Module* m = module_for(module_base);
    if (!m) return 0;
    auto it = m->image.exports_by_ordinal.find(ordinal);
    return it == m->image.exports_by_ordinal.end() ? 0 : it->second;
}

const char* Emulator::well_known_ordinal(const std::string& dll, uint32_t ordinal) {
    std::string lower;
    for (char c : dll) lower += static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
    if (lower == "oleaut32.dll" || lower == "oleaut32") {
        switch (ordinal) {
            case 2: return "SysAllocString";
            case 3: return "SysReAllocString";
            case 4: return "SysAllocStringLen";
            case 5: return "SysReAllocStringLen";
            case 6: return "SysFreeString";
            case 7: return "SysStringLen";
            case 8: return "VariantInit";
            case 9: return "VariantClear";
            case 149: return "SysAllocStringByteLen";
            case 150: return "SysStringByteLen";
            default: return nullptr;
        }
    }
    return nullptr;
}

void Emulator::bind_imports(PeImage& img) {
    for (const auto& imp : img.imports) {
        uint64_t target = 0;
        uint64_t base = load_library(imp.dll);
        if (base) {
            target = imp.symbol.empty() ? find_export_ordinal(base, imp.ordinal)
                                        : find_export(base, imp.symbol);
        }
        if (!target) {
            // Either a system library, or a real DLL that turned out not to export
            // it; a hook is the answer in both cases, and an unknown name becomes
            // a stub that only fails if it is actually called.
            std::string symbol = imp.symbol;
            if (symbol.empty()) {
                if (const char* known = well_known_ordinal(imp.dll, imp.ordinal))
                    symbol = known;
                else
                    symbol = "#" + std::to_string(imp.ordinal);
            }
            target = resolve_import(imp.dll, symbol);
        }
        if (img.mode == Mode::X86_64)
            mem.write64(imp.slot, target);
        else
            mem.write32(imp.slot, static_cast<uint32_t>(target));
    }
}

void Emulator::setup_static_tls(Module& module) {
    const PeImage& img = module.image;
    if (module.tls_ready) return;
    if (!img.tls_index_address || img.tls_raw_end < img.tls_raw_start) return;
    module.tls_ready = true;

    uint32_t slot = next_tls_slot_++;
    uint64_t template_size = img.tls_raw_end - img.tls_raw_start;
    uint64_t total = template_size + img.tls_zero_fill;
    if (total == 0) total = 16;  // a module can declare TLS and use none of it

    // The code compiled from __declspec(thread) reads the slot number from the
    // module's own data and indexes the thread's array with it.  Leaving that
    // number at whatever the file held - zero - is not a missing feature but a
    // collision: the module then reads *another* module's thread-local block and
    // treats whatever is there as its own data.
    mem.write32(img.tls_index_address, slot);
    // Remember the template: every thread created later needs its own copy.
    tls_templates_.push_back({slot, img.tls_raw_start, template_size, total});

    // Every thread that already exists needs one too, which is what makes this
    // work for a library loaded at run time rather than at startup.
    auto install = [&](uint64_t array) {
        if (!array) return;
        uint64_t block = heap_alloc(total);
        if (!block) return;
        std::vector<uint8_t> bytes(static_cast<size_t>(total), 0);
        if (template_size) mem.read(img.tls_raw_start, bytes.data(), template_size);
        mem.write(block, bytes.data(), bytes.size());
        mem.write_sized(array + static_cast<uint64_t>(slot) * pointer_size(), pointer_size(),
                        block);
        log_call("static TLS for %s: slot %u, %llu bytes at 0x%llX in array 0x%llX",
                 module.name.c_str(), slot, (unsigned long long)total,
                 (unsigned long long)block, (unsigned long long)array);
    };
    install(tls_array_);
    for (auto& t : threads_)
        if (t->tls_array && t->tls_array != tls_array_) install(t->tls_array);
}

void Emulator::run_pending_module_init() {
    guest_env_ready_ = true;
    // Every module's TLS block has to exist before any of them runs, because an
    // initialiser in one may touch thread-local data in another.
    for (auto& m : modules_) setup_static_tls(*m);
    // Dependencies were appended after their dependents, so initialise in reverse
    // to give each module its imports already live.
    for (size_t i = modules_.size(); i-- > 0;) run_module_init(*modules_[i]);
    // The executable's own TLS callbacks run last, just before its entry point.
    for (uint64_t callback : exe_tls_callbacks_) {
        if (cpu_->halted) return;
        call_guest(callback, {image_.image_base, 1 /* DLL_PROCESS_ATTACH */, 0});
    }
}

void Emulator::run_module_init(Module& module) {
    if (module.initialised) return;
    module.initialised = true;

    // TLS callbacks run before DllMain, exactly as the real loader does it.
    for (uint64_t callback : module.image.tls_callbacks) {
        constexpr uint64_t kDllProcessAttach = 1;
        call_guest(callback, {module.image.base, kDllProcessAttach, 0});
        if (cpu_->halted) return;
    }
    if (module.image.entry) {
        constexpr uint64_t kDllProcessAttach = 1;
        uint64_t ok = call_guest(module.image.entry, {module.image.base, kDllProcessAttach, 0});
        // DllMain returning FALSE means the library refused to initialise; say so
        // rather than carrying on with a half-live module.
        if (!cpu_->halted && (ok & 0xFFFFFFFFull) == 0)
            std::fprintf(stderr, "x86emu: warning: DllMain of %s returned FALSE\n",
                         module.name.c_str());
    }
}

}  // namespace x86emu
