// WebAssembly entry point.
//
// The emulator core has no filesystem or terminal dependencies, so the browser
// build only needs to hand it an image as bytes and route guest output into JS.
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "emulator.h"

#if defined(__EMSCRIPTEN__)
#include <emscripten.h>

// Guest output is bytes, not text: hand JS the raw slice and let it decode.
// The callbacks live on globalThis rather than on Module so that the reference
// resolves the same way regardless of how the module is bundled.
EM_JS(void, js_guest_output, (int fd, const char* ptr, int len), {
    globalThis.x86emuOutput(fd, HEAPU8.slice(ptr, ptr + len));
});
EM_JS(void, js_guest_log, (const char* ptr), { globalThis.x86emuLog(UTF8ToString(ptr)); });
#else
static void js_guest_output(int, const char*, int) {}
static void js_guest_log(const char*) {}
#endif

namespace {

std::string g_error;
uint64_t g_instructions = 0;
std::string g_format;

}  // namespace

extern "C" {

// Runs an image and returns its exit code, or -1 if it could not run (in which
// case emu_error() explains why).
int emu_run(const uint8_t* data, int len, int trace_calls, double max_insns) {
    g_error.clear();
    g_instructions = 0;
    g_format.clear();

    x86emu::Emulator::Options opt;
    opt.trace_calls = trace_calls != 0;
    opt.max_instructions = static_cast<uint64_t>(max_insns);

    x86emu::Emulator emu(opt);
    emu.output_sink = [](int fd, const char* p, size_t n) {
        js_guest_output(fd, p, static_cast<int>(n));
    };

    std::vector<uint8_t> file(data, data + len);
    try {
        emu.load_bytes(file, {"program"});
    } catch (const std::exception& err) {
        g_error = err.what();
        return -1;
    }

    g_format = emu.image().format;
    {
        char buf[160];
        std::snprintf(buf, sizeof buf, "loaded %s, entry 0x%llX, base 0x%llX",
                      emu.image().format.c_str(),
                      static_cast<unsigned long long>(emu.image().entry),
                      static_cast<unsigned long long>(emu.image().image_base));
        js_guest_log(buf);
    }

    int code;
    try {
        code = emu.run();
    } catch (const std::exception& err) {
        g_error = err.what();
        g_instructions = emu.cpu().instructions_executed;
        return -1;
    }
    g_instructions = emu.cpu().instructions_executed;
    return code;
}

const char* emu_error() { return g_error.c_str(); }
const char* emu_format() { return g_format.c_str(); }
double emu_instructions() { return static_cast<double>(g_instructions); }

}  // extern "C"
