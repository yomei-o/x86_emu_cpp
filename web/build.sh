#!/bin/sh
# Builds the browser demo.
#
# Everything lands in a single self-contained x86emu.js (the wasm is embedded via
# SINGLE_FILE), so web/ can be served as plain static files - no MIME setup, no
# separate .wasm fetch, and it works straight from GitHub Pages.
#
# Needs emscripten on PATH, or EMCC pointing at emcc.
set -e
cd "$(dirname "$0")/.."
EMCC=${EMCC:-emcc}
command -v "$EMCC" >/dev/null 2>&1 || { echo "emcc not found; set EMCC=/path/to/emcc"; exit 1; }

echo "== building web/x86emu.js"
# Everything in src/ except the command line front end, which web/wasm_api.cpp
# replaces.  Globbing keeps this from going stale when a source file is added.
SOURCES=$(ls src/*.cpp | grep -v '/main\.cpp$')

"$EMCC" -std=c++17 -O2 -Isrc \
    $SOURCES web/wasm_api.cpp \
    -o web/x86emu.js \
    -sMODULARIZE=1 \
    -sEXPORT_NAME=createX86Emu \
    -sSINGLE_FILE=1 \
    -sALLOW_MEMORY_GROWTH=1 \
    -sEXPORTED_FUNCTIONS='["_emu_run","_emu_run_path","_emu_error","_emu_format","_emu_instructions","_malloc","_free"]' \
    -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","HEAPU8","FS"]' \
    -sFORCE_FILESYSTEM=1 \
    -sDISABLE_EXCEPTION_CATCHING=0 \
    -sENVIRONMENT=web,worker,node \
    --no-entry

ls -l web/x86emu.js
echo "done - serve web/ over http and open index.html"
