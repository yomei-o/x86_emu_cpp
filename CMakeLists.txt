cmake_minimum_required(VERSION 3.16)
project(x86emu CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Every translation unit in src/ (bar none): globbing keeps this from going stale
# when a source file is added, the same way build.sh does. CONFIGURE_DEPENDS re-runs
# the glob when the set of files changes.
file(GLOB X86EMU_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_executable(x86emu ${X86EMU_SOURCES})
target_include_directories(x86emu PRIVATE src)

if(MSVC)
  # /utf-8  : the sources are UTF-8; without this MSVC assumes the ANSI codepage.
  # /EHsc   : the wasm/native code paths use C++ exceptions (try/catch around load/run).
  # NOMINMAX + _CRT_SECURE_NO_WARNINGS: this is a POSIX-leaning codebase using
  #           std::min/max and fopen/strncpy directly.
  target_compile_options(x86emu PRIVATE /utf-8 /EHsc /W3)
  target_compile_definitions(x86emu PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(x86emu PRIVATE -Wall -Wextra)
endif()

# Generates the hand-built ELF test binaries (see tests/).
add_executable(gen_elf_tests tools/gen_elf_tests.cpp)
if(MSVC)
  target_compile_options(gen_elf_tests PRIVATE /utf-8 /EHsc)
  target_compile_definitions(gen_elf_tests PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
endif()
