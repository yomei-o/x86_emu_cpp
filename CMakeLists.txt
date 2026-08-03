cmake_minimum_required(VERSION 3.16)
project(x86emu CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(x86emu
  src/main.cpp
  src/emulator.cpp
  src/cpu.cpp
  src/memory.cpp
  src/loader.cpp
  src/pe_loader.cpp
  src/elf_loader.cpp
  src/hooks.cpp
  src/syscalls.cpp
)
target_include_directories(x86emu PRIVATE src)

if(MSVC)
  target_compile_options(x86emu PRIVATE /W4)
else()
  target_compile_options(x86emu PRIVATE -Wall -Wextra)
endif()

# Generates the hand-built ELF test binaries (see tests/).
add_executable(gen_elf_tests tools/gen_elf_tests.cpp)
