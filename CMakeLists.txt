cmake_minimum_required(VERSION 3.16)
project(atld C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_executable(atld
    src/main.c
    src/loader/elf.c
    src/loader/reloc.c
    src/interp/decode.c
    src/interp/exec.c
    src/syscall/table.c
    src/thunk/dispatch.c
)

target_include_directories(atld PRIVATE include)
target_link_libraries(atld PRIVATE m dl)
target_compile_options(atld PRIVATE -Wall -Wextra -Wno-unused-parameter -g -O0)
target_link_options(atld PRIVATE -pie)
