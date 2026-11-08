#pragma once
#include "atld/guest_cpu.h"
int elf_load(const char *path, struct guest_cpu *cpu);
int elf_dump(const char *path);
