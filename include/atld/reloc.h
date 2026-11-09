#pragma once
#include "atld/guest_cpu.h"
#include <elf.h>

struct tramp_pool;

/* Parse PT_DYNAMIC .rela.plt, resolve symbols via .dynsym/.dynstr,
 * register each as thunk, patch GOT slot with trampoline.
 * Returns number patched, or -1 on error. */
int reloc_plt_patch(const Elf64_Ehdr *eh, struct tramp_pool *pool);
