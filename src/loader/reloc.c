/* reloc.c — M6.3 MVP2a: parse .rela.plt, register thunks, patch GOT.
 *
 * Assumes dyn.jmprel / .symtab / .strtab are already mapped (vaddr == loaded).
 * Requires ET_EXEC (no PIE base). */
#include "atld/reloc.h"
#include "atld/thunk.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>

struct dyn_info {
    uint64_t symtab, strtab, jmprel, pltrelsz, pltrel, syment;
};

static void parse_dynamic(const Elf64_Ehdr *eh, struct dyn_info *dyn) {
    memset(dyn, 0, sizeof(*dyn));
    const Elf64_Phdr *ph = (const Elf64_Phdr *)((const char *)eh + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++,
         ph = (const Elf64_Phdr *)((const char *)ph + eh->e_phentsize)) {
        if (ph->p_type != PT_DYNAMIC) continue;
        const Elf64_Dyn *d = (const Elf64_Dyn *)((const char *)eh + ph->p_offset);
        int n = ph->p_filesz / (int)sizeof(Elf64_Dyn);
        for (int j = 0; j < n; j++, d++) {
            switch (d->d_tag) {
            case DT_SYMTAB:  dyn->symtab  = d->d_un.d_ptr; break;
            case DT_STRTAB:  dyn->strtab  = d->d_un.d_ptr; break;
            case DT_JMPREL:  dyn->jmprel  = d->d_un.d_ptr; break;
            case DT_PLTRELSZ: dyn->pltrelsz = d->d_un.d_val; break;
            case DT_PLTREL:  dyn->pltrel  = d->d_un.d_val; break;
            case DT_SYMENT:  dyn->syment  = d->d_un.d_val; break;
            }
        }
        return;
    }
}

int reloc_plt_patch(const Elf64_Ehdr *eh, struct tramp_pool *pool) {
    struct dyn_info dyn;
    parse_dynamic(eh, &dyn);

    if (!dyn.jmprel || !dyn.symtab || !dyn.strtab) {
        fprintf(stderr, "atld: no .rela.plt (jmprel=%llx symtab=%llx strtab=%llx)\n",
                (unsigned long long)dyn.jmprel,
                (unsigned long long)dyn.symtab,
                (unsigned long long)dyn.strtab);
        return 0;
    }
    if (dyn.pltrel != DT_RELA) {
        fprintf(stderr, "atld: only DT_RELA supported (got %llu)\n",
                (unsigned long long)dyn.pltrel);
        return -1;
    }

    size_t n = dyn.pltrelsz / sizeof(Elf64_Rela);
    fprintf(stderr, "atld: .rela.plt at 0x%llx (%zu entries)\n",
            (unsigned long long)dyn.jmprel, n);

    const Elf64_Rela *rela = (const Elf64_Rela *)dyn.jmprel;
    const Elf64_Sym  *sym  = (const Elf64_Sym *)dyn.symtab;
    const char       *str  = (const char *)dyn.strtab;

    int patched = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t r_type   = (uint32_t)(rela[i].r_info & 0xffffffff);
        uint32_t r_symidx = (uint32_t)(rela[i].r_info >> 32);
        uint64_t r_offset = rela[i].r_offset;

        if (r_type != R_AARCH64_JUMP_SLOT) {
            fprintf(stderr, "atld: skip reloc[%zu] type=0x%x\n", i, r_type);
            continue;
        }

        const char *name = str + sym[r_symidx].st_name;
        fprintf(stderr, "atld: PLT slot [0x%llx] -> '%s' (sym %u)\n",
                (unsigned long long)r_offset, name, r_symidx);

        int idx = thunk_register(name);
        if (idx < 0) {
            fprintf(stderr, "atld: thunk register failed for '%s'\n", name);
            continue;
        }
        void *tramp = tramp_pool_alloc(pool, idx);
        if (!tramp) {
            fprintf(stderr, "atld: tramp pool full at idx %d\n", idx);
            return -1;
        }
        *(uint64_t *)(uintptr_t)r_offset = (uint64_t)tramp;
        patched++;
    }
    fprintf(stderr, "atld: patched %d PLT slots\n", patched);
    return patched;
}
