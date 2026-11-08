#include "atld/loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <errno.h>

int elf_load(const char *path, struct guest_cpu *cpu) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return -1; }

    size_t fsize = (size_t)st.st_size;
    void *fmap = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (fmap == MAP_FAILED) { perror("mmap file"); return -1; }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)fmap;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS]  != ELFCLASS64 ||
        eh->e_ident[EI_DATA]   != ELFDATA2LSB ||
        eh->e_machine          != EM_AARCH64) {
        fprintf(stderr, "atld: not an AArch64 ELF64 file\n");
        munmap(fmap, fsize); return -1;
    }
    if (eh->e_type != ET_EXEC) {
        fprintf(stderr, "atld: only ET_EXEC (non-PIE) supported in M2, got e_type=%u\n",
                (unsigned)eh->e_type);
        munmap(fmap, fsize); return -1;
    }

    fprintf(stderr, "atld: entry=0x%llx phnum=%u\n",
            (unsigned long long)eh->e_entry, (unsigned)eh->e_phnum);

    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)((char *)fmap + eh->e_phoff + (size_t)i*eh->e_phentsize);
        if (ph->p_type != PT_LOAD) continue;

        uint64_t vaddr = ph->p_vaddr, memsz = ph->p_memsz;
        uint64_t filesz = ph->p_filesz, off = ph->p_offset;

        uint64_t page = 4096;
        uint64_t vstart = vaddr & ~(page - 1);
        uint64_t vend   = (vaddr + memsz + page - 1) & ~(page - 1);
        uint64_t msize  = vend - vstart;

        int prot = 0;
        if (ph->p_flags & PF_R) prot |= PROT_READ;
        if (ph->p_flags & PF_W) prot |= PROT_WRITE;
        if (ph->p_flags & PF_X) prot |= PROT_EXEC;

        /* Map RW first so we can memcpy file contents; make final perms
         * after.  PT_LOAD with PF_X but no PF_W (typical .text) would
         * otherwise SIGSEGV on the copy.  Anonymous mmap is zeroed, so
         * .bss (memsz > filesz) is covered. */
        void *m = mmap((void *)vstart, msize, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (m == MAP_FAILED) {
            fprintf(stderr, "atld: mmap segment [0x%llx,+0x%llx) failed: %s\n",
                    (unsigned long long)vstart, (unsigned long long)msize, strerror(errno));
            fprintf(stderr, "atld: hint: rebuild atld as PIE (default on Arch) if collision at 0x%llx\n",
                    (unsigned long long)vstart);
            munmap(fmap, fsize); return -1;
        }
        memcpy(m, (char *)fmap + off, filesz);
        if (mprotect(m, msize, prot) < 0) {
            fprintf(stderr, "atld: mprotect [0x%llx,+0x%llx) -> %d failed: %s\n",
                    (unsigned long long)vstart, (unsigned long long)msize,
                    prot, strerror(errno));
            munmap(fmap, fsize); return -1;
        }
        __builtin___clear_cache((char *)vstart, (char *)vend);
        fprintf(stderr, "atld: mapped [0x%llx, 0x%llx) prot=%d\n",
                (unsigned long long)vaddr, (unsigned long long)(vaddr + memsz), prot);
    }

    memset(cpu->x, 0, sizeof(cpu->x));
    memset(cpu->v, 0, sizeof(cpu->v));
    cpu->pc = eh->e_entry;

    void *stack = mmap(NULL, 1 << 20, PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) { perror("mmap stack"); munmap(fmap, fsize); return -1; }
    cpu->sp = (uint64_t)stack + (1 << 20) - 16;
    *(uint64_t *)cpu->sp = 0;   /* argc = 0 */

    munmap(fmap, fsize);
    return 0;
}
