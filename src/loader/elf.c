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

    uint64_t tls_tdata_vaddr = 0, tls_tdata_filesz = 0;
    uint64_t tls_memsz = 0, tls_align = 0;

    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)((char *)fmap + eh->e_phoff + (size_t)i*eh->e_phentsize);
        if (ph->p_type == PT_TLS) {
            tls_tdata_vaddr  = ph->p_vaddr;
            tls_tdata_filesz = ph->p_filesz;
            tls_memsz        = ph->p_memsz;
            tls_align        = ph->p_align ? ph->p_align : 16;
            continue;
        }
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
        /* PT_LOAD vaddr may not be page-aligned (e.g. t2_arm64 RW segment
         * at 0x48c618).  mmap returned address is vstart-aligned, but
         * contents must land at vaddr.  Copy at (vaddr - vstart) offset
         * within the mapping. */
        memcpy((char *)m + (vaddr - vstart), (char *)fmap + off, filesz);
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

    /* Proper TLS setup per ARM64 glibc ABI:
     *   tpidr_el0 -> TCB start (low address)
     *   tpidr_el0 + TCB_SIZE -> .tdata (copied from file)
     *   tpidr_el0 + TCB_SIZE + tdata_filesz -> .tbss (zero-filled)
     * TCB_SIZE is glibc's tcbhead_t size. 0x30 is common for aarch64. */
    if (tls_memsz > 0) {
        const uint64_t TCB_SIZE = 0x30;
        uint64_t align = tls_align < 16 ? 16 : tls_align;
        uint64_t total = TCB_SIZE + tls_memsz + align;

        void *tls_map = mmap(NULL, total, PROT_READ|PROT_WRITE,
                             MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (tls_map == MAP_FAILED) { perror("mmap tls"); munmap(fmap, fsize); return -1; }
        uint64_t tcb_addr = ((uint64_t)tls_map + align - 1) & ~(align - 1);

        /* Copy .tdata from mapped PT_LOAD area (same address as file vaddr) */
        if (tls_tdata_filesz > 0) {
            memcpy((void *)(tcb_addr + TCB_SIZE),
                   (void *)tls_tdata_vaddr, tls_tdata_filesz);
        }

        /* Initialize TCB header (aarch64 glibc tcbhead_t = 0x30 bytes):
         *   tcb[0] 0x00 = tcb (self-pointer)
         *   tcb[1] 0x08 = dtv
         *   tcb[2] 0x10 = self
         *   tcb[3] 0x18 = multiple_threads (int) + gscope_flag (int)
         *   tcb[4] 0x20 = sysinfo
         *   tcb[5] 0x28 = stack_guard
         * tcb[6] onwards (offset 0x30) is .tdata — DO NOT write there. */
        uint64_t *tcb = (uint64_t *)tcb_addr;
        tcb[0] = tcb_addr;
        tcb[1] = 0;
        tcb[2] = tcb_addr;
        tcb[3] = 0;
        tcb[4] = 0;
        tcb[5] = 0xDEADBEEFCAFEBABEULL;

        cpu->tls_base = tcb_addr;
    } else {
        /* No PT_TLS: dummy fallback */
        void *tls = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (tls == MAP_FAILED) { perror("mmap tls"); munmap(fmap, fsize); return -1; }
        cpu->tls_base = (uint64_t)tls;
    }

    void *stack = mmap(NULL, 1 << 20, PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) { perror("mmap stack"); munmap(fmap, fsize); return -1; }

    /* Linux process ABI: minimal stack frame so glibc's __libc_start_main
     * walk of argv/envp/auxv terminates at AT_NULL and does not read past
     * the top of the stack.
     *   sp[0] = argc = 0
     *   sp[1] = argv[0] = NULL           (argv terminator)
     *   sp[2] = envp[0] = NULL           (envp terminator)
     *   sp[3] = auxv[0].type = AT_NULL   (auxv terminator)
     *   sp[4] = auxv[0].val = 0
     * sp = stack_top - 40 so sp+16 is still inside the mapping. */
    uint64_t *top = (uint64_t *)((char *)stack + (1 << 20));
    /* aarch64 Linux ABI: sp must be 16-byte aligned at _start.
     * 5-word frame (40 bytes) is NOT 16-aligned (40 % 16 == 8). Pad to
     * 6 words (48 bytes) so sp = top - 48 is 16-aligned. */
    top[-1] = 0;   /* padding slot (keeps sp 16-aligned) */
    top[-2] = 0;   /* auxv[0].val */
    top[-3] = 0;   /* auxv[0].type = AT_NULL */
    top[-4] = 0;   /* envp[0] = NULL */
    top[-5] = 0;   /* argv[0] = NULL */
    top[-6] = 0;   /* argc = 0 */
    cpu->sp = (uint64_t)&top[-6];
    fprintf(stderr, "atld: stack sp=0x%llx top=0x%llx (40-byte frame: argc/argv/envp/auxv)",
            (unsigned long long)cpu->sp, (unsigned long long)(uintptr_t)top);

    munmap(fmap, fsize);
    return 0;
}


static const char *elf_type_name(uint16_t t) {
    switch (t) {
    case ET_NONE: return "NONE";
    case ET_REL:  return "REL";
    case ET_EXEC: return "EXEC";
    case ET_DYN:  return "DYN";
    case ET_CORE: return "CORE";
    default:      return "UNKNOWN";
    }
}

static const char *elf_machine_name(uint16_t m) {
    switch (m) {
    case EM_AARCH64: return "AArch64";
    case EM_ARM:     return "ARM";
    case EM_X86_64:  return "Advanced Micro Devices X86-64";
    case EM_386:     return "Intel 80386";
    default:         return "UNKNOWN";
    }
}

static const char *phdr_type_name(uint32_t t) {
    switch (t) {
    case PT_NULL:    return "NULL";
    case PT_LOAD:    return "LOAD";
    case PT_DYNAMIC: return "DYNAMIC";
    case PT_INTERP:  return "INTERP";
    case PT_NOTE:    return "NOTE";
    case PT_SHLIB:   return "SHLIB";
    case PT_PHDR:    return "PHDR";
    case PT_TLS:     return "TLS";
#ifdef PT_GNU_EH_FRAME
    case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
#endif
#ifdef PT_GNU_STACK
    case PT_GNU_STACK:    return "GNU_STACK";
#endif
#ifdef PT_GNU_RELRO
    case PT_GNU_RELRO:    return "GNU_RELRO";
#endif
    default:         return "UNKNOWN";
    }
}

static void fmt_phdr_flags(uint32_t flags, char out[4]) {
    out[0] = (flags & PF_R) ? 'R' : ' ';
    out[1] = (flags & PF_W) ? 'W' : ' ';
    out[2] = (flags & PF_X) ? 'E' : ' ';
    out[3] = '\0';
}

/* Read-only inspection: print ELF header + program headers.
 * Does NOT map any segment, does NOT set up guest CPU state.
 * Output format is deliberately readelf-like so tests can diff fields. */
int elf_dump(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return -1; }
    size_t fsize = (size_t)st.st_size;
    void *fmap = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (fmap == MAP_FAILED) { perror("mmap"); return -1; }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)fmap;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA]  != ELFDATA2LSB ||
        eh->e_machine         != EM_AARCH64) {
        fprintf(stderr, "atld: not an AArch64 ELF64 file\n");
        munmap(fmap, fsize); return -1;
    }

    printf("atld: ELF Header:\n");
    printf("atld:   Class:                             ELF64\n");
    printf("atld:   Data:                              little endian\n");
    printf("atld:   Type:                              %s\n", elf_type_name(eh->e_type));
    printf("atld:   Machine:                           %s\n", elf_machine_name(eh->e_machine));
    printf("atld:   Entry point address:               0x%llx\n", (unsigned long long)eh->e_entry);
    printf("atld:   Start of program headers:          %llu (bytes into file)\n", (unsigned long long)eh->e_phoff);
    printf("atld:   Start of section headers:          %llu (bytes into file)\n", (unsigned long long)eh->e_shoff);
    printf("atld:   Flags:                             0x%x\n", eh->e_flags);
    printf("atld:   Size of this header:               %u (bytes)\n", eh->e_ehsize);
    printf("atld:   Size of program headers:           %u (bytes)\n", eh->e_phentsize);
    printf("atld:   Number of program headers:         %u\n", eh->e_phnum);
    printf("atld:   Size of section headers:           %u (bytes)\n", eh->e_shentsize);
    printf("atld:   Number of section headers:         %u\n", eh->e_shnum);
    printf("atld:   Section header string table index: %u\n", eh->e_shstrndx);

    printf("atld: \n");
    printf("atld: Program Headers:\n");
    printf("atld:   %-14s %-10s %-18s %-18s %-10s %-10s %-3s %s\n",
           "Type", "Offset", "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flg", "Align");

    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)((char *)fmap + eh->e_phoff + (size_t)i*eh->e_phentsize);
        char flg[4];
        fmt_phdr_flags(ph->p_flags, flg);
        printf("atld:   %-14s 0x%08llx 0x%016llx 0x%016llx 0x%08llx 0x%08llx %s 0x%llx\n",
               phdr_type_name(ph->p_type),
               (unsigned long long)ph->p_offset,
               (unsigned long long)ph->p_vaddr,
               (unsigned long long)ph->p_paddr,
               (unsigned long long)ph->p_filesz,
               (unsigned long long)ph->p_memsz,
               flg,
               (unsigned long long)ph->p_align);
        if (ph->p_type == PT_INTERP && ph->p_offset + ph->p_filesz <= fsize) {
            printf("atld:   [Requesting program interpreter: %.*s]\n",
                   (int)ph->p_filesz, (char *)fmap + ph->p_offset);
        }
    }

    munmap(fmap, fsize);
    return 0;
}
