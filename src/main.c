#include "atld/guest_cpu.h"
#include "atld/loader.h"
#include "atld/interp.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

static struct guest_cpu *g_cpu = NULL;

static void segv_handler(int sig, siginfo_t *si, void *ctx) {
    (void)sig; (void)ctx;
    fprintf(stderr, "\natld: SIGSEGV host_addr=%p\n", si->si_addr);
    if (g_cpu) {
        fprintf(stderr, "atld: guest pc=0x%llx sp=0x%llx x30=0x%llx\n",
                (unsigned long long)g_cpu->pc,
                (unsigned long long)g_cpu->sp,
                (unsigned long long)g_cpu->x[30]);
        fprintf(stderr, "atld: all GPRs:\n");
        for (int i = 0; i < 31; i++) {
            fprintf(stderr, "  x%-2d = 0x%016llx\n", i,
                    (unsigned long long)g_cpu->x[i]);
        }
        fprintf(stderr, "  sp  = 0x%016llx\n", (unsigned long long)g_cpu->sp);
        fprintf(stderr, "  pstate = 0x%08x  (N=%d Z=%d C=%d V=%d)\n",
                g_cpu->pstate,
                (g_cpu->pstate>>31)&1, (g_cpu->pstate>>30)&1,
                (g_cpu->pstate>>29)&1, (g_cpu->pstate>>28)&1);
        fprintf(stderr, "atld: last 32 guest PCs (oldest first):\n");
        int n = g_cpu->pc_history_idx < 32 ? g_cpu->pc_history_idx : 32;
        for (int i = n; i > 0; i--) {
            int idx = (g_cpu->pc_history_idx - i) & 63;
            fprintf(stderr, "  0x%llx\n",
                    (unsigned long long)g_cpu->pc_history[idx]);
        }
    }
    _exit(139);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s [--dump] <aarch64-elf>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "--dump") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s --dump <aarch64-elf>\n", argv[0]);
            return 2;
        }
        return elf_dump(argv[2]) == 0 ? 0 : 1;
    }
    struct guest_cpu *cpu = calloc(1, sizeof(*cpu));
    if (!cpu) { perror("calloc"); return 1; }

    g_cpu = cpu;
    struct sigaction sa = {0};
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    if (elf_load(argv[1], cpu) != 0) return 1;

    fprintf(stderr, "atld: start pc=0x%llx sp=0x%llx\n",
            (unsigned long long)cpu->pc, (unsigned long long)cpu->sp);

    for (;;) {
        if (interp_step(cpu) != 0) {
            fprintf(stderr, "atld: halted at pc=0x%llx\n",
                    (unsigned long long)cpu->pc);
            fprintf(stderr, "atld: last 16 PCs:\n");
            int n = cpu->pc_history_idx < 16 ? cpu->pc_history_idx : 16;
            for (int i = n; i > 0; i--) {
                int idx = (cpu->pc_history_idx - i) & 63;
                fprintf(stderr, "  pc=0x%llx\n",
                        (unsigned long long)cpu->pc_history[idx]);
            }
            return 1;
        }
    }
}
