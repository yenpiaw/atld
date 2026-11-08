#include "atld/guest_cpu.h"
#include "atld/loader.h"
#include "atld/interp.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <aarch64-elf>\n", argv[0]);
        return 2;
    }
    struct guest_cpu *cpu = calloc(1, sizeof(*cpu));
    if (!cpu) { perror("calloc"); return 1; }

    if (elf_load(argv[1], cpu) != 0) return 1;

    fprintf(stderr, "atld: start pc=0x%llx sp=0x%llx\n",
            (unsigned long long)cpu->pc, (unsigned long long)cpu->sp);

    for (;;) {
        if (interp_step(cpu) != 0) {
            fprintf(stderr, "atld: halted at pc=0x%llx\n",
                    (unsigned long long)cpu->pc);
            return 1;
        }
    }
}
