/* thunk_dispatch — call host libc function from guest context.
 * Phase 1 (MVP): hardcoded puts() to prove mechanism.
 * Phase 2: generic per-signature trampolines.
 * Phase 3: dlsym-resolved (libEGL, libvulkan, libandroid).
 */
#include "atld/thunk.h"
#include <stdio.h>
#include <stdint.h>

int thunk_dispatch(struct guest_cpu *cpu, unsigned long idx) {
    fprintf(stderr, "atld: thunk idx=0x%lx x0=0x%llx x1=0x%llx x2=0x%llx\n",
            idx,
            (unsigned long long)cpu->x[0],
            (unsigned long long)cpu->x[1],
            (unsigned long long)cpu->x[2]);

    switch (idx) {
    case 0: {   /* THUNK_BASE + 0 = puts */
        /* puts(const char *s) — 1 arg in x0, return int in x0 */
        int ret = puts((const char *)cpu->x[0]);
        cpu->x[0] = (uint64_t)ret;
        return 0;
    }
    default:
        fprintf(stderr, "atld: unknown thunk idx 0x%lx (returning -ENOSYS)\n", idx);
        cpu->x[0] = (uint64_t)(-38);
        return 0;
    }
}
