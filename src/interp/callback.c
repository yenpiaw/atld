/* M6.4: callback host->guest. Host can invoke a guest function via
 * interp_step_until_pc, with proper AAPCS64 argument setup and return. */
#include "atld/callback.h"
#include "atld/interp.h"

static uint64_t g_cbs[CB_MAX] = {0};

int cb_register(int idx, uint64_t fn_ptr) {
    if (idx < 0 || idx >= CB_MAX) return -1;
    g_cbs[idx] = fn_ptr;
    return 0;
}

int interp_step_until_pc(struct guest_cpu *cpu, uint64_t stop_pc) {
    while (cpu->pc != stop_pc) {
        if (interp_step(cpu) != 0) return -1;
    }
    return 0;
}

uint64_t cb_invoke(struct guest_cpu *cpu, int idx, uint64_t *args, int nargs) {
    if (idx < 0 || idx >= CB_MAX || !g_cbs[idx]) return (uint64_t)-1;

    struct guest_cpu saved = *cpu;

    for (int i = 0; i < nargs && i < 8; i++) cpu->x[i] = args[i];
    cpu->pc = g_cbs[idx];
    cpu->x[30] = CB_RETURN_STUB;

    if (interp_step_until_pc(cpu, CB_RETURN_STUB) != 0) {
        *cpu = saved;
        return (uint64_t)-1;
    }

    uint64_t ret = cpu->x[0];
    *cpu = saved;
    return ret;
}
