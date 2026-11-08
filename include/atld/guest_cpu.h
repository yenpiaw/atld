#pragma once
#include <stdint.h>

struct guest_cpu {
    uint64_t x[31];       /* x0..x30; x31 = XZR/SP handled specially */
    uint64_t sp;
    uint64_t pc;
    uint32_t pstate;      /* NZCV + DAIF, unused in M2 */
    uint32_t _pad;
    uint64_t v[32][2];    /* v0..v31, 128-bit, unused in M2 */
    uint64_t fpcr;
    uint64_t fpsr;
    uint64_t tls_base;
    /* trace: 64 PC terakhir, untuk debug crash */
    uint64_t pc_history[64];
    int pc_history_idx;
};

static inline uint64_t get_x(const struct guest_cpu *c, int i) {
    return i == 31 ? 0 : c->x[i];
}
static inline void set_x(struct guest_cpu *c, int i, uint64_t v) {
    if (i != 31) c->x[i] = v;
}
