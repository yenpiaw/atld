/* thunk_dispatch — call host function from guest context.
 *
 * Phase 1 (MVP): hardcoded puts.
 * Phase 2 (this):  table + lazy dlsym + signature dispatch.
 * Phase 3:         .so dynamic loading (PT_INTERP + DT_NEEDED).
 */
#define ATLD_THUNK_HOST
#include "atld/thunk.h"
#include "atld/thunk_abi.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

struct thunk_entry {
    const char   *name;
    enum thunk_sig sig;
    void         *fn;   /* lazy-resolved via dlsym */
};

static struct thunk_entry thunks[] = {
    { "puts",   SIG_I1, NULL },
    { "strlen", SIG_L1, NULL },
    { "cos",    SIG_D1, NULL },
    { "pow",    SIG_D2, NULL },
};

#define THUNK_COUNT (sizeof(thunks) / sizeof(thunks[0]))

static inline double v0_get(const struct guest_cpu *c) {
    double d; memcpy(&d, &c->v[0][0], 8); return d;
}
static inline double v1_get(const struct guest_cpu *c) {
    double d; memcpy(&d, &c->v[1][0], 8); return d;
}
static inline void v0_set(struct guest_cpu *c, double d) {
    memcpy(&c->v[0][0], &d, 8);
}

int thunk_dispatch(struct guest_cpu *cpu, unsigned long idx) {
    if (idx >= THUNK_COUNT) {
        fprintf(stderr, "atld: thunk idx=0x%lx out of range (max 0x%lx)\n",
                idx, (unsigned long)(THUNK_COUNT - 1));
        cpu->x[0] = (uint64_t)(-38);
        return 0;
    }
    struct thunk_entry *t = &thunks[idx];

    if (!t->fn) {
        t->fn = dlsym(RTLD_DEFAULT, t->name);
        if (!t->fn) {
            fprintf(stderr, "atld: thunk '%s' not found via dlsym\n", t->name);
            cpu->x[0] = (uint64_t)(-38);
            return 0;
        }
        fprintf(stderr, "atld: thunk resolved '%s' -> %p\n", t->name, t->fn);
    }

    switch (t->sig) {
    case SIG_I0:
        cpu->x[0] = (uint64_t)(int64_t)((int(*)(void))t->fn)();
        break;
    case SIG_I1:
        cpu->x[0] = (uint64_t)(int64_t)((int(*)(long))t->fn)((long)cpu->x[0]);
        break;
    case SIG_L1:
        cpu->x[0] = (uint64_t)((long(*)(long))t->fn)((long)cpu->x[0]);
        break;
    case SIG_D1: {
        double r = ((double(*)(double))t->fn)(v0_get(cpu));
        v0_set(cpu, r);
        break;
    }
    case SIG_D2: {
        double r = ((double(*)(double,double))t->fn)(v0_get(cpu), v1_get(cpu));
        v0_set(cpu, r);
        break;
    }
    default:
        fprintf(stderr, "atld: thunk '%s' unsupported sig %d\n", t->name, t->sig);
        cpu->x[0] = (uint64_t)(-38);
    }
    return 0;
}
