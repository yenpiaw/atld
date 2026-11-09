/* thunk_dispatch — host function call from guest context.
 * Phase 2 (this): named table + lazy dlsym + SIG_I0/I1/L1/I4/I6/D1/D2/D3/D4.
 * Phase 3:        .so loading + full AAPCS64 (stack spill > 8 args). */
#define ATLD_THUNK_HOST
#include "atld/thunk.h"
#include "atld/thunk_abi.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

struct thunk_entry {
    const char    *name;
    enum thunk_sig sig;
    void          *fn;      /* lazy dlsym cache */
    void          *builtin; /* non-NULL: use directly, no dlsym */
};

/* Built-in test functions — verify multi-arg marshalling without libc deps. */
static double test_d4(double a, double b, double c, double d) {
    return a + b*10.0 + c*100.0 + d*1000.0;
}
static long test_i6(long a, long b, long c, long d, long e, long f) {
    return a + b*10 + c*100 + d*1000 + e*10000 + f*100000;
}

static struct thunk_entry thunks[] = {
    { "puts",           SIG_I1, NULL, NULL },
    { "strlen",         SIG_L1, NULL, NULL },
    { "cos",            SIG_D1, NULL, NULL },
    { "pow",            SIG_D2, NULL, NULL },
    { "fma",            SIG_D3, NULL, NULL },
    { "__atld_test_d4", SIG_D4, NULL, (void*)&test_d4 },
    { "__atld_test_i6", SIG_I6, NULL, (void*)&test_i6 },
};

#define THUNK_COUNT (sizeof(thunks) / sizeof(thunks[0]))

static inline double v_get(const struct guest_cpu *c, int i) {
    double d; memcpy(&d, &c->v[i][0], 8); return d;
}
static inline void v_set(struct guest_cpu *c, int i, double d) {
    memcpy(&c->v[i][0], &d, 8);
}

int thunk_dispatch(struct guest_cpu *cpu, unsigned long idx) {
    if (idx >= THUNK_COUNT) {
        fprintf(stderr, "atld: thunk idx=%lu out of range (max %lu)\n",
                idx, (unsigned long)(THUNK_COUNT - 1));
        cpu->x[0] = (uint64_t)(-38);
        return 0;
    }
    struct thunk_entry *t = &thunks[idx];

    if (!t->fn) {
        if (t->builtin) {
            t->fn = t->builtin;
        } else {
            t->fn = dlsym(RTLD_DEFAULT, t->name);
            if (!t->fn) {
                fprintf(stderr, "atld: thunk '%s' not found\n", t->name);
                cpu->x[0] = (uint64_t)(-38);
                return 0;
            }
            fprintf(stderr, "atld: thunk resolved '%s' -> %p\n", t->name, t->fn);
        }
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
    case SIG_I4:
        cpu->x[0] = (uint64_t)(int64_t)((long(*)(long,long,long,long))t->fn)(
            (long)cpu->x[0], (long)cpu->x[1], (long)cpu->x[2], (long)cpu->x[3]);
        break;
    case SIG_I6:
        cpu->x[0] = (uint64_t)(int64_t)((long(*)(long,long,long,long,long,long))t->fn)(
            (long)cpu->x[0], (long)cpu->x[1], (long)cpu->x[2],
            (long)cpu->x[3], (long)cpu->x[4], (long)cpu->x[5]);
        break;
    case SIG_D1:
        v_set(cpu, 0, ((double(*)(double))t->fn)(v_get(cpu, 0)));
        break;
    case SIG_D2:
        v_set(cpu, 0, ((double(*)(double,double))t->fn)(v_get(cpu, 0), v_get(cpu, 1)));
        break;
    case SIG_D3:
        v_set(cpu, 0, ((double(*)(double,double,double))t->fn)(
            v_get(cpu, 0), v_get(cpu, 1), v_get(cpu, 2)));
        break;
    case SIG_D4:
        v_set(cpu, 0, ((double(*)(double,double,double,double))t->fn)(
            v_get(cpu, 0), v_get(cpu, 1), v_get(cpu, 2), v_get(cpu, 3)));
        break;
    default:
        fprintf(stderr, "atld: thunk '%s' unsupported sig %d\n", t->name, t->sig);
        cpu->x[0] = (uint64_t)(-38);
    }
    return 0;
}
