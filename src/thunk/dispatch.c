/* thunk_dispatch — host function call from guest context.
 * Phase 2b: named table + lazy dlsym + SIG_I0/I1/L1/I4/I6/D1/D2/D3/D4.
 * M6.3 MVP2a: dynamic thunk_register + trampoline pool. */
#define ATLD_THUNK_HOST
#include "atld/thunk.h"
#include "atld/thunk_abi.h"
#include "atld/callback.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define THUNK_STATIC_COUNT 9
#define THUNK_MAX 256
#define TRAMP_BYTES (THUNK_MAX * 16)
#define TRAMP_PAGE_SIZE 8192

struct thunk_entry {
    const char    *name;
    enum thunk_sig sig;
    void          *fn;
    void          *builtin;
};

static double test_d4(double a, double b, double c, double d) {
    return a + b*10.0 + c*100.0 + d*1000.0;
}
static long test_i6(long a, long b, long c, long d, long e, long f) {
    return a + b*10 + c*100 + d*1000 + e*10000 + f*100000;
}

static struct thunk_entry thunks[THUNK_MAX] = {
    { "puts",           SIG_I1, NULL, NULL },
    { "strlen",         SIG_L1, NULL, NULL },
    { "cos",            SIG_D1, NULL, NULL },
    { "pow",            SIG_D2, NULL, NULL },
    { "fma",            SIG_D3, NULL, NULL },
    { "__atld_test_d4", SIG_D4, NULL, (void*)&test_d4 },
    { "__atld_test_i6", SIG_I6, NULL, (void*)&test_i6 },
    { "__atld_register_cb", SIG_I1, NULL, NULL },  /* special: (idx, fn) */
    { "__atld_trigger_cb",  SIG_I1, NULL, NULL },  /* special: (idx, a, b) */
};
static int thunk_count = THUNK_STATIC_COUNT;

struct tramp_pool {
    uint8_t *base;   /* executable page */
    int next_idx;    /* next free slot (<= THUNK_MAX) */
};

struct tramp_pool *g_tramp_pool = NULL;

struct tramp_pool *tramp_pool_create(void) {
    void *p = mmap(NULL, TRAMP_PAGE_SIZE,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "atld: tramp pool mmap failed\n");
        return NULL;
    }
    struct tramp_pool *pool = calloc(1, sizeof(*pool));
    pool->base = p;
    pool->next_idx = 0;
    g_tramp_pool = pool;
    fprintf(stderr, "atld: tramp pool at %p (%d slots)\n", p, THUNK_MAX);
    return pool;
}

/* Emit trampoline at slot idx:
 *   MOVZ x8, #0x0100, LSL #16   ; x8 = THUNK_BASE
 *   MOVK x8, #idx                ; x8 = THUNK_BASE + idx
 *   SVC #0
 *   RET
 * Only low 16 bits of idx supported (idx < 65536, we have 256). */
void *tramp_pool_alloc(struct tramp_pool *pool, int idx) {
    if (!pool || idx < 0 || idx >= THUNK_MAX) return NULL;
    uint32_t *t = (uint32_t *)(pool->base + idx * 16);
    t[0] = 0xD2A02008;                                   /* MOVZ x8, #0x100, LSL16 */
    t[1] = 0xF2800008 | ((uint32_t)(idx & 0xffff) << 5);  /* MOVK x8, #idx (Rd=8) */
    t[2] = 0xD4000001;                                   /* SVC #0 */
    t[3] = 0xD65F03C0;                                   /* RET */
    __builtin___clear_cache((char *)t, (char *)t + 16);
    return t;
}

void *tramp_pool_exit_stub(struct tramp_pool *pool) {
    if (!pool) return NULL;
    /* Exit stub at slot THUNK_MAX (past last trampoline, still in page).
     * Preserves x0 from main's return as exit code. */
    uint32_t *t = (uint32_t *)(pool->base + THUNK_MAX * 16);
    t[0] = 0xD2800BC8;   /* MOVZ x8, #94 (exit_group) */
    t[1] = 0xD4000001;   /* SVC #0 -> exit_group(x0 from main) */
    t[2] = 0xD65F03C0;   /* RET (safety, not reached) */
    t[3] = 0xD503201F;   /* NOP padding */
    __builtin___clear_cache((char *)t, (char *)t + 16);
    return t;
}

int thunk_register(const char *name) {
    if (!name || !*name) return -1;
    for (int i = 0; i < thunk_count; i++) {
        if (thunks[i].name && strcmp(thunks[i].name, name) == 0) {
            return i;
        }
    }
    if (thunk_count >= THUNK_MAX) return -1;
    int idx = thunk_count++;
    thunks[idx].name    = strdup(name);
    thunks[idx].fn      = NULL;
    thunks[idx].builtin = NULL;

    /* Infer sig: default to SIG_I1 (1 int arg, int return).
     * Real functions need explicit sig — this is MVP heuristic.
     * Better: caller passes sig, or we parse name patterns. */
    thunks[idx].sig = SIG_I1;

    fprintf(stderr, "atld: thunk_register '%s' -> idx %d (sig %d)\n",
            name, idx, thunks[idx].sig);
    return idx;
}

static inline double v_get(const struct guest_cpu *c, int i) {
    double d; memcpy(&d, &c->v[i][0], 8); return d;
}
static inline void v_set(struct guest_cpu *c, int i, double d) {
    memcpy(&c->v[i][0], &d, 8);
}

int thunk_dispatch(struct guest_cpu *cpu, unsigned long idx) {
    if (idx >= (unsigned long)thunk_count) {
        fprintf(stderr, "atld: thunk idx=%lu out of range (max %d)\n",
                idx, thunk_count - 1);
        cpu->x[0] = (uint64_t)(-38);
        return 0;
    }
    struct thunk_entry *t = &thunks[idx];

    /* M6.4: callback infra — special-case BEFORE dlsym (name is not a host symbol) */
    if (strcmp(t->name, "__atld_register_cb") == 0) {
        cb_register((int)cpu->x[0], cpu->x[1]);
        cpu->x[0] = 0;
        return 0;
    }
    if (strcmp(t->name, "__atld_trigger_cb") == 0) {
        uint64_t args[2] = { cpu->x[1], cpu->x[2] };
        uint64_t r = cb_invoke(cpu, (int)cpu->x[0], args, 2);
        cpu->x[0] = r;
        return 0;
    }

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
    case SIG_I0: cpu->x[0] = (uint64_t)(int64_t)((int(*)(void))t->fn)(); break;
    case SIG_I1: cpu->x[0] = (uint64_t)(int64_t)((int(*)(long))t->fn)((long)cpu->x[0]); break;
    case SIG_L1: cpu->x[0] = (uint64_t)((long(*)(long))t->fn)((long)cpu->x[0]); break;
    case SIG_I4:
        cpu->x[0] = (uint64_t)(int64_t)((long(*)(long,long,long,long))t->fn)(
            (long)cpu->x[0], (long)cpu->x[1], (long)cpu->x[2], (long)cpu->x[3]);
        break;
    case SIG_I6:
        cpu->x[0] = (uint64_t)(int64_t)((long(*)(long,long,long,long,long,long))t->fn)(
            (long)cpu->x[0], (long)cpu->x[1], (long)cpu->x[2],
            (long)cpu->x[3], (long)cpu->x[4], (long)cpu->x[5]);
        break;
    case SIG_D1: v_set(cpu, 0, ((double(*)(double))t->fn)(v_get(cpu, 0))); break;
    case SIG_D2: v_set(cpu, 0, ((double(*)(double,double))t->fn)(v_get(cpu,0), v_get(cpu,1))); break;
    case SIG_D3: v_set(cpu, 0, ((double(*)(double,double,double))t->fn)(v_get(cpu,0), v_get(cpu,1), v_get(cpu,2))); break;
    case SIG_D4: v_set(cpu, 0, ((double(*)(double,double,double,double))t->fn)(v_get(cpu,0), v_get(cpu,1), v_get(cpu,2), v_get(cpu,3))); break;
    default:
        fprintf(stderr, "atld: thunk '%s' unsupported sig %d\n", t->name, t->sig);
        cpu->x[0] = (uint64_t)(-38);
    }
    return 0;
}
