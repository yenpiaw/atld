#pragma once
#include "atld/guest_cpu.h"

struct tramp_pool;

int thunk_dispatch(struct guest_cpu *cpu, unsigned long idx);
int thunk_register(const char *name);

struct tramp_pool *tramp_pool_create(void);
void *tramp_pool_alloc(struct tramp_pool *pool, int idx);
void *tramp_pool_exit_stub(struct tramp_pool *pool);
