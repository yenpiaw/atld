#pragma once
#include "atld/guest_cpu.h"
#include <stdint.h>

#define CB_MAX 16
#define CB_RETURN_STUB 0xDEADBEEFCAFEULL

int cb_register(int idx, uint64_t fn_ptr);
uint64_t cb_invoke(struct guest_cpu *cpu, int idx, uint64_t *args, int nargs);
int interp_step_until_pc(struct guest_cpu *cpu, uint64_t stop_pc);
