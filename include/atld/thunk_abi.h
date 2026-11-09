#pragma once

/* Thunk base: jauh di atas jangkauan syscall aarch64 (~450). */
#define THUNK_BASE      0x1000000UL
#define THUNK_PUTS      (THUNK_BASE + 0)
#define THUNK_STRLEN    (THUNK_BASE + 1)
#define THUNK_COS       (THUNK_BASE + 2)
#define THUNK_POW       (THUNK_BASE + 3)

/* Signature classes — host only (guest hardcodes indices). */
#ifdef ATLD_THUNK_HOST
enum thunk_sig {
    SIG_I0,   /* int (void)                    — return x0 */
    SIG_I1,   /* int (long)                    — arg x0, return x0 */
    SIG_L1,   /* long (long)                   — arg x0, return x0 (64-bit) */
    SIG_D1,   /* double (double)               — arg v0[0], return v0[0] */
    SIG_D2,   /* double (double, double)       — arg v0[0], v1[0] */
};
#endif
