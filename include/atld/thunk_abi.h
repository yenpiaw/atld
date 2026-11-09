#pragma once

/* Thunk base: jauh di atas jangkauan syscall aarch64 (~450). */
#define THUNK_BASE      0x1000000UL
#define THUNK_PUTS      (THUNK_BASE + 0)
#define THUNK_STRLEN    (THUNK_BASE + 1)
#define THUNK_COS       (THUNK_BASE + 2)
#define THUNK_POW       (THUNK_BASE + 3)
#define THUNK_FMA       (THUNK_BASE + 4)
/* Test-only built-ins (no dlsym): verify multi-arg marshalling. */
#define THUNK_TEST_D4   (THUNK_BASE + 5)
#define THUNK_TEST_I6   (THUNK_BASE + 6)
#define THUNK_REGISTER_CB (THUNK_BASE + 7)
#define THUNK_TRIGGER_CB  (THUNK_BASE + 8)

/* Signature classes — host only (guest hardcodes indices). */
#ifdef ATLD_THUNK_HOST
enum thunk_sig {
    SIG_I0,   /* int (void)                              */
    SIG_I1,   /* int (long)                              */
    SIG_L1,   /* long (long)                             */
    SIG_I4,   /* int (long, long, long, long)            */
    SIG_I6,   /* int (long×6)                            */
    SIG_D1,   /* double (double)                         */
    SIG_D2,   /* double (double, double)                 */
    SIG_D3,   /* double (double, double, double)         */
    SIG_D4,   /* double (double×4)                       */
    SIG_UNRESOLVED,  /* unknown symbol — return -ENOSYS, never call */
};
#endif
