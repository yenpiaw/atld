/* hello_puts.c — guest ARM64 panggil host puts() via thunk.
 * Thunk base = 0x1000000 (di atas jangkauan syscall aarch64 ~450). */
typedef long s64;

#define THUNK_BASE 0x1000000
#define THUNK_PUTS (THUNK_BASE + 0)

static inline s64 thunk_call1(s64 idx, s64 arg0) {
    register s64 x8 __asm__("x8") = idx;
    register s64 x0 __asm__("x0") = arg0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

static inline s64 sys_exit_group(s64 code) {
    register s64 x8 __asm__("x8") = 94;
    register s64 x0 __asm__("x0") = code;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

__attribute__((noreturn)) void _start(void) {
    static const char msg[] = "hello from host puts";  /* puts adds \n */
    s64 r = thunk_call1(THUNK_PUTS, (s64)msg);
    if (r < 0) sys_exit_group(1);   /* thunk failed */
    sys_exit_group(0);
    __builtin_unreachable();
}
