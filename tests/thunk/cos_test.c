typedef long s64;
typedef unsigned long u64;
#define THUNK_COS (0x1000000L + 2)

static double thunk_call_d1(s64 idx, double a0) {
    register s64 x8 __asm__("x8") = idx;
    register double v0 __asm__("v0") = a0;
    __asm__ volatile("svc #0" : "+w"(v0) : "r"(x8) : "memory");
    return v0;
}
static s64 sys_write(s64 fd, const void *buf, s64 n) {
    register s64 x8 __asm__("x8") = 64;
    register s64 x0 __asm__("x0") = fd;
    register s64 x1 __asm__("x1") = (s64)buf;
    register s64 x2 __asm__("x2") = n;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static __attribute__((noreturn)) void sys_exit(s64 code) {
    register s64 x8 __asm__("x8") = 94;
    register s64 x0 __asm__("x0") = code;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory");
    __builtin_unreachable();
}

__attribute__((noreturn)) void _start(void) {
    static const char ok[] = "cos(0.0)=1.0 OK\n";
    static const char fail[] = "cos(0.0)!=1.0 FAIL\n";
    double r = thunk_call_d1(THUNK_COS, 0.0);
    union { double d; u64 u; } u;
    u.d = r;
    if (u.u == 0x3FF0000000000000ULL) { sys_write(1, ok, sizeof(ok)-1); sys_exit(0); }
    sys_write(1, fail, sizeof(fail)-1); sys_exit(1);
}
