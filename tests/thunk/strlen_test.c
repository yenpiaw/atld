typedef long s64;
#define THUNK_STRLEN (0x1000000L + 1)

static s64 thunk_call_i1(s64 idx, s64 a0) {
    register s64 x8 __asm__("x8") = idx;
    register s64 x0 __asm__("x0") = a0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
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
    static const char s[] = "hello";
    static const char ok[] = "strlen(hello)=5 OK\n";
    static const char fail[] = "strlen(hello)!=5 FAIL\n";
    s64 r = thunk_call_i1(THUNK_STRLEN, (s64)s);
    if (r == 5) { sys_write(1, ok, sizeof(ok)-1); sys_exit(0); }
    sys_write(1, fail, sizeof(fail)-1); sys_exit(1);
}
