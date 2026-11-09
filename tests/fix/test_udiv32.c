typedef long s64;
static s64 sys_write(s64 fd, const void *buf, s64 n) {
    register s64 x8 __asm__("x8") = 64;
    register s64 x0 __asm__("x0") = fd;
    register s64 x1 __asm__("x1") = (s64)buf;
    register s64 x2 __asm__("x2") = n;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static __attribute__((noreturn)) void sys_exit(s64 c) {
    register s64 x8 __asm__("x8") = 94;
    register s64 x0 __asm__("x0") = c;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory");
    __builtin_unreachable();
}
__attribute__((noreturn)) void _start(void) {
    unsigned int r;
    __asm__ volatile("udiv %w0, %w1, %w2" : "=r"(r) : "r"(0xFFFFFFFFu), "r"(2u));
    if (r == 0x7FFFFFFFu) {
        static const char ok[] = "udiv32(0xFFFFFFFF, 2) = 0x7FFFFFFF OK\n";
        sys_write(1, ok, sizeof(ok)-1);
        sys_exit(0);
    } else {
        static const char fail[] = "udiv32 FAIL\n";
        sys_write(1, fail, sizeof(fail)-1);
        sys_exit(1);
    }
}
