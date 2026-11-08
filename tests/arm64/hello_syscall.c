typedef long s64;

static inline s64 syscall3(s64 n, s64 a0, s64 a1, s64 a2) {
    register s64 x8 __asm__("x8") = n;
    register s64 x0 __asm__("x0") = a0;
    register s64 x1 __asm__("x1") = a1;
    register s64 x2 __asm__("x2") = a2;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static inline s64 syscall1(s64 n, s64 a0) {
    register s64 x8 __asm__("x8") = n;
    register s64 x0 __asm__("x0") = a0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

__attribute__((noreturn)) void _start(void) {
    static const char msg[] = "hello from arm64 (static, no libc)\n";
    syscall3(64, 1, (s64)msg, (s64)(sizeof(msg) - 1));   /* write(1, msg, len) */
    syscall1(94, 0);                                     /* exit_group(0)     */
    __builtin_unreachable();
}
