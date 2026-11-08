/* loop_sum_syscall.c — sum 1..100, format ke decimal, write */
typedef long s64;

static inline s64 syscall3(s64 n, s64 a0, s64 a1, s64 a2) {
    register s64 x8 __asm__("x8") = n;
    register s64 x0 __asm__("x0") = a0;
    register s64 x1 __asm__("x1") = a1;
    register s64 x2 __asm__("x2") = a2;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

__attribute__((noreturn)) void _start(void) {
    static char buf[16];
    char tmp[8];
    int len = 0, t = 0, v = 0;

    /* sum = 1 + 2 + ... + 100 = 5050 */
    for (int i = 1; i <= 100; i++) {
        v += i;
    }

    /* decimal format, digit terbalik ke tmp */
    while (v > 0) {
        tmp[t++] = (char)('0' + (v % 10));
        v = v / 10;
    }
    /* reverse ke buf */
    while (t > 0) {
        buf[len++] = tmp[--t];
    }
    buf[len++] = '\n';

    syscall3(64, 1, (s64)buf, (s64)len);  /* write(1, buf, len) */
    syscall3(94, 0, 0, 0);                /* exit_group(0)      */
    __builtin_unreachable();
}
