/* test_multiarg.c — verify FP and int multi-arg marshalling.
 *   fma(2,3,4) = 2*3+4 = 10.0        (SIG_D3, real libm)
 *   __test_d4(1,2,3,4) = 4321.0      (SIG_D4, builtin)
 *   __test_i6(1..6) = 654321         (SIG_I6, builtin)
 */
typedef long s64;
typedef unsigned long u64;

static double thunk_call_d3(s64 idx, double a, double b, double c) {
    register s64 x8 __asm__("x8") = idx;
    register double v0 __asm__("v0") = a;
    register double v1 __asm__("v1") = b;
    register double v2 __asm__("v2") = c;
    __asm__ volatile("svc #0" : "+w"(v0) : "r"(x8), "w"(v1), "w"(v2) : "memory");
    return v0;
}
static double thunk_call_d4(s64 idx, double a, double b, double c, double d) {
    register s64 x8 __asm__("x8") = idx;
    register double v0 __asm__("v0") = a;
    register double v1 __asm__("v1") = b;
    register double v2 __asm__("v2") = c;
    register double v3 __asm__("v3") = d;
    __asm__ volatile("svc #0" : "+w"(v0) : "r"(x8), "w"(v1), "w"(v2), "w"(v3) : "memory");
    return v0;
}
static s64 thunk_call_i6(s64 idx, s64 a, s64 b, s64 c, s64 d, s64 e, s64 f) {
    register s64 x8 __asm__("x8") = idx;
    register s64 x0 __asm__("x0") = a;
    register s64 x1 __asm__("x1") = b;
    register s64 x2 __asm__("x2") = c;
    register s64 x3 __asm__("x3") = d;
    register s64 x4 __asm__("x4") = e;
    register s64 x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
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
static __attribute__((noreturn)) void sys_exit(s64 c) {
    register s64 x8 __asm__("x8") = 94;
    register s64 x0 __asm__("x0") = c;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0) : "memory");
    __builtin_unreachable();
}

static u64 d2u(double d) {
    union { double d; u64 u; } u;
    u.d = d;
    return u.u;
}

__attribute__((noreturn)) void _start(void) {
    int pass = 0;

    /* D3: fma(2,3,4) = 10.0 */
    double r1 = thunk_call_d3(0x1000000L + 4, 2.0, 3.0, 4.0);
    if (d2u(r1) == 0x4024000000000000ULL) {   /* 10.0 */
        static const char m[] = "fma(2,3,4)=10 OK\n";
        sys_write(1, m, sizeof(m)-1);
        pass++;
    } else {
        static const char m[] = "fma FAIL\n";
        sys_write(1, m, sizeof(m)-1);
    }

    /* D4: test_d4(1,2,3,4) = 1+20+300+4000 = 4321.0 */
    double r2 = thunk_call_d4(0x1000000L + 5, 1.0, 2.0, 3.0, 4.0);
    if (d2u(r2) == 0x40B0E10000000000ULL) {   /* 4321.0 */
        static const char m[] = "test_d4(1,2,3,4)=4321 OK\n";
        sys_write(1, m, sizeof(m)-1);
        pass++;
    } else {
        static const char m[] = "test_d4 FAIL\n";
        sys_write(1, m, sizeof(m)-1);
    }

    /* I6: test_i6(1..6) = 654321 */
    s64 r3 = thunk_call_i6(0x1000000L + 6, 1, 2, 3, 4, 5, 6);
    if (r3 == 654321) {
        static const char m[] = "test_i6(1..6)=654321 OK\n";
        sys_write(1, m, sizeof(m)-1);
        pass++;
    } else {
        static const char m[] = "test_i6 FAIL\n";
        sys_write(1, m, sizeof(m)-1);
    }

    sys_exit(pass == 3 ? 0 : 1);
}
