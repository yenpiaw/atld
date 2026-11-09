typedef long s64;
typedef unsigned long u64;
typedef int i32;
typedef long i64;

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
    /* Test 1: normal (no overflow) */
    i32 a = 3, b = 5;
    i64 c = 100, r1;
    __asm__ volatile("smaddl %0, %w1, %w2, %3" : "=r"(r1) : "r"(a), "r"(b), "r"(c));
    /* 3*5 + 100 = 115 */

    /* Test 2: overflow — c = INT64_MAX, a=b=1 → 1 + INT64_MAX = INT64_MIN (wrapped) */
    a = 1; b = 1;
    c = 0x7FFFFFFFFFFFFFFFLL;  /* INT64_MAX */
    i64 r2;
    __asm__ volatile("smaddl %0, %w1, %w2, %3" : "=r"(r2) : "r"(a), "r"(b), "r"(c));
    /* Per ARM ARM: 1 + INT64_MAX = INT64_MIN = 0x8000000000000000 */

    if (r1 == 115 && (u64)r2 == 0x8000000000000000ULL) {
        static const char ok[] = "smaddl OK\n";
        sys_write(1, ok, sizeof(ok)-1);
        sys_exit(0);
    } else {
        static const char fail[] = "smaddl FAIL\n";
        sys_write(1, fail, sizeof(fail)-1);
        sys_exit(1);
    }
}
