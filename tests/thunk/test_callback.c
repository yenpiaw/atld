typedef long s64;

static inline s64 thunk2(s64 idx, s64 a, s64 b) {
    register s64 x8 __asm__("x8") = idx;
    register s64 x0 __asm__("x0") = a;
    register s64 x1 __asm__("x1") = b;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory");
    return x0;
}
static inline s64 thunk3(s64 idx, s64 a, s64 b, s64 c) {
    register s64 x8 __asm__("x8") = idx;
    register s64 x0 __asm__("x0") = a;
    register s64 x1 __asm__("x1") = b;
    register s64 x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
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

/* Guest callback. AAPCS64: args x0, x1; return x0. */
static s64 my_add(s64 a, s64 b) {
    return a + b;
}

/* Callback that calls a host thunk (nested interp test) */
static s64 my_add_puts(s64 a, s64 b) {
    s64 sum = a + b;
    static const char msg[] = "[cb] hello from guest callback\n";
    sys_write(1, msg, sizeof(msg)-1);
    return sum;
}

__attribute__((noreturn)) void _start(void) {
    int pass = 0;

    /* Test 1: simple add callback */
    thunk2(0x1000007L, 0, (s64)my_add);           /* register slot 0 = my_add */
    s64 r1 = thunk3(0x1000008L, 0, 3, 4);         /* trigger slot 0 (3, 4) */
    if (r1 == 7) {
        static const char m[] = "cb1 add(3,4)=7 OK\n";
        sys_write(1, m, sizeof(m)-1);
        pass++;
    } else {
        static const char m[] = "cb1 add FAIL\n";
        sys_write(1, m, sizeof(m)-1);
    }

    /* Test 2: nested — callback itself does SVC (nested interp) */
    thunk2(0x1000007L, 1, (s64)my_add_puts);      /* register slot 1 */
    s64 r2 = thunk3(0x1000008L, 1, 10, 20);       /* trigger slot 1 (10, 20) */
    if (r2 == 30) {
        static const char m[] = "cb2 nested add(10,20)=30 OK\n";
        sys_write(1, m, sizeof(m)-1);
        pass++;
    } else {
        static const char m[] = "cb2 nested FAIL\n";
        sys_write(1, m, sizeof(m)-1);
    }

    sys_exit(pass == 2 ? 0 : 1);
}
