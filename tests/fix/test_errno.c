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
static s64 sys_openat(s64 dirfd, const char *path, s64 flags, s64 mode) {
    register s64 x8 __asm__("x8") = 56;
    register s64 x0 __asm__("x0") = dirfd;
    register s64 x1 __asm__("x1") = (s64)path;
    register s64 x2 __asm__("x2") = flags;
    register s64 x3 __asm__("x3") = mode;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}
__attribute__((noreturn)) void _start(void) {
    static const char path[] = "/__nonexistent_path_xyz__";
    s64 r = sys_openat(-100, path, 0, 0);
    /* Should be -ENOENT = -2, NOT -EPERM = -1 */
    if (r == -2) {
        static const char ok[] = "openat(nonexistent) = -ENOENT OK\n";
        sys_write(1, ok, sizeof(ok)-1);
        sys_exit(0);
    } else {
        static const char fail[] = "openat FAIL (expected -2 = -ENOENT)\n";
        sys_write(1, fail, sizeof(fail)-1);
        sys_exit(1);
    }
}
