/* file_read_syscall.c — openat("/etc/os-release") + read + write + exit */
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
    static const char path[]     = "/etc/os-release";
    static const char err_open[] = "openat failed\n";
    static const char err_read[] = "read failed\n";
    char buf[256];

    /* openat(AT_FDCWD, path, O_RDONLY, 0) */
    s64 fd = syscall3(56, -100, (s64)path, 0);
    if (fd < 0) {
        syscall3(64, 2, (s64)err_open, sizeof(err_open) - 1);
        syscall3(94, 1, 0, 0);
        __builtin_unreachable();
    }

    /* read(fd, buf, sizeof(buf)) */
    s64 n = syscall3(63, fd, (s64)buf, sizeof(buf));
    if (n < 0) {
        syscall3(64, 2, (s64)err_read, sizeof(err_read) - 1);
        syscall3(94, 1, 0, 0);
        __builtin_unreachable();
    }

    /* write(1, buf, n) */
    syscall3(64, 1, (s64)buf, n);

    /* close(fd) */
    syscall3(57, fd, 0, 0);

    /* exit_group(0) */
    syscall3(94, 0, 0, 0);
    __builtin_unreachable();
}
