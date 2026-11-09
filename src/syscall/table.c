#include "atld/syscall.h"
#include "atld/thunk.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>

struct syscall_map { uint16_t guest_nr, host_nr; };

static const struct syscall_map syscall_map[] = {
    /* aarch64 -> x86_64 */
    {  96, 218 },  /* set_tid_address */
    { 261, 302 },  /* prlimit64       */
    { 278, 318 },  /* getrandom       */
    { 56, 257 },  /* openat       */
    { 62,   8 },  /* lseek        */
    { 63,   0 },  /* read         */
    { 64,   1 },  /* write        */
    { 57,   3 },  /* close        */
    { 93,  60 },  /* exit         */
    { 94, 231 },  /* exit_group   */
    {214,  12 },  /* brk          */
    {215,  11 },  /* munmap       */
    {222,   9 },  /* mmap         */
    {226,  10 },  /* mprotect     */
};

static long host_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    return syscall(n, a1, a2, a3, a4, a5, a6);
}

int syscall_dispatch(struct guest_cpu *cpu) {
    uint64_t nr = cpu->x[8];
    fprintf(stderr, "atld: svc nr=%llu x0=%llx x1=%llx x2=%llx x3=%llx\n",
        (unsigned long long)nr,
        (unsigned long long)cpu->x[0],
        (unsigned long long)cpu->x[1],
        (unsigned long long)cpu->x[2],
        (unsigned long long)cpu->x[3]);
    /* Thunk namespace: x8 >= 0x1000000 -> host function call (M6).
     * aarch64 syscall numbers max ~450, so 0x1000000 is safely above.
     * Guest sends THUNK_BASE + idx; idx (0-based) passed to dispatcher. */
    #define THUNK_BASE 0x1000000UL
    if (nr >= THUNK_BASE) {
        return thunk_dispatch(cpu, (unsigned long)(nr - THUNK_BASE));
    }

    /* set_robust_list: 32-bit aarch64 has no host equivalent — fake success.
     * glibc doesn't check return value; robust futexes won't work but that
     * matches QEMU's workaround. */
    if (nr == 99) { cpu->x[0] = 0; return 0; }
    /* rseq: return -ENOSYS so glibc disables rseq and falls back to futex. */
    if (nr == 293) { cpu->x[0] = (uint64_t)(-38); return 0; }

    for (size_t i = 0; i < sizeof(syscall_map)/sizeof(syscall_map[0]); i++) {
        if (syscall_map[i].guest_nr == nr) {
            if (nr == 94 || nr == 93) {  /* exit_group / exit */
                /* _exit() skips atexit + stdio flush. Guest's puts()
                 * (or any host thunk that wrote to stdout/stderr) leaves
                 * data in glibc buffers. fflush(NULL) flushes all. */
                fflush(NULL);
                _exit((int)cpu->x[0]);
            }
            long ret = host_syscall6(syscall_map[i].host_nr,
                (long)cpu->x[0], (long)cpu->x[1], (long)cpu->x[2],
                (long)cpu->x[3], (long)cpu->x[4], (long)cpu->x[5]);
            fprintf(stderr, "atld: svc %llu -> host %u ret=%ld errno=%d\n",
                    (unsigned long long)nr, syscall_map[i].host_nr, ret,
                    ret < 0 ? errno : 0);
            cpu->x[0] = (uint64_t)ret;
            return 0;
        }
    }
    fprintf(stderr, "atld: unknown aarch64 syscall %llu\n", (unsigned long long)nr);
    cpu->x[0] = (uint64_t)(-38);  /* -ENOSYS */
    return 0;
}
