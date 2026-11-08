#include "atld/syscall.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>

struct syscall_map { uint16_t guest_nr, host_nr; };

static const struct syscall_map syscall_map[] = {
    /* aarch64 -> x86_64 */
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
    for (size_t i = 0; i < sizeof(syscall_map)/sizeof(syscall_map[0]); i++) {
        if (syscall_map[i].guest_nr == nr) {
            if (nr == 94 || nr == 93) {  /* exit_group / exit */
                fflush(stderr);
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
