.text
.global _start
_start:
    /* S1a: add sp, sp, x0 (extended, Rn=SP, Rd=SP) */
    mov x0, #32
    mov x1, sp
    add sp, sp, x0
    sub x2, sp, x1
    cmp x2, #32
    b.ne s1a_fail
    sub sp, sp, #32

    /* S1b: sub sp, sp, x0 */
    mov x0, #16
    mov x1, sp
    sub sp, sp, x0
    mov x3, sp              /* SP not allowed as Rm in SUB; copy */
    sub x2, x1, x3
    cmp x2, #16
    b.ne s1b_fail
    add sp, sp, #16

    /* S2: cmp sp, #0x1000 (SP as Rn) */
    cmp sp, #0x1000
    b.ls s2_fail

    /* pass */
    mov x0, #0
    mov x8, #94
    svc #0

s1a_fail:
    mov x0, #1
    mov x8, #94
    svc #0
s1b_fail:
    mov x0, #2
    mov x8, #94
    svc #0
s2_fail:
    mov x0, #3
    mov x8, #94
    svc #0
