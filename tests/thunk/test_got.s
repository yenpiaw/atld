.text
.global _start
_start:
    adr x0, msg
    adrp x16, puts_got
    add x16, x16, #:lo12:puts_got
    ldr x16, [x16]
    blr x16
    mov x8, #94
    mov x0, #0
    svc #0

.data
msg:
    .asciz "hello from GOT trampoline"
    .balign 8
puts_got:
    .quad 0xDEADBEEFDEADBEEF
