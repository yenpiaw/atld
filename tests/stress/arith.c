typedef long s64; typedef unsigned long u64; typedef unsigned int u32;
static s64 sys3(s64 n, s64 a, s64 b, s64 c) {
    register s64 x8 __asm__("x8") = n; register s64 x0 __asm__("x0") = a;
    register s64 x1 __asm__("x1") = b; register s64 x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static void say(const char *s) { int n=0; while(s[n]) n++; sys3(64,1,(s64)s,n); }
static void say_hex(u64 v) { char b[19]="0x"; for(int i=0;i<16;i++) b[2+i]="0123456789abcdef"[(v>>((15-i)*4))&0xf]; b[18]=0; say(b); }
static int total, pass;
static void ck(const char *n, u64 got, u64 want) {
    total++; say(n); say(": ");
    if (got==want) { say("PASS\n"); pass++; return; }
    say("FAIL got="); say_hex(got); say(" want="); say_hex(want); say("\n");
}
static u64 a_madd(u64 a, u64 b, u64 c)   { u64 r; __asm__ volatile("madd %0,%1,%2,%3"   : "=r"(r) : "r"(a), "r"(b), "r"(c)); return r; }
static u64 a_msub(u64 a, u64 b, u64 c)   { u64 r; __asm__ volatile("msub %0,%1,%2,%3"   : "=r"(r) : "r"(a), "r"(b), "r"(c)); return r; }
static u64 a_smaddl(u64 a, u64 b, u64 c){ u64 r; __asm__ volatile("smaddl %0,%w1,%w2,%3" : "=r"(r) : "r"((u32)a), "r"((u32)b), "r"(c)); return r; }
static u64 a_umaddl(u64 a, u64 b, u64 c){ u64 r; __asm__ volatile("umaddl %0,%w1,%w2,%3" : "=r"(r) : "r"((u32)a), "r"((u32)b), "r"(c)); return r; }
static u64 a_smulh(u64 a, u64 b)         { u64 r; __asm__ volatile("smulh %0,%1,%2"     : "=r"(r) : "r"(a), "r"(b)); return r; }
static u64 a_umulh(u64 a, u64 b)         { u64 r; __asm__ volatile("umulh %0,%1,%2"     : "=r"(r) : "r"(a), "r"(b)); return r; }
void _start(void) {
    ck("madd",   a_madd(3, 5, 7),                     22);
    ck("msub",   a_msub(3, 5, 100),                   85);
    ck("smaddl", a_smaddl((u64)-3, 5, 100),           85);
    ck("umaddl", a_umaddl((u64)-3, 5, 100),           21474836565);
    ck("smulh",  a_smulh(0x1000000000000000, 0x1000000000000000), 0x0100000000000000);
    ck("umulh",  a_umulh(0x1000000000000000, 0x1000000000000000), 0x0100000000000000);
    if (pass==total) say("ALL PASS\n");
    else { say("FAIL "); say_hex(pass); say("/"); say_hex(total); say("\n"); }
    sys3(94,0,0,0); __builtin_unreachable();
}
