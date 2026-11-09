typedef long s64; typedef unsigned long u64;
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
static u64 a_ubfx(u64 v)  { u64 r; __asm__ volatile("ubfx %0,%1,#8,#16"  : "=r"(r) : "r"(v)); return r; }
static u64 a_ubfiz(u64 v) { u64 r; __asm__ volatile("ubfiz %0,%1,#4,#20" : "=r"(r) : "r"(v)); return r; }
static u64 a_sbfx(u64 v)  { s64 r; __asm__ volatile("sbfx %0,%1,#8,#16"  : "=r"(r) : "r"(v)); return (u64)r; }
static u64 a_sbfiz(u64 v) { s64 r; __asm__ volatile("sbfiz %0,%1,#4,#20" : "=r"(r) : "r"(v)); return (u64)r; }
static u64 a_extr(u64 n, u64 m) { u64 r; __asm__ volatile("extr %0,%1,%2,#4" : "=r"(r) : "r"(n), "r"(m)); return r; }
static u64 a_bfi(u64 d, u64 s)  { u64 r=d; __asm__ volatile("bfi %0,%1,#4,#8"   : "+r"(r) : "r"(s)); return r; }
static u64 a_bfxil(u64 d, u64 s){ u64 r=d; __asm__ volatile("bfxil %0,%1,#8,#16" : "+r"(r) : "r"(s)); return r; }
void _start(void) {
    ck("ubfx",  a_ubfx(0xFFFFFFFFFFFFFFFF),           0xFFFF);
    ck("ubfiz", a_ubfiz(0xFFFFFFFF),                   0xFFFFF0);
    ck("sbfx",  a_sbfx(0xFFFFFFFFFFFFFFFF),           0xFFFFFFFFFFFFFFFF);
    ck("sbfiz", a_sbfiz(0xFFFFFFFF),                   0xFFFFFFFFFFFFFFF0);
    ck("extr",  a_extr(1, 2),                          0x1000000000000000);
    ck("bfi",   a_bfi(0xFFFFFFFFFFFFFFFF, 0xAB),       0xFFFFFFFFFFFFFABF);
    ck("bfxil", a_bfxil(0xFFFFFFFFFFFFFFFF, 0x123456789ABCDEF0), 0xFFFFFFFFFFFFBCDE);
    if (pass==total) say("ALL PASS\n");
    else { say("FAIL "); say_hex(pass); say("/"); say_hex(total); say("\n"); }
    sys3(94,0,0,0); __builtin_unreachable();
}
