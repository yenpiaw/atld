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
static u64 a_rev(u64 v)   { u64 r; __asm__ volatile("rev %0,%1"   : "=r"(r) : "r"(v)); return r; }
static u64 a_rev16(u64 v) { u64 r; __asm__ volatile("rev16 %0,%1" : "=r"(r) : "r"(v)); return r; }
static u64 a_rev32(u64 v) { u64 r; __asm__ volatile("rev32 %0,%1" : "=r"(r) : "r"(v)); return r; }
static u64 a_rbit(u64 v)  { u64 r; __asm__ volatile("rbit %0,%1"  : "=r"(r) : "r"(v)); return r; }
static u64 a_clz(u64 v)   { u64 r; __asm__ volatile("clz %0,%1"   : "=r"(r) : "r"(v)); return r; }
void _start(void) {
    ck("rev",   a_rev(0x0123456789ABCDEF),   0xEFCDAB8967452301);
    ck("rev16", a_rev16(0x0123456789ABCDEF), 0x23016745AB89EFCD);
    ck("rev32", a_rev32(0x0123456789ABCDEF), 0x67452301EFCDAB89);
    ck("rbit",  a_rbit(0x0000000000000001),  0x8000000000000000);
    ck("clz",   a_clz(0x0000000000000001),   63);
    if (pass==total) say("ALL PASS\n");
    else { say("FAIL "); say_hex(pass); say("/"); say_hex(total); say("\n"); }
    sys3(94,0,0,0); __builtin_unreachable();
}
