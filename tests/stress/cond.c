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
static u64 a_csel(u64 a, u64 b)  { u64 r; __asm__ volatile("cmp %1,%2\n\tcsel %0,%1,%2,lt"   : "=r"(r) : "r"(a), "r"(b) : "memory"); return r; }
static u64 a_csinc(u64 a, u64 b) { u64 r; __asm__ volatile("cmp %1,%2\n\tcsinc %0,%1,%2,lt"  : "=r"(r) : "r"(a), "r"(b) : "memory"); return r; }
static u64 a_csinv(u64 a, u64 b) { u64 r; __asm__ volatile("cmp %1,%2\n\tcsinv %0,%1,%2,lt"  : "=r"(r) : "r"(a), "r"(b) : "memory"); return r; }
static u64 a_csneg(u64 a, u64 b) { u64 r; __asm__ volatile("cmp %1,%2\n\tcsneg %0,%1,%2,lt"  : "=r"(r) : "r"(a), "r"(b) : "memory"); return r; }
void _start(void) {
    ck("csel_10_20",  a_csel(10, 20),  10);
    ck("csel_20_10",  a_csel(20, 10),  10);
    ck("csinc_10_20", a_csinc(10, 20), 10);
    ck("csinc_20_10", a_csinc(20, 10), 11);
    ck("csinv_10_20", a_csinv(10, 20), 10);
    ck("csinv_20_10", a_csinv(20, 10), 0xFFFFFFFFFFFFFFF5);
    ck("csneg_10_20", a_csneg(10, 20), 10);
    ck("csneg_20_10", a_csneg(20, 10), 0xFFFFFFFFFFFFFFF6);
    if (pass==total) say("ALL PASS\n");
    else { say("FAIL "); say_hex(pass); say("/"); say_hex(total); say("\n"); }
    sys3(94,0,0,0); __builtin_unreachable();
}
