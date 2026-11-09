typedef long s64; typedef unsigned long u64;
typedef signed char i8; typedef short i16; typedef int i32;
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
static volatile i8  arr8[3]  = {-1, -2, -3};
static volatile i16 arr16[3] = {-100, -200, -300};
static volatile i32 arr32[3] = {-1000, -2000, -3000};
static s64 ld8(int i)  { return (s64)arr8[i]; }
static s64 ld16(int i) { return (s64)arr16[i]; }
static s64 ld32(int i) { return (s64)arr32[i]; }
void _start(void) {
    ck("ldrsb_1", (u64)ld8(1),  (u64)(s64)-2);
    ck("ldrsh_1", (u64)ld16(1), (u64)(s64)-200);
    ck("ldrsw_1", (u64)ld32(1), (u64)(s64)-2000);
    ck("ldrsb_2", (u64)ld8(2),  (u64)(s64)-3);
    if (pass==total) say("ALL PASS\n");
    else { say("FAIL "); say_hex(pass); say("/"); say_hex(total); say("\n"); }
    sys3(94,0,0,0); __builtin_unreachable();
}
