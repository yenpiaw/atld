#!/bin/bash
cd ~/atld
FAIL=0
for f in tests/stress/*.c; do
    name=$(basename "$f" .c)
    out=/tmp/stress_$name
    if ! aarch64-linux-gnu-gcc -O0 -static -nostdlib -fno-stack-protector \
         -fno-asynchronous-unwind-tables -o "$out" "$f" 2>/tmp/cc_$name.err; then
        echo "=== $name: COMPILE FAIL ==="
        cat /tmp/cc_$name.err
        FAIL=1
        continue
    fi
    echo "=== $name ==="
    timeout 10 ./build/atld "$out" 2>/tmp/run_$name.err
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "  RUN FAIL rc=$rc"
        grep -E 'unknown (insn|syscall)|SIGSEGV|guest pc=' /tmp/run_$name.err | head -3
        FAIL=1
    fi
    echo
done
if [ $FAIL -eq 0 ]; then echo "ALL 5 CATEGORIES PASS"; else echo "SOME FAILED"; fi
exit $FAIL
