#!/usr/bin/env python3
"""M1 verification: compare `atld --dump` against `readelf -h -lW`.

Usage:  ./tests/test_dump.py [target]
Env:    ATLD=/path/to/atld  (default ./build/atld)
Exit:   0 if all checks pass, 1 otherwise.
"""

import os
import re
import subprocess
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "tests/arm64/hello_arm64"
BINARY = os.environ.get("ATLD", "./build/atld")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def grab_hex(text, pattern):
    m = re.search(pattern + r"[^\n]*?(0x[0-9a-fA-F]+)", text)
    return int(m.group(1), 16) if m else None


def grab_int(text, pattern):
    m = re.search(pattern + r"[^\n]*?(\d+)", text)
    return int(m.group(1)) if m else None


def parse_loads(text):
    """Return list of (offset, vaddr, paddr, filesz, memsz, flags, align)."""
    loads = []
    for line in text.splitlines():
        if not re.search(r"\bLOAD\b", line):
            continue
        hexes = re.findall(r"0x[0-9a-fA-F]+", line)
        if len(hexes) < 6:
            continue
        no_hex = re.sub(r"0x[0-9a-fA-F]+", "", line)
        flags = "".join(c for c in no_hex if c in "RWE")
        vals = [int(h, 16) for h in hexes]
        loads.append((vals[0], vals[1], vals[2], vals[3], vals[4], flags, vals[-1]))
    return loads


def fmt(v):
    return f"0x{v:x}" if isinstance(v, int) else str(v)


def main():
    readelf = run(["readelf", "-hW", "-lW", TARGET])
    atld = run([BINARY, "--dump", TARGET])

    checks = []

    def check(name, expected, actual):
        checks.append((name, expected, actual, expected == actual))

    check("type", "EXEC", "EXEC" if re.search(r"Type:\s+EXEC", atld) else "??")
    check("entry",
          grab_hex(readelf, r"Entry point address:"),
          grab_hex(atld, r"Entry point address:"))
    check("phnum",
          grab_int(readelf, r"Number of program headers:"),
          grab_int(atld, r"Number of program headers:"))

    rl = parse_loads(readelf)
    al = parse_loads(atld)
    check("PT_LOAD count", len(rl), len(al))

    field_names = ["offset", "vaddr", "paddr", "filesz", "memsz", "flags", "align"]
    for i, (r, a) in enumerate(zip(rl, al)):
        for j, name in enumerate(field_names):
            check(f"LOAD[{i}].{name}", r[j], a[j])

    ok = True
    for name, exp, act, pass_ in checks:
        status = "ok  " if pass_ else "FAIL"
        if not pass_:
            ok = False
        print(f"  {status}  {name:<24}  expected={fmt(exp):<20}  actual={fmt(act)}")

    n_pass = sum(1 for c in checks if c[3])
    print()
    print(f"{n_pass}/{len(checks)} passed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
