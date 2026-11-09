# Thunk ABI — guest ARM64 → host x86_64 function call

## Overview

Guest sends `x8 = THUNK_BASE + idx`, lalu `SVC #0`. Interpreter
(`syscall_dispatch`) lihat `x8 >= THUNK_BASE`, lempar ke `thunk_dispatch(idx)`.
Host lookup `thunks[idx]`, lazy resolve via dlsym (atau builtin),
panggil dengan signature yang sesuai, return value ke `x0` atau `v0`.

## Register mapping (AAPCS64 subset)

| Arg index | Guest | Host x86_64 |
|---|---|---|
| int 0-7   | x0-x7 | rdi, rsi, rdx, rcx, r8, r9, stack, stack |
| fp 0-7    | v0-v7 (D form) | xmm0-xmm7 |
| int 8+    | stack | stack |
| fp 8+     | stack | stack |
| return int| x0    | rax |
| return fp | v0    | xmm0 |

Phase 2: hanya 0-7 args, no stack spill. Arg >8 → tolak (return -ENOSYS).
Phase 3: full AAPCS64 dengan stack spill.

## Signature classes

| Enum | Contoh | Return |
|---|---|---|
| SIG_I0 | `int getpid(void)` | x0 |
| SIG_I1 | `int puts(const char *)` | x0 |
| SIG_L1 | `long strlen(const char *)` | x0 (64-bit) |
| SIG_I4 | `int foo(int, int, int, int)` | x0 |
| SIG_I6 | `int foo(int, int, int, int, int, int)` | x0 |
| SIG_D1 | `double cos(double)` | v0 |
| SIG_D2 | `double pow(double, double)` | v0 |
| SIG_D3 | `double fma(double, double, double)` | v0 |
| SIG_D4 | `double foo(double, double, double, double)` | v0 |

## Lazy resolution

Setiap entry punya field `fn` (init NULL). Saat pertama dipanggil:
- Kalau `builtin != NULL`, pakai `builtin` (test functions, no dlsym)
- Else `dlsym(RTLD_DEFAULT, name)`, cache di `fn`

Kegagalan dlsym → `x0 = -ENOSYS` (guest bisa fallback).

## Known limitations (Phase 2)

- Tidak ada stack spill (> 8 args)
- Tidak ada argumen campuran int+fp (`glUniform4f` nanti butuh `SIG_D2_I2`)
- Tidak ada variadic (`printf` butuh Phase 3)
- Tidak ada struct-by-value (butuh AAPCS64 composite rules)
