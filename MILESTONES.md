# atld — ARM64 → x86_64 userspace ISA translator

Translator untuk mengeksekusi binary userspace ARM64/AArch64 di host Linux x86_64.
Komponen ISA opsional untuk ATL (Android Translation Layer) — bukan ATL itu sendiri.

**Fokus**: ABI + syscall Linux umum, bukan API framework tertentu.

---

## Status milestone

| Tag | Isi | Test gate |
|---|---|---|
| `m1-dump` | ELF loader + `atld --dump` (format readelf-like) | `tests/test_dump.py` 11/11 field |
| `m2-interp` | Interpreter ARM64 subset | `hello_arm64` print, exit 0 |
| `m3-syscall` | Syscall: openat/read/write/close/lseek | `file_read_arm64` byte-exact `/etc/os-release` |
| `m3.5-loop` | Decoder +loop/arith (SDIV, SMULL, SXTW, LDRB/STRB) | `loop_sum_arm64` = `5050` |
| `v0.4-general` | Decoder 60+ instruksi + loader TLS/stack ABI (dari glibc work, tanpa glibc baggage) | regresi 3 test hijau |
| `v0.5-stress` | Stress test 5 kategori decoder | `tests/run-stress.sh` **5/5 PASS** |
| `m6-mvp` | Thunk dispatch — guest panggil host function | `tests/thunk/hello_puts` → `hello from host puts` |
| `m6-phase2` | Generic thunk via dlsym + FP args | `tests/thunk/cos_test` → `cos(0.0)=1.0 OK` |
| `m6-phase2b-multiarg` | FMOV immediate + multi-arg thunk | `fma(2,3,4)=10`, `test_d4=4321`, `test_i6=654321` |
| `m6-phase3-mvp` | GOT trampoline — guest indirect call | `tests/thunk/test_got` → `hello from GOT trampoline` |
| `m6-phase3-mvp2a` | `.rela.plt` parser + named trampolines | `dyn_test` → 4 PLT slots patched |
| `m6-phase3-mvp2b` | **Dynamic ARM64 executable runs** | `ATLD_MAIN=0x... dyn_test` → `hello from dynamic`, rc=0 |

---

## Apa yang sudah bekerja

### Instruksi ARM64 (verified via stress test)

**Integer arithmetic** (`v0.5-stress`):
- `MADD`, `MSUB`, `SMADDL`, `UMADDL`, `SMULH`, `UMULH`, `SMULL`
- `SDIV`, `UDIV`, `LSL/LSR/ASR` immediate, `EXTR`
- `ADC/ADCS/SBC/SBCS`

**Bitfield** (`v0.5-stress`):
- `UBFX`, `UBFIZ`, `SBFX`, `SBFIZ`, `BFI`, `BFXIL` (via UBFM/SBFM/BFM)

**Bit manipulation** (`v0.5-stress`):
- `REV`, `REV16`, `REV32`, `RBIT`, `CLZ`

**Conditional** (`v0.5-stress`):
- `CSEL`, `CSINC`, `CSINV`, `CSNEG`
- `B.cond`, `CBZ/CBNZ`, `TBZ/TBNZ`

**Load/store** (`v0.5-stress`):
- `LDR/STR` immediate (32/64), register offset, pre/post-index
- `LDRSB/LDRSH/LDRSW` sign-extend (imm + reg offset)
- `LDRB/STRB/LDRH/STRH` byte/half
- `STP/LDP` 32/64-bit + SIMD 128-bit (`STP_Q/LDP_Q`)
- `LDUR/STUR` unscaled

**Branches**: `B`, `BL`, `BLR`, `BR`, `RET`, `RET xN`

**Others**: `MOVZ/N/K`, `ADR/ADRP`, `ADD/SUB` imm/reg/ext, `ORR/ORN/EON/AND/ANDS/EOR/BIC` reg, `ANDS_IMM` (TST), `SDIV`, `MRS/MSR` (TPIDR_EL0, DCZID_EL0, CTR_EL0), `MOVI V.4S`, `DUP V.16B`

**NOP-safe (fitur x86_64 tidak ada)**:
- Barrier: `DSB/DMB/ISB/CLREX/SB/SSBB/PSSBB/CSDB`
- PAC: `PACIASP/AUTIASP/PACIBSP/AUTIBSP/AUTIA1716/AUTIB1716/...`
- HINT: `BTI/NOP/YIELD/WFE/WFI`

### Syscall (aarch64 → x86_64 mapping)

| Guest | Host | Nama |
|---|---|---|
| 56 | 257 | openat |
| 57 | 3 | close |
| 62 | 8 | lseek |
| 63 | 0 | read |
| 64 | 1 | write |
| 93 | 60 | exit |
| 94 | 231 | exit_group |
| 96 | 218 | set_tid_address |
| 214 | 12 | brk |
| 215 | 11 | munmap |
| 222 | 9 | mmap |
| 226 | 10 | mprotect |
| 261 | 302 | prlimit64 |
| 278 | 318 | getrandom |
| 99 | — | set_robust_list (stub return 0) |
| 293 | — | rseq (stub return -ENOSYS) |

### Loader

- Parse ELF64 AArch64, validasi class/data/machine
- **Hanya ET_EXEC (non-PIE)** — PIE ditolak
- Map PT_LOAD: RW → memcpy → mprotect (handle RX-only segment)
- **Non-aligned PT_LOAD fix**: `memcpy(m + (vaddr - vstart), ...)` — penting untuk segment seperti `vaddr=0x48c618`
- **TLS setup**: parse PT_TLS, alokasi TCB (0x30 header) + .tdata + .tbss, init `tcb[0..5]` (self, dtv, self, flags, sysinfo, stack_guard)
- **Stack ABI**: 40-byte frame (argc=0, argv terminator, envp terminator, auxv AT_NULL)

### Debugging tools

- `atld --dump <elf>` — ELF header + program headers (readelf-like)
- SIGSEGV handler — print GPRs + pc_history (64 entries) saat crash
- `pc_history` — trace 64 PC terakhir, cross-reference dengan `objdump`

---

## Apa yang **belum** (atau gagal)

### Glibc static — TIDAK jalan

`tests/glibc/glibc_write` (glibc static write-only) crash di `__ctype_init` (SIGSEGV null deref). Root cause: relokasi `.tdata` glibc butuh `R_AARCH64_IRELATIVE` processing (5 relocation entries di glibc), loader belum handle. **Branch `wip/glibc-write`** menyimpan 40 patch eksperimen untuk referensi.

**Glibc static bukan target ATL** — aplikasi Android pakai Bionic dinamis.

### Belum diimplementasi

- **M6 (thunk)**: guest ARM64 panggil fungsi host x86_64 — inti ATL. Ini milestone berikutnya.
- **M5 (JIT)**: performance near-native. Interpreter lambat (~100× native).
- **M4 (struct translation)**: `stat`, `ioctl`, `getdents` Bionic ↔ host. Butuh M6 dulu.
- **M7 (ATL integration)**: frame pertama Unity di Wayland.
- **Dynamic linker**: `PT_INTERP`, `DT_NEEDED`, `.so` loading, symbol resolution.
- **Bionic libc shim ARM64**: `libc.so`, `libEGL.so`, `libvulkan.so` guest → host via thunk.
- **Signal handling**: `rt_sigaction`/`rt_sigreturn` sebenarnya (sekarang crash silently).
- **Thread**: `clone`, `futex`, `set_robust_list` proper (sekarang stub).
- **SIMD berat**: `FADD V`, `FMUL V`, `CMEQ`, `ZIP1`, `TBL`, `CNT`, `XTN` — hanya basic SIMD (`MOVI_4S`, `DUP_B16`, LDR/STR Q/S) yang ada.

---

## Cara resume

```bash
cd ~/atld
git checkout v0.5-stress
cmake --build build -j"$(nproc)"

# Regresi (3 test dasar — WAJIB hijau)
timeout 5 ./build/atld tests/arm64/hello_arm64
timeout 5 ./build/atld tests/arm64/loop_sum_arm64    # harus 5050
timeout 5 ./build/atld tests/arm64/file_read_arm64   # harus byte-exact /etc/os-release

# Stress test 5 kategori (WAJIB hijau di milestone v0.5)
bash tests/run-stress.sh
# Expected: ALL 5 CATEGORIES PASS




## Branch

| Branch | Isi |
|---|---|
| `main` | m3.5-loop + ADC fix |
| `v0.4-general` | glibc-derived, tanpa baggage |
| `v0.5-stress` | HEAD, verified 5/5 |
| `wip/glibc-write` | 40 patch, crash TLS, arsip |

## Gotchas

1. TSO menguntungkan: ARM→x86, host lebih ketat, barrier boleh NOP
2. Decoder mask sering salah bit 31 (B vs BL, ADR vs ADRP)
3. Collision mask: ADC vs SDIV (bit 22=3), CSEL vs ADC (bit 29)
4. Stack ABI butuh argc→argv→envp→auxv AT_NULL
5. Non-aligned PT_LOAD: memcpy ke `vaddr - vstart`
6. Glibc bukan target ATL — jangan lanjut wip/glibc-write
7. Null deref di glibc = bug loader, bukan decoder

## Next: M6 Phase 3 full (proper .rela.plt parser)

Phase 1 (MVP) selesai: hardcoded `puts` via `THUNK_BASE + idx`.

Phase 2:
1. Format signature `.def` (parse `int puts(const char *)`)
2. Trampoline generator: pack args (x0-x7 + stack) per signature
3. `dlsym` resolution untuk host libc
4. FP args (`v0-v7` → xmm) untuk fungsi seperti `cos`, `glClearColor`
5. Test: guest panggil `cos(0.0)` dari libm host

Phase 3 (setelah Phase 2):
- Callback dari host ke guest (wajib untuk `eglSwapBuffers`)
- `.so` dynamic loading (butuh PT_INTERP + DT_NEEDED support di loader)
- Bionic shim ARM64 (`libc.so`, `libEGL.so`, `libvulkan.so`)

Setelah M6 Phase 2: M4 (Bionic struct) + M3.6 (Bionic shim) terbuka.

## M6 Phase 3 (next)

Setelah Phase 2 (generic thunk + FP args) berjalan:

1. **Dynamic .so loading** — guest `dlopen("libm.so")` → loader host resolve → thunk table otomatis
   - Butuh `PT_INTERP` handling (Bionic linker)
   - `DT_NEEDED` parsing
   - `dlsym` di host + symbol table
2. **Callback host → guest** — guest daftar fn pointer, host panggil balik
   - Wajib untuk `eglSwapBuffers`, `pthread_create`, event callback
   - Format: `thunk_register_callback(idx, fn_ptr)` + `interp_step_until_return(fn_ptr, args)`
3. **Test**: `.so` ARM64 handwritten panggil `write` via `libc.so` yang di-`dlopen`

Setelah Phase 3: Bionic shim ARM64 (M3.6) + ATL integration (M7) terbuka.

## M6.3 MVP status — GOT trampoline works

MVP (this session): magic `0xDEADBEEFDEADBEEF` in `.data` replaced by loader
with trampoline address. Guest `ldr x16, [got]; blr x16` executes trampoline.

Full M6.3 (next session, 2-4 jam):
1. Parse `PT_DYNAMIC`, `DT_RELA`, `DT_RELASZ`
2. Iterate `R_AARCH64_JUMP_SLOT` entries
3. Resolve symbol name: `r_info` → `.dynsym[r_info>>32].st_name` → `.dynstr`
4. For each unresolved symbol: allocate trampoline, add to thunk table,
   lookup host via dlsym
5. Replace magic-scan with proper GOT patch
6. Test: `.so` dynamically linked, calls `write` via PLT
