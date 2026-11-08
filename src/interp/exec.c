#include "atld/interp.h"
#include "atld/decode.h"
#include "atld/syscall.h"
#include <stdio.h>

static int64_t sext64(uint64_t v, int bits) {
    uint64_t m = 1ULL << (bits - 1);
    uint64_t x = v & ((1ULL << bits) - 1);
    return (int64_t)((x ^ m) - m);
}
static uint64_t getr(const struct guest_cpu *c, int i) {
    return i == 31 ? 0 : c->x[i];
}
static void setr(struct guest_cpu *c, int i, uint64_t v) {
    if (i != 31) c->x[i] = v;
}
static uint64_t apply_sf(uint64_t v, uint8_t sf) {
    return sf ? v : (v & 0xffffffffULL);
}
static uint64_t shifted(uint64_t v, uint8_t kind, uint32_t amt, uint8_t sf) {
    if (!sf) v &= 0xffffffffULL;
    switch (kind) {
    case 0: return v << amt;                                  /* LSL */
    case 1: return v >> amt;                                  /* LSR */
    case 2: return (uint64_t)(((int64_t)v) >> amt);           /* ASR */
    default: return 0;
    }
}

int interp_step(struct guest_cpu *cpu) {
    uint32_t insn = *(uint32_t *)cpu->pc;
    struct decoded d;
    if (decode_insn(insn, &d) != 0) {
        fprintf(stderr, "atld: unknown insn 0x%08x at pc=0x%llx\n",
                insn, (unsigned long long)cpu->pc);
        return -1;
    }

    uint64_t next_pc = cpu->pc + 4;

    switch (d.op) {
    case OP_NOP: break;

    case OP_MOVZ: {
        uint64_t v = (uint64_t)d.imm16 << (d.hw * 16);
        setr(cpu, d.rd, apply_sf(v, d.sf));
        break;
    }
    case OP_MOVN: {
        uint64_t v = ~((uint64_t)d.imm16 << (d.hw * 16));
        setr(cpu, d.rd, apply_sf(v, d.sf));
        break;
    }
    case OP_MOVK: {
        uint64_t old = getr(cpu, d.rd);
        uint64_t mask = (uint64_t)0xffff << (d.hw * 16);
        uint64_t v = (old & ~mask) | ((uint64_t)d.imm16 << (d.hw * 16));
        setr(cpu, d.rd, apply_sf(v, d.sf));
        break;
    }
    case OP_ADR:
        setr(cpu, d.rd, cpu->pc + (uint64_t)d.imm);
        break;
    case OP_ADRP:
        setr(cpu, d.rd, (cpu->pc & ~0xfffULL) + (uint64_t)d.imm);
        break;

    case OP_ADD_IMM:
    case OP_SUB_IMM: {
        uint64_t rn = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t imm = (uint64_t)d.imm12;
        if (d.shift) imm <<= 12;
        uint64_t r = (d.op == OP_ADD_IMM) ? (rn + imm) : (rn - imm);
        r = apply_sf(r, d.sf);
        if (d.rd == 31) cpu->sp = r; else setr(cpu, d.rd, r);
        break;
    }
    case OP_ADD_REG:
    case OP_SUB_REG: {
        uint64_t rn = getr(cpu, d.rn);
        uint64_t rm = shifted(getr(cpu, d.rm), d.shift, (uint32_t)d.imm, d.sf);
        uint64_t r = (d.op == OP_ADD_REG) ? (rn + rm) : (rn - rm);
        setr(cpu, d.rd, apply_sf(r, d.sf));
        break;
    }
    case OP_ORR_REG: {
        uint64_t rn = getr(cpu, d.rn);
        uint64_t rm = shifted(getr(cpu, d.rm), d.shift, (uint32_t)d.imm, d.sf);
        setr(cpu, d.rd, apply_sf(rn | rm, d.sf));
        break;
    }

    case OP_LDR_LIT: {
        uint64_t addr = cpu->pc + (uint64_t)d.imm;
        uint64_t v = d.sf ? *(uint64_t *)addr : (uint64_t)*(uint32_t *)addr;
        setr(cpu, d.rd, v);
        break;
    }
    case OP_LDR_IMM: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t scale = d.sf ? 3 : 2;
        uint64_t addr = base + ((uint64_t)d.imm12 << scale);
        uint64_t v = d.sf ? *(uint64_t *)addr : (uint64_t)*(uint32_t *)addr;
        setr(cpu, d.rd, v);
        break;
    }
    case OP_STR_IMM: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t scale = d.sf ? 3 : 2;
        uint64_t addr = base + ((uint64_t)d.imm12 << scale);
        uint64_t v = getr(cpu, d.rd);
        if (d.sf) *(uint64_t *)addr = v;
        else      *(uint32_t *)addr = (uint32_t)v;
        break;
    }

    case OP_STP:
    case OP_LDP: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        int64_t off = sext64(d.imm16, 7) * 8;
        uint64_t addr, wb = 0;
        if (d.shift == 0)      addr = base + (uint64_t)off;
        else if (d.shift == 1) { addr = base + (uint64_t)off; wb = addr; }
        else                   { addr = base;                  wb = base + (uint64_t)off; }
        if (d.op == OP_STP) {
            *(uint64_t *)addr       = getr(cpu, d.rd);
            *(uint64_t *)(addr + 8) = getr(cpu, d.rm);
        } else {
            setr(cpu, d.rd, *(uint64_t *)addr);
            setr(cpu, d.rm, *(uint64_t *)(addr + 8));
        }
        if (d.shift != 0) {
            if (d.rn == 31) cpu->sp = wb;
            else            cpu->x[d.rn] = wb;
        }
        break;
    }

    case OP_B:
        next_pc = cpu->pc + (uint64_t)d.imm;
        break;
    case OP_BL:
        setr(cpu, 30, cpu->pc + 4);
        next_pc = cpu->pc + (uint64_t)d.imm;
        break;
    case OP_RET:
    case OP_BR:
        next_pc = getr(cpu, d.rn);
        break;

    case OP_SVC:
        if (syscall_dispatch(cpu) != 0) return -1;
        break;

    case OP_BRK:
        fprintf(stderr, "atld: BRK #%u at pc=0x%llx\n",
                d.imm16, (unsigned long long)cpu->pc);
        return -1;

    default:
        fprintf(stderr, "atld: unimpl op=%d at pc=0x%llx\n",
                d.op, (unsigned long long)cpu->pc);
        return -1;
    }

    cpu->pc = next_pc;
    return 0;
}
