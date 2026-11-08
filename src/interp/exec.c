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

static void set_nzcv(struct guest_cpu *cpu, uint64_t result, uint8_t sf,
                      int sub, uint64_t a, uint64_t b) {
    uint32_t flags = cpu->pstate & ~((1u<<31)|(1u<<30)|(1u<<29)|(1u<<28));
    uint64_t mask = sf ? ~0ULL : 0xffffffffULL;
    uint64_t ma = a & mask, mb = b & mask, mr = result & mask;
    int sb = sf ? 63 : 31;

    if ((mr >> sb) & 1) flags |= (1u<<31);                  /* N */
    if (mr == 0)        flags |= (1u<<30);                  /* Z */
    if (sub) {
        if (ma >= mb)   flags |= (1u<<29);                  /* C: no borrow */
    } else {
        if (sf) { if ((ma + mb) < ma) flags |= (1u<<29); }
        else    { if ((ma + mb) > 0xffffffffULL) flags |= (1u<<29); }
    }
    uint64_t sa = (ma>>sb)&1, sbv = (mb>>sb)&1, sr = (mr>>sb)&1;
    if (sub) { if (sa != sbv && sr != sa) flags |= (1u<<28); }   /* V */
    else     { if (sa == sbv && sr != sa) flags |= (1u<<28); }
    cpu->pstate = flags;
}

static int check_cond(const struct guest_cpu *cpu, uint8_t cond) {
    uint32_t f = cpu->pstate;
    int N=(f>>31)&1, Z=(f>>30)&1, C=(f>>29)&1, V=(f>>28)&1;
    switch (cond) {
    case 0:  return Z;
    case 1:  return !Z;
    case 2:  return C;
    case 3:  return !C;
    case 4:  return N;
    case 5:  return !N;
    case 6:  return V;
    case 7:  return !V;
    case 8:  return C && !Z;
    case 9:  return !C || Z;
    case 10: return N == V;
    case 11: return N != V;
    case 12: return !Z && (N == V);
    case 13: return Z || (N != V);
    default: return 1;
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

    case OP_ADDS_IMM:
    case OP_SUBS_IMM: {
        uint64_t rn  = getr(cpu, d.rn);
        uint64_t imm = (uint64_t)d.imm12;
        if (d.shift) imm <<= 12;
        uint64_t r = (d.op == OP_ADDS_IMM) ? (rn + imm) : (rn - imm);
        r = apply_sf(r, d.sf);
        if (d.rd != 31) setr(cpu, d.rd, r);
        set_nzcv(cpu, r, d.sf, d.op == OP_SUBS_IMM, rn, imm);
        break;
    }
    case OP_ADDS_REG:
    case OP_SUBS_REG: {
        uint64_t rn = getr(cpu, d.rn);
        uint64_t rm = shifted(getr(cpu, d.rm), d.shift, (uint32_t)d.imm, d.sf);
        uint64_t r = (d.op == OP_ADDS_REG) ? (rn + rm) : (rn - rm);
        r = apply_sf(r, d.sf);
        if (d.rd != 31) setr(cpu, d.rd, r);
        set_nzcv(cpu, r, d.sf, d.op == OP_SUBS_REG, rn, rm);
        break;
    }
    case OP_B_COND:
        if (check_cond(cpu, (uint8_t)d.shift)) next_pc = cpu->pc + (uint64_t)d.imm;
        break;
    case OP_CBZ:
    case OP_CBNZ: {
        uint64_t rt = getr(cpu, d.rd);
        if (!d.sf) rt &= 0xffffffffULL;
        int take = (d.op == OP_CBZ) ? (rt == 0) : (rt != 0);
        if (take) next_pc = cpu->pc + (uint64_t)d.imm;
        break;
    }
    case OP_LDUR:
    case OP_STUR: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + (uint64_t)d.imm;
        uint8_t size = d.shift;
        uint64_t v;
        if (d.op == OP_STUR) {
            v = getr(cpu, d.rd);
            switch (size) {
            case 0: *(uint8_t *)addr  = (uint8_t)v;  break;
            case 1: *(uint16_t *)addr = (uint16_t)v; break;
            case 2: *(uint32_t *)addr = (uint32_t)v; break;
            case 3: *(uint64_t *)addr = v;            break;
            }
        } else {
            switch (size) {
            case 0: v = *(uint8_t *)addr;  break;
            case 1: v = *(uint16_t *)addr; break;
            case 2: v = *(uint32_t *)addr; break;
            case 3: v = *(uint64_t *)addr; break;
            default: v = 0;
            }
            setr(cpu, d.rd, v);
        }
        break;
    }

    default:
        fprintf(stderr, "atld: unimpl op=%d at pc=0x%llx\n",
                d.op, (unsigned long long)cpu->pc);
        return -1;
    }

    cpu->pc = next_pc;
    return 0;
}
