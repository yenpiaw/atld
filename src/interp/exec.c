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
    case 0: return v << amt;
    case 1: return v >> amt;
    case 2:
        if (sf) return (uint64_t)(((int64_t)v) >> amt);
        return (uint64_t)(uint32_t)(((int32_t)(uint32_t)v) >> amt);
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
    cpu->pc_history[cpu->pc_history_idx & 63] = cpu->pc;
    cpu->pc_history_idx++;
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
        int elem_sz = d.sf ? 8 : 4;
        int64_t off = sext64(d.imm16, 7) * elem_sz;
        uint64_t addr, wb = 0;
        if (d.shift == 0)      addr = base + (uint64_t)off;
        else if (d.shift == 1) { addr = base + (uint64_t)off; wb = addr; }
        else                   { addr = base;                  wb = base + (uint64_t)off; }
        if (d.op == OP_STP) {
            if (d.sf) {
                *(uint64_t *)addr       = getr(cpu, d.rd);
                *(uint64_t *)(addr + 8) = getr(cpu, d.rm);
            } else {
                *(uint32_t *)addr       = (uint32_t)getr(cpu, d.rd);
                *(uint32_t *)(addr + 4) = (uint32_t)getr(cpu, d.rm);
            }
        } else {
            if (d.sf) {
                setr(cpu, d.rd, *(uint64_t *)addr);
                setr(cpu, d.rm, *(uint64_t *)(addr + 8));
            } else {
                setr(cpu, d.rd, (uint64_t)*(uint32_t *)addr);
                setr(cpu, d.rm, (uint64_t)*(uint32_t *)(addr + 4));
            }
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
    case OP_BLR:
        setr(cpu, 30, cpu->pc + 4);
        next_pc = getr(cpu, d.rn);
        break;

    case OP_SDIV:
    case OP_UDIV: {
        uint64_t a = getr(cpu, d.rn), b = getr(cpu, d.rm);
        uint64_t r;
        if (!d.sf) { a = (uint64_t)(int64_t)(int32_t)a; b = (uint64_t)(int64_t)(int32_t)b; }
        if (b == 0) r = 0;
        else if (d.op == OP_SDIV) r = (uint64_t)((int64_t)a / (int64_t)b);
        else r = a / b;
        setr(cpu, d.rd, apply_sf(r, d.sf));
        break;
    }
    case OP_SBFM: {
        int datasize = d.sf ? 64 : 32;
        uint64_t src = getr(cpu, d.rn);
        if (datasize == 32) src &= 0xFFFFFFFF;
        int R = (int)d.imm;
        int S = (int)d.imm16;
        uint64_t result;
        if (R <= S) {
            /* SBFX: extract (S-R+1) bits from R, sign-extend */
            int width = S - R + 1;
            uint64_t mask = (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
            uint64_t extracted = (src >> R) & mask;
            int sign = (extracted >> (width - 1)) & 1;
            if (sign) {
                if (width < 64) {
                    uint64_t sign_ext = ~mask;
                    result = extracted | sign_ext;
                } else {
                    result = extracted;
                }
            } else {
                result = extracted;
            }
        } else {
            /* SBFIZ: sign-extend low (S+1) bits, shift left (datasize-R) */
            int width = S + 1;
            int lsb = (datasize - R) & (datasize - 1);
            uint64_t mask = (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
            uint64_t extracted = src & mask;
            /* sign-extend */
            int sign = (extracted >> (width - 1)) & 1;
            if (sign) {
                if (width < 64) result = extracted | ~mask;
                else result = extracted;
            } else {
                result = extracted;
            }
            result <<= lsb;
        }
        if (datasize == 32) result &= 0xFFFFFFFF;
        setr(cpu, d.rd, result);
        break;
    }

    case OP_BFM: {
        int datasize = d.sf ? 64 : 32;
        uint64_t src_val = getr(cpu, d.rn);
        uint64_t dst_val = getr(cpu, d.rd);
        if (datasize == 32) { src_val &= 0xFFFFFFFF; dst_val &= 0xFFFFFFFF; }
        int R = (int)d.imm;
        int S = (int)d.imm16;
        uint64_t result;
        if (S >= R) {
            /* BFXIL: extract (S-R+1) bits from src starting at R, insert at dst low */
            int width = S - R + 1;
            uint64_t mask = (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
            uint64_t extracted = (src_val >> R) & mask;
            result = (dst_val & ~mask) | (extracted & mask);
        } else {
            /* BFI: insert (S+1) bits from src low at position (datasize - R) in dst */
            int width = S + 1;
            int lsb = (datasize - R) & (datasize - 1);
            uint64_t mask = (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
            uint64_t extracted = src_val & mask;
            result = (dst_val & ~(mask << lsb)) | ((extracted & mask) << lsb);
        }
        if (datasize == 32) result &= 0xFFFFFFFF;
        setr(cpu, d.rd, result);
        break;
    }

    case OP_UBFM: {
        int datasize = d.sf ? 64 : 32;
        uint64_t src = getr(cpu, d.rn);
        if (datasize == 32) src &= 0xFFFFFFFF;
        int R = (int)d.imm;
        int S = (int)d.imm16;
        uint64_t result;
        if (R <= S) {
            /* UBFX: extract (S-R+1) bits from position R */
            int width = S - R + 1;
            uint64_t mask = (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
            result = (src >> R) & mask;
        } else {
            /* UBFIZ: insert low (S+1) bits at position (datasize-R) */
            int width = S + 1;
            int lsb = (datasize - R) & (datasize - 1);
            uint64_t mask = (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
            result = (src & mask) << lsb;
        }
        if (datasize == 32) result &= 0xFFFFFFFF;
        setr(cpu, d.rd, result);
        break;
    }

    case OP_LSL_IMM:
        setr(cpu, d.rd, apply_sf(getr(cpu, d.rn) << d.imm, d.sf));
        break;
    case OP_LSR_IMM: {
        uint64_t v = getr(cpu, d.rn);
        if (!d.sf) v &= 0xffffffffULL;
        setr(cpu, d.rd, apply_sf(v >> d.imm, d.sf));
        break;
    }
    case OP_ASR_IMM: {
        int64_t v = d.sf ? (int64_t)getr(cpu, d.rn)
                         : (int64_t)(int32_t)(uint32_t)getr(cpu, d.rn);
        setr(cpu, d.rd, apply_sf((uint64_t)(v >> d.imm), d.sf));
        break;
    }
    case OP_AND_IMM:
    case OP_ORR_IMM:
    case OP_EOR_IMM: {
        uint64_t v = getr(cpu, d.rn);
        uint64_t imm = (uint64_t)d.imm;
        uint64_t r = (d.op == OP_AND_IMM) ? (v & imm) :
                     (d.op == OP_ORR_IMM) ? (v | imm) : (v ^ imm);
        setr(cpu, d.rd, apply_sf(r, d.sf));
        break;
    }
    case OP_SXTW:
        setr(cpu, d.rd, (uint64_t)(int64_t)(int32_t)(uint32_t)getr(cpu, d.rn));
        break;
    case OP_SXTB: {
        uint64_t v = getr(cpu, d.rn);
        setr(cpu, d.rd, apply_sf((uint64_t)(int64_t)(int8_t)(uint8_t)v, d.sf));
        break;
    }
    case OP_SXTH: {
        uint64_t v = getr(cpu, d.rn);
        setr(cpu, d.rd, apply_sf((uint64_t)(int64_t)(int16_t)(uint16_t)v, d.sf));
        break;
    }
    case OP_SMULL: {
        int64_t a = (int64_t)(int32_t)getr(cpu, d.rn);
        int64_t b = (int64_t)(int32_t)getr(cpu, d.rm);
        setr(cpu, d.rd, (uint64_t)(a * b));
        break;
    }
    case OP_LDR_REG:
    case OP_STR_REG: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t rm_val = getr(cpu, d.rm);
        /* S bit (bit 12) = apply LSL shift by size */
        if ((d.raw >> 12) & 1) rm_val <<= d.shift;
        uint64_t addr = base + rm_val;
        uint8_t sz = d.shift;
        uint8_t hw = d.hw;  /* 0=zero-ext, 2=sign32, 3=sign64 */
        if (d.op == OP_STR_REG) {
            uint64_t v = getr(cpu, d.rd);
            switch (sz) {
            case 0: *(uint8_t *)addr  = (uint8_t)v;  break;
            case 1: *(uint16_t *)addr = (uint16_t)v; break;
            case 2: *(uint32_t *)addr = (uint32_t)v; break;
            case 3: *(uint64_t *)addr = v;            break;
            }
        } else {
            uint64_t v = 0;
            if (hw == 2) {
                /* LDRS* to 32-bit */
                switch (sz) {
                case 0: v = (uint64_t)(uint32_t)(int32_t)(int8_t)*(uint8_t *)addr; break;
                case 1: v = (uint64_t)(uint32_t)(int32_t)(int16_t)*(uint16_t *)addr; break;
                case 2: v = (uint64_t)(uint32_t)(int32_t)*(int32_t *)addr; break;
                default: v = *(uint32_t *)addr;
                }
            } else if (hw == 3) {
                /* LDRS* to 64-bit */
                switch (sz) {
                case 0: v = (uint64_t)(int64_t)(int8_t)*(uint8_t *)addr; break;
                case 1: v = (uint64_t)(int64_t)(int16_t)*(uint16_t *)addr; break;
                case 2: v = (uint64_t)(int64_t)*(int32_t *)addr; break;
                default: v = *(uint64_t *)addr;
                }
            } else {
                switch (sz) {
                case 0: v = *(uint8_t *)addr;  break;
                case 1: v = *(uint16_t *)addr; break;
                case 2: v = *(uint32_t *)addr; break;
                case 3: v = *(uint64_t *)addr; break;
                }
            }
            setr(cpu, d.rd, v);
        }
        break;
    }
    case OP_LDRSW_IMM: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + ((uint64_t)d.imm12 << 2);
        int32_t v = *(int32_t *)addr;
        setr(cpu, d.rd, (uint64_t)(int64_t)v);
        break;
    }

    case OP_ADD_EXT:
    case OP_SUB_EXT: {
        uint64_t rm = getr(cpu, d.rm);
        uint64_t ext;
        switch (d.shift) {
        case 0: ext = (uint64_t)(uint8_t)rm; break;
        case 1: ext = (uint64_t)(uint16_t)rm; break;
        case 2: ext = (uint64_t)(uint32_t)rm; break;
        case 3: ext = rm; break;
        case 4: ext = (uint64_t)(int64_t)(int8_t)(uint8_t)rm; break;
        case 5: ext = (uint64_t)(int64_t)(int16_t)(uint16_t)rm; break;
        case 6: ext = (uint64_t)(int64_t)(int32_t)(uint32_t)rm; break;
        case 7: ext = rm; break;
        default: ext = 0;
        }
        ext <<= (uint32_t)d.imm;
        uint64_t rn = getr(cpu, d.rn);
        if (!d.sf) rn &= 0xffffffffULL;
        uint64_t r = (d.op == OP_ADD_EXT) ? (rn + ext) : (rn - ext);
        setr(cpu, d.rd, apply_sf(r, d.sf));
        break;
    }
    case OP_LDR_PRE:
    case OP_STR_PRE:
    case OP_LDR_POST:
    case OP_STR_POST: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        int is_pre  = (d.op == OP_LDR_PRE || d.op == OP_STR_PRE);
        int is_load = (d.op == OP_LDR_PRE || d.op == OP_LDR_POST);
        uint64_t addr = is_pre ? (base + (uint64_t)d.imm) : base;
        uint64_t newbase = is_pre ? addr : (base + (uint64_t)d.imm);
        if (is_load) {
            uint64_t v = d.sf ? *(uint64_t *)addr : (uint64_t)*(uint32_t *)addr;
            setr(cpu, d.rd, v);
        } else {
            uint64_t v = getr(cpu, d.rd);
            if (d.sf) *(uint64_t *)addr = v;
            else      *(uint32_t *)addr = (uint32_t)v;
        }
        if (d.rn == 31) cpu->sp = newbase;
        else            cpu->x[d.rn] = newbase;
        break;
    }

    case OP_ANDS_IMM: {
        uint64_t rn = getr(cpu, d.rn);
        uint64_t imm = (uint64_t)d.imm;
        uint64_t r = rn & imm;
        if (d.rd != 31) setr(cpu, d.rd, apply_sf(r, d.sf));
        /* logical ops: NZ from result, C=0, V=0 */
        uint32_t flags = cpu->pstate & ~((1u<<31)|(1u<<30)|(1u<<29)|(1u<<28));
        uint64_t mask = d.sf ? ~0ULL : 0xffffffffULL;
        uint64_t mr = r & mask;
        int sb = d.sf ? 63 : 31;
        if ((mr >> sb) & 1) flags |= (1u<<31);
        if (mr == 0)        flags |= (1u<<30);
        cpu->pstate = flags;
        break;
    }
    case OP_MRS: {
        switch (d.shift) {
        case 0: setr(cpu, d.rd, cpu->tls_base); break;   // TPIDR_EL0
        case 1: setr(cpu, d.rd, 0x10);           break;   // DCZID_EL0: DZP=1, skip DC ZVA
        case 2: setr(cpu, d.rd, 0x8444c004);     break;   // CTR_EL0: 64-byte I/D cache
        }
        break;
    }

    case OP_STP_Q:
    case OP_LDP_Q: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        int64_t off = sext64(d.imm16, 7) * 16;
        uint64_t addr, wb = 0;
        if (d.shift == 0)      addr = base + (uint64_t)off;
        else if (d.shift == 1) { addr = base + (uint64_t)off; wb = addr; }
        else                   { addr = base;                  wb = base + (uint64_t)off; }
        if (d.op == OP_STP_Q) {
            *(uint64_t *)addr         = cpu->v[d.rd][0];
            *(uint64_t *)(addr + 8)   = cpu->v[d.rd][1];
            *(uint64_t *)(addr + 16)  = cpu->v[d.rm][0];
            *(uint64_t *)(addr + 24)  = cpu->v[d.rm][1];
        } else {
            cpu->v[d.rd][0] = *(uint64_t *)addr;
            cpu->v[d.rd][1] = *(uint64_t *)(addr + 8);
            cpu->v[d.rm][0] = *(uint64_t *)(addr + 16);
            cpu->v[d.rm][1] = *(uint64_t *)(addr + 24);
        }
        if (d.shift != 0) {
            if (d.rn == 31) cpu->sp = wb;
            else            cpu->x[d.rn] = wb;
        }
        break;
    }

    case OP_CSEL:
    case OP_CSINC:
    case OP_CSINV:
    case OP_CSNEG: {
        int take = check_cond(cpu, (uint8_t)d.shift);
        uint64_t rn = getr(cpu, d.rn);
        uint64_t rm = getr(cpu, d.rm);
        uint64_t r;
        if (d.op == OP_CSEL)       r = take ? rn : rm;
        else if (d.op == OP_CSINC) r = take ? rn : (rm + 1);
        else if (d.op == OP_CSINV) r = take ? rn : ~rm;
        else                       r = take ? rn : (~rm + 1);
        setr(cpu, d.rd, apply_sf(r, d.sf));
        break;
    }
    case OP_LDR_BH: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + ((uint64_t)d.imm12 << d.shift);
        uint64_t v;
        if (d.shift == 0) {
            uint8_t b = *(uint8_t *)addr;
            if (d.hw == 0)      v = (uint64_t)b;
            else if (d.hw == 1) v = (uint64_t)(uint32_t)(int32_t)(int8_t)b;
            else                v = (uint64_t)(int64_t)(int8_t)b;
        } else {
            uint16_t h = *(uint16_t *)addr;
            if (d.hw == 0)      v = (uint64_t)h;
            else if (d.hw == 1) v = (uint64_t)(uint32_t)(int32_t)(int16_t)h;
            else                v = (uint64_t)(int64_t)(int16_t)h;
        }
        setr(cpu, d.rd, v);
        break;
    }
    case OP_STR_BH: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + ((uint64_t)d.imm12 << d.shift);
        uint64_t v = getr(cpu, d.rd);
        if (d.shift == 0) *(uint8_t *)addr  = (uint8_t)v;
        else              *(uint16_t *)addr = (uint16_t)v;
        break;
    }

    case OP_TBZ:
    case OP_TBNZ: {
        uint64_t rt = getr(cpu, d.rd);
        int bit = (int)d.shift;
        int bitval = (bit < 64) ? ((rt >> bit) & 1) : 0;
        int take = (d.op == OP_TBZ) ? (bitval == 0) : (bitval == 1);
        if (take) next_pc = cpu->pc + (uint64_t)d.imm;
        break;
    }

    case OP_MOVI_4S: {
        uint64_t imm32 = (uint64_t)(d.imm16 & 0xff);
        uint64_t w = imm32 | (imm32 << 32);   /* 2 × 32-bit lanes in uint64 */
        cpu->v[d.rd][0] = w;
        cpu->v[d.rd][1] = w;
        break;
    }

    case OP_MSR: {
        switch (d.shift) {
        case 0: cpu->tls_base = getr(cpu, d.rd); break;  // TPIDR_EL0
        case 1: break;                                    // TPIDRRO_EL0 (readonly alias) — ignore
        }
        break;
    }

    /* === Batch 1 exec === */
    case OP_MADD:
    case OP_MSUB: {
        uint64_t a = getr(cpu, d.rn);
        uint64_t b = getr(cpu, d.rm);
        uint64_t c = getr(cpu, (int)d.imm);
        if (!d.sf) { a &= 0xFFFFFFFF; b &= 0xFFFFFFFF; c &= 0xFFFFFFFF; }
        uint64_t r = (d.op == OP_MADD) ? (a * b + c) : (c - a * b);
        setr(cpu, d.rd, apply_sf(r, d.sf));
        break;
    }
    case OP_SMADDL: {
        int64_t a = (int64_t)(int32_t)(uint32_t)getr(cpu, d.rn);
        int64_t b = (int64_t)(int32_t)(uint32_t)getr(cpu, d.rm);
        int64_t c = (int64_t)getr(cpu, (int)d.imm);
        setr(cpu, d.rd, (uint64_t)(a * b + c));
        break;
    }
    case OP_UMADDL: {
        uint64_t a = getr(cpu, d.rn) & 0xFFFFFFFF;
        uint64_t b = getr(cpu, d.rm) & 0xFFFFFFFF;
        uint64_t c = getr(cpu, (int)d.imm);
        setr(cpu, d.rd, a * b + c);
        break;
    }
    case OP_SMULH: {
        __int128 a = (int64_t)getr(cpu, d.rn);
        __int128 b = (int64_t)getr(cpu, d.rm);
        __int128 r = a * b;
        setr(cpu, d.rd, (uint64_t)(r >> 64));
        break;
    }
    case OP_UMULH: {
        unsigned __int128 a = getr(cpu, d.rn);
        unsigned __int128 b = getr(cpu, d.rm);
        unsigned __int128 r = a * b;
        setr(cpu, d.rd, (uint64_t)(r >> 64));
        break;
    }
    case OP_RBIT: {
        if (d.sf) {
            uint64_t v = getr(cpu, d.rn), r = 0;
            for (int i = 0; i < 64; i++) { r = (r << 1) | (v & 1); v >>= 1; }
            setr(cpu, d.rd, r);
        } else {
            uint32_t v = (uint32_t)getr(cpu, d.rn), r = 0;
            for (int i = 0; i < 32; i++) { r = (r << 1) | (v & 1); v >>= 1; }
            setr(cpu, d.rd, (uint64_t)r);
        }
        break;
    }
    case OP_REV: {
        if (d.sf) {
            uint64_t v = getr(cpu, d.rn), r = 0;
            for (int i = 0; i < 8; i++) { r = (r << 8) | (v & 0xFF); v >>= 8; }
            setr(cpu, d.rd, r);
        } else {
            uint32_t v = (uint32_t)getr(cpu, d.rn), r = 0;
            for (int i = 0; i < 4; i++) { r = (r << 8) | (v & 0xFF); v >>= 8; }
            setr(cpu, d.rd, (uint64_t)r);
        }
        break;
    }
    case OP_REV16: {
        if (d.sf) {
            uint64_t v = getr(cpu, d.rn);
            uint64_t r = ((v & 0x00FF00FF00FF00FFULL) << 8) | ((v & 0xFF00FF00FF00FF00ULL) >> 8);
            setr(cpu, d.rd, r);
        } else {
            uint32_t v = (uint32_t)getr(cpu, d.rn);
            uint32_t r = ((v & 0x00FF00FF) << 8) | ((v & 0xFF00FF00) >> 8);
            setr(cpu, d.rd, (uint64_t)r);
        }
        break;
    }
    case OP_REV32: {
        uint64_t v = getr(cpu, d.rn);
        uint32_t lo = (uint32_t)v, hi = (uint32_t)(v >> 32);
        lo = ((lo & 0xFF) << 24) | ((lo & 0xFF00) << 8) | ((lo & 0xFF0000) >> 8) | ((lo & 0xFF000000) >> 24);
        hi = ((hi & 0xFF) << 24) | ((hi & 0xFF00) << 8) | ((hi & 0xFF0000) >> 8) | ((hi & 0xFF000000) >> 24);
        setr(cpu, d.rd, (uint64_t)lo | ((uint64_t)hi << 32));
        break;
    }
    case OP_CLZ: {
        if (d.sf) {
            uint64_t v = getr(cpu, d.rn);
            setr(cpu, d.rd, v == 0 ? 64 : (uint64_t)__builtin_clzll(v));
        } else {
            uint32_t v = (uint32_t)getr(cpu, d.rn);
            setr(cpu, d.rd, v == 0 ? 32 : (uint64_t)__builtin_clz(v));
        }
        break;
    }
    case OP_EXTR: {
        int lsb = (int)d.imm;
        uint64_t n = getr(cpu, d.rn);
        uint64_t m = getr(cpu, d.rm);
        if (d.sf) {
            uint64_t r = (lsb == 0) ? m : ((m >> lsb) | (n << (64 - lsb)));
            setr(cpu, d.rd, r);
        } else {
            uint32_t nn = (uint32_t)n, mm = (uint32_t)m;
            uint32_t r = (lsb == 0) ? mm : ((mm >> lsb) | (nn << (32 - lsb)));
            setr(cpu, d.rd, (uint64_t)r);
        }
        break;
    }
    case OP_AND_REG:
    case OP_ANDS_REG:
    case OP_EOR_REG:
    case OP_ORN_REG:
    case OP_EON_REG:
    case OP_BIC_REG: {
        uint64_t rn = getr(cpu, d.rn);
        uint64_t rm = shifted(getr(cpu, d.rm), d.shift, (uint32_t)d.imm, d.sf);
        uint64_t r;
        int set_flg = 0;
        switch (d.op) {
        case OP_AND_REG:  r = rn & rm;  break;
        case OP_ANDS_REG: r = rn & rm;  set_flg = 1; break;
        case OP_EOR_REG:  r = rn ^ rm;  break;
        case OP_ORN_REG:  r = rn | ~rm; break;
        case OP_EON_REG:  r = rn ^ ~rm; break;
        case OP_BIC_REG:  r = rn & ~rm; break;
        default: r = 0;
        }
        if (d.rd != 31) setr(cpu, d.rd, apply_sf(r, d.sf));
        if (set_flg) {
            uint32_t flags = cpu->pstate & ~((1u<<31)|(1u<<30)|(1u<<29)|(1u<<28));
            uint64_t mask = d.sf ? ~0ULL : 0xffffffffULL;
            uint64_t mr = r & mask;
            int sb = d.sf ? 63 : 31;
            if ((mr >> sb) & 1) flags |= (1u<<31);
            if (mr == 0)        flags |= (1u<<30);
            cpu->pstate = flags;
        }
        break;
    }

    /* === SIMD minimal === */
    case OP_DUP_B16: {
        uint8_t b = (uint8_t)getr(cpu, d.rn);
        uint64_t w = 0x0101010101010101ULL * b;
        cpu->v[d.rd][0] = w;
        cpu->v[d.rd][1] = w;
        break;
    }
    case OP_STR_Q_IMM: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + ((uint64_t)d.imm12 << 4);
        *(uint64_t *)addr       = cpu->v[d.rd][0];
        *(uint64_t *)(addr + 8) = cpu->v[d.rd][1];
        break;
    }
    case OP_STR_Q_REG: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + (getr(cpu, d.rm) << (d.shift ? 4 : 0));
        *(uint64_t *)addr       = cpu->v[d.rd][0];
        *(uint64_t *)(addr + 8) = cpu->v[d.rd][1];
        break;
    }
    case OP_STUR_Q: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + (uint64_t)d.imm;
        *(uint64_t *)addr       = cpu->v[d.rd][0];
        *(uint64_t *)(addr + 8) = cpu->v[d.rd][1];
        break;
    }
    case OP_LDR_Q_IMM: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + ((uint64_t)d.imm12 << 4);
        cpu->v[d.rd][0] = *(uint64_t *)addr;
        cpu->v[d.rd][1] = *(uint64_t *)(addr + 8);
        break;
    }
    case OP_LDR_Q_REG: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + (getr(cpu, d.rm) << (d.shift ? 4 : 0));
        cpu->v[d.rd][0] = *(uint64_t *)addr;
        cpu->v[d.rd][1] = *(uint64_t *)(addr + 8);
        break;
    }
    case OP_LDUR_Q: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + (uint64_t)d.imm;
        cpu->v[d.rd][0] = *(uint64_t *)addr;
        cpu->v[d.rd][1] = *(uint64_t *)(addr + 8);
        break;
    }
    case OP_STR_S_IMM: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + ((uint64_t)d.imm12 << 2);
        *(uint32_t *)addr = (uint32_t)cpu->v[d.rd][0];
        break;
    }
    case OP_STR_S_REG: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + (getr(cpu, d.rm) << (d.shift ? 2 : 0));
        *(uint32_t *)addr = (uint32_t)cpu->v[d.rd][0];
        break;
    }
    case OP_STUR_S: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + (uint64_t)d.imm;
        *(uint32_t *)addr = (uint32_t)cpu->v[d.rd][0];
        break;
    }
    case OP_LDR_S_IMM: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + ((uint64_t)d.imm12 << 2);
        cpu->v[d.rd][0] = (uint64_t)*(uint32_t *)addr;
        break;
    }
    case OP_LDR_S_REG: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + (getr(cpu, d.rm) << (d.shift ? 2 : 0));
        cpu->v[d.rd][0] = (uint64_t)*(uint32_t *)addr;
        break;
    }
    case OP_LDUR_S: {
        uint64_t base = (d.rn == 31) ? cpu->sp : getr(cpu, d.rn);
        uint64_t addr = base + (uint64_t)d.imm;
        cpu->v[d.rd][0] = (uint64_t)*(uint32_t *)addr;
        break;
    }

    case OP_ADC_REG:
    case OP_ADCS_REG:
    case OP_SBC_REG:
    case OP_SBCS_REG: {
        uint64_t a = getr(cpu, d.rn);
        uint64_t b = shifted(getr(cpu, d.rm), d.shift, (uint32_t)d.imm, d.sf);
        uint32_t C_in = (cpu->pstate >> 29) & 1;
        int is_sub  = (d.op == OP_SBC_REG || d.op == OP_SBCS_REG);
        int set_flg = (d.op == OP_ADCS_REG || d.op == OP_SBCS_REG);
        int width = d.sf ? 64 : 32;
        uint64_t mask = d.sf ? ~0ULL : 0xffffffffULL;
        a &= mask;
        b &= mask;

        uint64_t rb = is_sub ? (~b & mask) : b;
        __uint128_t full = (__uint128_t)a + rb + C_in;
        uint64_t r = (uint64_t)full & mask;
        int C_out = (int)((full >> width) & 1);

        if (set_flg) {
            uint32_t flags = cpu->pstate & ~((1u<<31)|(1u<<30)|(1u<<29)|(1u<<28));
            int sb = width - 1;
            if ((r >> sb) & 1) flags |= (1u<<31);
            if (r == 0)        flags |= (1u<<30);
            if (C_out)         flags |= (1u<<29);
            uint64_t sa = (a >> sb) & 1;
            uint64_t sbv = (rb >> sb) & 1;
            uint64_t sr = (r >> sb) & 1;
            if (sa == sbv && sr != sa) flags |= (1u<<28);
            cpu->pstate = flags;
        }
        setr(cpu, d.rd, apply_sf(r, d.sf));
        break;
    }

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
