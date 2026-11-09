#include "atld/decode.h"
#include <stddef.h>

#define OPCODE(insn, mask, val) (((insn) & (mask)) == (val))

static int64_t sext(uint64_t v, int bits) {
    uint64_t m = 1ULL << (bits - 1);
    uint64_t x = v & ((1ULL << bits) - 1);
    return (int64_t)((x ^ m) - m);
}

static int decode_bitmask_imm(int N, int imms, int immr, int datasize, uint64_t *out) {
    int combined = (N << 6) | (~imms & 0x3F);
    if (combined == 0) return -1;
    int len = 31 - __builtin_clz((unsigned)combined);
    if (len < 1) return -1;
    int levels = (1 << len) - 1;
    int S = imms & levels;
    int R = immr & levels;
    if (S == levels) return -1;
    int esize = 1 << len;
    uint64_t welem = (S == 63) ? ~0ULL : ((1ULL << (S + 1)) - 1);
    /* 1ULL << 64 is UB; mask explicitly for esize==64 */
    uint64_t mask64 = (esize == 64) ? ~0ULL : ((1ULL << esize) - 1);
    uint64_t wmask;
    if (R == 0) wmask = welem & mask64;
    else wmask = ((welem >> R) | (welem << (esize - R))) & mask64;
    uint64_t mask = 0;
    for (int i = 0; i < datasize; i += esize) mask |= wmask << i;
    if (datasize == 32) mask &= 0xFFFFFFFF;
    *out = mask;
    return 0;
}

int decode_insn(uint32_t insn, struct decoded *o) {
    *o = (struct decoded){0};
    o->raw = insn;

    /* MOVZ / MOVN / MOVK (both sf) */
    if (OPCODE(insn, 0x7f800000, 0x52800000)) {
        o->op = OP_MOVZ; o->sf = (insn>>31)&1;
        o->hw = (insn>>21)&3; o->imm16 = (insn>>5)&0xffff; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0x7f800000, 0x12800000)) {
        o->op = OP_MOVN; o->sf = (insn>>31)&1;
        o->hw = (insn>>21)&3; o->imm16 = (insn>>5)&0xffff; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0x7f800000, 0x72800000)) {
        o->op = OP_MOVK; o->sf = (insn>>31)&1;
        o->hw = (insn>>21)&3; o->imm16 = (insn>>5)&0xffff; o->rd = insn&0x1f;
        return 0;
    }

    /* ADR / ADRP */
    if (OPCODE(insn, 0x9f000000, 0x10000000)) {
        o->op = OP_ADR; o->rd = insn&0x1f;
        o->imm = sext(((insn>>5)&0x7ffff)<<2 | ((insn>>29)&3), 21);
        return 0;
    }
    if (OPCODE(insn, 0x9f000000, 0x90000000)) {
        o->op = OP_ADRP; o->rd = insn&0x1f;
        o->imm = sext(((insn>>5)&0x7ffff)<<2 | ((insn>>29)&3), 21) << 12;
        return 0;
    }

    /* ADD/SUB (immediate) */
    if (OPCODE(insn, 0x7f000000, 0x11000000)) {
        o->op = OP_ADD_IMM; o->sf = (insn>>31)&1;
        o->shift = (insn>>22)&1;
        o->imm12 = (insn>>10)&0xfff; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0x7f000000, 0x51000000)) {
        o->op = OP_SUB_IMM; o->sf = (insn>>31)&1;
        o->shift = (insn>>22)&1;
        o->imm12 = (insn>>10)&0xfff; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* ADDS / SUBS (immediate, also CMP/CMN imm) */
    if (OPCODE(insn, 0x7f000000, 0x31000000)) {
        o->op = OP_ADDS_IMM; o->sf = (insn>>31)&1;
        o->shift = (insn>>22)&1;
        o->imm12 = (insn>>10)&0xfff; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0x7f000000, 0x71000000)) {
        o->op = OP_SUBS_IMM; o->sf = (insn>>31)&1;
        o->shift = (insn>>22)&1;
        o->imm12 = (insn>>10)&0xfff; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* ADDS / SUBS (shifted register, also CMP/CMN reg) */
    if (OPCODE(insn, 0x7f200000, 0x2b000000)) {
        o->op = OP_ADDS_REG; o->sf = (insn>>31)&1;
        o->shift = (insn>>22)&3;
        o->rm = (insn>>16)&0x1f;
        o->imm = (insn>>10)&0x3f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0x7f200000, 0x6b000000)) {
        o->op = OP_SUBS_REG; o->sf = (insn>>31)&1;
        o->shift = (insn>>22)&3;
        o->rm = (insn>>16)&0x1f;
        o->imm = (insn>>10)&0x3f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* ADD/SUB (extended register, no flags) */
    if (OPCODE(insn, 0x3fe00000, 0x0b200000)) {
        o->op = ((insn>>30)&1) ? OP_SUB_EXT : OP_ADD_EXT;
        o->sf = (insn>>31)&1;
        o->shift = (insn>>13)&0x7;
        o->rm = (insn>>16)&0x1f;
        o->imm = (insn>>10)&0x7;
        o->rn = (insn>>5)&0x1f;
        o->rd = insn&0x1f;
        return 0;
    }

    /* ADD/SUB (shifted register, no flags) */
    if (OPCODE(insn, 0x3f200000, 0x0b000000)) {
        o->op = ((insn>>30)&1) ? OP_SUB_REG : OP_ADD_REG;
        o->sf = (insn>>31)&1;
        o->shift = (insn>>22)&3;
        o->rm = (insn>>16)&0x1f;
        o->imm = (insn>>10)&0x3f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    /* ORR (shifted register) */
    if (OPCODE(insn, 0x7f200000, 0x2a000000)) {
        o->op = OP_ORR_REG; o->sf = (insn>>31)&1;
        o->shift = (insn>>22)&3;
        o->rm = (insn>>16)&0x1f;
        o->imm = (insn>>10)&0x3f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* CSEL/CSINC/CSINV/CSNEG — bits[28:21]=11010100, cond in [15:12].
     * Placed BEFORE ADC so CSEL (shift=2 pattern) is not caught by ADC. */
    {
        uint32_t base = insn & 0x7FE00C00;
        if (base == 0x1A800000 || base == 0x1A800400 ||
            base == 0x5A800000 || base == 0x5A800400) {
            o->op = (base == 0x1A800000) ? OP_CSEL :
                    (base == 0x1A800400) ? OP_CSINC :
                    (base == 0x5A800000) ? OP_CSINV : OP_CSNEG;
            o->sf    = (insn>>31)&1;
            o->rm    = (insn>>16)&0x1f;
            o->shift = (insn>>12)&0xf;
            o->rn    = (insn>>5)&0x1f;
            o->rd    = insn&0x1f;
            return 0;
        }
    }

    /* ADC/ADCS/SBC/SBCS shifted register — bits[28:24]=11010, bit21=0.
     * Shift=3 (ROR) reserved in ARM64 → reject it so SDIV/UDIV (which also
     * has bits[28:24]=11010 with bits[23:22]=11) fall through correctly. */
    if (OPCODE(insn, 0x1f200000, 0x1a000000) && ((insn>>22)&3) != 3) {
        uint8_t op = (insn>>30)&1;
        uint8_t S  = (insn>>29)&1;
        o->op = op ? (S ? OP_SBCS_REG : OP_SBC_REG)
                   : (S ? OP_ADCS_REG : OP_ADC_REG);
        o->sf    = (insn>>31)&1;
        o->shift = (insn>>22)&3;
        o->rm    = (insn>>16)&0x1f;
        o->imm   = (insn>>10)&0x3f;
        o->rn    = (insn>>5)&0x1f;
        o->rd    = insn&0x1f;
        return 0;
    }

    /* LDR (literal) 64-bit / 32-bit */
    if (OPCODE(insn, 0xff000000, 0x58000000)) {
        o->op = OP_LDR_LIT; o->sf = 1;
        o->imm = sext((insn>>5)&0x7ffff, 19) << 2; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0xff000000, 0x18000000)) {
        o->op = OP_LDR_LIT; o->sf = 0;
        o->imm = sext((insn>>5)&0x7ffff, 19) << 2; o->rd = insn&0x1f;
        return 0;
    }

    /* LDR/STR (unsigned offset) 64-bit */
    if (OPCODE(insn, 0xffc00000, 0xf9400000)) {
        o->op = OP_LDR_IMM; o->sf = 1;
        o->imm12 = (insn>>10)&0xfff; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xf9000000)) {
        o->op = OP_STR_IMM; o->sf = 1;
        o->imm12 = (insn>>10)&0xfff; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    /* LDR/STR (unsigned offset) 32-bit */
    if (OPCODE(insn, 0xffc00000, 0xb9400000)) {
        o->op = OP_LDR_IMM; o->sf = 0;
        o->imm12 = (insn>>10)&0xfff; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xb9000000)) {
        o->op = OP_STR_IMM; o->sf = 0;
        o->imm12 = (insn>>10)&0xfff; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* STP/LDP (64-bit): offset / pre-index / post-index */
    if (OPCODE(insn, 0xffc00000, 0xa9000000)) {
        o->op = OP_STP; o->sf = 1; o->shift = 0;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
if (OPCODE(insn, 0xffc00000, 0x29000000)) {
        o->op = OP_STP; o->sf = 0; o->shift = 0;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xa9800000)) {
        o->op = OP_STP; o->sf = 1; o->shift = 1;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
if (OPCODE(insn, 0xffc00000, 0x29800000)) {
        o->op = OP_STP; o->sf = 0; o->shift = 1;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xa8800000)) {
        o->op = OP_STP; o->sf = 1; o->shift = 2;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
if (OPCODE(insn, 0xffc00000, 0x28800000)) {
        o->op = OP_STP; o->sf = 0; o->shift = 2;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xa9400000)) {
        o->op = OP_LDP; o->sf = 1; o->shift = 0;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
if (OPCODE(insn, 0xffc00000, 0x29400000)) {
        o->op = OP_LDP; o->sf = 0; o->shift = 0;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xa9c00000)) {
        o->op = OP_LDP; o->sf = 1; o->shift = 1;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
if (OPCODE(insn, 0xffc00000, 0x29c00000)) {
        o->op = OP_LDP; o->sf = 0; o->shift = 1;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xa8c00000)) {
        o->op = OP_LDP; o->sf = 1; o->shift = 2;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
if (OPCODE(insn, 0xffc00000, 0x28c00000)) {
        o->op = OP_LDP; o->sf = 0; o->shift = 2;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }

    /* LDR/STR pre-index (imm9), 32/64-bit */
    if (OPCODE(insn, 0xffc00c00, 0xf8400c00)) {
        o->op = OP_LDR_PRE; o->sf = 1; o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00c00, 0xf8000c00)) {
        o->op = OP_STR_PRE; o->sf = 1; o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00c00, 0xb8400c00)) {
        o->op = OP_LDR_PRE; o->sf = 0; o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00c00, 0xb8000c00)) {
        o->op = OP_STR_PRE; o->sf = 0; o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    /* LDR/STR post-index (imm9), 32/64-bit */
    if (OPCODE(insn, 0xffc00c00, 0xf8400400)) {
        o->op = OP_LDR_POST; o->sf = 1; o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00c00, 0xf8000400)) {
        o->op = OP_STR_POST; o->sf = 1; o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00c00, 0xb8400400)) {
        o->op = OP_LDR_POST; o->sf = 0; o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00c00, 0xb8000400)) {
        o->op = OP_STR_POST; o->sf = 0; o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }

    /* B / BL */
    if (OPCODE(insn, 0xfc000000, 0x14000000)) {
        o->op = OP_B; o->imm = sext(insn&0x3ffffff, 26) << 2; return 0;
    }
    if (OPCODE(insn, 0xfc000000, 0x94000000)) {
        o->op = OP_BL; o->imm = sext(insn&0x3ffffff, 26) << 2; return 0;
    }

    /* B.cond */
    if (OPCODE(insn, 0xff000010, 0x54000000)) {
        o->op = OP_B_COND; o->shift = insn & 0xf;
        o->imm = sext((insn>>5)&0x7ffff, 19) << 2;
        return 0;
    }

    /* CBZ / CBNZ */
    if (OPCODE(insn, 0x7e000000, 0x34000000)) {
        o->op = ((insn>>24)&1) ? OP_CBNZ : OP_CBZ;
        o->sf = (insn>>31)&1;
        o->rd = insn & 0x1f;
        o->imm = sext((insn>>5)&0x7ffff, 19) << 2;
        return 0;
    }

    /* LDUR / STUR (unscaled immediate, integer, no writeback) */
    if (OPCODE(insn, 0x3f200c00, 0x38000000)) {
        uint8_t opc  = (insn>>22)&3;
        uint8_t size = (insn>>30)&3;
        if (opc == 0)      o->op = OP_STUR;
        else if (opc == 1) o->op = OP_LDUR;
        else return -1;
        o->shift = size;
        o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* RET / BR */
    if (OPCODE(insn, 0xfffffc1f, 0xd65f0000)) {
        o->op = OP_RET; o->rn = (insn>>5)&0x1f; return 0;
    }
    if (OPCODE(insn, 0xfffffc1f, 0xd61f0000)) {
        o->op = OP_BR; o->rn = (insn>>5)&0x1f; return 0;
    }
    if (OPCODE(insn, 0xfffffc1f, 0xd63f0000)) {
        o->op = OP_BLR; o->rn = (insn>>5)&0x1f; return 0;
    }

    /* SVC */
    if (OPCODE(insn, 0xffe0001f, 0xd4000001)) {
        o->op = OP_SVC; o->imm16 = (insn>>5)&0xffff; return 0;
    }

    /* HINT space: NOP, YIELD, WFE, WFI, BTI, PACIASP, AUTIASP, PACIBSP,
     * AUTIBSP, ESB, PSB, CSDB, etc.  All safe to NOP on a CPU without the
     * corresponding feature (x86_64 has none of these).  ARM defines them
     * as HINT so compliant CPUs without the feature execute them as NOP. */
    if (OPCODE(insn, 0xfffff01f, 0xd503201f)) {
        o->op = OP_NOP;
        return 0;
    }

    /* NOP */
    if (insn == 0xd503201f) { o->op = OP_NOP; return 0; }

    /* BRK */
    if (OPCODE(insn, 0xffe0001f, 0xd4200000)) {
        o->op = OP_BRK; o->imm16 = (insn>>5)&0xffff; return 0;
    }

    /* SDIV / UDIV */
    if (OPCODE(insn, 0x7FE0FC00, 0x1AC00C00)) {
        o->op = OP_SDIV; o->sf = (insn>>31)&1;
        o->rm = (insn>>16)&0x1f; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0x7FE0FC00, 0x1AC00800)) {
        o->op = OP_UDIV; o->sf = (insn>>31)&1;
        o->rm = (insn>>16)&0x1f; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* UBFM -> LSL/LSR immediate */
    if (OPCODE(insn, 0x7F800000, 0x53000000)) {
        int sf = (insn>>31)&1, N = (insn>>22)&1;
        int immr = (insn>>16)&0x3f, imms = (insn>>10)&0x3f;
        int datasize = sf ? 64 : 32;
        int rd = insn&0x1f, rn = (insn>>5)&0x1f;
        if (N != sf) return -1;
        if (imms == datasize - 1 && immr != 0) {
            o->op = OP_LSR_IMM; o->sf = sf; o->imm = immr;
            o->rn = rn; o->rd = rd; return 0;
        }
        if (imms < datasize - 1) {
            int shift = datasize - 1 - imms;
            int expected_immr = (-shift) & (datasize - 1);
            if (immr == expected_immr) {
                o->op = OP_LSL_IMM; o->sf = sf; o->imm = shift;
                o->rn = rn; o->rd = rd; return 0;
            }
        }
        /* Fall through to general UBFM (covers UBFIZ cases like R > S) */
    }

    /* UBFM general (bit field extract/insert with wrap-around).
     * Semantics per ARM ARM:
     *   width = (R <= S) ? (S - R + 1) : (S + 1)
     *   if R + width <= datasize: simple extract from src[.]
     *   else: wrap — extract [datasize-1:R] to low, [S-(datasize-R):0] to high.
     * Decoded as OP_UBFM with imm=R, imm16=S. */
    if (OPCODE(insn, 0x7F800000, 0x53000000)) {
        int sf = (insn>>31)&1, N = (insn>>22)&1;
        if (N != sf) return -1;
        o->op = OP_UBFM;
        o->sf = sf;
        o->imm = (insn>>16)&0x3f;   /* R */
        o->imm16 = (insn>>10)&0x3f; /* S */
        o->rn = (insn>>5)&0x1f;
        o->rd = insn & 0x1f;
        return 0;
    }

    /* SBFM -> ASR/SXTW/SXTB/SXTH */
    if (OPCODE(insn, 0x7F800000, 0x13000000)) {
        int sf = (insn>>31)&1, N = (insn>>22)&1;
        int immr = (insn>>16)&0x3f, imms = (insn>>10)&0x3f;
        int datasize = sf ? 64 : 32;
        int rd = insn&0x1f, rn = (insn>>5)&0x1f;
        if (N != sf) return -1;
        if (sf && immr == 0 && imms == 31) { o->op = OP_SXTW; o->rn = rn; o->rd = rd; return 0; }
        if (immr == 0 && imms == 7)  { o->op = OP_SXTB; o->sf = sf; o->rn = rn; o->rd = rd; return 0; }
        if (immr == 0 && imms == 15) { o->op = OP_SXTH; o->sf = sf; o->rn = rn; o->rd = rd; return 0; }
        if (imms == datasize - 1 && immr != 0) {
            o->op = OP_ASR_IMM; o->sf = sf; o->imm = immr;
            o->rn = rn; o->rd = rd; return 0;
        }
        /* Fall through to general SBFM (SBFX/SBFIZ) */
        o->op = OP_SBFM; o->sf = sf;
        o->imm = immr; o->imm16 = imms;
        o->rn = rn; o->rd = rd;
        return 0;
    }

    /* BFM (BitField Move) — BFI/BFXIL base. Encoding: opc=01, 0x33... */
    if (OPCODE(insn, 0x7F800000, 0x33000000)) {
        int sf = (insn>>31)&1, N = (insn>>22)&1;
        int immr = (insn>>16)&0x3f, imms = (insn>>10)&0x3f;
        if (N != sf) return -1;
        o->op = OP_BFM; o->sf = sf;
        o->imm = immr; o->imm16 = imms;
        o->rn = (insn>>5)&0x1f;
        o->rd = insn & 0x1f;
        return 0;
    }

    /* AND/ORR/EOR immediate (bitmask) */
    if (OPCODE(insn, 0x1F800000, 0x12000000)) {
        int sf = (insn>>31)&1;
        int opc = (insn>>29)&3;
        int N = (insn>>22)&1;
        int immr = (insn>>16)&0x3f, imms = (insn>>10)&0x3f;
        int datasize = sf ? 64 : 32;
        uint64_t imm;
        if (N != sf) return -1;
        if (decode_bitmask_imm(N, imms, immr, datasize, &imm) != 0) return -1;
        o->op = (opc == 0) ? OP_AND_IMM :
                (opc == 1) ? OP_ORR_IMM :
                (opc == 2) ? OP_EOR_IMM : OP_ANDS_IMM;
        o->sf = sf;
        o->imm = (int64_t)imm;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* SMULL (32x32 -> 64 signed) */
    if (OPCODE(insn, 0xFFE0FC00, 0x9B207C00)) {
        o->op = OP_SMULL;
        o->rm = (insn>>16)&0x1f; o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* LDR/STR register offset (byte/half/word/dword) */
    {
        int sz = -1, is_load = 0;
        if      (OPCODE(insn, 0xFFE0EC00, 0x38206800)) { sz = 0; is_load = 0; }
        else if (OPCODE(insn, 0xFFE0EC00, 0x38606800)) { sz = 0; is_load = 1; }
        else if (OPCODE(insn, 0xFFE0EC00, 0x78206800)) { sz = 1; is_load = 0; }
        else if (OPCODE(insn, 0xFFE0EC00, 0x78606800)) { sz = 1; is_load = 1; }
        else if (OPCODE(insn, 0xFFE0EC00, 0xB8206800)) { sz = 2; is_load = 0; }
        else if (OPCODE(insn, 0xFFE0EC00, 0xB8606800)) { sz = 2; is_load = 1; }
        else if (OPCODE(insn, 0xFFE0EC00, 0xF8206800)) { sz = 3; is_load = 0; }
        else if (OPCODE(insn, 0xFFE0EC00, 0xF8606800)) { sz = 3; is_load = 1; }
        /* LDRSB/LDRSH (32/64-bit dest) + LDRSW register offset */
        else if (OPCODE(insn, 0xFFE0EC00, 0x38A06800)) { sz = 0; is_load = 2; }  /* LDRSB W */
        else if (OPCODE(insn, 0xFFE0EC00, 0x38E06800)) { sz = 0; is_load = 3; }  /* LDRSB X */
        else if (OPCODE(insn, 0xFFE0EC00, 0x78A06800)) { sz = 1; is_load = 2; }  /* LDRSH W */
        else if (OPCODE(insn, 0xFFE0EC00, 0x78E06800)) { sz = 1; is_load = 3; }  /* LDRSH X */
        else if (OPCODE(insn, 0xFFE0EC00, 0xB8A06800)) { sz = 2; is_load = 3; }  /* LDRSW X (64-bit) */
        if (sz >= 0) {
            o->op = (is_load >= 1) ? OP_LDR_REG : OP_STR_REG;
            o->shift = sz;
            o->hw = (uint16_t)(is_load >= 2 ? is_load : 0);  /* 2=sign32, 3=sign64 */
            o->rm = (insn>>16)&0x1f;
            o->rn = (insn>>5)&0x1f;
            o->rd = insn&0x1f;
            return 0;
        }
    }

    /* LDRSW (imm, unsigned offset) */
    if (OPCODE(insn, 0xFFC00000, 0xB9800000)) {
        o->op = OP_LDRSW_IMM;
        o->imm12 = (insn>>10)&0xfff;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* ANDS (immediate) — TST alias */
    if (OPCODE(insn, 0x7f800000, 0x72000000)) {
        int sf = (insn>>31)&1, N = (insn>>22)&1;
        int immr = (insn>>16)&0x3f, imms = (insn>>10)&0x3f;
        int datasize = sf ? 64 : 32;
        uint64_t imm;
        if (N != sf) return -1;
        if (decode_bitmask_imm(N, imms, immr, datasize, &imm) != 0) return -1;
        o->op = OP_ANDS_IMM;
        o->sf = sf;
        o->imm = (int64_t)imm;
        o->rn = (insn>>5)&0x1f;
        o->rd = insn&0x1f;
        return 0;
    }

    /* MRS Xt, <sysreg> — hanya register spesifik yang di-handle.
     * shift field menyimpan sysreg ID: 0=TPIDR_EL0, 1=DCZID_EL0, 2=CTR_EL0. */
    if (OPCODE(insn, 0xffffffe0, 0xd53bd040)) {  // MRS Xt, TPIDR_EL0
        o->op = OP_MRS; o->shift = 0; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffffffe0, 0xd53b00e0)) {  // MRS Xt, DCZID_EL0
        o->op = OP_MRS; o->shift = 1; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffffffe0, 0xd53b0020)) {  // MRS Xt, CTR_EL0
        o->op = OP_MRS; o->shift = 2; o->rd = insn&0x1f; return 0;
    }

    /* STP/LDP (SIMD&FP, 128-bit Q), offset/pre/post.
     * Base: 0xAD000000 signed offset / 0xAD800000 pre / 0xAC800000 post (STP)
     *       0xAD400000 signed offset / 0xADC00000 pre / 0xACC00000 post (LDP)
     * imm7 in [21:15], Rt2 [14:10], Rn [9:5], Rt [4:0].
     * shift: 0=offset, 1=pre, 2=post — sama dengan STP/LDP int. */
    {
        struct { uint32_t mask, val; int kind, mode; } tbl[] = {
            { 0xFFC00000, 0xAD000000, 0, 0 }, { 0xFFC00000, 0xAD800000, 0, 1 }, { 0xFFC00000, 0xAC800000, 0, 2 },
            { 0xFFC00000, 0xAD400000, 1, 0 }, { 0xFFC00000, 0xADC00000, 1, 1 }, { 0xFFC00000, 0xACC00000, 1, 2 },
        };
        for (size_t k = 0; k < sizeof(tbl)/sizeof(tbl[0]); k++) {
            if ((insn & tbl[k].mask) == tbl[k].val) {
                o->op = tbl[k].kind ? OP_LDP_Q : OP_STP_Q;
                o->shift = (uint8_t)tbl[k].mode;
                o->imm16 = (insn>>15)&0x7f;
                o->rm = (insn>>10)&0x1f;
                o->rn = (insn>>5)&0x1f;
                o->rd = insn&0x1f;
                return 0;
            }
        }
    }

    /* === SIMD minimal: untuk __memset_generic & __memcpy_generic === */

    /* DUP Vd.16B, Wn — broadcast byte */
    if (OPCODE(insn, 0xFFFFFC00, 0x4E010C00)) {
        o->op = OP_DUP_B16;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* STR Q, [Xn, #imm12*16] */
    if (OPCODE(insn, 0xFFC00000, 0x3D800000)) {
        o->op = OP_STR_Q_IMM;
        o->imm12 = (insn>>10)&0xfff;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    /* STR Q, [Xn, Xm{, lsl #4}] — register offset, S bit at 12 */
    if (OPCODE(insn, 0xFFE0EC00, 0x3CA06800)) {
        o->op = OP_STR_Q_REG;
        o->shift = (insn>>12)&1;
        o->rm = (insn>>16)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    /* STUR Q, [Xn, #imm9] */
    if (OPCODE(insn, 0xFFE00C00, 0x3C800000)) {
        o->op = OP_STUR_Q;
        o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* LDR Q, [Xn, #imm12*16] */
    if (OPCODE(insn, 0xFFC00000, 0x3DC00000)) {
        o->op = OP_LDR_Q_IMM;
        o->imm12 = (insn>>10)&0xfff;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    /* LDR Q, [Xn, Xm{, lsl #4}] */
    if (OPCODE(insn, 0xFFE0EC00, 0x3CE06800)) {
        o->op = OP_LDR_Q_REG;
        o->shift = (insn>>12)&1;
        o->rm = (insn>>16)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    /* LDUR Q, [Xn, #imm9] */
    if (OPCODE(insn, 0xFFE00C00, 0x3CC00000)) {
        o->op = OP_LDUR_Q;
        o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* STR S, [Xn, #imm12*4] */
    if (OPCODE(insn, 0xFFC00000, 0xBD000000)) {
        o->op = OP_STR_S_IMM;
        o->imm12 = (insn>>10)&0xfff;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    /* STR S, [Xn, Xm{, lsl #2}] */
    if (OPCODE(insn, 0xFFE0EC00, 0xBC206800)) {
        o->op = OP_STR_S_REG;
        o->shift = (insn>>12)&1;
        o->rm = (insn>>16)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    /* STUR S, [Xn, #imm9] */
    if (OPCODE(insn, 0xFFE00C00, 0xBC000000)) {
        o->op = OP_STUR_S;
        o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* LDR S, [Xn, #imm12*4] */
    if (OPCODE(insn, 0xFFC00000, 0xBD400000)) {
        o->op = OP_LDR_S_IMM;
        o->imm12 = (insn>>10)&0xfff;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    /* LDR S, [Xn, Xm{, lsl #2}] */
    if (OPCODE(insn, 0xFFE0EC00, 0xBC606800)) {
        o->op = OP_LDR_S_REG;
        o->shift = (insn>>12)&1;
        o->rm = (insn>>16)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    /* LDUR S, [Xn, #imm9] */
    if (OPCODE(insn, 0xFFE00C00, 0xBC400000)) {
        o->op = OP_LDUR_S;
        o->imm = sext((insn>>12)&0x1ff, 9);
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }

    /* LDR/STR byte/half, unsigned offset.
     *   size: 0=byte, 1=half; opc: 0=STR, 1=LDRZ, 2=LDRS32, 3=LDRS64. */
    {
        int size = -1, opc = -1;
        if      ((insn & 0xFFC00000) == 0x39000000) { size = 0; opc = 0; }
        else if ((insn & 0xFFC00000) == 0x79000000) { size = 1; opc = 0; }
        else if ((insn & 0xFFC00000) == 0x39400000) { size = 0; opc = 1; }
        else if ((insn & 0xFFC00000) == 0x79400000) { size = 1; opc = 1; }
        else if ((insn & 0xFFC00000) == 0x39800000) { size = 0; opc = 2; }
        else if ((insn & 0xFFC00000) == 0x79800000) { size = 1; opc = 2; }
        else if ((insn & 0xFFC00000) == 0x39C00000) { size = 0; opc = 3; }
        else if ((insn & 0xFFC00000) == 0x79C00000) { size = 1; opc = 3; }
        if (size >= 0) {
            o->op = (opc == 0) ? OP_STR_BH : OP_LDR_BH;
            o->shift = (uint8_t)size;
            o->hw = (uint16_t)(opc == 0 ? 0 : (opc == 1 ? 0 : (opc == 2 ? 1 : 2)));
            o->imm12 = (insn>>10)&0xfff;
            o->rn = (insn>>5)&0x1f;
            o->rd = insn&0x1f;
            return 0;
        }
    }

    /* TBZ/TBNZ — test bit dan branch.
     * bits 30:25=011011, bit 24=op (0=TBZ, 1=TBNZ), bit 31=b5 (test bit 32-63).
     * test_bit = (bit31 << 5) | bits[23:19]; imm14 signed * 4; Rt [4:0]. */
    if ((insn & 0x7E000000) == 0x36000000) {
        int b5 = (insn >> 31) & 1;
        int op = (insn >> 24) & 1;
        int b40 = (insn >> 19) & 0x1f;
        o->op = op ? OP_TBNZ : OP_TBZ;
        o->shift = (uint8_t)((b5 << 5) | b40);   /* test bit 0..63 */
        o->imm = sext((insn >> 5) & 0x3fff, 14) << 2;
        o->rd = insn & 0x1f;
        return 0;
    }

    /* MOVI Vd.4S, #imm8 (and .2S variant). Detected pattern from objdump:
     *   0x4F00041F = movi v31.4s, #0x0
     * Layout (empirically from objdump):
     *   bits 18:16 = imm8[7:5]
     *   bits  9: 5 = imm8[4:0]
     *   fixed       = 0x4F000400 (mask 0xEFF8FC00)
     * Fills all 128 bits (4 lanes × 32-bit) with imm8.  Works for both
     * .2S and .4S since immediate is lane-replicated either way. */
    if ((insn & 0xEFF8FC00) == 0x4F000400) {
        uint32_t imm8 = (uint32_t)((((insn >> 16) & 0x7) << 5) | ((insn >> 5) & 0x1F));
        o->op = OP_MOVI_4S;
        o->imm16 = (uint16_t)imm8;
        o->rd = insn & 0x1f;
        return 0;
    }

    /* ============ Batch 1: integer + bitops + NOP-safe ============ */

    /* MADD / MSUB (32 and 64-bit) — op31=11011, bits[23:21]=000, bit15=0/1 */
    if (OPCODE(insn, 0x7FE08000, 0x1B000000)) {
        o->op = OP_MADD; o->sf = (insn>>31)&1;
        o->rm = (insn>>16)&0x1f; o->imm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0x7FE08000, 0x1B008000)) {
        o->op = OP_MSUB; o->sf = (insn>>31)&1;
        o->rm = (insn>>16)&0x1f; o->imm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    /* SMADDL / UMADDL (64-bit only) — bit 31=1, bits[23:21]=001/101 */
    if (OPCODE(insn, 0xFFE08000, 0x9B200000)) {
        o->op = OP_SMADDL; o->sf = 1;
        o->rm = (insn>>16)&0x1f; o->imm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xFFE08000, 0x9BA00000)) {
        o->op = OP_UMADDL; o->sf = 1;
        o->rm = (insn>>16)&0x1f; o->imm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    /* SMULH / UMULH — bits[23:21]=010/110, Ra=11111 */
    if (OPCODE(insn, 0xFFE0FC00, 0x9B407C00)) {
        o->op = OP_SMULH; o->sf = 1;
        o->rm = (insn>>16)&0x1f; o->rn = (insn>>5)&0x1f;
        o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xFFE0FC00, 0x9BC07C00)) {
        o->op = OP_UMULH; o->sf = 1;
        o->rm = (insn>>16)&0x1f; o->rn = (insn>>5)&0x1f;
        o->rd = insn&0x1f; return 0;
    }

    /* Data-processing (1-source): RBIT, REV16, REV32, REV, CLZ */
    if (OPCODE(insn, 0xFFFFFC00, 0x5AC00000)) { o->op = OP_RBIT; o->sf=0; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0xFFFFFC00, 0xDAC00000)) { o->op = OP_RBIT; o->sf=1; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0xFFFFFC00, 0x5AC00400)) { o->op = OP_REV16; o->sf=0; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0xFFFFFC00, 0xDAC00400)) { o->op = OP_REV16; o->sf=1; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0xFFFFFC00, 0x5AC00800)) { o->op = OP_REV; o->sf=0; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0xFFFFFC00, 0xDAC00C00)) { o->op = OP_REV; o->sf=1; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0xFFFFFC00, 0xDAC00800)) { o->op = OP_REV32; o->sf=1; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0xFFFFFC00, 0x5AC01000)) { o->op = OP_CLZ; o->sf=0; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0xFFFFFC00, 0xDAC01000)) { o->op = OP_CLZ; o->sf=1; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }

    /* EXTR — extract from register pair */
    if (OPCODE(insn, 0x7FA00000, 0x13800000)) {
        o->op = OP_EXTR; o->sf = (insn>>31)&1;
        o->rm = (insn>>16)&0x1f;
        o->imm = (insn>>10)&0x3f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }

    /* Logical register forms: AND/ANDS/EOR/ORR/ORN/EON/BIC (mask 0x7F200000) */
    if (OPCODE(insn, 0x7F200000, 0x0A000000)) { o->op = OP_AND_REG;  o->sf=(insn>>31)&1; o->shift=(insn>>22)&3; o->rm=(insn>>16)&0x1f; o->imm=(insn>>10)&0x3f; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0x7F200000, 0x0A200000)) { o->op = OP_BIC_REG;  o->sf=(insn>>31)&1; o->shift=(insn>>22)&3; o->rm=(insn>>16)&0x1f; o->imm=(insn>>10)&0x3f; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0x7F200000, 0x2A200000)) { o->op = OP_ORN_REG;  o->sf=(insn>>31)&1; o->shift=(insn>>22)&3; o->rm=(insn>>16)&0x1f; o->imm=(insn>>10)&0x3f; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0x7F200000, 0x4A000000)) { o->op = OP_EOR_REG;  o->sf=(insn>>31)&1; o->shift=(insn>>22)&3; o->rm=(insn>>16)&0x1f; o->imm=(insn>>10)&0x3f; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0x7F200000, 0x4A200000)) { o->op = OP_EON_REG;  o->sf=(insn>>31)&1; o->shift=(insn>>22)&3; o->rm=(insn>>16)&0x1f; o->imm=(insn>>10)&0x3f; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }
    if (OPCODE(insn, 0x7F200000, 0x6A000000)) { o->op = OP_ANDS_REG; o->sf=(insn>>31)&1; o->shift=(insn>>22)&3; o->rm=(insn>>16)&0x1f; o->imm=(insn>>10)&0x3f; o->rn=(insn>>5)&0x1f; o->rd=insn&0x1f; return 0; }

    /* ARMv8 barrier class: DSB, DMB, ISB, CLREX, SB, SSBB, PSSBB, CSDB.
     * Encoding space: 0xd5033000-0xd5033fff (bits[31:12]=0xd5033, CRn=3).
     * All are safe to NOP on x86_64 TSO:
     *   - DSB/DMB: TSO already provides strict ordering
     *   - ISB: no self-modifying code in interpreter
     *   - CLREX: no ARM exclusive monitor
     *   - SB/SSBB/PSSBB/CSDB: speculation barriers, NOP is correct */
    if ((insn & 0xfffff000) == 0xd5033000) {
        o->op = OP_NOP;
        return 0;
    }

    /* NOP-safe PAC indirect: autia1716/autib1716/autiza1716/autizb1716/pacia1716/pacib1716/paciza1716/pacizb1716 */
    if (insn == 0xDAC14310 || insn == 0xDAC14330 ||
        insn == 0xDAC13310 || insn == 0xDAC13330 ||
        insn == 0xDAC10310 || insn == 0xDAC10330 ||
        insn == 0xDAC12310 || insn == 0xDAC12330) {
        o->op = OP_NOP;
        return 0;
    }

    /* MSR <sysreg>, Xt — writes to system register.
     * Only TPIDR_EL0 (TLS base) and TPIDRRO_EL0 (read-only alias) matter for glibc. */
    if (OPCODE(insn, 0xffffffe0, 0xd51bd040)) {  // MSR TPIDR_EL0, Xt
        o->op = OP_MSR; o->shift = 0; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffffffe0, 0xd51bd060)) {  // MSR TPIDRRO_EL0, Xt
        o->op = OP_MSR; o->shift = 1; o->rd = insn&0x1f; return 0;
    }

    /* FP D-form (8-byte double) */
    if ((insn & 0xFFFFFFE0) == 0x2F00E400) {   /* MOVI Dd, #0 */
        o->op = OP_MOVI_D0;
        o->rd = insn & 0x1f;
        return 0;
    }
    if (OPCODE(insn, 0xFFC00000, 0xFD000000)) { /* STR Dd, [Xn, #imm12*8] */
        o->op = OP_STR_D_IMM;
        o->imm12 = (insn>>10)&0xfff;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0xFFC00000, 0xFD400000)) { /* LDR Dd, [Xn, #imm12*8] */
        o->op = OP_LDR_D_IMM;
        o->imm12 = (insn>>10)&0xfff;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
        return 0;
    }
    if (OPCODE(insn, 0xFFE0FC00, 0x1E604000)) { /* FMOV Dd, Dm */
        o->op = OP_FMOV_D;
        o->rm = (insn>>16)&0x1f;
        o->rd = insn&0x1f;
        return 0;
    }

    o->op = OP_UNKNOWN;
    return -1;
}
