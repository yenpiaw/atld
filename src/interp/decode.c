#include "atld/decode.h"

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
    uint64_t wmask;
    if (R == 0) wmask = welem & ((1ULL << esize) - 1);
    else wmask = ((welem >> R) | (welem << (esize - R))) & ((1ULL << esize) - 1);
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
    if (OPCODE(insn, 0x3f200000, 0x2a000000)) {
        o->op = OP_ORR_REG; o->sf = (insn>>31)&1;
        o->shift = (insn>>22)&3;
        o->rm = (insn>>16)&0x1f;
        o->imm = (insn>>10)&0x3f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f;
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
        o->op = OP_STP; o->shift = 0;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xa9800000)) {
        o->op = OP_STP; o->shift = 1;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xa8800000)) {
        o->op = OP_STP; o->shift = 2;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xa9400000)) {
        o->op = OP_LDP; o->shift = 0;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xa9c00000)) {
        o->op = OP_LDP; o->shift = 1;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
        o->rn = (insn>>5)&0x1f; o->rd = insn&0x1f; return 0;
    }
    if (OPCODE(insn, 0xffc00000, 0xa8c00000)) {
        o->op = OP_LDP; o->shift = 2;
        o->imm16 = (insn>>15)&0x7f; o->rm = (insn>>10)&0x1f;
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

    /* SVC */
    if (OPCODE(insn, 0xffe0001f, 0xd4000001)) {
        o->op = OP_SVC; o->imm16 = (insn>>5)&0xffff; return 0;
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
        return -1;
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
        return -1;
    }

    /* AND/ORR/EOR immediate (bitmask) */
    if (OPCODE(insn, 0x7F800000, 0x12000000)) {
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
                (opc == 2) ? OP_EOR_IMM : OP_AND_IMM;
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
        if      (OPCODE(insn, 0xFFE0FC00, 0x38206800)) { sz = 0; is_load = 0; }
        else if (OPCODE(insn, 0xFFE0FC00, 0x38606800)) { sz = 0; is_load = 1; }
        else if (OPCODE(insn, 0xFFE0FC00, 0x78206800)) { sz = 1; is_load = 0; }
        else if (OPCODE(insn, 0xFFE0FC00, 0x78606800)) { sz = 1; is_load = 1; }
        else if (OPCODE(insn, 0xFFE0FC00, 0xB8206800)) { sz = 2; is_load = 0; }
        else if (OPCODE(insn, 0xFFE0FC00, 0xB8606800)) { sz = 2; is_load = 1; }
        else if (OPCODE(insn, 0xFFE0FC00, 0xF8206800)) { sz = 3; is_load = 0; }
        else if (OPCODE(insn, 0xFFE0FC00, 0xF8606800)) { sz = 3; is_load = 1; }
        if (sz >= 0) {
            o->op = is_load ? OP_LDR_REG : OP_STR_REG;
            o->shift = sz;
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

    o->op = OP_UNKNOWN;
    return -1;
}
