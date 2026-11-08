#pragma once
#include <stdint.h>

enum op_kind {
    OP_UNKNOWN = 0,
    OP_MOVZ, OP_MOVN, OP_MOVK,
    OP_ADR, OP_ADRP,
    OP_ADD_IMM, OP_SUB_IMM,
    OP_ADDS_IMM, OP_SUBS_IMM,
    OP_ADDS_REG, OP_SUBS_REG,
    OP_SDIV, OP_UDIV,
    OP_LSL_IMM, OP_LSR_IMM, OP_ASR_IMM,
    OP_AND_IMM, OP_ORR_IMM, OP_EOR_IMM,
    OP_SXTW, OP_SXTB, OP_SXTH,
    OP_SMULL,
    OP_LDR_REG, OP_STR_REG,
    OP_LDRSW_IMM,
    OP_ADD_REG, OP_SUB_REG, OP_ORR_REG,
    OP_LDR_LIT,
    OP_LDR_IMM, OP_STR_IMM,
    OP_STP, OP_LDP,
    OP_B, OP_BL, OP_RET, OP_BR,
    OP_B_COND, OP_CBZ, OP_CBNZ,
    OP_LDUR, OP_STUR,
    OP_SVC, OP_NOP, OP_BRK,
};

struct decoded {
    enum op_kind op;
    uint8_t  rd, rn, rm;
    uint8_t  sf;        /* 0=32-bit, 1=64-bit */
    uint8_t  shift;     /* generic aux: 0/1/2 depending on op */
    uint16_t imm16;     /* MOVZ/MOVK/MOVN hw/imm, STP/LDP imm7 */
    uint16_t hw;
    uint32_t imm12;
    int64_t  imm;       /* branch/ADR/ADRP target offset, or shift amount */
    uint32_t raw;
};

int decode_insn(uint32_t insn, struct decoded *out);
