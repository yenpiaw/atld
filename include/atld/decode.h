#pragma once
#include <stdint.h>

enum op_kind {
    OP_UNKNOWN = 0,
    OP_MOVZ, OP_MOVN, OP_MOVK,
    OP_ADR, OP_ADRP,
    OP_ADD_IMM, OP_SUB_IMM,
    OP_ADDS_IMM, OP_SUBS_IMM,
    OP_ADDS_REG, OP_SUBS_REG,
    OP_CSEL, OP_CSINC, OP_CSINV, OP_CSNEG,
    OP_TBZ, OP_TBNZ,
    OP_UBFM, OP_SBFM, OP_BFM,
    OP_MOVI_4S,
    OP_LDR_BH, OP_STR_BH,
    OP_STP_Q, OP_LDP_Q,
    OP_STR_D_IMM, OP_LDR_D_IMM, OP_FMOV_D, OP_MOVI_D0,
    OP_FMOV_D_IMM,
    OP_ANDS_IMM, OP_MRS, OP_MSR,
    OP_MADD, OP_MSUB, OP_SMADDL, OP_UMADDL, OP_SMULH, OP_UMULH,
    OP_EXTR,
    OP_REV, OP_REV16, OP_REV32, OP_RBIT, OP_CLZ,
    OP_ORN_REG, OP_EON_REG, OP_AND_REG, OP_ANDS_REG, OP_EOR_REG, OP_BIC_REG,
    OP_ADC_REG, OP_ADCS_REG, OP_SBC_REG, OP_SBCS_REG,
    OP_DUP_B16,
    OP_STR_Q_IMM, OP_STR_Q_REG, OP_STUR_Q,
    OP_LDR_Q_IMM, OP_LDR_Q_REG, OP_LDUR_Q,
    OP_STR_S_IMM, OP_STR_S_REG, OP_STUR_S,
    OP_LDR_S_IMM, OP_LDR_S_REG, OP_LDUR_S,
    OP_ADD_EXT, OP_SUB_EXT,
    OP_LDR_PRE, OP_STR_PRE,
    OP_LDR_POST, OP_STR_POST,
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
    OP_B, OP_BL, OP_RET, OP_BR, OP_BLR,
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
