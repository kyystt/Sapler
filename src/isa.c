#include "../include/isa.h"

const Instruction SAPIENS_INSTRUCTIONS[] = {
    {"ADC", OP_ADC_DIR, MODE_DIR | MODE_IDIR | MODE_IMM},
    {"ADD", OP_ADD_DIR, MODE_DIR | MODE_IDIR | MODE_IMM},
    {"AND", OP_AND_DIR, MODE_DIR | MODE_IDIR | MODE_IMM},

    {"HLT", OP_HLT, 0},

    {"IN", OP_IN, MODE_DIR},

    {"JC", OP_JC_DIR, MODE_DIR | MODE_IDIR},
    {"JMP", OP_JMP_DIR, MODE_DIR | MODE_IDIR},
    {"JN", OP_JN_DIR, MODE_DIR | MODE_IDIR},
    {"JNC", OP_JNC_DIR, MODE_DIR | MODE_IDIR},
    {"JNZ", OP_JNZ_DIR, MODE_DIR | MODE_IDIR},
    {"JP", OP_JP_DIR, MODE_DIR | MODE_IDIR},
    {"JSR", OP_JSR_DIR, MODE_DIR | MODE_IDIR},
    {"JZ", OP_JZ_DIR, MODE_DIR | MODE_IDIR},

    {"LDA", OP_LDA_DIR, MODE_DIR | MODE_IDIR | MODE_IMM},
    {"LDS", OP_LDS_DIR, MODE_DIR | MODE_IDIR | MODE_IMM16},

    {"NOP", OP_NOP, 0},
    {"NOT", OP_NOT, 0},

    {"OR", OP_OR_DIR, MODE_DIR | MODE_IDIR | MODE_IMM},

    {"OUT", OP_OUT, MODE_DIR},

    {"POP", OP_POP, 0},
    {"PUSH", OP_PUSH, 0},
    {"RET", OP_RET, 0},

    {"SBC", OP_SBC_DIR, MODE_DIR | MODE_IDIR | MODE_IMM},

    {"SHL", OP_SHL, 0},
    {"SHR", OP_SHR, 0},
    {"SRA", OP_SRA, 0},

    {"STA", OP_STA_DIR, MODE_DIR | MODE_IDIR},
    {"STS", OP_STS_DIR, MODE_DIR | MODE_IDIR},

    {"SUB", OP_SUB_DIR, MODE_DIR | MODE_IDIR | MODE_IMM},

    {"TRAP", OP_TRAP_DIR, MODE_DIR | MODE_IDIR},

    {"XOR", OP_XOR_DIR, MODE_DIR | MODE_IDIR | MODE_IMM},
};

const size_t SAPIENS_INSTRUCTION_COUNT =
    sizeof(SAPIENS_INSTRUCTIONS) / sizeof(SAPIENS_INSTRUCTIONS[0]);

size_t get_instr_size(const Instruction *i, AddressingFlags mode)
{
    if (i->supported_modes == 0)
        return 1;

    if (i->base_opcode == OP_IN || i->base_opcode == OP_OUT)
        return 2;

    if (mode == MODE_IMM)
        return 2;
    if (mode == MODE_IMM16)
        return 3;

    return 3;
}
