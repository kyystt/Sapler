#ifndef _ISA_H_
#define _ISA_H_

#include <stdint.h>
#include <stdlib.h>

typedef enum {
    OP_NOP          = 0x00,
    OP_HLT          = 0xFC,

    OP_STA_DIR      = 0x10,
    OP_STA_IND      = 0x11,

    OP_STS_DIR      = 0x14,
    OP_STS_IND      = 0x15,

    OP_LDA_DIR      = 0x20,
    OP_LDA_IND      = 0x21,
    OP_LDA_IMM      = 0x22,

    OP_LDS_DIR      = 0x24,
    OP_LDS_IND      = 0x25,
    OP_LDS_IMM_16   = 0x27,

    OP_ADD_DIR      = 0x30,
    OP_ADD_IND      = 0x31,
    OP_ADD_IMM      = 0x32,

    OP_ADC_DIR      = 0x34,
    OP_ADC_IND      = 0x35,
    OP_ADC_IMM      = 0x36,

    OP_SUB_DIR      = 0x38,
    OP_SUB_IND      = 0x39,
    OP_SUB_IMM      = 0x3A,

    OP_SBC_DIR      = 0x3C,
    OP_SBC_IND      = 0x3D,
    OP_SBC_IMM      = 0x3E,
    
    OP_OR_DIR       = 0x40,
    OP_OR_IND       = 0x41,
    OP_OR_IMM       = 0x42,

    OP_XOR_DIR      = 0x44,
    OP_XOR_IND      = 0x45,
    OP_XOR_IMM      = 0x46,

    OP_AND_DIR      = 0x50,
    OP_AND_IND      = 0x51,
    OP_AND_IMM      = 0x52,

    OP_NOT          = 0x60,
    OP_SHL          = 0x70,
    OP_SHR          = 0x74,
    OP_SRA          = 0x78,

    OP_JMP_DIR      = 0x80,
    OP_JMP_IND      = 0x81,

    OP_JN_DIR       = 0x90,
    OP_JN_IND       = 0x91,

    OP_JP_DIR       = 0x94,
    OP_JP_IND       = 0x95,

    OP_JZ_DIR       = 0xA0,
    OP_JZ_IND       = 0xA1,

    OP_JNZ_DIR      = 0xA4,
    OP_JNZ_IND      = 0xA5,

    OP_JC_DIR       = 0xB0,
    OP_JC_IND       = 0xB1,

    OP_JNC_DIR      = 0xB4,
    OP_JNC_IND      = 0xB5,

    OP_IN           = 0xC0,
    OP_OUT          = 0xC4,

    OP_JSR_DIR      = 0xD0,
    OP_JSR_IND      = 0xD1,

    OP_RET          = 0xD8,
    OP_PUSH         = 0xE0,
    OP_POP          = 0xE4,

    OP_TRAP_DIR     = 0xF0,
    OP_TRAP_IND     = 0xF1,
} OPCODE;

typedef enum {
    MODE_DIR = 1u << 0,
    MODE_IDIR = 1u << 1,
    MODE_IMM = 1u << 2,
    MODE_IMM16 = 1u << 3
} AddressingFlags;

typedef struct {
    const char *mnemonic;
    uint8_t opcode;
    uint8_t supported_modes;
} Instruction;

const Instruction SAPIENS_INSTRUCTIONS[] = {
    {"ADC",  OP_ADC_DIR,  MODE_DIR | MODE_IDIR | MODE_IMM},
    {"ADD",  OP_ADD_DIR,  MODE_DIR | MODE_IDIR | MODE_IMM},
    {"AND",  OP_AND_DIR,  MODE_DIR | MODE_IDIR | MODE_IMM},

    {"HLT",  OP_HLT,      0},

    {"IN",   OP_IN,       MODE_DIR},

    {"JC",   OP_JC_DIR,   MODE_DIR | MODE_IDIR},
    {"JMP",  OP_JMP_DIR,  MODE_DIR | MODE_IDIR},
    {"JN",   OP_JN_DIR,   MODE_DIR | MODE_IDIR},
    {"JNC",  OP_JNC_DIR,  MODE_DIR | MODE_IDIR},
    {"JNZ",  OP_JNZ_DIR,  MODE_DIR | MODE_IDIR},
    {"JP",   OP_JP_DIR,   MODE_DIR | MODE_IDIR},
    {"JSR",  OP_JSR_DIR,  MODE_DIR | MODE_IDIR},
    {"JZ",   OP_JZ_DIR,   MODE_DIR | MODE_IDIR},

    {"LDA",  OP_LDA_DIR,  MODE_DIR | MODE_IDIR | MODE_IMM},
    {"LDS",  OP_LDS_DIR,  MODE_DIR | MODE_IDIR | MODE_IMM16},

    {"NOP",  OP_NOP,      0},
    {"NOT",  OP_NOT,      0},

    {"OR",   OP_OR_DIR,   MODE_DIR | MODE_IDIR | MODE_IMM},

    {"OUT",  OP_OUT,      MODE_DIR},

    {"POP",  OP_POP,      0},
    {"PUSH", OP_PUSH,     0},
    {"RET",  OP_RET,      0},

    {"SBC",  OP_SBC_DIR,  MODE_DIR | MODE_IDIR | MODE_IMM},

    {"SHL",  OP_SHL,      0},
    {"SHR",  OP_SHR,      0},
    {"SRA",  OP_SRA,      0},

    {"STA",  OP_STA_DIR,  MODE_DIR | MODE_IDIR},
    {"STS",  OP_STS_DIR,  MODE_DIR | MODE_IDIR},

    {"SUB",  OP_SUB_DIR,  MODE_DIR | MODE_IDIR | MODE_IMM},

    {"TRAP", OP_TRAP_DIR, MODE_DIR | MODE_IDIR},

    {"XOR",  OP_XOR_DIR,  MODE_DIR | MODE_IDIR | MODE_IMM},
};

const size_t SAPIENS_INSTRUCTION_COUNT =
    sizeof(SAPIENS_INSTRUCTIONS) / sizeof(SAPIENS_INSTRUCTIONS[0]);

#ifdef _ISA_IMPLEMENTATION

size_t get_instr_size(const Instruction *i, AddressingFlags mode)
{
    if (i->supported_modes == 0) return 1;

    if (i->opcode == OP_IN || i->opcode == OP_OUT) return 2;

    if (mode == MODE_IMM) return 2;
    if (mode == MODE_IMM16) return 3;

    return 3;
}

#endif // _ISA_IMPLEMENTATION
#endif // _ISA_H_
