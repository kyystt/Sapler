#include "../include/isa.h"

size_t get_instr_size(const Instruction *i, AddressingFlags mode)
{
    if (i->supported_modes == 0) return 1;

    if (i->base_opcode == OP_IN || i->base_opcode == OP_OUT) return 2;

    if (mode == MODE_IMM) return 2;
    if (mode == MODE_IMM16) return 3;

    return 3;
}
