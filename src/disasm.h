#ifndef __CCDBG_DIS
#define __CCDBG_DIS
#include <capstone/capstone.h>

typedef cs_insn dis_insn;

int init_disasm();
size_t disasm(const uint8_t *code, 
        size_t code_size,
        uint64_t address,cs_insn **insn);
#endif