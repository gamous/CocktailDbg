#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#include "disasm.h"

//
csh handle;

int init_disasm(){
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
    else 
        return 0;
}

size_t disasm(const uint8_t *code, 
        size_t code_size,
        uint64_t address,cs_insn **insn){
    size_t count;
    count = cs_disasm(handle, code, code_size, address, 0, insn);
    return count;
}