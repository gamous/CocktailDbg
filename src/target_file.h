#ifndef __CCDBG_FILE
#define __CCDBG_FILE

#define FILEPATH_LEN 127
#define SYMBOL_NAME_LEN 50

typedef struct {
    char name[SYMBOL_NAME_LEN+1];
    long addr;
}symbol_tbl;

void register_func(int id, char* name,long addr);
void parse_elf_file();

long find_func_addr(char* name);

#endif