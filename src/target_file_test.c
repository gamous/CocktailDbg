#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<elf.h>
#include<string.h>

#include "target_file.h"

extern char filename[FILEPATH_LEN+1];
extern symbol_tbl* func_table;

int main(int argc,char**argv){
    if(argc<2)return 1;
    strncpy(filename,argv[1],FILEPATH_LEN);
    parse_elf_file();
}