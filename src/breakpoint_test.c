#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "breakpoint.h"

extern char filename[FILEPATH_LEN+1];

int main(int argc,char**argv){
    if(argc<2)return 1;
    strncpy(filename,argv[1],FILEPATH_LEN);
    parse_elf_file();

    bp_init();
    bp_add(0xdeadbeef,"happy");
    bp_add(0xcafebeef,"world");
    bp_add_noname(0x23333333);
    bp_add_func("main");
    bp_info(1);
    bp_info(2);
    bp_info(3);
    bp_info(0);
    bp_info_all();
    bp_getid_from_addr(0xdeadbeef);
    bp_getid_from_addr(0xdeadaaaa);
    bp_getid_from_name("main");
    bp_delete(2);
    bp_info_all();
    bp_delete(2);
    bp_delete(2);
    bp_delete(2);
    bp_delete(0);
    bp_info_all();
    bp_add(0xcafebeef,"world");
    bp_add_noname(0x23333333);
    bp_add_func("main");
    bp_insert(1);
    bp_info_all();
    bp_delete_all();
    bp_info_all();
}