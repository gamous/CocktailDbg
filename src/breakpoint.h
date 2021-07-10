
#ifndef __CCDBG_BP
#define __CCDBG_BP

#include "target_file.h"

#define INT3 0xCC


typedef struct __bp{
    long addr;
    long orig; //saved code to recover after int3 triggered
    char name[SYMBOL_NAME_LEN+1];
    int  status;
    void (*hook)();
    struct __bp* __next;
}breakpoint;

void bp_init();

/* return idx */
int bp_add(long addr,char* name);
int bp_add_noname(long addr);
int bp_add_temp(long addr);
int bp_add_func(char* name);

int  bp_getid_from_addr(long addr);
int  bp_getid_from_name(char*name);

breakpoint*  bp_get(int idx);

void bp_delete(int idx);
void bp_delete_func(char* name);
void bp_delete_all();

void bp_info(int idx);
void bp_info_all();

void bp_insert(int idx);
void bp_insert_all();
void bp_hangup(int idx);
void bp_hangup_all();


#endif