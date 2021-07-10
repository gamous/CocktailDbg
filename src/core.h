#ifndef __CCDBG_CORE
#define __CCDBG_CORE

/* maybe marco is more efficient when rw high frequency*/
void pt_write(long addr,long data);
long pt_read(long addr);
void pt_cont();
void pt_step();
void pt_sysc();

typedef struct user_regs_struct pt_regs;

void pt_getregs(pt_regs* regs);
void pt_setregs(pt_regs* regs);
void show_regs(pt_regs* regs);
void show_stack(pt_regs* regs);
void show_dis(pt_regs* regs,size_t num);

int init_base();
long rebase(long);
void pt_read_nw(long addr,size_t n,long*target);
#endif