#include<stdio.h>
#include<unistd.h>
#include<sys/ptrace.h>
#include<stdlib.h>
#include<string.h>
#include<sys/wait.h>
#include<sys/user.h>
#include<errno.h>

#include"core.h"
#include "disasm.h"

int pid;
long textbase;

void pt_write(long addr,long data){
    ptrace(PTRACE_POKETEXT, pid, (void*)addr, data);
}

long pt_read(long addr){
    long data;
    data=ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, 0);
    return data;
}

void pt_cont(){
    ptrace(PTRACE_CONT,pid,0,0);
}
void pt_step(){
    ptrace(PTRACE_SINGLESTEP,pid,0,0);
}
void pt_sysc(){
    ptrace(PTRACE_SYSCALL,pid,0,0);
}
void pt_getregs(pt_regs* regs){
    ptrace(PTRACE_GETREGS,pid,0,regs);
}
void pt_setregs(pt_regs* regs){
    ptrace(PTRACE_SETREGS,pid,0,regs);
}

int init_base(){
	FILE *fp;
    char file_name[64]={0};
    char cmdline[64]={0};
    long addr;
    snprintf(cmdline,63,"cat /proc/%d/maps",pid);
    system(cmdline);
    snprintf(file_name,63,"/proc/%d/maps",pid);
	if ((fp=fopen(file_name,"r"))==NULL){
		printf("Open Failed\n");
		return 1;
	}
	fscanf(fp,"%lx-",&addr);
	fclose(fp);
    textbase=addr;
    return 0;
}

void pt_read_nw(long addr,size_t n,long*target){
    for(int i=0;i<n;i++)
        target[i]=ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+i*8, 0);
}

long rebase(long addr){
    return addr+textbase;
}

void show_regs(pt_regs* regs){
    printf("rip:%llx rsp:%llx rbp:%llx \n"
    "rdi:%llx rsi:%llx rdx:%llx rcx:%llx r8:%llx r9:%llx\n",
    regs->rip,
    regs->rsp,
    regs->rbp,
    regs->rdi,
    regs->rsi,
    regs->rdx,
    regs->rcx,
    regs->r8,
    regs->r9);
}
void show_stack(pt_regs* regs){
    long stack_base=regs->rbp,stack_top=regs->rsp,stack_buf;
    for(long addr=stack_top;addr<=stack_base;addr+=0x8){
        stack_buf=pt_read(addr);
        printf("%016lx: %016lx\n",addr,stack_buf);
    }
}
void show_dis(pt_regs* regs,size_t num){
    long dis_addr,*dis_buf;
    cs_insn *dis_ins;

    dis_addr=regs->rip;
    dis_buf=(long*)malloc(num*8);
    pt_read_nw(dis_addr,num,dis_buf);
    
    num=disasm((const uint8_t *)dis_buf,num*8,dis_addr,&dis_ins);
    if(num>0){
        for (int j = 0; j < num-1; j++) {
            printf("0x%"PRIx64":\t%s\t\t%s\n", dis_ins[j].address, dis_ins[j].mnemonic,
                    dis_ins[j].op_str);
            }
            cs_free(dis_ins,num);
    }
    free(dis_buf);dis_buf=NULL;
}