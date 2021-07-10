#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ptrace.h>
#include<sys/wait.h>
#include<sys/user.h>
#include<errno.h>

#include "core.h"
#include "breakpoint.h"
#include "syscall_tbl.h"
#include "target_file.h"
#include "plugin.h"
#include "interactive.h"
#include "disasm.h"

extern int pid;
extern syscall_tbl syscall_table[MAX_SYSCALL];
extern symbol_tbl* func_table;
extern char filename[FILEPATH_LEN+1];


void ctdbg(){
    int status;

    interactive();
    wait(NULL);
    pt_sysc();

    printf("[+]Tracing started\n======\n");
    
    while(1){
        waitpid(pid,&status,0);
        //printf("status:0x%x\n",status);
        if(WIFEXITED(status)){
            printf("\n[!]Child finished\n");
            return;
        }

        if(WIFSTOPPED(status)){
            if(WSTOPSIG(status)==SIGTRAP){
                
                pt_regs regs;
                pt_getregs(&regs);

                int idx = bp_getid_from_addr(regs.rip-1);
                breakpoint* bp = bp_get(idx);

                if(idx){
                /*breakpoint hit*/    
                    bp_info(idx);
                    regs.rip-=1;
                    /* run real code */
                    pt_setregs(&regs);
                    bp_hangup(idx);
                    pt_step();
                    wait(NULL);
                    bp_insert(idx);
                    /* run break event
                       default interactive */
                    //show_regs(&regs);
                    if(bp->hook)bp->hook(idx);

                }else if(!valid_syscall(regs.orig_rax)){
                /* syscall maybe hit */
                    
                    int syscall_id=regs.orig_rax;
                    info_syscall(syscall_id);
                    if(syscall_table[syscall_id].hook)syscall_table[syscall_id].hook();
                }else{
                    //printf("Unexpected SIGTRAP %lld",regs.rip);
                    //return;
                }
            }
            if(((status>>16)&0xffff)==PTRACE_EVENT_EXIT){
                printf("\nChild finished\n");
                return;
            }
        }
        pt_sysc();
    }
}

int main(int argc,char**argv){

    /*init syscall table*/
    init_syscall_tbl();
    bp_init();
    init_disasm();

    preload_plugins();

    printf("Interactive MODE(%p)\n",interactive);
    if(argc<2){
        printf("Usage: tracer elf_path\n");
        return -1;
    }

    strncpy(filename,argv[1],FILEPATH_LEN);
    

    int c_pid=fork();
    
    if(c_pid==0){ //tracee
        ptrace(PTRACE_TRACEME,0,NULL,NULL);
        execl(argv[1],argv[1],NULL);
        printf("Failed to execl!!\n");
        exit(-1);
    }
    else{ 
    //tracer
        pid=c_pid;
        parse_elf_file();
        
        printf("Pid:%d %s ",pid,filename);
        if(init_base(pid)){
            printf("[+] Init Base Error!\n");
            exit(-1);
        }
        printf("TextBase:0x%lx\n",rebase(0));
        

        ctdbg();
    }
    return 0;
}