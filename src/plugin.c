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



void anti_anti_ptrace(){
    pt_regs regs;
    pt_getregs(&regs);
    regs.rax=1;
    pt_setregs(&regs);
    printf("\033[32m[+]\033[0mInterupt Ptrace Anti-Debugger Method.\n");
}
void preload_plugins(){
    register_syscall(101, anti_anti_ptrace, "64"    ,"ptrace");
}