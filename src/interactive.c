#include<stdio.h>
#include<unistd.h>
#include<sys/ptrace.h>
#include<stdlib.h>
#include<string.h>
#include<sys/wait.h>
#include<sys/user.h>
#include<errno.h>

#include "core.h"
#include "breakpoint.h"
#include "disasm.h"

extern int pid;

void interactive(){
    char buf[0x100]={0};
    char *argv[0x20]={0};
    int argc=0;
    pt_regs regs;
    
    //panel
    pt_getregs(&regs);
    show_regs(&regs);
    show_stack(&regs);
    show_dis(&regs,6);

    while (1){

        //mainloop
        putchar('>');
        fflush(stdout);
        
        //getinput
        memset(buf,0,0x100);
        memset(argv,0,sizeof(argv));
        argc=0;

        buf[read(0,buf,255)-1]='\0';

        if(buf[0]==' ' || buf[0]=='\n'|| buf[0]=='\0'){
            printf("\033[31m[!]\033[0mError Ident\n");
            continue;
        }
        else{
            argv[argc++]=buf;
        }

        //split argv
        for(int i=1;i<0x100;i++){
            if(buf[i]==' ')buf[i]='\0';
            else if(buf[i-1]=='\0')argv[argc++]=buf+i;
            else if(buf[i]=='\0')break;
        }
        for(int i=0;i<argc;i++)printf("[%d]%s\n",i,argv[i]);


        if(!strcmp(argv[0],"b") ){
            long b_addr;
            if(argc>=3){
                if(!strcmp(argv[1],"*")){
                    sscanf(argv[2],"%16lx",&b_addr);
                    bp_add_noname(b_addr);
                }
                else if(!strcmp(argv[1],"?")){
                    sscanf(argv[2],"%16lx",&b_addr);
                    bp_add_temp(b_addr);
                }
                else
                    printf("[!]Unkown command\n");
            }else if(argc>=2){
                if(bp_add_func(argv[1])==-1)printf("[!]Unkown function name\n");
            }else{
                printf("[!]Unkown command\n");
            }
        }else if(!strcmp(argv[0],"c") || !strcmp(argv[0],"continue")){
            break;
        }else if(!strcmp(argv[0],"gdb")){
            bp_hangup_all();
            //ptrace(PTRACE_CONT,pid,0,0);
            ptrace(PTRACE_DETACH, pid, 1, SIGSTOP);
            char cmdline[64]={0};
            snprintf(cmdline,63,"gdb attach %d",pid);
            system(cmdline);
            if(!ptrace(PTRACE_ATTACH, pid, NULL, NULL)){
                printf("[+]Welcome Back\n");
                bp_insert_all();
            }else{
                printf("[!]Process Terminated\n");
                exit(0);
            };
        }else if(!strcmp(argv[0],"info") || !strcmp(argv[0],"show")){
            //show something infomation
            if(!strcmp(argv[1],"reg") || !strcmp(argv[1],"r")){
                //show all reg
                pt_getregs(&regs);
                if(argv[2]){
                    ;;;; if(!strcmp(argv[2],"r15"))     printf("%s = %llu\n", argv[2], regs.r15     );   
                    else if(!strcmp(argv[2],"r14"))     printf("%s = %llu\n", argv[2], regs.r14     );   
                    else if(!strcmp(argv[2],"r13"))     printf("%s = %llu\n", argv[2], regs.r13     );   
                    else if(!strcmp(argv[2],"r12"))     printf("%s = %llu\n", argv[2], regs.r12     );   
                    else if(!strcmp(argv[2],"rbp"))     printf("%s = %llu\n", argv[2], regs.rbp     );   
                    else if(!strcmp(argv[2],"rbx"))     printf("%s = %llu\n", argv[2], regs.rbx     );   
                    else if(!strcmp(argv[2],"r11"))     printf("%s = %llu\n", argv[2], regs.r11     );   
                    else if(!strcmp(argv[2],"r10"))     printf("%s = %llu\n", argv[2], regs.r10     );   
                    else if(!strcmp(argv[2],"r9"))      printf("%s = %llu\n", argv[2], regs.r9      );   
                    else if(!strcmp(argv[2],"r8"))      printf("%s = %llu\n", argv[2], regs.r8      );   
                    else if(!strcmp(argv[2],"rax"))     printf("%s = %llu\n", argv[2], regs.rax     );   
                    else if(!strcmp(argv[2],"rcx"))     printf("%s = %llu\n", argv[2], regs.rcx     );   
                    else if(!strcmp(argv[2],"rdx"))     printf("%s = %llu\n", argv[2], regs.rdx     );   
                    else if(!strcmp(argv[2],"rsi"))     printf("%s = %llu\n", argv[2], regs.rsi     );   
                    else if(!strcmp(argv[2],"rdi"))     printf("%s = %llu\n", argv[2], regs.rdi     );   
                    else if(!strcmp(argv[2],"orig_rax"))printf("%s = %llu\n", argv[2], regs.orig_rax); 
                    else if(!strcmp(argv[2],"rip"))     printf("%s = %llu\n", argv[2], regs.rip     );   
                    else if(!strcmp(argv[2],"cs"))      printf("%s = %llu\n", argv[2], regs.cs      );  
                    else if(!strcmp(argv[2],"eflags"))  printf("%s = %llu\n", argv[2], regs.eflags  );  
                    else if(!strcmp(argv[2],"rsp"))     printf("%s = %llu\n", argv[2], regs.rsp     );  
                    else if(!strcmp(argv[2],"ss"))      printf("%s = %llu\n", argv[2], regs.ss      );  
                    else if(!strcmp(argv[2],"fs_base")) printf("%s = %llu\n", argv[2], regs.fs_base ); 
                    else if(!strcmp(argv[2],"gs_base")) printf("%s = %llu\n", argv[2], regs.gs_base );
                    else if(!strcmp(argv[2],"ds"))      printf("%s = %llu\n", argv[2], regs.ds      );
                    else if(!strcmp(argv[2],"es"))      printf("%s = %llu\n", argv[2], regs.es      );
                    else if(!strcmp(argv[2],"fs"))      printf("%s = %llu\n", argv[2], regs.fs      );  
                    else if(!strcmp(argv[2],"gs"))      printf("%s = %llu\n", argv[2], regs.gs      );
                    else if(!strcmp(argv[2],"all"))     show_regs(&regs);
                    else                                printf("\033[31m[!]\033[0mUnkown regeister\n");
                }else{
                    show_regs(&regs);
                }
                
            }if(!strcmp(argv[1],"b")){
                bp_info_all();
            }
        }else if(!strcmp(argv[0],"x")){
            long x_addr,x_buf[2]; int x_count=10;
            if(argc<2){
                printf("x <address> (<count>)\n");
            }else{
                if(argc>=3){
                    x_count=atoi(argv[2]);
                    if(x_count<1&&x_count>0x200)x_count=10;
                }
                sscanf(argv[1],"%16lx",&x_addr);
                //x_addr=atol(argv[1]);
                for(int i=0;i<x_count;i++){
                    x_buf[0]=pt_read(x_addr+i*0x10);
                    x_buf[1]=pt_read(x_addr+i*0x10+0x8);
                    printf("%016lx: %016lx %016lx\n",x_addr+i*0x10,x_buf[0],x_buf[1]);
                }
            }

        }else if(!strcmp(argv[0],"dis")){
            long d_addr,*d_buf; int d_count=10;
            if(argc<2){
                printf("dis <address> (<count>)\n");
            }else{
                if(argc>=3){
                    d_count=atoi(argv[2]);
                    if(d_count<1&&d_count>0x200)d_count=10;
                }
                sscanf(argv[1],"%16lx",&d_addr);
                d_buf=(long*)malloc(d_count*8);
                pt_read_nw(d_addr,d_count,d_buf);
                cs_insn *d_ins;
                size_t d_dcount;
                d_dcount=disasm((const uint8_t *)d_buf,d_count*8,d_addr,&d_ins);
                if(d_dcount>0){
                    for (int j = 0; j < d_dcount-1; j++) {
                        printf("0x%"PRIx64":\t%s\t\t%s\n", d_ins[j].address, d_ins[j].mnemonic,
                                d_ins[j].op_str);
                        }
                        cs_free(d_ins,d_dcount);
                }
                
                free(d_buf);d_buf=NULL;
            }
        }else if(!strcmp(argv[0],"ni")){
            //getnext rip
            pt_getregs(&regs);
            bp_add_temp(regs.rip);
            return;

        }else if(!strcmp(argv[0],"si")){
            ptrace(PTRACE_SINGLESTEP,pid,0,0);
        }else if(!strcmp(argv[0],"stack")){
            pt_getregs(&regs);
            show_stack(&regs);

        }else if(!strcmp(argv[0],"q")){
            bp_hangup_all();
            ptrace(PTRACE_DETACH, pid, 1, SIGQUIT);
            exit(0);
        }else if(!strcmp(argv[0],"vmmap")){
            char cmdline[64]={0};
            snprintf(cmdline,63,"cat /proc/%d/maps",pid);
            system(cmdline);
        }else {
            printf("[!]Unkown command\n");
        }
    }
}