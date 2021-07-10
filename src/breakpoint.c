#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "breakpoint.h"
#include "core.h"

breakpoint * bp_chain;
extern void interactive();
extern symbol_tbl func_table;

#define BP_SIZE sizeof(breakpoint)

void bp_init(){
    bp_chain=(breakpoint*)malloc(BP_SIZE);
    if(!bp_chain){
        printf("[!]breakpoint init error!\n");
        exit(1);
    }
    memset(bp_chain,0,BP_SIZE);
    strcpy(bp_chain->name,"..");
}

int bp_add(long addr,char* name){
    int count=0;
    breakpoint* bp=bp_chain;
    if(!bp_chain)bp_init();
    while(bp->__next){
        count++;
        bp=bp->__next;
    }
    bp->__next=(breakpoint*)malloc(BP_SIZE);
    if(!bp->__next){
        printf("[!]breakpoint add error!\n");
        return 0;
    }
    else{
        count++;
        bp=bp->__next;
    }
    memset(bp,0,BP_SIZE);
    bp->addr=addr;
    #ifndef DEBUG_BP
    bp->hook=interactive;
    #else
    bp->hook=NULL;
    #endif
    strncpy(bp->name,name,SYMBOL_NAME_LEN);
    return count;
}

//temp temp!
void temp_handler(int idx){
    bp_delete(idx);
    interactive();
}
int bp_add_temp(long addr){
    int count=0;
    breakpoint* bp=bp_chain;
    if(!bp_chain)bp_init();
    while(bp->__next){
        count++;
        bp=bp->__next;
    }
    bp->__next=(breakpoint*)malloc(BP_SIZE);
    if(!bp->__next){
        printf("[!]breakpoint add error!\n");
        return 0;
    }
    else{
        count++;
        bp=bp->__next;
    }
    memset(bp,0,BP_SIZE);
    bp->addr=addr;
    #ifndef DEBUG_BP
    bp->hook=temp_handler;
    #else
    bp->hook=NULL;
    #endif
    strncpy(bp->name,"__temp",SYMBOL_NAME_LEN);
    bp_insert(count);
    return count;
}

int bp_add_noname(long addr){
    int idx;
    idx=bp_add(addr,"__anonymous");
    if(idx){
        bp_insert(idx);
    }
    return idx;
}

int bp_add_func(char* name){
    int idx;
    long addr;
    addr=find_func_addr(name);
    if(!addr){
        printf("[!]func symbol %s not found\n",name);
        return -1;
    }
    /* todo: judge pie on*/
    idx=bp_add(rebase(addr),name);
    if(idx){
        bp_insert(idx);
    }
    return idx;
}

int  bp_getid_from_addr(long addr){
    int count=0,found=0;
    breakpoint* bp=bp_chain;
    while(bp->__next){
        bp=bp->__next;
        count++;
        if(bp->addr==addr){
            found=1;
            break;
        }
    }
    if(found){
        printf("[+] breakpoint: %lx => %d\n",bp->addr,count);
        return count;
    }
    else{
        //printf("[!] breakpoint: %lx => ? not found\n",addr);
        return 0;
    }
}

int  bp_getid_from_name(char*name){
    int count=0,found=0;
    breakpoint* bp=bp_chain;
    while(bp->__next){
        bp=bp->__next;
        count++;
        if(!strcmp(bp->name,name)){
            found=1;
            break;
        }
    }
    if(found){
        printf("[+] breakpoint: %s => %d\n",name,count);
        return count;
    }
    else{
        printf("[!] breakpoint: %s => ? not found\n",name);
        return 0;
    }
}

void bp_delete(int idx){
    int count=0,found=0;
    breakpoint* bp=bp_chain;
    breakpoint* bp_bk;
    while(bp->__next){
        bp_bk=bp;
        bp=bp->__next;
        count++;
        if(count==idx){
            found=1;
            break;
        }
    }
    if(found){
        printf("[+] breakpoint[%d] %lx (%s) --delete\n",count,bp->addr,bp->name);
        if(bp->status){
            #ifndef DEBUG_BP
            pt_write(bp->addr,bp->orig);
            #endif
        }
        free(bp);
        bp_bk->__next=bp->__next;
    }
    else{
        printf("[!] breakpoint[%d] not found --delete\n",idx);
    }
}

void bp_delete_func(char* name){
    int idx;
    idx=bp_getid_from_name(name);
    if(idx)bp_delete(idx);
}

void bp_delete_all(){
    int count=0;
    breakpoint* bp=bp_chain;
    //breakpoint* bp_fd;
    while(bp->__next){
        bp=bp->__next;
        count++;
        if(bp->status){
            #ifndef DEBUG_BP
            pt_write(bp->addr,bp->orig);
            #endif
        }
        printf("[+] breakpoint[%d] %lx (%s) --delete\n",count,bp->addr,bp->name);
        free(bp);
    }
    bp_chain->__next=0;
}

breakpoint* bp_get(int idx){
    int count=0,found=0;
    breakpoint* bp=bp_chain;
    while(bp->__next){
        bp=bp->__next;
        count++;
        if(count==idx){
            found=1;
            break;
        }
    }
    if(found){
        return bp;
    }
    else{
        return NULL;
    }
}

void bp_info(int idx){
    int count=0,found=0;
    breakpoint* bp=bp_chain;
    while(bp->__next){
        bp=bp->__next;
        count++;
        if(count==idx){
            found=1;
            break;
        }
    }
    if(found){
        printf("[+] breakpoint[%d] %lx (%s)\n",count,bp->addr,bp->name);
    }
    else{
        printf("[!] breakpoint[%d] not found\n",idx);
    }
}

void bp_info_all(){
    int count=0;
    breakpoint* bp=bp_chain;
    while(bp->__next){
        bp=bp->__next;
        count++;
        printf("[+] breakpoint[%d] %lx (%s) st:%d\n",count,bp->addr,bp->name,bp->status);
    }
}


void bp_insert(int idx){
    int count=0,found=0;
    long code;
    breakpoint* bp=bp_chain;
    while(bp->__next){
        bp=bp->__next;
        count++;
        if(count==idx){
            found=1;
            break;
        }
    }
    if(found||!bp->status){
        #ifndef DEBUG_BP
        code=pt_read(bp->addr);
        bp->orig=code;
        pt_write(bp->addr,code&~0xff|INT3);
        #endif
        bp->status=1;
        printf("[+] breakpoint[%d] %lx (%s) --insert\n",count,bp->addr,bp->name);
    }
    else{
        printf("[!] breakpoint[%d] not found --insert\n",idx);
    }
}
void bp_insert_all(){
    int count=0;
    long code;
    breakpoint* bp=bp_chain;
    while(bp->__next){
        bp=bp->__next;
        count++;
        if(!bp->status){
            #ifndef DEBUG_BP
            code=pt_read(bp->addr);
            bp->orig=code;
            pt_write(bp->addr,code&~0xff|INT3);
            #endif
            bp->status=1;
            printf("[+] breakpoint[%d] %lx (%s) st:%d\n --insert",count,bp->addr,bp->name,bp->status);
        }
    }
}
void bp_hangup(int idx){
    int count=0,found=0;
    breakpoint* bp=bp_chain;
    while(bp->__next){
        bp=bp->__next;
        count++;
        if(count==idx){
            found=1;
            break;
        }
    }
    if(found||bp->status){
        #ifndef DEBUG_BP
        pt_write(bp->addr,bp->orig);
        #endif
        bp->status=0;
        printf("[+] breakpoint[%d] %lx (%s) --hangup\n",count,bp->addr,bp->name);
    }
    else{
        printf("[!] breakpoint[%d] not found --hangup\n",idx);
    }
}
void bp_hangup_all(){
    int count=0;
    breakpoint* bp=bp_chain;
    while(bp->__next){
        bp=bp->__next;
        count++;
        if(bp->status){
            #ifndef DEBUG_BP
            pt_write(bp->addr,bp->orig);
            #endif
            bp->status=0;
            printf("[+] breakpoint[%d] %lx (%s) st:%d\n --hangup",count,bp->addr,bp->name,bp->status);
        }
    }
}

