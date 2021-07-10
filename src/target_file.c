#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<elf.h>
#include<string.h>

#include "target_file.h"

char filename[FILEPATH_LEN+1];
FILE* fp;

symbol_tbl* func_table;
int         func_count=0;

void parse_elf_file(){
    Elf64_Ehdr elf_header;
    Elf64_Shdr section_header;
    fp=fopen(filename,"r");
    if(!fp){
        printf("Failed to open ELF file!\n");
        exit(-1);
    }
    fread(&elf_header,1,sizeof(elf_header),fp);
    fseek(fp,elf_header.e_shoff,SEEK_SET);
    for(int i=0;i<elf_header.e_shnum;i++){
        fread(&section_header,1,sizeof(section_header),fp);
        if(section_header.sh_type==SHT_SYMTAB){
            
            Elf64_Shdr strtab_header;
            long strtab_hdr_offset = elf_header.e_shoff + section_header.sh_link*sizeof(section_header);
            
            fseek(fp,strtab_hdr_offset,SEEK_SET);
            fread(&strtab_header,1,sizeof(strtab_header),fp);
            fseek(fp,section_header.sh_offset,SEEK_SET);
            
            int entries=section_header.sh_size/section_header.sh_entsize;
            printf("Found symtab with %d entries\n",entries);
            func_table=malloc(entries*2*sizeof(symbol_tbl));
                
                for(i=0;i<entries;++i){
                    
                    Elf64_Sym symbol;
                    char sym_name[SYMBOL_NAME_LEN+1];
                    

                    fread(&symbol,1,sizeof(symbol),fp);
                    if(ELF64_ST_TYPE(symbol.st_info)==STT_FUNC //is a function
                        && symbol.st_name!=0  //has name
                        && symbol.st_value!=0) {//has address within binary
                        
                        long pos =ftell(fp);
                        fseek(fp,strtab_header.sh_offset+symbol.st_name,SEEK_SET);
                        fread(sym_name,SYMBOL_NAME_LEN,sizeof(char),fp);

                        printf("Found function at offset 0x%lx: %s\n",symbol.st_value,sym_name);

                        register_func(func_count++,sym_name,symbol.st_value);
                        
                        fseek(fp,pos,SEEK_SET);
                    }
                }
        }
    }
}

void register_func(int id, char* name,long addr){
    strncpy(func_table[id].name,name,SYMBOL_NAME_LEN);
    func_table[id].addr=addr;
}

long find_func_addr(char* name){
    for(int i=0;i<func_count;i++){
        //printf("%s - %s \n",func_table[i].name,name);
        if(!strcmp(func_table[i].name,name))return func_table[i].addr; 
    }
    return 0;
}

/*
int main(int argc,char**argv){
    strncpy(filename,argv[1],FILEPATH_LEN);
    parse_elf_file();
}*/

