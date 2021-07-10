/* define a global syscall table in
 order to catch syscall from id*/

#ifndef __CCDBG_SYSCALL
#define __CCDBG_SYSCALL

#define MAX_SYSCALL 576

/* table struct */
typedef struct{
    void (*hook)();
    char type[8];
    char name[32];
}syscall_tbl;

/* register all x64 linux syscall */
void register_syscall(int id, void* hook, char* type, char* name);
void init_syscall_tbl();

/* success -> 0 else ->1 */
int valid_syscall(int);
int info_syscall(int);
#endif