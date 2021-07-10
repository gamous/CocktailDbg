#include<stdio.h>
#include<sys/ptrace.h>
#include<unistd.h>

int func1()
{
    printf("A");
}

void func2()
{
    printf("B");
}

void func3()
{
}
int main(int argc, char* argv[])
{
    func1();
    func3();
    func2();
    func2();
    func3();
    if(-1 == ptrace(PTRACE_TRACEME))
    {
        printf("Debugger!\n");
        return 1;
    }
    printf("Hello Ptrace!\n");
    return 0;
}


