#include "kernel/types.h"
#include "kernel/defs.h"
#include "kernel/param.h"
#include "kernel/memlayout.h"
#include "kernel/mmu.h"
#include "kernel/proc.h"
#include "kernel/x86.h"
#include "kernel/syscall.h"
#include "kernel/trace.h"

extern int e_flag;
extern int s_flag;
extern int f_flag;

int e_flag = -1;;
int s_flag = 0;
int f_flag = 0;

// User code makes a system call with INT T_SYSCALL.
// System call number in %eax.
// Arguments on the stack, from the user call to the C
// library system call function. The saved user %esp points
// to a saved program counter, and then the first argument.

// Fetch the int at addr from the current process.
int fetchint(uint addr, int *ip) {
  if (addr >= proc->sz || addr + 4 > proc->sz)
    return -1;
  *ip = *(int *)(addr);
  return 0;
}

// Fetch the nul-terminated string at addr from the current process.
// Doesn't actually copy the string - just sets *pp to point at it.
// Returns length of string, not including nul.
int fetchstr(uint addr, char **pp) {
  char *s, *ep;

  if (addr >= proc->sz)
    return -1;
  *pp = (char *)addr;
  ep = (char *)proc->sz;
  for (s = *pp; s < ep; s++)
    if (*s == 0)
      return s - *pp;
  return -1;
}

// Fetch the nth 32-bit system call argument.
int argint(int n, int *ip) { return fetchint(proc->tf->esp + 4 + 4 * n, ip); }

// Fetch the nth word-sized system call argument as a pointer
// to a block of memory of size n bytes.  Check that the pointer
// lies within the process address space.
int argptr(int n, char **pp, int size) {
  int i;

  if (argint(n, &i) < 0)
    return -1;
  if ((uint)i >= proc->sz || (uint)i + size > proc->sz)
    return -1;
  *pp = (char *)i;
  return 0;
}

// Fetch the nth word-sized system call argument as a string pointer.
// Check that the pointer is valid and the string is nul-terminated.
// (There is no shared writable memory, so the string can't change
// between this check and being used by the kernel.)
int argstr(int n, char **pp) {
  int addr;
  if (argint(n, &addr) < 0)
    return -1;
  return fetchstr(addr, pp);
}

extern int sys_chdir(void);
extern int sys_close(void);
extern int sys_dup(void);
extern int sys_exec(void);
extern int sys_exit(void);
extern int sys_fork(void);
extern int sys_fstat(void);
extern int sys_getpid(void);
extern int sys_kill(void);
extern int sys_link(void);
extern int sys_mkdir(void);
extern int sys_mknod(void);
extern int sys_open(void);
extern int sys_pipe(void);
extern int sys_read(void);
extern int sys_sbrk(void);
extern int sys_sleep(void);
extern int sys_unlink(void);
extern int sys_wait(void);
extern int sys_write(void);
extern int sys_uptime(void);
extern int sys_trace(void);
extern int sys_setEFlag(void);
extern int sys_setSFlag(void);
extern int sys_setFFlag(void);
extern int sys_dump(void);

static int (*syscalls[])(void) = {
    [SYS_fork] sys_fork,   [SYS_exit] sys_exit,     [SYS_wait] sys_wait,
    [SYS_pipe] sys_pipe,   [SYS_read] sys_read,     [SYS_kill] sys_kill,
    [SYS_exec] sys_exec,   [SYS_fstat] sys_fstat,   [SYS_chdir] sys_chdir,
    [SYS_dup] sys_dup,     [SYS_getpid] sys_getpid, [SYS_sbrk] sys_sbrk,
    [SYS_sleep] sys_sleep, [SYS_uptime] sys_uptime, [SYS_open] sys_open,
    [SYS_write] sys_write, [SYS_mknod] sys_mknod,   [SYS_unlink] sys_unlink,
    [SYS_link] sys_link,   [SYS_mkdir] sys_mkdir,   [SYS_close] sys_close,
    [SYS_trace] sys_trace, [SYS_setEFlag] sys_setEFlag, [SYS_setSFlag] sys_setSFlag,
    [SYS_setFFlag] sys_setFFlag, [SYS_dump] sys_dump,
};

static char* syscall_names[] = {
    [SYS_fork] "fork",
    [SYS_exit] "exit",
    [SYS_wait] "wait",
    [SYS_pipe] "pipe",
    [SYS_read] "read",
    [SYS_kill] "kill",
    [SYS_exec] "exec",
    [SYS_fstat] "fstat",
    [SYS_chdir] "chdir",
    [SYS_dup] "dup",
    [SYS_getpid] "getpid",
    [SYS_sbrk] "sbrk",
    [SYS_sleep] "sleep",
    [SYS_uptime] "uptime",
    [SYS_open] "open",
    [SYS_write] "write",
    [SYS_mknod] "mknod",
    [SYS_unlink] "unlink",
    [SYS_link] "link",
    [SYS_mkdir] "mkdir",
    [SYS_close] "close",
    [SYS_trace] "trace",
    [SYS_dump] "dump",
};

int sys_trace(void) {
    int n;
    argint(0, &n);
    proc->traced = (n & T_TRACE) ? n:0;
    return 0;
}

int strcompare(char str1[], char str2[]) {
    int ctr = 0;
    while(str1[ctr] == str2[ctr]) {
        if(str1[ctr]=='\0'||str2[ctr]=='\0')
        break;
        ctr++;
    }
    if(str1[ctr]=='\0' && str2[ctr]=='\0')
        return 0;
    else
        return -1;
}

int sys_setEFlag(void) {
    argint(0, &e_flag);
    return 0;
}

int sys_setSFlag(void) {
    argint(0, &s_flag);
    return 0;
}

int sys_setFFlag(void) {
    argint(0, &f_flag);
    return 0;
}

char dumpBuff[N][100];
int headIndex=0;
int* headptr = &headIndex;
int tailIndex=0;
int* tailptr = &tailIndex;
int passedZero =0;
int* passedZeroptr = &passedZero;

void addToBuff(char* event) {
    int head = *headptr;
    int tail = *tailptr;
    int s=0;
    int passedZeroFunc = *passedZeroptr;
    if(head == tail && passedZero) {
         memset(dumpBuff[tail],0,strlen(dumpBuff[tail]));
         tail = (tail+1)%N;
    }
    while(event[s] != '\0') {
          dumpBuff[head][s] = event[s];
          s+=1;
    }
    head= (head+1)%N;
    if(head==0) {
        passedZeroFunc =1;
    }
    *headptr = head;
    *tailptr = tail;
    *passedZeroptr = passedZeroFunc;
}

int sys_dump(void) {
    for(int i=0; i<N && dumpBuff[i]!=0; i+=1) {
        cprintf("%s\n", dumpBuff[i]);
    }
    return 0;
}

void syscall(void) {
    int num, i, num2;
    int is_traced = (proc->traced & T_TRACE);
    int procNameSize = 0;
    for(int j = 0; proc->name[j] != 0; j += 1) {
        procNameSize += 1;
    }
    char procname[procNameSize];
    for(i = 0; proc->name[i] != 0; i += 1) {
        procname[i] = proc->name[i];
    }
    procname[i] = proc->name[i];
    num = proc->tf->eax;
    num2 = proc->tf->eax;

    if(num == SYS_exit && is_traced) {
        //char pid = proc->pid + '0';
        char s1[50] = "TRACE: pid = ";
        //char s2[50] = " | process name = ";
        char s2[50] = " | command name = ";
        char s3[50] = " | syscall = ";
        int k =0, j=0;
        char event[100];
        while(s1[k] != '\0') {
            event[j] = s1[k];
            k+=1;
            j+=1;
        }
        int pid = proc->pid;
                // event[j] = pid;
                char temp1[5];
                    int counter1 =0;
                    while(pid!=0){
                        int k = pid%10;
                        temp1[counter1] = k+'0';
                        counter1 +=1;
                        pid /=10;
                    }
                    counter1 -=1;
                    while(counter1>=0){
                    event[j] = temp1[counter1];
                    j+=1;
                    counter1-=1;
                    }
        j+=1;
        k =0;
        while(s2[k] != '\0') {
            event[j] = s2[k];
            k+=1;
            j+=1;
        }
        k=0;
        event[j] = ' ';
        j+=1;
        while(procname[k] != '\0') {
            event[j] = procname[k];
            k+=1;
            j+=1;
        }
        k =0;
        event[j] = ' ';
        j+=1;
        while(s3[k] != '\0') {
            event[j] = s3[k];
            k+=1;
            j+=1;
        } 
        event[j] = ' ';
        j+=1;
        k=0;
        num = proc->tf->eax;
        while(syscall_names[num][k] != '\0') {
            event[j] = syscall_names[num][k];
            k+=1;
            j+=1;
        }
        event[j] = '\0';
        addToBuff(event);

        if(e_flag == -1 && s_flag == 0 && f_flag == 0)
            cprintf("TRACE: pid = %d | command name = %s | syscall = %s\n", proc->pid, procname, syscall_names[num2]);
        else {
            if(e_flag != -1) {
                if(strcompare(syscall_names[e_flag+1], syscall_names[num2]) == 0) {
                    if(f_flag == 0)
                        cprintf("TRACE: pid = %d | command name = %s | syscall = %s\n", proc->pid, procname, syscall_names[num2]);
                }
            }
            else if(f_flag == 0)
                cprintf("TRACE: pid = %d | command name = %s | syscall = %s\n", proc->pid, procname, syscall_names[num2]);
            
            e_flag = -1;
            s_flag = 0;
            f_flag = 0;
        }
    }
    if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
        proc->tf->eax = syscalls[num]();

        if(is_traced) {
            if(num == SYS_exec && proc->tf->eax == 0) {
                //char pid = proc->pid + '0';
                char s1[50] = "TRACE: pid = ";
                //char s2[50] = " | process name = ";
                char s2[50] = " | command name = ";
                char s3[50] = " | syscall = ";
                int k =0, j=0;
                char event[100];
                while(s1[k] != '\0'){
                    event[j] = s1[k];
                    k+=1;
                    j+=1;
                }
                int pid = proc->pid;
                // event[j] = pid;
                char temp1[5];
                    int counter1 =0;
                    while(pid!=0){
                        int k = pid%10;
                        temp1[counter1] = k+'0';
                        counter1 +=1;
                        pid /=10;
                    }
                    counter1 -=1;
                    while(counter1>=0){
                    event[j] = temp1[counter1];
                    j+=1;
                    counter1-=1;
                    }
                j+=1;
                k =0;
                while(s2[k] != '\0'){
                    event[j] = s2[k];
                    k+=1;
                    j+=1;
                }
                k=0;
                event[j] = ' ';
                j+=1;
                while(procname[k] != '\0'){
                    event[j] = procname[k];
                    k+=1;
                    j+=1;
                }
                k =0;
                event[j] = ' ';
                j+=1;
                while(s3[k] != '\0'){
                    event[j] = s3[k];
                    k+=1;
                    j+=1;
                } 
                event[j] = ' ';
                j+=1;
                k=0;
                while(syscall_names[num][k] != '\0'){
                    event[j] = syscall_names[num][k];
                    k+=1;
                    j+=1;
                }
                event[j] = '\0';
                addToBuff(event);

                if(e_flag == -1 && s_flag == 0 && f_flag == 0) {
                    cprintf("TRACE: pid = %d | command name = sh | syscall = trace | return value = 0\n", proc->pid);
                    cprintf("TRACE: pid = %d | command name = %s | syscall = %s\n", proc->pid, procname, syscall_names[num2]);
                }
                else {
                    if(e_flag != -1) {
                        if(strcompare(syscall_names[e_flag+1], syscall_names[num2]) == 0) {
                            if(f_flag == 0)
                                cprintf("TRACE: pid = %d | command name = %s | syscall = %s\n", proc->pid, procname, syscall_names[num2]);
                        }
                    }
                    else if(s_flag == 1) {
                        cprintf("TRACE: pid = %d | command name = sh | syscall = trace | return value = 0\n", proc->pid);
                        cprintf("TRACE: pid = %d | command name = %s | syscall = %s\n", proc->pid, procname, syscall_names[num2]);
                    }
                    else if(f_flag == 1) { }
                }
            }
            else {
                //int pid = proc->pid;
                char s1[50] = "TRACE: pid = ";
                //char s2[50] = " | process name = ";
                char s2[50] = " | command name = ";
                char s3[50] = " | syscall = ";
                char s5[50] = " | return value = ";
                int k =0, j=0;
                char event[100];
                while(s1[k] != '\0'){
                    event[j] = s1[k];
                    k+=1;
                    j+=1;
                }
                int pid = proc->pid;
                // event[j] = pid;
                char temp1[5];
                    int counter1 =0;
                    while(pid!=0){
                        int k = pid%10;
                        temp1[counter1] = k+'0';
                        counter1 +=1;
                        pid /=10;
                    }
                    counter1 -=1;
                    while(counter1>=0){
                    event[j] = temp1[counter1];
                    j+=1;
                    counter1-=1;
                    }
                j+=1;
                k =0;
                while(s2[k] != '\0'){
                    event[j] = s2[k];
                    k+=1;
                    j+=1;
                }
                k=0;
                event[j] = ' ';
                j+=1;
                while(procname[k] != '\0'){
                    event[j] = procname[k];
                    k+=1;
                    j+=1;
                }
                k =0;
                event[j] = ' ';
                j+=1;
                while(s3[k] != '\0'){
                    event[j] = s3[k];
                    k+=1;
                    j+=1;
                } 
                event[j] = ' ';
                j+=1;
                k=0;
                while(syscall_names[num][k] != '\0'){
                    event[j] = syscall_names[num][k];
                    k+=1;
                    j+=1;
                }
                k =0;
                event[j] = ' ';
                j+=1;
                while(s5[k] != '\0'){
                    event[j] = s5[k];
                    k+=1;
                    j+=1;
                } 
                int num = proc->tf->eax;
                if(num == 0){
                    event[j] = num +'0';
                }
                else{
                    char temp[5];
                    int counter =0;
                    while(num!=0){
                        int k = num%10;
                        temp[counter] = k+'0';
                        counter +=1;
                        num /=10;
                    }
                    counter -=1;
                    while(counter>=0){
                    event[j] = temp[counter];
                    j+=1;
                    counter-=1;
                    }
                }
                event[j+1] = '\0';
                addToBuff(event);

                if(e_flag == -1 && s_flag == 0 && f_flag == 0)
                    cprintf("TRACE: pid = %d | command name = %s | syscall = %s | return value = %d\n", proc->pid, procname, syscall_names[num2], proc->tf->eax);
                else {
                    int returnval = proc->tf->eax;
                    if(e_flag != -1) {
                        if(strcompare(syscall_names[e_flag+1], syscall_names[num2]) == 0) {
                            if(s_flag == 1 && returnval >= 0) 
                                cprintf("TRACE: pid = %d | command name = %s | syscall = %s | return value = %d\n", proc->pid, procname, syscall_names[num2], proc->tf->eax);
                            else if(s_flag == 1 && returnval <= -1) { }
                            else if(f_flag == 1 && returnval <= -1)
                                cprintf("TRACE: pid = %d | command name = %s | syscall = %s | return value = %d\n", proc->pid, procname, syscall_names[num2], proc->tf->eax);
                            else if(f_flag == 1 && returnval >= 0) { }  
                            else
                                cprintf("TRACE: pid = %d | command name = %s | syscall = %s | return value = %d\n", proc->pid, procname, syscall_names[num2], proc->tf->eax);
                        }
                    }
                    else if(s_flag == 1 && returnval >= 0)
                        cprintf("TRACE: pid = %d | command name = %s | syscall = %s | return value = %d\n", proc->pid, procname, syscall_names[num2], proc->tf->eax);
                    else if(f_flag == 1 && returnval <= -1)
                        cprintf("TRACE: pid = %d | command name = %s | syscall = %s | return value = %d\n", proc->pid, procname, syscall_names[num2], proc->tf->eax);
                }
            }
        }
    } 
    else {
        cprintf("%d %s: unknown sys call %d\n", proc->pid, proc->name, num); 
        proc->tf->eax = -1;
    }
}
