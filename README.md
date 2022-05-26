# Strace
Built strace for xv6 
Command: strace on
We used flags for tracing in the shell and added a trace value to our proc struct. If the shell detected the string “strace on” in the buffer, then it would set the tracing flag to one. We used a trace system call (sys_trace) to set the trace value in the proc to 1. If tracing was set to 1 in shell, then in runcmd we use the trace system call to set the global variable T_TRACE (in trace.h) to 1, and to set a forked process trace to 1 as well. Then in syscall.c we have the syscall function check to see if proc->trace =1, and if it is then we print out the system call events. We first split the system call events into three categories: SYS_exit, SYS_exec, and all other system calls. The first two system calls don’t have a return value, so we need to take care of their events separately than the rest. We use the information from the proc to print out the events (ie num = proc->tf->eax to get the return value, system call).



Command: strace off
Here we used the same concepts as strace on, however, we have added the global variable T_UNTRACE to set the proc->trace back to zero and strace would stop. Here, the shell checks to see if the buffer contains the string “strace off” and then it sets the tracing variable to zero. Then, in runcmd the if(tracing) won’t occur and so the trace system call will set the proc->trace to zero. The if condition inside trace uses the fact that the shell will not send an int value to trace.


Command: strace run
Here, we use very similar concepts to both strace on and strace off except here we are setting tracing to 1 and 0 in the same instance. Therefore, the tracing will only occur for the command on the same line. The shell first checks to see if “strace run” is in the buf, and then it sets tracing to one. We also created another flag called straceRunCalled to check for strace run being called. This way, we fork the process and check to make sure that we are in the child process. If we are, we runcmd for buf+11 (the actual command to trace after “strace run”) and this will have a tracing value of 1. Else, if we are still in the parent, then we wait for the child process to finish. We then check to see if straceRunCalled is 1 and set tracing to zero to make sure that the next command lines aren’t traced. We also reset the straceRunCalled flag to zero.


Command: strace dump
To implement dump, we used a circular buffer declared as a global double char array in trace.h. The circular buffer is of size N (which is a global defined variable that is hard coded and can be changed). The buffer will fill up and use global pointers to keep track of where the head is relative to the tail. The head is always added by 1 and modded by N so that we can keep track of where in the buffer we are. If we pass tail, then the string inside the tail pointer is deleted and tail is added by 1 mod N. We then fill in the new empty space with the new event and increase head by 1 and continue like this. We used a dumping flag which is set if the shell sees that “strace dump” is in the buf. Then it saids the variable dumping to 1 and proceeds to call the dump command which is implemented as a user file (we did this to help us with the -o flag but unfortunately we didn’t have time to finish that flag). It then proceeds to act very similarly to strace run by forking the process and waiting and then resetting the flags etc. We have the user file call the dump system call which prints out the circular buffer. 
**For our purposes, please do not call dump while also in strace on.

** For when N=5

Trace a Child Process
We created the test program, straceTest.c, to test whether our strace accurately traced forked processes by calling fork() three times and calling trace on them. From the output below, we can see that our strace clearly works because we can see the three different pid values and three different fork syscalls.


Extra Credit: Formatting more Readable Output
We created a more readable output by suppressing the command output and leaving only the strace output when strace is on. We did this by editing the writei() method in fs.c to only write when tracing was set to off. If we could still see the command output, line 3 would have an ‘h’ before the trace line, line 4 would have an ‘i’ before the trace line, and line 5 would be a newline followed by the last 2 trace lines.


3. Building option for strace
Option: -e <system call name>
We created system calls for each of the flags that allow us to set an integer value in the userspace and retrieve it in the kernel to see which flag was set. For the -e flag, we set an integer value from 0 to 22 in the userspace that represented which command the user wanted outputted and used that value in the kernel to only output the corresponding system call.


Option: -s
The system call for the -s flag sets an integer to 0 if the flag isn’t called and 1 if the flag is called. In syscall.c, depending on whether the flag is set or not and on the return value that we retrieve using proc->tf->eax, we print the appropriate trace lines. The first screenshot below shows all the trace lines of echo hi because they all succeed. The second screenshot only excludes the trace line for exec because it returns a -1 and keeps all the other trace lines that output the exec failed message and exit.




Option: -f
The system call for the -f flag works the same way as the system call for the -s flag, however, we only output when the return value is -1. The output for echo hi is nothing because none of the system calls fail but the output for the random letters is the trace line for exec because it fails.


Extra Credit: Combine Options
strace -s -e <system call name>
We combined the flags by calling the appropriate system calls in the userspace to set both flags and using if else statements in syscall.c to print the appropriate results.

strace -f -e <system call name>


4.  Write output of strace to file
We were unable to finish this part of strace :( . We were planning on using the shell to redirect the output and use filewrite in kernel (in the dump system call) to output the events from the dumpbuffer to the file specified by the user. 

5. Application of strace
We created the test program, memleak.c, that creates a memory leak by using a while loop to repeatedly allocate memory using malloc and never freeing the allocated memory. After enough iterations, the program crashes because we’re out of memory. After using strace on our program, we get the output shown below. Strace shows us the sbrk syscalls that are made every time we dynamically allocate more memory in our while loop. Sbrk returns the prior value of the program break and because we keep allocating more memory, the return value keeps increasing. When sbrk fails because we’re out of memory, it returns a -1 and exits. We wrote the same program in Linux in the memleak2.c file. We run strace on this file by typing ‘strace ./memleak2 &> memleakfile.txt’ into the command line and redirecting the output to a different file to easily see all the strace lines. The screenshot below shows the last few lines of the strace text file and we can see that mmap is called every time we dynamically allocate memory in our while loop until it’s killed by SIGKILL for running out of memory. Both our strace and linux’s strace clearly show us that we have a memory leak, however, linux’s system call is superior because it displays more information like the address where the memory mapping was placed and therefore, the exact memory address where we run out of memory.
