#define T_TRACE 1
#define T_ONFORK 2
#define T_UNTRACE 0
#define N 5

extern char dumpBuff[N][100];
extern int headIndex;
extern int* headptr;
extern int tailIndex;
extern int* tailptr;