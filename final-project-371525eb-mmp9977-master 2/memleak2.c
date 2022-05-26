#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

int main() {
    int *data;
    int data_size = sizeof(int) * 10000000;

    while(1){
        data = malloc(data_size);
        if(data == 0) break;
    }
   return 0;
}