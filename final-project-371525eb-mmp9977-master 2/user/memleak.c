#include "kernel/types.h"
#include "kernel/stat.h"
#include "user.h"
#include "kernel/trace.h"

int main() {
    trace(T_TRACE);
    int *data;
    int data_size = sizeof(int) * 10000000;

    while(1) {
        data = malloc(data_size);
        if(data == 0) break;
    }
    exit();
}