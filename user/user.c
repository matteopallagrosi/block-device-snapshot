#include <stdlib.h>
#include <unistd.h>

#define SYSCALL1 156 //Put here the syscall number returned by the kernel when loading the syscall_table_discoverer module
#define SYSCALL2 174

int main(int argc, char** argv){
       
    //Test syscall 1
    syscall(SYSCALL1, "device_1", "test");
    
    //Test syscall 2
    syscall(SYSCALL2, "device_1", "test");
	return 0;
}
