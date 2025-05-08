#include <stdlib.h>

#define SYSCALL1 174 //Put here the syscall number returned by the kernel when loading the syscall_table_discoverer module
#define SYSCALL2 177

int main(int argc, char** argv){
       
    //Test syscall 1
    syscall(SYSCALL1, "device_1", "password_1");
    
    //Test syscall 2
    syscall(SYSCALL2, "device_2", "password_2");	
	return 0;
}
