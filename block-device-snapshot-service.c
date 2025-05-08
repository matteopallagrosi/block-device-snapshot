#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Pallagrosi");
MODULE_DESCRIPTION("block device snapshot service");

#define MODNAME "BLOCK DEVICE SNAPSHOT SERVICE"

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;


unsigned long new_sys_call_array[] = {0x0,0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _activate_snapshot, char *, dev_name, char *, passwd){
#else
asmlinkage long sys_activate_snapshot(char * dev_name, char * passwd){
#endif
//TODO: implement the activate snapshot syscall
printk("%s: activate_snapshot",MODNAME);
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _deactivate_snapshot, char *, dev_name, char *, passwd){
#else
asmlinkage long sys_deactivate_snapshot(char * dev_name, char * passwd){
#endif
//TODO: implement the deactivate snapshot syscall
printk("%s: deactivate_snapshot",MODNAME);
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_activate_snapshot = (unsigned long) __x64_sys_activate_snapshot;
long sys_deactivate_snapshot = (unsigned long) __x64_sys_deactivate_snapshot;
#else
#endif


//Inizializzazione del modulo
int init_module(void) {

    int i;
    int ret;

    if (the_syscall_table == 0x0){
        printk("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
        return -1;
    }

    AUDIT{
        printk("%s: received sys_call_table address %px\n",MODNAME,(void*)the_syscall_table);
        printk("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);
    }

    new_sys_call_array[0] = (unsigned long)sys_activate_snapshot;
    new_sys_call_array[1] = (unsigned long)sys_deactivate_snapshot;

    ret = get_entries(restore,HACKED_ENTRIES,(unsigned long)the_syscall_table,&the_ni_syscall);

    if (ret != HACKED_ENTRIES) {
        printk("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret); 
        return -1;      
    }

    unprotect_memory();

    for(i=0;i<HACKED_ENTRIES;i++){
        ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
    }

    protect_memory();

    printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

    return 0;

    }



//Rimozione del modulo
void cleanup_module(void) {

    int i;
            
    printk("%s: shutting down\n",MODNAME);

    unprotect_memory();
    for(i=0;i<HACKED_ENTRIES;i++){
        ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
    }
    protect_memory();
    printk("%s: sys-call table restored to its original content\n",MODNAME);
    
}