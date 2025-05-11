#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/user_namespace.h>
#include "lib/include/scth.h"

#define AUDIT if(1)

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
printk("%s: activate_snapshot\n",MODNAME);
return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _deactivate_snapshot, char *, dev_name, char *, passwd){
#else
asmlinkage long sys_deactivate_snapshot(char * dev_name, char * passwd){
#endif
//TODO: implement the deactivate snapshot syscall
printk("%s: deactivate_snapshot\n",MODNAME);
return 0;
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
    struct path root_path;
    struct dentry *dentry;
    int err;

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

    //Creazione della directory /snapshot nel root filesystem
    //Questa directory sarà utilizzata per memorizzare gli snapshot dei block device
    //kern_path risolve il percorso specificato. Se il percorso è valido e accessibile, riempie il campo struct path *path con mount point e dentry.
    err = kern_path("/", LOOKUP_DIRECTORY, &root_path);
    if (err) {
        printk("%s: cannot retrieve requested root directory\n", MODNAME);
        return err;
    }

    //Verifica se la directory snapshot è gia esistente. Se non esiste crea la dentry con quel nome.
    dentry = lookup_one_len("snapshot", root_path.dentry, strlen("snapshot"));
    if (IS_ERR(dentry)) {
        printk("%s: error in lookup dentry\n", MODNAME);
        return -1;
    }

    // Crea la directory /snapshot se non esiste (crea inode da associare alla dentry).
    if (!dentry->d_inode) {
        #if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
        err = vfs_mkdir(d_inode(root_path.dentry), dentry, S_IFDIR | 0755);
        #elif LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0)
        struct user_namespace *user_ns = root_path.mnt->mnt_sb->s_user_ns;
        err = vfs_mkdir(user_ns, d_inode(root_path.dentry), dentry, S_IFDIR | 0755);
        #else
        struct mnt_idmap = mnt_idmap(root_path.mnt);
        err = vfs_mkdir(idmap, d_inode(root_path.dentry), dentry, S_IFDIR | 0755);
        #endif
        if (err)
            printk("%s: cannot create /snapshot directory (%d)\n", MODNAME, err);
        else
            printk("%s: directory /snapshot succesfully created.\n", MODNAME);
    } else {
        printk("%s: /snapshot already exists.\n", MODNAME);
    }

    dput(dentry);

    return 0;

}



//Rimozione del modulo
void cleanup_module(void) {

    int i, err;
    struct path root_path;
    struct dentry *dentry;

            
    printk("%s: shutting down\n",MODNAME);

    unprotect_memory();
    for(i=0;i<HACKED_ENTRIES;i++){
        ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
    }
    protect_memory();
    printk("%s: sys-call table restored to its original content\n",MODNAME);

    //Recupera mount point e dentry della root directory.
    err = kern_path("/", LOOKUP_DIRECTORY, &root_path);
    if (err) {
        printk("%s: cannot retrieve requested root directory\n", MODNAME);
    }

    //recupera la dentry associata alla directory /snapshot.
    dentry = lookup_one_len("snapshot", root_path.dentry, strlen("snapshot"));
    if (IS_ERR(dentry)) {
        printk("%s: error in lookup dentry\n", MODNAME);
    }


    //Rimuove la directory se esiste.
    if (dentry->d_inode) {
        #if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
        err = vfs_rmdir(d_inode(root_path.dentry), dentry);
        #elif LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0)
        struct user_namespace *user_ns = root_path.mnt->mnt_sb->s_user_ns;
        err = vfs_rmdir(user_ns, d_inode(root_path.dentry), dentry);
        #else
        struct mnt_idmap = mnt_idmap(root_path.mnt);
        err = vfs_rmdir(idmap, d_inode(root_path.dentry), dentry);
        #endif
        if (err)
            printk("%s: cannot remove /snapshot directory (%d)\n", MODNAME, err);
        else
            printk("%s: directory /snapshot succesfully removed.\n", MODNAME);
    } else {
        printk("%s: /snapshot does not exist.\n", MODNAME);
    }

    dput(dentry);

}