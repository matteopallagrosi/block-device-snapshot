#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/user_namespace.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/rcupdate.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include "lib/include/scth.h"
#include "lib/include/auth.h"

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


#define MAX_PASSWD_SIZE 32

#define MAX_DEV_NAME_SIZE 120

//dev_name può essere un nome di device oppure il path di un file device
typedef struct _device{
	char dev_name[MAX_DEV_NAME_SIZE];
    int name_size;    
    struct _device * next;
} device;

//lista di device per cui è stato attivato il servizio di snapshot
device *head = NULL;
//lock per update della lista di device
spinlock_t queue_lock;

struct kmem_cache *cache;

static struct kprobe kp_mount;

static int mount_pre_hook(struct kprobe *kp, struct pt_regs *regs){
    printk("%s: mount_pre_hook\n", MODNAME);
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _activate_snapshot, char *, dev_name, char *, passwd){
#else
asmlinkage long sys_activate_snapshot(char * dev_name, char * passwd){
#endif

    device *node;
    char buffer[MAX_DEV_NAME_SIZE];
    int ret;

    printk("%s: activate_snapshot\n",MODNAME);

    // Controlla che l'euid sia root (0)
    if (current_euid().val != 0) {
        printk("%s: permission denied, not root\n", MODNAME);
        return -EPERM;
    }

    // Controlla che la password sia corretta
    ret = check_password(passwd);
    if (ret != 0) {
        printk("%s: password check failed\n", MODNAME);
        return -EINVAL;
    }

    //registra dev_name all'interno della lista dei device con snapshot attivo
    node = kmem_cache_alloc(cache, GFP_USER);
    if (node == NULL) return -ENOMEM;

    size_t size = strnlen_user(dev_name, MAX_DEV_NAME_SIZE);
    if (size == 0 || size > MAX_DEV_NAME_SIZE) {
        kmem_cache_free(cache, node);
        printk("%s: device name size is invalid\n", MODNAME);
        return -EINVAL;
    }

    //Non è possibile usare il chunck dal cached allocator custom direttamente nella copy_from_user, quindi si utilizza un buffer intermedio
    ret = copy_from_user((char*)buffer,(char*)dev_name,size);
    // Se copy_from_user fallisce, ossia non copia completamente il nome del device, allora si libera il nodo allocato e si ritorna errore
    if (ret != 0) {
        printk("%s: failed to copy device name from user space\n", MODNAME);
        kmem_cache_free(cache, node);
        return -EFAULT;
    }
    node->name_size = size - ret;

    //Copia dal buffer intermedio nel chunk allocato con cached allocator
	memcpy((char*)node->dev_name,buffer,node->name_size);

    //La coda à globale, quindi è necessario gestire la concorrenza negli accessi in scrittura
    spin_lock(&queue_lock);

    //inserimento in testa -> l'ultimo device registrato è probabile sia il prossimo ad essere montato, quindi velocizza la scansione dalla lista partendo dalla testa
    node->next = head;
    //mefence per rendere gli update immediatamente visibili a tutti
    asm volatile("mfence");
    head = node;
    asm volatile("mfence");
    //I lettori che accedono alla struttura dopo questo update vedono la nuova testa.
	//I lettori che in concorrenza stanno attraversando la lista non hanno problemi con questo inserimento in testa.

    spin_unlock(&queue_lock);

    printk("%s: activated snapshot service for device %s\n",MODNAME,head->dev_name);

    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _deactivate_snapshot, char *, dev_name, char *, passwd){
#else
asmlinkage long sys_deactivate_snapshot(char * dev_name, char * passwd){
#endif

    device *p, *removed = NULL;
    char buffer[MAX_DEV_NAME_SIZE];
    int ret;

    printk("%s: deactivate_snapshot\n",MODNAME);

    // Controlla che l'euid sia root (0)
    if (current_euid().val != 0) {
        printk("%s: permission denied, not root\n", MODNAME);
        return -EPERM;
    }

    // Controlla che la password sia corretta
    ret = check_password(passwd);
    if (ret != 0) {
        printk("%s: password check failed\n", MODNAME);
        return -EINVAL;
    }

    //Copia il nome del device in un buffer del kernel
    size_t size = strnlen_user(dev_name, MAX_DEV_NAME_SIZE);
    if (size == 0 || size > MAX_DEV_NAME_SIZE) {
        printk("%s: device name size is invalid\n", MODNAME);
        return -EINVAL;
    }
    ret = copy_from_user((char*)buffer, (char*)dev_name, size);
    if (ret != 0) {
        printk("%s: failed to copy device name from user space\n", MODNAME);
        return -EFAULT;
    }

    //Il thread viene messo non preemptabile
    spin_lock(&queue_lock);

    //Recupera il nodo associato a dev_name dalla lista
    p = head;

	if(p != NULL && strcmp(p->dev_name, buffer) == 0){
        removed = p;
		head = removed->next;
		asm volatile("mfence");
    }
    else{
	    while(p != NULL){
			if ( p->next != NULL && strcmp(p->next->dev_name, buffer) == 0) {
				removed = p->next;
				p->next = p->next->next;
				asm volatile("mfence");
				break;
			}	
			p = p->next;	
		}
	}

    if (removed == NULL) {
        spin_unlock(&queue_lock);
        printk("%s: device %s not found in snapshot service list\n", MODNAME, buffer);
        return -ENOENT;
    }

    //Il thread è rimesso preemptabile
    spin_unlock(&queue_lock);

    //Attende che eventuali standing readers abbiano completato la lettura
    synchronize_rcu();

    //Rimuove il nodo in modo safe rispetto alla concorrenza
    kmem_cache_free(cache, removed);

    printk("%s: deactivated snapshot service for device %s\n",MODNAME, buffer);

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

    if (the_syscall_table == 0x0){
        printk("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
        return -1;
    }

    AUDIT{
        printk("%s: received sys_call_table address %px\n",MODNAME,(void*)the_syscall_table);
        printk("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);
    }

    cache = kmem_cache_create ("snapshot-service", sizeof(device), 0, SLAB_POISON, NULL);
    if (cache == NULL){
            printk("%s: could not setup the service memcache\n",MODNAME);
            return -ENOMEM;
    }


    kp_mount.symbol_name = "mount_bdev";
    kp_mount.pre_handler = (kprobe_pre_handler_t)mount_pre_hook;
    ret = register_kprobe(&kp_mount);
    if (ret < 0) {
		printk("%s: hook init failed, returned %d\n", MODNAME, ret);
        kmem_cache_destroy(cache);
		return ret;
	}

    spin_lock_init(&queue_lock);

    new_sys_call_array[0] = (unsigned long)sys_activate_snapshot;
    new_sys_call_array[1] = (unsigned long)sys_deactivate_snapshot;

    ret = get_entries(restore,HACKED_ENTRIES,(unsigned long)the_syscall_table,&the_ni_syscall);

    if (ret != HACKED_ENTRIES) {
        printk("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret);
        kmem_cache_destroy(cache);
        unregister_kprobe(&kp_mount);
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

    //TODO: rimuovere  tutti i nodi della lista dei device prima di distruggere la memcache
    kmem_cache_destroy(cache);
    printk("%s: memcache destroyed\n",MODNAME);

    unregister_kprobe(&kp_mount);
    printk("%s: mount kprobe unregistered\n",MODNAME);
}