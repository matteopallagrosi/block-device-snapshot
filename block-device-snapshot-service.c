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
#include <linux/blkdev.h>
#include <linux/dcache.h>
#include "lib/include/scth.h"
#include "lib/include/auth.h"
#include "lib/include/loop.h"

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

#define setup_target_func "run_on_cpu"

DEFINE_PER_CPU(unsigned long, BRUTE_START);
DEFINE_PER_CPU(unsigned long *, kprobe_context_pointer);

//number of CPUs that succesfully found the address of the per-CPU variable (current_krpobe) that keeps the reference to the current kprobe context
unsigned long successful_search_counter = 0;

//offset of the per-CPU variable that keeps the reference to the current kprobe context
unsigned long* reference_offset = 0x0;

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

static struct kretprobe setup_probe; //probe per gestione variabili per-cpu
static struct kretprobe *the_retprobe = &setup_probe; 
static struct kprobe kp_mount;

///Funzione di cui viene richiesta l'esecuzione alle altre cpu con smp_call_fuction() -> IPI
void run_on_cpu(void* x) {//this is here just to enable a kprobe on it 
	printk("%s: running on CPU %d\n", MODNAME, smp_processor_id());
	return;
}

//Quando installo il modulo, nella init lancia con smp_call_function su ogni cpu la run_on_cpu, che al momento della return provoca l'esecuzione dell'hook the_search
static int the_search(struct kretprobe_instance *ri, struct pt_regs *the_regs) { 

	unsigned long* temp = (unsigned long)&BRUTE_START;

	printk("%s: running the brute force search on CPU %d\n", MODNAME, smp_processor_id());

	while (temp > 0) {
        //brute force search of the current_kprobe per-CPU variable
		//for enabling blocking execution of the kretprobe
		//you can save this time setting up a per CPU-variable via 
		//smp_call_function() upon module startup
        temp -= 1; 
        #ifndef CONFIG_KRETPROBE_ON_RETHOOK
        if ((unsigned long) __this_cpu_read(*temp) == (unsigned long) &ri->rp->kp) {
        #else
        if ((unsigned long) __this_cpu_read(*temp) == (unsigned long) &the_retprobe->kp) {
        #endif
		    atomic_inc((atomic_t*)&successful_search_counter);//mention we have found the target 
		    printk("%s: found the target per-cpu variable (CPU %d) - offset is %p\n", MODNAME, smp_processor_id(),temp);
		    reference_offset = temp;//this assignment is done by multiple threads with no problem (perchè la struttura della per-cpu memory è la stessa per tutte le cpu, quindi tutte scrivono lo stesso offset qui)
            break;
        }
	    if(temp <= 0) return 1;
    }

	//Su ogni cpu viene scritta una nuova variabile per cpu che mantiene per quella cpu il riferimento al contesto di krpobing (ossia l'indirizzo della variabile per-cpu current_kprobe)
	__this_cpu_write(kprobe_context_pointer, temp);

	return 0;
}

static int mount_pre_hook(struct kprobe *kp, struct pt_regs *regs){

    unsigned long* kprobe_cpu;
    struct block_device *bdev;
    device *p;
    struct loop_device *lo;
    struct file *backing_file;
    struct path file_path;
    char *file_buff, *file_name;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
    struct bdev_handle *handle;
    #endif
    
    char *dev_name = (char *)regs->dx; // dx contiene il terzo argomento della syscall mount, ossia il nome del device

    printk("%s: mount called on block device %s\n", MODNAME, dev_name);

    //Verifica se il device è un file device (ossia se il nome inizia con /dev/loop)
    //In tal caso deve recuperare il nome del file associato al device
    if (strncmp(dev_name, "/dev/loop", 9) == 0) {

        //Annulla il contesto corrente di probing
        kprobe_cpu = __this_cpu_read(kprobe_context_pointer);
        __this_cpu_write(*kprobe_cpu, NULL);
        preempt_enable();

        //Apre il block device tramite il nome. Può essere bloccante (TODO: gestire preemption sistema probing)
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
        backing_file = bdev_file_open_by_path(dev_name, BLK_OPEN_READ, NULL, NULL);
        if (IS_ERR(backing_file)) {
            printk("%s: Failed to open block device with error %ld\n", MODNAME, PTR_ERR(backing_file));
            return -1;
        }
        #elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
        handle = bdev_open_by_path(dev_name, BLK_OPEN_READ, NULL, NULL);
        if (IS_ERR(handle)) {
            printk("%s: Failed to open block device with error %ld\n", MODNAME, PTR_ERR(handle));
            return -1;
        }
        bdev = handle -> bdev;
        #elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
        bdev = blkdev_get_by_path(dev_name, FMODE_READ, NULL, NULL);
        if (IS_ERR(bdev)) {
            printk("%s: Failed to open block device with error %ld\n", MODNAME, PTR_ERR(bdev));
            return -1;
        }
        #else 
        bdev = blkdev_get_by_path(dev_name, FMODE_READ, NULL);
        if (IS_ERR(bdev)) {
            printk("%s: Failed to open block device with error %ld\n", MODNAME, PTR_ERR(bdev));
            return -1;
        }
        #endif    

        preempt_disable();
        //Recupera l'indirizzo della variabile per-cpu con il contesto di probing
 	    kprobe_cpu = __this_cpu_read(kprobe_context_pointer);
        //Ripristina il contesto di probing
        __this_cpu_write(*kprobe_cpu, kp);
        
        #if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
        //Recupera i private data del block device
        lo = (struct loop_device *)bdev->bd_disk->private_data;

        //Recupera la sessione verso il file associato al device
        backing_file = lo->lo_backing_file;
        #endif
        if (!backing_file) {
            printk("%s: No backing file attached to loop device %s\n", MODNAME, dev_name);
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
            bdev_release(backing_file);
            #elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
            bdev_release(handle);
            #else
            blkdev_put(bdev, FMODE_READ);
            #endif
            return -1;
        }

        //Recupera il path del file associato al device
        file_path = backing_file->f_path;
        path_get(&file_path); //Incrementa il reference counter del path

        //L'allocazione di memoria non può essere bloccante con GFP_ATOMIC
        file_buff = kmalloc(PATH_MAX, GFP_ATOMIC);
        if (!file_buff) {
            path_put(&file_path);
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
            bdev_release(backing_file);
            #elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
            bdev_release(handle);
            #else
            blkdev_put(bdev, FMODE_READ);
            #endif
            return -1;
        }

        //Rrecupera il path name del file associato al device
        //Dalla documentazione -> Note: Callers should use the returned pointer, not the passed
        //in buffer, to use the name! The implementation often starts at an offset
        //into the buffer, and may leave 0 bytes at the start.
        file_name = d_path(&file_path, file_buff, PATH_MAX);

        printk("%s: loop device %s is associated with file %s\n", MODNAME, dev_name, file_name);
        dev_name = file_name; //Aggiorna dev_name con il nome del file associato al device
        kfree(file_buff);
        path_put(&file_path);
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
        bdev_release(backing_file);
        #elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
        bdev_release(handle);
        #else
        blkdev_put(bdev, FMODE_READ);
        #endif
    }

    //Controlla se il device è nella lista dei device con snapshot attivo
    p = head;
    while (p != NULL) {
        if (strncmp(p->dev_name, dev_name, p->name_size) == 0) {
            printk("%s: (file-)device %s has snapshot service active\n", MODNAME, dev_name);
            //Se il device è nella lista, allora non è possibile montarlo
            return 0; // Permesso negato
        }
        p = p->next;
    }

    printk("%s: device %s has snapshot service not active\n", MODNAME, dev_name);
    
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

    setup_probe.kp.symbol_name = setup_target_func;
	setup_probe.handler = NULL;
	setup_probe.entry_handler = (kretprobe_handler_t)the_search;
	setup_probe.maxactive = -1;
    ret = register_kretprobe(&setup_probe);
	if (ret < 0) {
		printk("%s: hook init failed for the init kprobe setup, returned %d\n", MODNAME, ret);
		return ret;
	}

    smp_call_function(run_on_cpu,NULL,1);

    if(successful_search_counter != (num_online_cpus() - 1)) {
	    printk("%s: read hook load failed - number of setup CPUs is %ld - number of remote online CPUs is %d\n", MODNAME, successful_search_counter, num_online_cpus() - 1);
		put_cpu();
	 	unregister_kretprobe(&setup_probe);
        unregister_kprobe(&kp_mount);
        kmem_cache_destroy(cache);
		return -1;
	}

    if (reference_offset == 0x0){
		printk("%s: inconsistent value found for refeence offset\n", MODNAME);
		put_cpu();
	 	unregister_kretprobe(&setup_probe);
        unregister_kprobe(&kp_mount);
        kmem_cache_destroy(cache);
		return -1;
	}

    //La cpu corrente su cui sta eseguendo la init è l'unica non colpita dall'IPI, quindi questo thread setta la varibaile per-cpu prendendo l'offset impostato da una qualunque altra cpu.
	//Questo perchè l'offset nella per-cpu memory a cui si trova la variabile current_kprobe è sempre lo stesso.
	__this_cpu_write(kprobe_context_pointer, reference_offset);

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