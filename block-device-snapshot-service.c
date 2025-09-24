#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <uapi/linux/mount.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/user_namespace.h>
#include <linux/mnt_idmapping.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/rcupdate.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/dcache.h>
#include <linux/time.h>
#include <linux/kdev_t.h>
#include <linux/hashtable.h>
#include <linux/buffer_head.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
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

#define MAX_BLOCKS 100 //Questo numero coincide con il numero massimo di blocchi previsti per il singlefilefs

#define SNAPSHOT_HASH_BITS 6  // 2^6 = 64 bucket

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
static struct kprobe kp_kill_sb;
static struct kprobe kp_write;
static struct kretprobe bread_probe;


#ifdef CONFIG_THREAD_INFO_IN_TASK
int offset = sizeof(struct thread_info);
#else
int offset = 0;
#endif

#define store_address(addr) *(unsigned long*)((void*)current->stack + offset) = addr
#define load_address(addr) addr = (*(unsigned long*)((void*)current->stack + offset))

typedef struct _snapshot_context {
    struct mutex lock;      //lock per l'accesso in scrittura ai file di snapshot
    struct file *data;
    struct file *index;
} snapshot_context;

typedef struct _snapshot_info {
    int active;                       //flag per indicare se lo snapshot è attivo
    char *name_dir;                   //nome della directory in cui salvare lo snapshot
    bool block_updated[MAX_BLOCKS];   //bitmask che tiene traccia dei blocchi updated almeno una volta
    snapshot_context *ctx;            //contesto per l'accesso in scrittura ai file di snapshot

} snapshot_info;

// Entry per la hash table degli snapshot attivi
struct snapshot_entry {
    dev_t dev;              // chiave
    snapshot_info *info;    // valore
    struct hlist_node node;
};

DEFINE_HASHTABLE(snapshot_table, SNAPSHOT_HASH_BITS);

struct packed_work {
    char *data;                     // copia del contenuto del blocco
    size_t size;
    sector_t block_nr;        
    char name_dir[PATH_MAX];
    snapshot_context *ctx;
    struct work_struct the_work;
};

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

//Crea un nome per la subdirectory dello snapshot a partire dal path del device e dal timestamp corrente
//La subdirectory avrà il nome <path>_YYYYMMDD_HHMMSS, con timestamp relativo al Coordinated Universal Time (UTC).
char *create_name_dir_from_path(char *path, struct timespec64 timestamp) {

    struct tm time;
    char *name, *p;
    int ret;

    //Allocazionde di memoria non bloccante
    name = kmalloc(strlen(path) + 17, GFP_ATOMIC);
    if (!name)
        return NULL;

    //Sostituisce i caratteri '/' con '_' nel path per creare un nome valido per la directory (gli "/"" infatti verrebbero interpretati come sottodirectory)
    p = name;
    while (*path) {
        if (*path == '/')
            *p = '_';
        else
            *p = *path;
        path++;
        p++;
    }

    //Converte il timestamp (tempo trascorso dal 1970) in un formato YYMMDD_HHMMSS
    time64_to_tm(timestamp.tv_sec, 0, &time);

    //Costruisce la stringa: <path>_YYYYMMDD_HHMMSS
    ret = snprintf(p, 17, "_%04ld%02d%02d_%02d%02d%02d",
        time.tm_year + 1900,
        time.tm_mon + 1,
        time.tm_mday,
        time.tm_hour,
        time.tm_min,
        time.tm_sec);
    if (ret !=  16) {
        kfree(name);
        return NULL;
    }

    return name;
}

//Creazione di una subdirectory dentro a /snapshot, utilizzata per memorizzare gli snapshot di un device
int create_directory(char *name_dir) {
    
    struct path parent_path;
    struct dentry *dentry;
    int err;

    //kern_path risolve il percorso specificato. Se il percorso è valido e accessibile, riempie il campo struct path *path con mount point e dentry.
    err = kern_path("/snapshot", LOOKUP_DIRECTORY, &parent_path);
    if (err) {
        printk("%s: cannot retrieve requested directory\n", MODNAME);
        return err;
    }

    //Verifica se la directory snapshot è gia esistente. Se non esiste crea la dentry con quel nome.
    dentry = lookup_one_len(name_dir, parent_path.dentry, strlen(name_dir));
    if (IS_ERR(dentry)) {
        printk("%s: error in lookup dentry %s with error %ld\n", MODNAME, name_dir, PTR_ERR(dentry));
        path_put(&parent_path);
        return -1;
    }

    /*err = vfs_path_lookup(parent_path.dentry, parent_path.mnt, name_dir, LOOKUP_DIRECTORY, &dir_path);
    if (err < 0) {
        printk("%s: error in lookup dentry (%d)\n", MODNAME, err);
        return err;
    }*/

    // Crea la subdirectory se non esiste (crea inode da associare alla dentry).
    if (!dentry->d_inode) {
        err = vfs_mkdir(&nop_mnt_idmap, d_inode(parent_path.dentry), dentry, S_IFDIR | 0755);
        if (err) {
            printk("%s: cannot create directory (%d)\n", MODNAME, err);
            dput(dentry);
            path_put(&parent_path);
        }
        else
            printk("%s: directory %s succesfully created.\n", MODNAME, name_dir);
    } else {
        printk("%s: %s already exists.\n", MODNAME, name_dir);
    }

    dput(dentry);
    path_put(&parent_path);

    return 0;
}

static int mount_pre_hook(struct kprobe *kp, struct pt_regs *regs){

    unsigned long* kprobe_cpu;
    struct block_device *bdev;
    dev_t dev;
    device *p;
    struct loop_device *lo;
    struct file *backing_file;
    struct path file_path;
    char *file_buff, *file_name;
    struct timespec64 ts;
    char *name_dir;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
    struct bdev_handle *handle;
    #endif

    //Recupera il timestamp corrente
    ktime_get_real_ts64(&ts);
    
    char *dev_name = (char *)regs->dx; // dx contiene il terzo argomento della mount_bdev, ossia il nome del device

    printk("%s: mount called on block device %s\n", MODNAME, dev_name);

    //Allocazionde di memoria non bloccante
    snapshot_info *info = kzalloc(sizeof(snapshot_info), GFP_ATOMIC);
    if (!info) {
        return -ENOMEM;
    }

    struct snapshot_entry *entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        return -ENOMEM;
    }

    entry->info = info;

    //Verifica se il device è un file device (ossia se il nome inizia con /dev/loop)
    //In tal caso deve recuperare il nome del file associato al device
    if (strncmp(dev_name, "/dev/loop", 9) == 0) {

        //Annulla il contesto corrente di probing
        kprobe_cpu = __this_cpu_read(kprobe_context_pointer);
        __this_cpu_write(*kprobe_cpu, NULL);
        preempt_enable();

        //Apre il block device tramite il nome. Può essere bloccante
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

        //Recupera il dev_t del block device
        dev = bdev->bd_dev;

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

        //Recupera il path name del file associato al device
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

    //Se il filesystem è montato in sola lettura non è necessario realizzare gli snapshot
    int flags = regs->si; //si contiene il secondo argomento della mount_bdev, ossia i flags
    if (flags & MS_RDONLY) {
        goto not_active;
    }

    //Controlla se il device è nella lista dei device con snapshot attivo (gestisce lettura della lista con rcu)
    rcu_read_lock();
    p = head;
    while (p != NULL) {
        if (strncmp(p->dev_name, dev_name, p->name_size) == 0) {
            printk("%s: (file-)device %s has snapshot service active\n", MODNAME, dev_name);
            rcu_read_unlock();
            name_dir = create_name_dir_from_path(dev_name, ts);
            if (!name_dir) {
                printk("%s: failed to create snapshot directory name for device %s\n", MODNAME, dev_name);
                return -ENOMEM;
            }
            //Crea la directory per lo snapshot di questo device
            if (create_directory(name_dir) < 0) {
                return -1;
            }
            info->active = 1; //Segna lo snapshot come attivo
            info->name_dir = name_dir;

            snapshot_context *ctx = kzalloc(sizeof(snapshot_context), GFP_ATOMIC);
            if (!ctx) {
                return -ENOMEM;
            }
            mutex_init(&ctx->lock);

            info->ctx = ctx;

            //Inserisce le info sullo snapshot nella hash table
            entry->dev = dev;
            hash_add(snapshot_table, &entry->node, dev);
            return 0;
        }

        p = p->next;
    }

    rcu_read_unlock();

not_active:
    printk("%s: (file-)device %s has snapshot service not active\n", MODNAME, dev_name);
    info->active = 0;
    entry->dev = dev;
    hash_add(snapshot_table, &entry->node, dev);

    return 0;
}

static int kill_sb_pre_hook(struct kprobe *kp, struct pt_regs *regs){
    
    struct super_block *sb;
    dev_t dev;

    printk("%s: kill_sb_pre_hook activated\n", MODNAME);

    sb = (struct super_block *)regs->di;

    dev = sb->s_bdev->bd_dev;

    //Libera la memoria allocata per lo snapshot_info
    struct snapshot_entry *entry;
    hash_for_each_possible(snapshot_table, entry, node, dev) {
        if (entry->dev == dev) {
            //Se non è stata realizzata alcuna modifica sul filesystem montato rimuove la sottodirectory per lo snapshot
            if (entry->info->active) {
                int remove_dir = 1;
                for (int i = 0; i < MAX_BLOCKS; i++) {
                    if (entry->info->block_updated[i]) {
                        remove_dir = 0;
                        break;
                    }
                }

                if (remove_dir) {
                    char *fullpath = kmalloc(PATH_MAX, GFP_KERNEL);
                    if (!fullpath) {
                        printk("%s: cannot allocate memory while removing snapshot directory\n", MODNAME);
                        return -ENOMEM;
                    }
                    
                    snprintf(fullpath, PATH_MAX, "/snapshot/%s", entry->info->name_dir);

                    struct path path;
                    int err = kern_path(fullpath, LOOKUP_FOLLOW, &path);
                    if (err) {
                        printk("%s: unable to remove snapshot dir %s (err=%d)\n", MODNAME, fullpath, err);
                        kfree(fullpath);
                        return err;
                    }

                    struct dentry *dentry = path.dentry;
                    struct inode *dir = d_inode(dentry->d_parent);

                    inode_lock(dir);
                    err = vfs_rmdir(&nop_mnt_idmap, dir, dentry);
                    inode_unlock(dir);
                    path_put(&path);
                    if (err) {
                        printk("%s: unable to remove snapshot dir %s (err=%d)\n", MODNAME, entry->info->name_dir, err);
                    }
                }
            }
 
            if (entry->info->name_dir!=NULL) {
                kfree(entry->info->name_dir); //Libera il nome della directory dello snapshot
            }
            //Rimuove le info di contesto per il salvataggio dei file di snapshot
            if (entry->info->ctx!=NULL) {
                if (entry->info->ctx->index != NULL) {
                    filp_close(entry->info->ctx->index, NULL); //Chiude il file index
                }
                if (entry->info->ctx->data != NULL) {
                    filp_close(entry->info->ctx->data, NULL); //Chiude il file dati
                }
                kfree(entry->info->ctx);
            }
            kfree(entry->info); //Libera la struttura snapshot_info
            hash_del(&entry->node);
            kfree(entry);
            return 0;
        }
    }

    return 0;
}

//Intercetta il buffer_head ritornato dalla __bread_gfp per registrare il contenuto originale
static int bread_return_hook(struct kretprobe_instance *ri, struct pt_regs *the_regs) {

    snapshot_info *info;
    struct snapshot_entry *entry;
    char *original_block;

    struct buffer_head *bh = (struct buffer_head *)regs_return_value(the_regs);
    dev_t dev = bh->b_bdev->bd_dev;
    sector_t block_nr = bh->b_blocknr;

    //TODO: se il file è aperto in sola lettura (o il filesystem è montato in sola lettura) non deve fare nulla

    //TODO: se questa read non è seguita da una write non deve fare nulla (non serve bufferizzare il contenuto originale)

    //Recupera lo snapshot_info per il filesystem montato
    hash_for_each_possible(snapshot_table, entry, node, dev) {
    if (entry->dev == dev)
        info = entry->info;
    }

    //Se è attivo il servizio di snapshot e il blocco non è stato precedentemente updated, registra il contenuto originale qualora venisse successivamente modificato
    if (info != NULL && info->active && !info->block_updated[block_nr]) {
       
        original_block = kzalloc(bh->b_size, GFP_ATOMIC);
        if (!original_block) {
            printk("%s: cannot allocate original block data\n", MODNAME);
            return -ENOMEM;
        }

        // Copia il contenuto del blocco in un buffer
        memcpy(original_block, bh->b_data, bh->b_size);

        store_address(original_block);
    }

    return 0;
}

void snapshot_worker(struct work_struct *the_work)
{
    struct packed_work *work = container_of(the_work, struct packed_work, the_work);
    snapshot_context *ctx = work->ctx;
    loff_t offset;
    int ret;
    char index_entry[128];
    size_t idx_len;

    printk("%s: snapshot_worker: saving block %llu in %s\n",MODNAME, (unsigned long long)work->block_nr, work->name_dir);

    //Acquisisce il lock per l'accesso in scrittura ai file di snapshot per uno specifico filesystem
    mutex_lock(&ctx->lock);

    if (ctx->data == NULL && ctx->index == NULL) {

        char *data_path = kmalloc(PATH_MAX, GFP_ATOMIC);
        char *index_path = kmalloc(PATH_MAX, GFP_ATOMIC);
        if (!data_path || !index_path) {
            printk("%s: error while allocating paths\n", MODNAME);
            goto out_unlock;
        }

        snprintf(index_path, PATH_MAX, "%s/index", work->name_dir);
        snprintf(data_path, PATH_MAX, "%s/data", work->name_dir);

        ctx->index = filp_open(index_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (IS_ERR(ctx->index)) {
            printk("%s: failed to open snapshot index file in %s\n", MODNAME, work->name_dir);
            goto out_unlock;
        }

        ctx->data = filp_open(data_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (IS_ERR(ctx->data)) {
            printk("%s: failed to open snapshot data file in %s\n", MODNAME, work->name_dir);
            filp_close(ctx->index, NULL);
            goto out_unlock;
        }

        kfree(data_path);
        kfree(index_path);
    }

    //Recupera la dimensione attuale del file dati
    offset = vfs_llseek(ctx->data, 0, SEEK_END);

    //Scrive il blocco nel file dati
    ret = kernel_write(ctx->data, work->data, work->size, &ctx->data->f_pos);
    if (ret < 0) {
        printk("%s: write snapshot data failed: %d\n", MODNAME, ret);
        goto out_unlock;
    }

    //Scrive i metadati per gestire lo snapshot del blocco nell’indice
    idx_len = snprintf(index_entry, sizeof(index_entry), "%llu %llu %zu\n", (unsigned long long)work->block_nr, (unsigned long long)offset, work->size);

    ret = kernel_write(ctx->index, index_entry, idx_len, &ctx->index->f_pos);
    if (ret < 0) {
        printk("%s: write snapshot index failed: %d\n", MODNAME, ret);
    }

out_unlock:
    mutex_unlock(&ctx->lock);

    kfree(work->data);
    kfree(work);
}

static int write_pre_hook(struct kprobe *kp, struct pt_regs *regs){

    snapshot_info *info;
    struct snapshot_entry *entry;
    struct buffer_head *bh;
    char *original_block;
    
    printk("%s: write_pre_hook activated\n", MODNAME);

    //Recupera il puntatore al buffer_head, da cui recupera il block number e il block_device, e quindi dev_t (major e minor)
    bh = (struct buffer_head *)regs->di;
    dev_t dev = bh->b_bdev->bd_dev;
    sector_t block_nr = bh->b_blocknr;

    //Recupera lo snapshot_info per il filesystem montato
    hash_for_each_possible(snapshot_table, entry, node, dev) {
        if (entry->dev == dev)
            info = entry->info;
    }

    //Se lo snapshot è attivo, e il blocco non è stato precedentemente updated, lo imposta come updated e realizza lo snapshot (deferred work)
    if (info != NULL && info->active && !__atomic_test_and_set(&info->block_updated[block_nr], __ATOMIC_SEQ_CST)) {
        printk("%s: write operation on device %d:%d tracked by snapshot service on directory %s\n", MODNAME, MAJOR(dev), MINOR(dev), info->name_dir);

        struct packed_work *work;

        work = kzalloc(sizeof(struct packed_work), GFP_ATOMIC);
        if (!work) {
            printk("%s: cannot allocate deferred work\n", MODNAME);
            return -ENOMEM;
        }

        //Recupera il contenuto originale del blocco
        load_address(original_block);

        // Copia il contenuto del blocco nel buffer per il deferred work
        work->size = bh->b_size;
        work->data = original_block;
        work->block_nr = block_nr;

        work->ctx = info->ctx;

        //Copia il nome della directory su cui verrà realizzato lo snapshot in deferred work
        snprintf(work->name_dir, sizeof(work->name_dir), "/snapshot/%s", info->name_dir);

        //Registra il deferred work che realizza lo snapshot del blocco modificato
        INIT_WORK(&work->the_work, snapshot_worker);
        schedule_work(&work->the_work);
    }

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
        goto err_5;
	}

    setup_probe.kp.symbol_name = setup_target_func;
	setup_probe.handler = NULL;
	setup_probe.entry_handler = (kretprobe_handler_t)the_search;
	setup_probe.maxactive = -1;
    ret = register_kretprobe(&setup_probe);
	if (ret < 0) {
		printk("%s: hook init failed for the init kprobe setup, returned %d\n", MODNAME, ret);
        goto err_4;
	}

    kp_kill_sb.symbol_name = "kill_block_super";
    kp_kill_sb.pre_handler = (kprobe_pre_handler_t)kill_sb_pre_hook;
    ret = register_kprobe(&kp_kill_sb);
    if (ret < 0) {
		printk("%s: hook init failed for kill_block_super, returned %d\n", MODNAME, ret);
        goto err_3;
	}

    kp_write.symbol_name = "write_dirty_buffer";
    kp_write.pre_handler = (kprobe_pre_handler_t)write_pre_hook;
    ret = register_kprobe(&kp_write);
    if (ret < 0) {
		printk("%s: hook init failed for vfs_write, returned %d\n", MODNAME, ret);
        goto err_2;
	}

    bread_probe.kp.symbol_name = "__bread_gfp";
	bread_probe.handler = (kretprobe_handler_t)bread_return_hook;
	bread_probe.entry_handler = NULL;
	bread_probe.maxactive = -1;
    ret = register_kretprobe(&bread_probe);
	if (ret < 0) {
		printk("%s: hook init failed for the bread probe, returned %d\n", MODNAME, ret);
        goto err_1;
	}

    smp_call_function(run_on_cpu,NULL,1);

    if(successful_search_counter != (num_online_cpus() - 1)) {
	    printk("%s: read hook load failed - number of setup CPUs is %ld - number of remote online CPUs is %d\n", MODNAME, successful_search_counter, num_online_cpus() - 1);
		put_cpu();
        goto err_0;
	}

    if (reference_offset == 0x0){
		printk("%s: inconsistent value found for reference offset\n", MODNAME);
		put_cpu();
        goto err_0;

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
        goto err_0;    
    }

    unprotect_memory();

    for(i=0;i<HACKED_ENTRIES;i++){
        ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
    }

    protect_memory();

    printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

    return 0;

err_0:
    unregister_kretprobe(&bread_probe);   
err_1:
    unregister_kprobe(&kp_write);
err_2:
    unregister_kprobe(&kp_kill_sb);
err_3:
    unregister_kretprobe(&setup_probe);
err_4:
    unregister_kprobe(&kp_mount);
err_5:
    kmem_cache_destroy(cache);

    return -1;

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

    unregister_kprobe(&kp_mount);
    printk("%s: mount kprobe unregistered\n",MODNAME);

    unregister_kretprobe(&setup_probe);
    printk("%s: setup kprobe unregistered\n",MODNAME);

    unregister_kprobe(&kp_kill_sb);
    printk("%s: kill superblock kprobe unregistered\n",MODNAME);

    unregister_kprobe(&kp_write);
    printk("%s: write kprobe unregistered\n",MODNAME);

    unregister_kretprobe(&bread_probe);
    printk("%s: bread kprobe unregistered\n",MODNAME);

    //Rimuove eventuali nodi ancora presenti nella lista dei device (per mancata invocazione della deactivate_snapshot) prima di distruggere la memcache
    device *p;
    while (head != NULL) {
        p = head;
        head = head->next;
        kmem_cache_free(cache, p);
    }
    kmem_cache_destroy(cache);
    printk("%s: memcache destroyed\n",MODNAME);
}