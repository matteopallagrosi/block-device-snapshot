/*
* loop.h - Loop device header file
* Dalla versione 5.16 (inclusa) la struttura loop_device non è più presente all'interno di un header file,
* ma è definita localmente all'interno del file /drivers/block/loop.c.
* Al fine di potere utilizzare tale struttura per recuperare dal nome di un loop device il path del file associato,
* struct loop_device è stata copiata all'interno di questo header file, per versioni del kernel >= 6.3.0.
* Dalla versione 6.14.0 la struttura è stata leggermente modificata.
*/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
#include <linux/blkpg.h>
#include <linux/init.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/suspend.h>
#include <linux/freezer.h>
#include <linux/mutex.h>
#include <linux/writeback.h>
#include <linux/completion.h>
#include <linux/highmem.h>
#include <linux/splice.h>
#include <linux/sysfs.h>
#include <linux/miscdevice.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/ioprio.h>
#include <linux/blk-cgroup.h>
#include <linux/sched/mm.h>
#include <linux/statfs.h>
#include <linux/uaccess.h>
#include <linux/blk-mq.h>
#include <linux/spinlock.h>
#include <uapi/linux/loop.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0)
struct loop_device {
	int		lo_number;
	loff_t		lo_offset;
	loff_t		lo_sizelimit;
	int		lo_flags;
	char		lo_file_name[LO_NAME_SIZE];

	struct file	*lo_backing_file;
	unsigned int	lo_min_dio_size;
	struct block_device *lo_device;

	gfp_t		old_gfp_mask;

	spinlock_t		lo_lock;
	int			lo_state;
	spinlock_t              lo_work_lock;
	struct workqueue_struct *workqueue;
	struct work_struct      rootcg_work;
	struct list_head        rootcg_cmd_list;
	struct list_head        idle_worker_list;
	struct rb_root          worker_tree;
	struct timer_list       timer;
	bool			sysfs_inited;

	struct request_queue	*lo_queue;
	struct blk_mq_tag_set	tag_set;
	struct gendisk		*lo_disk;
	struct mutex		lo_mutex;
	bool			idr_visible;
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,14,0)
struct loop_device {
	int		lo_number;
	loff_t		lo_offset;
	loff_t		lo_sizelimit;
	int		lo_flags;
	char		lo_file_name[LO_NAME_SIZE];

	struct file *	lo_backing_file;
	struct block_device *lo_device;

	gfp_t		old_gfp_mask;

	spinlock_t		lo_lock;
	int			lo_state;
	spinlock_t              lo_work_lock;
	struct workqueue_struct *workqueue;
	struct work_struct      rootcg_work;
	struct list_head        rootcg_cmd_list;
	struct list_head        idle_worker_list;
	struct rb_root          worker_tree;
	struct timer_list       timer;
	bool			sysfs_inited;

	struct request_queue	*lo_queue;
	struct blk_mq_tag_set	tag_set;
	struct gendisk		*lo_disk;
	struct mutex		lo_mutex;
	bool			idr_visible;
};
#else
struct loop_device {
	int		lo_number;
	loff_t		lo_offset;
	loff_t		lo_sizelimit;
	int		lo_flags;
	char		lo_file_name[LO_NAME_SIZE];

	struct file *	lo_backing_file;
	struct block_device *lo_device;

	gfp_t		old_gfp_mask;

	spinlock_t		lo_lock;
	int			lo_state;
	spinlock_t              lo_work_lock;
	struct workqueue_struct *workqueue;
	struct work_struct      rootcg_work;
	struct list_head        rootcg_cmd_list;
	struct list_head        idle_worker_list;
	struct rb_root          worker_tree;
	struct timer_list       timer;
	bool			use_dio;
	bool			sysfs_inited;

	struct request_queue	*lo_queue;
	struct blk_mq_tag_set	tag_set;
	struct gendisk		*lo_disk;
	struct mutex		lo_mutex;
	bool			idr_visible;
};
#endif