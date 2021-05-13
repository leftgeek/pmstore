/*
 * BRIEF DESCRIPTION
 *
 * Definitions for the OBJMS filesystem.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef __OBJMS_H
#define __OBJMS_H

#include <linux/crc16.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/obj.h>
#include <linux/kthread.h>
#include "objms_def.h"
#include "journal.h"
#include "../internal.h"
//adding latency
#include "latency.h"

#define PAGE_SHIFT_2M 21
#define PAGE_SHIFT_1G 30

#define OBJMS_ASSERT(x)                                                 \
	if (!(x)) {                                                     \
		printk(KERN_WARNING "assertion failed %s:%d: %s\n",     \
	               __FILE__, __LINE__, #x);                         \
	}

/*
 * Debug code
 */
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/* #define objms_dbg(s, args...)         pr_debug(s, ## args) */
/*#define objms_dbg(s, args ...)           pr_info(s, ## args)
#define objms_dbg1(s, args ...)
#define objms_err(sb, s, args ...)       objms_error_mng(sb, s, ## args)
#define objms_warn(s, args ...)          pr_warning(s, ## args)
#define objms_info(s, args ...)          pr_info(s, ## args)

extern unsigned int objms_dbgmask;
#define OBJMS_DBGMASK_MMAPHUGE          (0x00000001)
#define OBJMS_DBGMASK_MMAP4K            (0x00000002)
#define OBJMS_DBGMASK_MMAPVERBOSE       (0x00000004)
#define OBJMS_DBGMASK_MMAPVVERBOSE      (0x00000008)
#define OBJMS_DBGMASK_VERBOSE           (0x00000010)
#define OBJMS_DBGMASK_TRANSACTION       (0x00000020)

#define objms_dbg_mmaphuge(s, args ...)		 \
	((objms_dbgmask & OBJMS_DBGMASK_MMAPHUGE) ? objms_dbg(s, args) : 0)
#define objms_dbg_mmap4k(s, args ...)		 \
	((objms_dbgmask & OBJMS_DBGMASK_MMAP4K) ? objms_dbg(s, args) : 0)
#define objms_dbg_mmapv(s, args ...)		 \
	((objms_dbgmask & OBJMS_DBGMASK_MMAPVERBOSE) ? objms_dbg(s, args) : 0)
#define objms_dbg_mmapvv(s, args ...)		 \
	((objms_dbgmask & OBJMS_DBGMASK_MMAPVVERBOSE) ? objms_dbg(s, args) : 0)

#define objms_dbg_verbose(s, args ...)		 \
	((objms_dbgmask & OBJMS_DBGMASK_VERBOSE) ? objms_dbg(s, ##args) : 0)
#define objms_dbg_trans(s, args ...)		 \
	((objms_dbgmask & OBJMS_DBGMASK_TRANSACTION) ? objms_dbg(s, ##args) : 0)
*/
#define objms_set_bit                   __test_and_set_bit_le
#define objms_clear_bit                 __test_and_clear_bit_le
#define objms_find_next_zero_bit                find_next_zero_bit_le

#define clear_opt(o, opt)       (o &= ~OBJMS_MOUNT_ ## opt)
#define set_opt(o, opt)         (o |= OBJMS_MOUNT_ ## opt)
#define test_opt(sbi, opt)       (sbi->s_mount_opt & OBJMS_MOUNT_ ## opt)

#define OBJMS_LARGE_INODE_TABLE_SIZE    (0x200000)
/* OBJMS size threshold for using 2M blocks for inode table */
#define OBJMS_LARGE_INODE_TABLE_THREASHOLD    (0x20000000)
/*
 * objms inode flags
 *
 * OBJMS_EOFBLOCKS_FL	There are blocks allocated beyond eof
 */
#define OBJMS_EOFBLOCKS_FL      0x20000000
//the inode is in use flag
#define OBJMS_INODE_INUSE 0x00000001
//the inode is going to be free
#define OBJMS_INODE_BEFREE 0x00000010
/* Flags that should be inherited by new inodes from their parent. */
#define OBJMS_FL_INHERITED (FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL | \
			    FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL |	\
			    FS_COMPRBLK_FL | FS_NOCOMP_FL | FS_JOURNAL_DATA_FL | \
			    FS_NOTAIL_FL | FS_DIRSYNC_FL)
/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define OBJMS_REG_FLMASK (~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
/* Flags that are appropriate for non-directories/regular files. */
#define OBJMS_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)
#define OBJMS_FL_USER_VISIBLE (FS_FL_USER_VISIBLE | OBJMS_EOFBLOCKS_FL)

#define INODES_PER_BLOCK(bt) (1 << (blk_type_to_shift[bt] - OBJMS_INODE_BITS))
//@ayu: FIXME
#undef OBJMS_ENABLE_MEM_COW

//a 4K block can hold 128 name_entry
struct objms_name_entry{
  unsigned long objno;
  char name[24];
};

struct objms_name_info{
  u32 free_entries_count;
  u32 free_entry_hint;
  u32 end_entry_index;//free entry index
};

struct objms_blocknode_lowhigh {
  __le64 block_low;
  __le64 block_high;
};
               
struct objms_blocknode {
	struct list_head link;
	unsigned long block_low;
	unsigned long block_high;
};

//FIXME: first 12 bits of poff is the count 
//a extent can hold 2^12=4k pages
//meta node entry of the extent tree
struct objms_extent_meta_entry{
  __le64 poff;//physical page offset
  __le64 lpn;//logical page number
};
//leaf node entry of the extent tree
struct objms_extent_leaf_entry{
  __le64 poff;//physical page offset
  __le64 count;//page count
};
//object lock structure
struct olock{
  short l_type;
  pid_t l_pid;
  loff_t l_start;
  loff_t l_len;
	struct list_head l_list;//lock list
};
//in memory structure of struct objms_inode
struct objms_inode_info{
  struct objms_inode *pi;
  unsigned long i_ino;  //upper application communicate via i_ino
  atomic_t i_count;
  struct mutex i_mutex; //protects pi
  //struct mutex i_lock_mutex; //protects i_lock list
  spinlock_t i_lock;  //protects i_state, i_count, i_hash, i_truncated...
  unsigned long i_state;
  struct hlist_node i_hash;
	struct list_head i_truncated;//
#ifdef OBJMS_FINE_LOCK
	struct list_head i_lock_head;//lock list head
#endif
};

/*struct objms_inode_info {
	__u32   i_dir_start_lookup;
	struct list_head i_truncated;
	struct inode	vfs_inode;
};*/

typedef struct{
  int bit_mask;
  objms_transaction_t **current_trans;
	struct task_struct *flusher_thread;
	//struct task_struct *flusher_thread_shadow;
	wait_queue_head_t flusher_wait;
	spinlock_t flusher_queue_lock;//when modifying flusher queue

  //per-CPU block list
	struct list_head free_block_head;
	unsigned long	block_start;
	unsigned long	block_end;
  unsigned long num_free_blocks;
	spinlock_t block_list_lock;
	//struct mutex block_list_lock;
  //free le_info(ole) list
  struct list_head ole_free; //
	spinlock_t ole_list_lock;//
  //reset log entry list
  objms_logentry_t *reset_le_head; //
  objms_logentry_t *reset_le_tail; //
	spinlock_t rle_list_lock;//
  //free log entry list
  objms_logentry_t *free_le_head; //
  objms_logentry_t *free_le_tail; //
	spinlock_t le_list_lock;//free_le_list, num_free_logentries
  uint32_t num_free_logentries;  //free logentries number
  uint32_t num_reset_logentries;

	spinlock_t txn_list_lock;
  struct list_head txn_commit;//to be cleaned txn list
	//spinlock_t ino_list_lock;
	struct mutex ino_list_lock;
  struct list_head free_ino_list;
#ifdef OBJMS_ENABLE_DEBUG
  unsigned long flushed_bytes;
  unsigned long num_txns;
  unsigned long run_cpus[OBJMS_THREADS];
  unsigned long clean_time;
#endif
}objms_flusher_thread_t;

struct objms_sb_info {
	/*
	 * base physical and virtual address of OBJMS (which is also
	 * the pointer to the super block)
	 */
	phys_addr_t	phys_addr;
  void *virt_addr;
	struct list_head free_block_head;//FIXME: remove this
	unsigned long	block_start;
	unsigned long	block_end;
  unsigned long num_free_blocks;//FIXME: remove this
	struct mutex 	s_lock;	/* protects the SB's buffer-head */

  /* Mount options */
	unsigned long	bpi;
  unsigned long num_inodes;
  unsigned char blocksize_bits;//
	unsigned long	blocksize;
	unsigned long	initsize;
	unsigned long	s_mount_opt;
	unsigned long	s_flags;
	kuid_t		uid;    /* Mount uid for root directory */
	kgid_t		gid;    /* Mount gid for root directory */
	umode_t		mode;   /* Mount mode for root directory */
	/* inode tracking */
	struct mutex inode_table_mutex;
  unsigned int s_inodes_count;
  unsigned int s_free_inodes_count;
  unsigned int s_free_inode_hint;
  /*
	 * Backing store option:
	 * 1 = no load, 2 = no store,
	 * else do both
	 */
	unsigned int	objms_backing_option;

  //@ayu: FIXME, DEBUG
#ifdef OBJMS_ENABLE_DEBUG
  unsigned long wasted_les;
  unsigned long commit_time;
  unsigned long total_flushed_bytes;
  unsigned long forward_flushed_bytes;
  unsigned long backward_flushed_bytes;
  unsigned long forward_flushed_entries;
  unsigned long backward_flushed_entries;
  unsigned long wakeup_invalid;
  unsigned long wakeup_success;
  unsigned long wakeup_fail;
  unsigned long flushed_times;
  unsigned long flushing_times;
  unsigned long flushable_times;
  unsigned long run_cpus[OBJMS_THREADS];
  unsigned long obj_wakeup1;
  unsigned long obj_wakeup2;
  unsigned long obj_wakeup3;
#endif
#ifdef OBJMS_CLFLUSH_TIME
  unsigned long flush_success;
  unsigned long flush_fail;
#endif

  unsigned long num_blocknode_allocated;

	/* Journaling related structures */
	void       *journal_base_addr;
	uint32_t    jsize;  
  //uint32_t num_txns;  //running txn number
	atomic_t	num_txns;
  //uint32_t num_free_logentries;  //free logentries number
  int cpus;
  int per_node_blocks;
	//struct mutex txn_mutex;//lock txn_low, txn_high 
	//struct mutex journal_mutex;//free_le_list, num_free_logentries
  struct timer_list jc_timer;//journal cleaner timer
#ifdef OBJMS_LAZY_STOP
  struct timer_list fs_timer;//flusher stop timer
#endif
  struct timer_list bc_timer;//block cleaner timer
  //objms_logentry_t *free_le_head; //
  //objms_logentry_t *free_le_tail; //

	spinlock_t txn_list_lock;
	//spinlock_t txn_commit_list_lock;
  struct list_head txn_running;//running txn list
  //struct list_head txn_commit;//to be cleaned txn list
  //struct list_head txn_free;//free txn list
	struct task_struct *log_cleaner_thread;
	wait_queue_head_t  log_cleaner_wait;
	//struct mutex block_flusher_mutex;
	//struct mutex block_list_mutex;
  //spinlock_t log_flusher_lock;
	//struct mutex block_list_mutex;
  //struct list_head block_commit;//block list to be flushed before commit
  //struct list_head block_clean;//block list to be freed before umount
	//spinlock_t block_list_lock;
  //struct list_head ole_free;//free logentry_info list
	//spinlock_t ole_list_lock;
	//struct task_struct **log_flusher_threads;
	//wait_queue_head_t *log_flusher_waits;
  objms_flusher_thread_t *log_flusher_threads;
	bool redo_log;

	/* truncate list related structures */
	struct list_head s_truncate;
	struct mutex s_truncate_lock;
  //flusher_thread per-socket lock
	//spinlock_t fs_locks[OBJMS_SOCKETS];
};

//#include "journal-new.h"
//global objms_sbi definition
extern struct objms_sb_info *objms_sbi;
extern unsigned int blk_type_to_shift[OBJMS_BLOCK_TYPE_MAX];
extern unsigned int blk_type_to_size[OBJMS_BLOCK_TYPE_MAX];

/* Function Prototypes */
//extern void objms_error_mng(struct objms_sb_info *sbi, const char *fmt, ...);
//obj.c
extern inline u64 objms_find_and_alloc_blocks(objms_transaction_t *trans, struct objms_inode *pi,
    sector_t iblock);
/* file.c */
extern int objms_mmap(struct file *file, struct vm_area_struct *vma);

/* balloc.c */
int objms_setup_blocknode_map(struct objms_sb_info *sbi);
extern struct objms_blocknode *objms_alloc_blocknode(struct objms_sb_info *sbi);
extern void objms_free_blocknode(struct objms_sb_info *sbi, struct objms_blocknode *bnode);
extern void objms_init_blockmap(struct objms_sb_info *sbi,
		unsigned long init_used_size);
extern inline void objms_free_block(struct objms_sb_info *sbi, unsigned long blocknr,
	unsigned short btype);
extern inline void objms_free_num_blocks(struct objms_sb_info *sbi, unsigned long blocknr,
	unsigned long num_blocks);
extern void __objms_free_block(struct objms_sb_info *sbi,
    objms_flusher_thread_t *flusher_thread, unsigned long blocknr,
	unsigned long num_blocks, struct objms_blocknode **start_hint);
extern int objms_new_block(objms_transaction_t *trans, unsigned long *blocknr,
	unsigned short btype, int zero);
extern int objms_new_extent_block(objms_transaction_t *trans, unsigned long *blocknr,
	unsigned int count, int zero);
extern unsigned long objms_count_free_blocks(struct objms_sb_info *sbi);

/* namei.c */
extern struct dentry *objms_get_parent(struct dentry *child);

/* inode.c */
extern int init_inode_hashtable(void);
extern unsigned int objms_free_inode_subtree(objms_transaction_t *trans,
		__le64 root, u32 height, u32 btype, unsigned long last_blocknr);
extern int __objms_alloc_blocks(objms_transaction_t *trans,	struct objms_inode *pi,
		unsigned long file_blocknr, unsigned int num, bool zero);
extern int objms_init_inode_table(struct objms_sb_info *sbi);
extern int objms_alloc_blocks(objms_transaction_t *trans, struct objms_inode *pi,
    unsigned long file_blocknr, unsigned int num, bool zero);
extern u64 objms_find_data_block(struct objms_sb_info *sbi, struct objms_inode *pi,
	unsigned long file_blocknr);
extern int objms_set_blocksize_hint(struct objms_sb_info *sbi, struct objms_inode *pi,
		loff_t new_size);
extern void objms_setsize(struct objms_sb_info *sbi,
    struct objms_inode *pi, loff_t newsize);
extern int objms_obj_permission(struct objms_inode *pi, int mask);

extern struct objms_inode_info *objms_iget(unsigned long ino);
extern inline void objms_iput(objms_transaction_t *trans, struct objms_inode_info *inode);
extern void objms_evict_inode(objms_transaction_t *trans, struct objms_inode_info *inode);
extern void objms_destroy_inode(struct objms_inode_info *inode);
extern struct objms_inode_info *objms_new_inode(objms_transaction_t *trans,
	umode_t mode, unsigned long objno);
extern void objms_unlock_new_inode(struct objms_inode_info *inode);
extern void objms_clear_inode_inuse(struct objms_sb_info *sbi,
    struct objms_inode *pi);
extern void objms_update_isize(struct objms_sb_info *sbi,
    struct objms_inode *pi, unsigned int size);
extern void objms_update_atime(struct objms_sb_info *sbi, struct objms_inode *pi);
extern void objms_update_time(struct objms_sb_info *sbi, struct objms_inode *pi);
extern void objms_dirty_inode(struct objms_inode_info *inode, int flags);
extern unsigned long objms_find_region(struct objms_sb_info *sbi, struct objms_inode *pi,
    loff_t *offset, int hole);
extern void objms_truncate_del(struct objms_sb_info *sbi,
    struct objms_inode_info *inode);
extern void objms_truncate_add(struct objms_sb_info *sbi,
    struct objms_inode_info *inode, u64 truncate_size);

extern int objms_add_cowblk_list(objms_transaction_t *trans,
    unsigned long blknr, unsigned long num_blocks);
extern int objms_add_flusherblk_list(pid_t pid,
    unsigned long blknr, unsigned long num_blocks);
extern int objms_add_ptenode_list(objms_transaction_t *trans,
    unsigned long kaddr, unsigned long uaddr);
extern void objms_remove_inode_hash(struct objms_inode_info *inode);
/* ioctl.c */
extern long objms_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
extern long objms_compat_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg);
#endif

/* super.c */
extern struct objms_inode_info *objms_alloc_inode(void);
extern struct olock *objms_alloc_olock(void);
extern void objms_free_olock(struct olock *ol);
extern objms_logentry_info_t *objms_alloc_ole(void);
extern void objms_free_ole(objms_logentry_info_t *ole);
extern void __objms_free_blocknode(struct objms_blocknode *bnode);
extern struct objms_sb_info *objms_read_super(struct objms_sb_info *sbi, void *data,
	int silent);
//extern int objms_statfs(struct objms_sb_info *sbi, struct kstatfs *buf);
extern int objms_remount(struct objms_sb_info *sbi, int *flags, char *data);

/* Provides ordering from all previous clflush too */
static inline void PERSISTENT_MARK(void)
{
	/* TODO: Fix me. */
}

static inline void PERSISTENT_BARRIER(void)
{
	asm volatile ("sfence\n" : : );
}
//@ayu: FIXME
static inline void objms_flush_buffer_async(void *buf, uint32_t len, bool fence)
{
	uint32_t i;
	len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));
	for (i = 0; i < len; i += CACHELINE_SIZE){
#ifdef OBJMS_CLFLUSH_TIME
      struct timespec cl_begin, cl_end;
      getrawmonotonic(&cl_begin);
#endif
		asm volatile ("clflush %0\n" : "+m" (*(char *)(buf+i)));
#ifdef OBJMS_CLFLUSH_TIME
      getrawmonotonic(&cl_end);
      unsigned long cl_time1 = (cl_end.tv_sec - cl_begin.tv_sec) * 1000000000
        + (cl_end.tv_nsec - cl_begin.tv_nsec);
      //printk(KERN_ERR "@cl_time1=%lu\n", cl_time);
      /*if (cl_time1 < 30){
        objms_sbi->flush_fail++;
      } else {
        objms_sbi->flush_success++;
      }*/
#endif
#ifdef OBJMS_CLFLUSH_TIME
      getrawmonotonic(&cl_begin);
#endif
		asm volatile ("clflush %0\n" : "+m" (*(char *)(buf+i)));
#ifdef OBJMS_CLFLUSH_TIME
      getrawmonotonic(&cl_end);
      unsigned long cl_time2 = (cl_end.tv_sec - cl_begin.tv_sec) * 1000000000
        + (cl_end.tv_nsec - cl_begin.tv_nsec);
      //printk(KERN_ERR "@cl_time2=%lu\n", cl_time);
      //90%
      //printk(KERN_ERR "@objms: abs=%lu,%lu\n", abs(cl_time1 - cl_time2), min(cl_time1, cl_time2) / 10);
      //<= 5%
      if (abs(cl_time1 - cl_time2) < (min_t(unsigned long, cl_time1, cl_time2) / 10)){
        objms_sbi->flush_fail++;
      } else {
        objms_sbi->flush_success++;
      }
#endif
  }
	/* Do a fence only if asked. We often don't need to do a fence
	 * immediately after clflush because even if we get context switched
	 * between clflush and subsequent fence, the context switch operation
	 * provides implicit fence. */
	if (fence)
		//asm volatile ("sfence\n" : : );
		asm volatile ("mfence\n" : : );
#ifdef PCM_EMULATE_LATENCY
  //len/PCM_BANDWIDTH_MB - len/DRAM_BANDWIDTH_MB
  //int extra_latency = (int)i * (1 - (float)PCM_BANDWIDTH_MB / DRAM_BANDWIDTH_MB)
  //  / (((float)PCM_BANDWIDTH_MB) / 1000);
  emulate_latency_ns(i);
#endif
}

static inline void objms_flush_buffer(void *buf, uint32_t len, bool fence)
{
	uint32_t i;
	len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));
	for (i = 0; i < len; i += CACHELINE_SIZE){
		asm volatile ("clflush %0\n" : "+m" (*(char *)(buf+i)));
  }
#ifdef PCM_EMULATE_LATENCY
  //len/PCM_BANDWIDTH_MB - len/DRAM_BANDWIDTH_MB
  //int extra_latency = (int)i * (1 - (float)PCM_BANDWIDTH_MB / DRAM_BANDWIDTH_MB)
  //  / (((float)PCM_BANDWIDTH_MB) / 1000);
  emulate_latency_ns(i);
#endif
	/* Do a fence only if asked. We often don't need to do a fence
	 * immediately after clflush because even if we get context switched
	 * between clflush and subsequent fence, the context switch operation
	 * provides implicit fence. */
	if (fence)
		//asm volatile ("sfence\n" : : );
		asm volatile ("mfence\n" : : );
}

/* Inline functions start here */

/* Mask out flags that are inappropriate for the given type of inode. */
/*static inline __le32 objms_mask_flags(umode_t mode, __le32 flags)
{
	flags &= cpu_to_le32(OBJMS_FL_INHERITED);
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & cpu_to_le32(OBJMS_REG_FLMASK);
	else
		return flags & cpu_to_le32(OBJMS_OTHER_FLMASK);
}*/

static inline int objms_calc_checksum(u8 *data, int n)
{
	u16 crc = 0;

	crc = crc16(~0, (__u8 *)data + sizeof(__le16), n - sizeof(__le16));
	if (*((__le16 *)data) == cpu_to_le16(crc))
		return 0;
	else
		return 1;
}

/* If this is part of a read-modify-write of the super block,
 * objms_memunlock_super() before calling! */
static inline struct objms_super_block *objms_get_super(struct objms_sb_info *sbi)
{
	return (struct objms_super_block *)sbi->virt_addr;
}
/*
//get the first obj_system_type
static inline struct obj_system_type *objms_get_first_objsystem(struct objms_sb_info *sbi){
	struct objms_super_block *super = objms_get_super(sbi);

	return (struct obj_system_type *)((char *)super +
			le64_to_cpu(super->s_objsystem_offset));
}

static inline struct obj_system_type *objms_get_next_objsystem(struct obj_system_type *objsys){
  return (struct obj_system_type *)((char *)objsys + OBJ_SYSTEM_SIZE);
}
*/
static inline objms_journal_t *objms_get_journal(struct objms_sb_info *sbi)
{
	struct objms_super_block *super = objms_get_super(sbi);

	return (objms_journal_t *)((char *)super +
			le64_to_cpu(super->s_journal_offset));
}

static inline struct objms_inode *objms_get_inode_table(struct objms_sb_info *sbi)
{
	struct objms_super_block *super = objms_get_super(sbi);

	return (struct objms_inode *)((char *)super +
			le64_to_cpu(super->s_inode_table_offset));
}

static inline struct objms_super_block *objms_get_redund_super(struct objms_sb_info *sbi)
{
	return (struct objms_super_block *)(sbi->virt_addr + OBJMS_SB_SIZE);
}

/* If this is part of a read-modify-write of the block,
 * objms_memunlock_block() before calling! */
static inline void *objms_get_block(u64 block)
{
	struct objms_super_block *super = objms_get_super(objms_sbi);

	return block ? ((void *)super + block) : NULL;
}

/* uses CPU instructions to atomically write up to 8 bytes */
static inline void objms_memcpy_atomic (void *dst, const void *src, u8 size)
{
	switch (size) {
		case 1: {
			volatile u8 *daddr = dst;
			const u8 *saddr = src;
			*daddr = *saddr;
			break;
		}
		case 2: {
			volatile __le16 *daddr = dst;
			const u16 *saddr = src;
			*daddr = cpu_to_le16(*saddr);
			break;
		}
		case 4: {
			volatile __le32 *daddr = dst;
			const u32 *saddr = src;
			*daddr = cpu_to_le32(*saddr);
			break;
		}
		case 8: {
			volatile __le64 *daddr = dst;
			const u64 *saddr = src;
			*daddr = cpu_to_le64(*saddr);
			break;
		}
		default:
      break;
			//objms_dbg("error: memcpy_atomic called with %d bytes\n", size);
			//BUG();
	}
}

static inline int objms_memcpy_to_scm_nocache(void *dst, const void *src,
	unsigned int size)
{
  //int ret = __copy_from_user_inatomic_nocache(dst, src, size);
#ifdef PCM_EMULATE_LATENCY
  //len/PCM_BANDWIDTH_MB - len/DRAM_BANDWIDTH_MB
  //int extra_latency = (int)size * (1 - (float)PCM_BANDWIDTH_MB / DRAM_BANDWIDTH_MB)
  //  / (((float)PCM_BANDWIDTH_MB) / 1000);
  emulate_latency_ns(size);
#endif
  //return ret;
	return __copy_from_user_inatomic_nocache(dst, src, size);
}
/* assumes the length to be 4-byte aligned */
static inline void memset_nt(void *dest, uint32_t dword, size_t length)
{
	uint64_t dummy1, dummy2;
	uint64_t qword = ((uint64_t)dword << 32) | dword;

	asm volatile ("movl %%edx,%%ecx\n"
		"andl $63,%%edx\n"
		"shrl $6,%%ecx\n"
		"jz 9f\n"
		"1:      movnti %%rax,(%%rdi)\n"
		"2:      movnti %%rax,1*8(%%rdi)\n"
		"3:      movnti %%rax,2*8(%%rdi)\n"
		"4:      movnti %%rax,3*8(%%rdi)\n"
		"5:      movnti %%rax,4*8(%%rdi)\n"
		"8:      movnti %%rax,5*8(%%rdi)\n"
		"7:      movnti %%rax,6*8(%%rdi)\n"
		"8:      movnti %%rax,7*8(%%rdi)\n"
		"leaq 64(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 1b\n"
		"9:     movl %%edx,%%ecx\n"
		"andl $7,%%edx\n"
		"shrl $3,%%ecx\n"
		"jz 11f\n"
		"10:     movnti %%rax,(%%rdi)\n"
		"leaq 8(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 10b\n"
		"11:     movl %%edx,%%ecx\n"
		"shrl $2,%%ecx\n"
		"jz 12f\n"
		"movnti %%eax,(%%rdi)\n"
		"12:\n"
		: "=D"(dummy1), "=d" (dummy2) : "D" (dest), "a" (qword), "d" (length) : "memory", "rcx");
  //@ayu: FIXME:do we need to add latency here?
#ifdef PCM_EMULATE_LATENCY
  emulate_latency_ns(length);
#endif
}

static inline u64 __objms_find_data_block(struct objms_inode *pi,
    unsigned long blocknr)
{
	__le64 *level_ptr;
	u64 bp = 0;
	u32 height, bit_shift;
	unsigned int idx;

	height = pi->height;
	bp = le64_to_cpu(pi->root);

	while (height > 0) {//@ayu:height <= 3
		level_ptr = objms_get_block(bp);
		bit_shift = (height - 1) * META_BLK_SHIFT;
		idx = blocknr >> bit_shift;
		bp = le64_to_cpu(level_ptr[idx]);
		if (bp == 0)
			return 0;
		blocknr = blocknr & ((1 << bit_shift) - 1);
		height--;
	}
	return bp;
}
//@ayu: find the b-tree pointer of the data block, used by memory object cow
static __le64 *objms_find_btree_pointer(struct objms_inode *pi,
    unsigned long blocknr)
{
	__le64 *level_ptr;
	u64 bp = 0;
	u32 height, bit_shift;
	unsigned int idx;

	height = pi->height;
	bp = le64_to_cpu(pi->root);

	while (height > 0) {//@ayu:height <= 3
		level_ptr = objms_get_block(bp);
		bit_shift = (height - 1) * META_BLK_SHIFT;
		idx = blocknr >> bit_shift;
		bp = le64_to_cpu(level_ptr[idx]);
		if (bp == 0)
			return 0;
		blocknr = blocknr & ((1 << bit_shift) - 1);
		height--;
	}
	return &level_ptr[idx];
}

static inline u64 __objms_find_memory_data_block(struct objms_inode *pi,
    unsigned long blocknr)
{
	u64 bp = 0;
	u32 height;
	unsigned long rpn, rcount;//relative page number in all leaf entry of a meta entry
  struct objms_extent_meta_entry *ext_me;
  struct objms_extent_leaf_entry *ext_le;
  int i;

	height = pi->height;
	bp = le64_to_cpu(pi->root);

  if (!height){
    bp = bp + (blocknr << PAGE_SHIFT);
    return bp;
  }
  rpn = blocknr;
	while (height > 1) {//@ayu:height <= 3
		ext_me = objms_get_block(bp);
    for (i = 0; i < 256; i++){
      //find the meta entry from top to down
      //every time the entry become smaller
      if (blocknr < ext_me->lpn
            || !ext_me->poff){
        break;
      } 
      ext_me = ext_me + 1;
    }
    ext_me = ext_me - 1;
    bp = ext_me->poff;
    rpn = blocknr - ext_me->lpn;
		height--;
	}
  //find the leaf entry
  rcount = 0;
  ext_le = objms_get_block(bp);
  for (i = 0; i < 256; i++){
    rcount += ext_le->count;
    if (rpn < rcount){
      break;
    }
    ext_le = ext_le + 1;
  }
  bp = ext_le->poff + ((rcount - rpn) << PAGE_SHIFT);
	return bp;
}
static inline unsigned int objms_inode_blk_shift (struct objms_inode *pi)
{
	return blk_type_to_shift[pi->i_blk_type];
}

static inline uint32_t objms_inode_blk_size (struct objms_inode *pi)
{
	return blk_type_to_size[pi->i_blk_type];
}

static inline int objms_is_free_inode(struct objms_inode *pi){
  return !(pi->i_flags & OBJMS_INODE_INUSE);
}
//return the attr block number of an inode
//the last 8 bytes of pi
static inline unsigned long objms_get_attrblock(struct objms_inode *pi){
  return *(unsigned long *)((char *)pi + OBJMS_INODE_SIZE - 8);
}
static inline void objms_set_attrblock(struct objms_inode *pi, unsigned long blkoff){
  *(unsigned long *)((char *)pi + OBJMS_INODE_SIZE - 8) = blkoff;
}
/* If this is part of a read-modify-write of the inode metadata,
 * objms_memunlock_inode() before calling! */
static inline struct objms_inode *objms_get_inode(u64	ino){
	struct objms_super_block *super = objms_get_super(objms_sbi);
	struct objms_inode *inode_table = objms_get_inode_table(objms_sbi);
	u64 bp, block, ino_offset;

	if (ino == 0)
		return NULL;

	block = ino >> objms_inode_blk_shift(inode_table);
	bp = __objms_find_data_block(inode_table, block);

	if (bp == 0)
		return NULL;
	ino_offset = (ino & (objms_inode_blk_size(inode_table) - 1));
	return (struct objms_inode *)((void *)super + bp + ino_offset);
}

static inline u64
objms_get_addr_off(struct objms_sb_info *sbi, void *addr)
{
	OBJMS_ASSERT((addr >= sbi->virt_addr) &&
			(addr < (sbi->virt_addr + sbi->initsize)));
	return (u64)(addr - sbi->virt_addr);
}

static inline struct objms_inode *objms_get_naming_object(struct objms_sb_info *sbi)
{
	return objms_get_inode(OBJMS_ROOT_INO);
}

static inline u64
objms_get_block_off(unsigned long blocknr){
	return (u64)blocknr << PAGE_SHIFT;
}

static inline unsigned long
objms_get_numblocks(unsigned short btype)
{
	unsigned long num_blocks;

	if (btype == OBJMS_BLOCK_TYPE_4K) {
		num_blocks = 1;
	} else if (btype == OBJMS_BLOCK_TYPE_2M) {
		num_blocks = 512;
	} else {
		//btype == OBJMS_BLOCK_TYPE_1G 
		num_blocks = 0x40000;
	}
	return num_blocks;
}

static inline unsigned long objms_get_blocknr(u64 block){
	return block >> PAGE_SHIFT;
}

//static inline unsigned long objms_get_pfn(struct objms_sb_info *sbi, u64 block)
static inline unsigned long objms_get_pfn(u64 block)
{
	return (objms_sbi->phys_addr + block) >> PAGE_SHIFT;
}

static inline int objms_is_mounting(struct objms_sb_info *sbi)
{
	return sbi->s_mount_opt & OBJMS_MOUNT_MOUNTING;
}

static inline struct objms_inode_truncate_item * objms_get_truncate_item (struct 
		objms_sb_info *sbi, struct objms_inode *pi)
{
	return (struct objms_inode_truncate_item *)(pi + 1);
}

static inline struct objms_inode_truncate_item * objms_get_truncate_list_head (
		struct objms_sb_info *sbi)
{
	struct objms_inode *pi = objms_get_inode_table(sbi);
	return (struct objms_inode_truncate_item *)(pi + 1);
}

static inline void check_eof_blocks(struct objms_sb_info *sbi, 
		struct objms_inode *pi, loff_t size)
{
	if ((pi->i_flags & cpu_to_le32(OBJMS_EOFBLOCKS_FL)) &&
		(size + sbi->blocksize) > (le64_to_cpu(pi->i_blocks)
			<< sbi->blocksize_bits))
		pi->i_flags &= cpu_to_le32(~OBJMS_EOFBLOCKS_FL);
}
//whether should we log a redundant inode
static inline bool objms_need_log_inode(objms_transaction_t *trans,
    struct objms_inode *pi, uint16_t pi_buf_len){
  //useless when in auto_commit mode
  if (trans->flags & OBJMS_XAUTO){
    return true;
  }
  if (trans->pi_buf == pi){
    return false;
  }
  //FIXME: before replace the old pi_buf, flush it
  /*if (trans->pi_buf){
    objms_add_logentry_info(trans, trans->pi_buf, trans->pi_buf_len);
    trans->backward_ole->status |= OLE_FLUSHABLE;
    if (!trans->flusher_cpup){
      wakeup_log_flusher(trans);
    }
  }*/
  trans->pi_buf = pi;
  trans->pi_buf_len = pi_buf_len;
  return true;
}
#include "wprotect.h"

/* bbuild.c */
void objms_save_blocknode_mappings(struct objms_sb_info *sbi);

int objms_check_integrity(struct objms_sb_info *sbi,
	struct objms_super_block *super);
//void *objms_ioremap(struct objms_sb_info *sbi, phys_addr_t phys_addr,
//	ssize_t size);

//journal.c
extern objms_transaction_t *objms_current_txn(void);
extern int objms_journal_soft_init(struct objms_sb_info *sbi);
extern int objms_journal_hard_init(struct objms_sb_info *sbi,
    uint64_t journal_base, uint32_t journal_size);
extern int objms_journal_uninit(struct objms_sb_info *sbi);
extern int objms_recover_journal(struct objms_sb_info *sbi);
extern void wakeup_log_cleaner(struct objms_sb_info *sbi);
#endif /* __OBJMS_H */
