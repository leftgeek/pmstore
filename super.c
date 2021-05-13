/*
 * BRIEF DESCRIPTION
 *
 * Super block operations.
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

#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/parser.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/bitops.h>
#include <linux/magic.h>
#include <linux/exportfs.h>
#include <linux/random.h>
#include <linux/cred.h>
#include <linux/backing-dev.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/obj.h>
#include "objms.h"

struct objms_sb_info *objms_sbi = NULL;
EXPORT_SYMBOL(objms_sbi);

static struct kmem_cache *objms_inode_cachep;
static struct kmem_cache *objms_blocknode_cachep;
static struct kmem_cache *objms_transaction_cachep;
static struct kmem_cache *objms_olock_cachep;
static struct kmem_cache *objms_ole_cachep;
/* FIXME: should the following variable be one per OBJMS instance? */
unsigned int objms_dbgmask = 0;
/*
void objms_error_mng(struct objms_sb_info *sbi, const char *fmt, ...){
	va_list args;

	printk("objms error: ");
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

	if (test_opt(sbi, ERRORS_PANIC))
		panic("objms: panic from previous error\n");
	if (test_opt(sbi, ERRORS_RO)) {
		printk(KERN_CRIT "objms err: remounting filesystem read-only");
		sbi->s_flags |= MS_RDONLY;
	}
}
*/
static void objms_set_blocksize(struct objms_sb_info *sbi, unsigned long size){
	int bits;

	/*
	 * We've already validated the user input and the value here must be
	 * between OBJMS_MAX_BLOCK_SIZE and OBJMS_MIN_BLOCK_SIZE
	 * and it must be a power of 2.
	 */
	bits = fls(size) - 1;
	sbi->blocksize_bits = bits;
  sbi->blocksize = (1 << bits);
}

static inline int objms_has_huge_ioremap(struct objms_sb_info *sbi){
	return sbi->s_mount_opt & OBJMS_MOUNT_HUGEIOREMAP;
}
/*
void *objms_ioremap(struct objms_sb_info *sbi, phys_addr_t phys_addr, ssize_t size){
	void __iomem *retval;
	int protect, hugeioremap;

	if (sbi) {
		protect = objms_is_wprotected(sbi);
		hugeioremap = objms_has_huge_ioremap(sbi);
	} else {
		protect = 0;
		hugeioremap = 1;
	}
*/
	/*
	 * NOTE: Userland may not map this resource, we will mark the region so
	 * /dev/mem and the sysfs MMIO access will not be allowed. This
	 * restriction depends on STRICT_DEVMEM option. If this option is
	 * disabled or not available we mark the region only as busy.
	 */
/*	retval = (void __iomem *)
			request_mem_region_exclusive(phys_addr, size, "objms");
	if (!retval)
		goto fail;

	if (protect) {
		if (hugeioremap)
			retval = ioremap_hpage_cache_ro(phys_addr, size);
		else
			retval = ioremap_cache_ro(phys_addr, size);
	} else {
		if (hugeioremap)
			retval = ioremap_hpage_cache(phys_addr, size);
		else
			retval = ioremap_cache(phys_addr, size);
	}

fail:
	return (void __force *)retval;
}

static inline int objms_iounmap(void *virt_addr, ssize_t size, int protected){
	iounmap((void __iomem __force *)virt_addr);
	return 0;
}*/
/*
static loff_t objms_max_size(int bits){
	loff_t res;

	res = (1ULL << (3 * 9 + bits)) - 1;

	if (res > MAX_LFS_FILESIZE)
		res = MAX_LFS_FILESIZE;

	//objms_dbg_verbose("max file size %llu bytes\n", res);
	return res;
}
*/
enum {
	Opt_addr, Opt_bpi, Opt_size, Opt_jsize,
	Opt_num_inodes, Opt_mode, Opt_uid,
	Opt_gid, Opt_blocksize, Opt_wprotect, Opt_wprotectold,
	Opt_err_cont, Opt_err_panic, Opt_err_ro,
	Opt_hugemmap, Opt_nohugeioremap, Opt_dbgmask, Opt_err
};

static const match_table_t tokens = {
	{ Opt_addr,	     "physaddr=%x"	  },
	{ Opt_bpi,	     "bpi=%u"		  },
	{ Opt_size,	     "init=%s"		  },
	{ Opt_jsize,     "jsize=%s"		  },
	{ Opt_num_inodes,"num_inodes=%u"  },
	{ Opt_mode,	     "mode=%o"		  },
	{ Opt_uid,	     "uid=%u"		  },
	{ Opt_gid,	     "gid=%u"		  },
	{ Opt_wprotect,	     "wprotect"		  },
	{ Opt_wprotectold,   "wprotectold"	  },
	{ Opt_err_cont,	     "errors=continue"	  },
	{ Opt_err_panic,     "errors=panic"	  },
	{ Opt_err_ro,	     "errors=remount-ro"  },
	{ Opt_hugemmap,	     "hugemmap"		  },
	{ Opt_nohugeioremap, "nohugeioremap"	  },
	{ Opt_dbgmask,	     "dbgmask=%u"	  },
	{ Opt_err,	     NULL		  },
};
/*
static phys_addr_t get_phys_addr(void **data){
	phys_addr_t phys_addr;
	char *options = (char *)*data;

	if (!options || strncmp(options, "physaddr=", 9) != 0)
		return (phys_addr_t)ULLONG_MAX;
	options += 9;
	phys_addr = (phys_addr_t)simple_strtoull(options, &options, 0);
	if (*options && *options != ',') {
		printk(KERN_ERR "Invalid phys addr specification: %s\n",
		       (char *)*data);
		return (phys_addr_t)ULLONG_MAX;
	}
	if (phys_addr & (PAGE_SIZE - 1)) {
		printk(KERN_ERR "physical address 0x%16llx for objms isn't "
		       "aligned to a page boundary\n", (u64)phys_addr);
		return (phys_addr_t)ULLONG_MAX;
	}
	if (*options == ',')
		options++;
	*data = (void *)options;
	return phys_addr;
}
*/
static int objms_parse_options(char *options, struct objms_sb_info *sbi,
			       bool remount){
	char *p, *rest;
	substring_t args[MAX_OPT_ARGS];
	int option;

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_addr:
			if (remount)
				goto bad_opt;
			/* physaddr managed in get_phys_addr() */
			break;
		case Opt_bpi:
			if (remount)
				goto bad_opt;
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->bpi = option;
			break;
		case Opt_uid:
			if (remount)
				goto bad_opt;
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->uid = make_kuid(current_user_ns(), option);
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gid = make_kgid(current_user_ns(), option);
			break;
		case Opt_mode:
			if (match_octal(&args[0], &option))
				goto bad_val;
			sbi->mode = option & 01777U;
			break;
		case Opt_size:
			if (remount)
				goto bad_opt;
			/* memparse() will accept a K/M/G without a digit */
			if (!isdigit(*args[0].from))
				goto bad_val;
			sbi->initsize = memparse(args[0].from, &rest);
			set_opt(sbi->s_mount_opt, FORMAT);
			break;
		case Opt_jsize:
			if (remount)
				goto bad_opt;
			/* memparse() will accept a K/M/G without a digit */
			if (!isdigit(*args[0].from))
				goto bad_val;
			sbi->jsize = memparse(args[0].from, &rest);
			/* make sure journal size is integer power of 2 */
			if (sbi->jsize & (sbi->jsize - 1) ||
				sbi->jsize < OBJMS_MINIMUM_JOURNAL_SIZE) {
				/*objms_dbg("Invalid jsize: "
					"must be whole power of 2 & >= 64KB\n");*/
				goto bad_val;
			}
			break;
		case Opt_num_inodes:
			if (remount)
				goto bad_opt;
			if (match_int(&args[0], &option))
				goto bad_val;
			//sbi->num_inodes = option;//FIXME: maybe we should use another struct to store mount options
			break;
		case Opt_err_panic:
			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
			clear_opt(sbi->s_mount_opt, ERRORS_RO);
			set_opt(sbi->s_mount_opt, ERRORS_PANIC);
			break;
		case Opt_err_ro:
			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
			set_opt(sbi->s_mount_opt, ERRORS_RO);
			break;
		case Opt_err_cont:
			clear_opt(sbi->s_mount_opt, ERRORS_RO);
			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
			set_opt(sbi->s_mount_opt, ERRORS_CONT);
			break;
		case Opt_wprotect:
			if (remount)
				goto bad_opt;
			set_opt(sbi->s_mount_opt, PROTECT);
			/*objms_info
				("OBJMS: Enabling new Write Protection (CR0.WP)\n");*/
			break;
		case Opt_wprotectold:
			if (remount)
				goto bad_opt;
			set_opt(sbi->s_mount_opt, PROTECT_OLD);
			/*objms_info
				("OBJMS: Enabling old Write Protection (PAGE RW Bit)\n");*/
			break;
		case Opt_hugemmap:
			if (remount)
				goto bad_opt;
			set_opt(sbi->s_mount_opt, HUGEMMAP);
			//objms_info("OBJMS: Enabling huge mappings for mmap\n");
			break;
		case Opt_nohugeioremap:
			if (remount)
				goto bad_opt;
			clear_opt(sbi->s_mount_opt, HUGEIOREMAP);
			//objms_info("OBJMS: Disabling huge ioremap\n");
			break;
		case Opt_dbgmask:
			if (match_int(&args[0], &option))
				goto bad_val;
			objms_dbgmask = option;
			break;
		default: {
			goto bad_opt;
		}
		}
	}

	return 0;

bad_val:
	printk(KERN_INFO "Bad value '%s' for mount option '%s'\n", args[0].from,
	       p);
	return -EINVAL;
bad_opt:
	printk(KERN_INFO "Bad mount option: \"%s\"\n", p);
	return -EINVAL;
}

static bool objms_check_size (struct objms_sb_info *sbi, unsigned long size){
	unsigned long minimum_size, num_blocks;

	/* space required for super block and root directory */
	minimum_size = 2 << sbi->blocksize_bits;

	/* space required for inode table */
	if (sbi->num_inodes > 0)
		num_blocks = (sbi->num_inodes >>
			(sbi->blocksize_bits - OBJMS_INODE_BITS)) + 1;
	else
		num_blocks = 1;
	minimum_size += (num_blocks << sbi->blocksize_bits);
	/* space required for journal */
	minimum_size += sbi->jsize;

	if (size < minimum_size)
	    return false;

	return true;
}

//init the naming object
static int objms_init_naming_object(struct objms_sb_info *sbi){
  struct objms_inode *pi = objms_get_naming_object(sbi);
  struct objms_name_info *oni = (struct objms_name_info *)((char *)pi
      + OBJMS_INODE_XATTR_START);
  int errval;

  objms_memunlock_inode(sbi, pi);
  pi->i_blk_type = OBJMS_DEFAULT_BLOCK_TYPE;
  pi->i_flags = OBJMS_INODE_INUSE;//set the inode's used flag
  pi->height = 0;
  pi->root = 0;
  pi->i_blocks = 0;
  //pi->i_dtime = 0;
  //pi->i_attr = 0;
  pi->i_uid = current_fsuid().val;
  pi->i_gid = current_fsgid().val;
  pi->i_mode = 0600;
  pi->i_size = 4096;

  oni->free_entries_count = 4096 >> 5;
  oni->free_entry_hint = 0;
  oni->end_entry_index = 0;
  objms_memlock_inode(sbi, pi);

  errval = __objms_alloc_blocks(NULL, pi, 0, 1, true);//pre-allocate 4k space for naming object
  if (errval) {
    printk(KERN_ERR "@objms_init_naming_object: failed\n");
    return errval;
  }
  return 0;
}
static int objms_init(struct objms_sb_info *sbi,
				      unsigned long size){
	unsigned long blocksize;
	u64 journal_meta_start, journal_data_start, inode_table_start;
	struct objms_super_block *super;
	//unsigned long blocknr;

	printk(KERN_ERR "@objms: creating an empty objms of size %lu\n", size);
	//sbi->virt_addr = objms_ioremap(sbi, sbi->phys_addr, size);
	sbi->block_start = (unsigned long)0;
	sbi->block_end = ((unsigned long)(size) >> PAGE_SHIFT);

	if (!sbi->virt_addr) {
		printk(KERN_ERR "@objms_init: ioremap of the objms image failed(1)\n");
		return -EINVAL;
	}

	//objms_dbg_verbose("objms: Default block size set to 4K\n");
	blocksize = sbi->blocksize = OBJMS_DEF_BLOCK_SIZE_4K;

  objms_set_blocksize(sbi, blocksize);
  blocksize = sbi->blocksize;

  if (sbi->blocksize && sbi->blocksize != blocksize){
    sbi->blocksize = blocksize;
  }

	if (!objms_check_size(sbi, size)) {
		printk(KERN_ERR "@objms_init: size too small 0x%lx. Either increase"
			" OBJMS size, or reduce num. of inodes (minimum 32)" 
			" or journal size (minimum 64KB)\n", size);
		return -EINVAL;
	}
  //SB_SIZE1 = |super block|obj_system_type*8|journal_t|inode table(1 inode size)|
  //SB_SIZE2 = |super block|...|
  //objsystem_start = sizeof(struct objms_super_block);
  //objsystem_start = (objsystem_start + CACHELINE_SIZE - 1)
  //  & ~(CACHELINE_SIZE - 1);
	journal_meta_start = sizeof(struct objms_super_block);
  //journal_meta starts right after objsystem
	//journal_meta_start = objsystem_start + OBJ_SYSTEM_SIZE * OBJ_SYSTEM_MAX;
	journal_meta_start = (journal_meta_start + CACHELINE_SIZE - 1) &
		~(CACHELINE_SIZE - 1);//@AYU:cacheline(64B)对齐
	inode_table_start = journal_meta_start + sizeof(objms_journal_t);
	inode_table_start = (inode_table_start + CACHELINE_SIZE - 1) &
		~(CACHELINE_SIZE - 1);

	if ((inode_table_start + sizeof(struct objms_inode)) > OBJMS_SB_SIZE) {
		printk(KERN_ERR "@objms_init: super block defined too small. defined 0x%x, "
				"required 0x%llx\n", OBJMS_SB_SIZE,
			inode_table_start + sizeof(struct objms_inode));
		return -EINVAL;
	}

  //|SB_SIZE|SB_SIZE|log entries(jsize)|
	journal_data_start = OBJMS_SB_SIZE * 2;
	journal_data_start = (journal_data_start + blocksize - 1) &
		~(blocksize - 1);

	printk(KERN_ERR "@objms_init: journal meta start %llx,"
      "journal data start 0x%llx, journal size 0x%x, inode_table 0x%llx\n",
    journal_meta_start, journal_data_start,
    sbi->jsize, inode_table_start);

	super = objms_get_super(sbi);
	objms_memunlock_range(sbi, super, journal_data_start);

	/* clear out super-block and inode table */
	memset_nt(super, 0, journal_data_start);
	super->s_size = cpu_to_le64(size);
	super->s_blocksize = cpu_to_le32(blocksize);
	super->s_magic = cpu_to_le16(OBJMS_SUPER_MAGIC);
	super->s_num_free_blocks = ((unsigned long)(size) >> PAGE_SHIFT);
	//super->s_objsystem_offset = cpu_to_le64(objsystem_start);
	super->s_journal_offset = cpu_to_le64(journal_meta_start);
	super->s_inode_table_offset = cpu_to_le64(inode_table_start);

	objms_init_blockmap(sbi, journal_data_start + sbi->jsize);
	//super->s_objsystem_count = 0;
	objms_memlock_range(sbi, super, journal_data_start);

  //init the journal space
	if (objms_journal_hard_init(sbi,
        journal_data_start, sbi->jsize) < 0) {
		printk(KERN_ERR "Journal hard initialization failed\n");
		return -EINVAL;
	}

	if (objms_init_inode_table(sbi) < 0)
		return -EINVAL;

  //init naming object
  //objms_init_naming_object(sbi);//FIXME: do not need this
	objms_memunlock_range(sbi, super, OBJMS_SB_SIZE * 2);
	objms_sync_super(super);
	objms_memlock_range(sbi, super, OBJMS_SB_SIZE * 2);

	objms_flush_buffer(super, OBJMS_SB_SIZE, false);
	objms_flush_buffer((char *)super + OBJMS_SB_SIZE, sizeof(*super), false);

	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	return 0;
}

static inline void set_default_opts(struct objms_sb_info *sbi){
	/* set_opt(sbi->s_mount_opt, PROTECT); */
	set_opt(sbi->s_mount_opt, HUGEIOREMAP);
	set_opt(sbi->s_mount_opt, ERRORS_CONT);
	sbi->jsize = OBJMS_DEFAULT_JOURNAL_SIZE;
  sbi->cpus = num_online_cpus();
  //sbi->cpus = 16;
}

int objms_check_integrity(struct objms_sb_info *sbi,
			  struct objms_super_block *super){
	struct objms_super_block *super_redund;

	super_redund =
		(struct objms_super_block *)((char *)super + OBJMS_SB_SIZE);

	/* Do sanity checks on the superblock */
	if (le16_to_cpu(super->s_magic) != OBJMS_SUPER_MAGIC) {
		if (le16_to_cpu(super_redund->s_magic) != OBJMS_SUPER_MAGIC) {
			printk(KERN_ERR "Can't find a valid objms partition\n");
			goto out;
		} else {
			/*objms_warn
				("Error in super block: try to repair it with "
				"the redundant copy");*/
			/* Try to auto-recover the super block */
			if (sbi)
				objms_memunlock_super(sbi, super);
			memcpy(super, super_redund,
				sizeof(struct objms_super_block));
			if (sbi)
				objms_memlock_super(sbi, super);
			objms_flush_buffer(super, sizeof(*super), false);
			objms_flush_buffer((char *)super + OBJMS_SB_SIZE,
				sizeof(*super), false);

		}
	}

	/* Read the superblock */
	if (objms_calc_checksum((u8 *)super, OBJMS_SB_STATIC_SIZE(super))) {
		if (objms_calc_checksum((u8 *)super_redund,
					OBJMS_SB_STATIC_SIZE(super_redund))) {
			printk(KERN_ERR "checksum error in super block\n");
			goto out;
		} else {
			/*objms_warn
				("Error in super block: try to repair it with "
				"the redundant copy");*/
			/* Try to auto-recover the super block */
			if (sbi)
				objms_memunlock_super(sbi, super);
			memcpy(super, super_redund,
				sizeof(struct objms_super_block));
			if (sbi)
				objms_memlock_super(sbi, super);
			objms_flush_buffer(super, sizeof(*super), false);
			objms_flush_buffer((char *)super + OBJMS_SB_SIZE,
				sizeof(*super), false);
		}
	}

	return 1;
out:
	return 0;
}

static void objms_recover_truncate_list(struct objms_sb_info *sbi){
	struct objms_inode_truncate_item *head = objms_get_truncate_list_head(sbi);
	u64 ino_next = le64_to_cpu(head->i_next_truncate);
	struct objms_inode *pi;
	struct objms_inode_truncate_item *li;
	struct objms_inode_info *inode;

	if (ino_next == 0)
		return;

	while (ino_next != 0) {
		pi = objms_get_inode(ino_next);
		li = (struct objms_inode_truncate_item *)(pi + 1);
		inode = objms_iget(ino_next);
		if (IS_ERR(inode))
			break;
		/*objms_dbg("Recover ino %llx i_flags %d sz %llx:%llx\n", ino_next,
			pi->i_flags, pi->i_size, li->i_truncatesize);*/
		if (pi->i_flags & OBJMS_INODE_INUSE) {//FIXME: when i_links_count became i_flags
			/* set allocation hint */
			objms_set_blocksize_hint(sbi, pi, 
					le64_to_cpu(li->i_truncatesize));
			objms_setsize(sbi, pi, le64_to_cpu(li->i_truncatesize));
			//objms_update_isize(inode, pi);
		} else {
			/* free the inode */
			/*objms_dbg("deleting unreferenced inode %lx\n",
				inode->i_ino);*/
		}
		objms_iput(NULL, inode);
		objms_flush_buffer(pi, CACHELINE_SIZE, false);
		ino_next = le64_to_cpu(li->i_next_truncate);
	}
	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	/* reset the truncate_list */
	objms_memunlock_range(sbi, head, sizeof(*head));
	head->i_next_truncate = 0;
	objms_memlock_range(sbi, head, sizeof(*head));
	objms_flush_buffer(head, sizeof(*head), false);
	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
}
//FIXME: name is not used now, but will assign it go volumn_name later?
static int objms_fill_super(void *data, const char *dev_name){
	struct objms_super_block *super;
	struct objms_sb_info *sbi = NULL;
	unsigned long blocksize, initsize = 0;
	//u32 random = 0;
  struct block_device *bdev;
  unsigned long pfn;
	int retval = -EINVAL;

	BUILD_BUG_ON(sizeof(struct objms_super_block) > OBJMS_SB_SIZE);
	BUILD_BUG_ON(sizeof(struct objms_inode) > OBJMS_INODE_SIZE);

  //init global objms_sbi
	objms_sbi = kzalloc(sizeof(struct objms_sb_info), GFP_KERNEL);
	if (!objms_sbi)
		return -ENOMEM;

  sbi = objms_sbi;
	set_default_opts(sbi);

  bdev = blkdev_get_by_path(dev_name, FMODE_READ | FMODE_WRITE | FMODE_EXCL, objms_sbi);
  initsize = bdev->bd_disk->fops->direct_access(bdev, 0, &sbi->virt_addr, &pfn);
  sbi->phys_addr = pfn << PAGE_SHIFT;
  sbi->initsize = initsize;
  printk(KERN_ERR "@objms_fill_super: dev_name=%s,scm_start=%p,initsize=%lu,scm_end=%p\n",
      dev_name, sbi->virt_addr, initsize, (unsigned long)sbi->virt_addr + initsize);
/*
	sbi->phys_addr = get_phys_addr(&data);
	if (sbi->phys_addr == (phys_addr_t)ULLONG_MAX)
		goto out;
*/
	//get_random_bytes(&random, sizeof(u32));
	//atomic_set(&sbi->next_generation, random);

	INIT_LIST_HEAD(&sbi->txn_running);
	spin_lock_init(&sbi->txn_list_lock);
	/* Init with default values */
	INIT_LIST_HEAD(&sbi->free_block_head);
	sbi->mode = (S_IRUGO | S_IXUGO | S_IWUSR);
	sbi->uid = current_fsuid();
	sbi->gid = current_fsgid();
	clear_opt(sbi->s_mount_opt, PROTECT);
	set_opt(sbi->s_mount_opt, HUGEIOREMAP);

	INIT_LIST_HEAD(&sbi->s_truncate);
	mutex_init(&sbi->s_truncate_lock);
	mutex_init(&sbi->inode_table_mutex);
	mutex_init(&sbi->s_lock);

	if (objms_parse_options(data, sbi, 0))
		goto out;

	set_opt(sbi->s_mount_opt, MOUNTING);
	initsize = sbi->initsize;

	/* Init a new objms instance */
	if (initsize) {
		if (objms_init(sbi, initsize)){//failed
			goto out;
    }
		super = objms_get_super(sbi);
		goto setup_sb;
	}
  //load an objms that is already exist
	/*objms_dbg_verbose("checking physical address 0x%016llx for objms image\n",
		  (u64)sbi->phys_addr);*/

	/* Map only one page for now. Will remap it when fs size is known. */
	initsize = PAGE_SIZE;
	/*sbi->virt_addr = objms_ioremap(sbi, sbi->phys_addr, initsize);
	if (!sbi->virt_addr) {
		printk(KERN_ERR "ioremap of the objms image failed(2)\n");
		goto out;
	}*/

	super = objms_get_super(sbi);

	initsize = le64_to_cpu(super->s_size);
	sbi->initsize = initsize;
	/*objms_dbg_verbose("objms image appears to be %lu KB in size\n",
		   initsize >> 10);*/

	//objms_iounmap(sbi->virt_addr, PAGE_SIZE, objms_is_wprotected(sbi));

	/* Remap the whole filesystem now */
	//release_mem_region(sbi->phys_addr, PAGE_SIZE);
	/* FIXME: Remap the whole filesystem in objms virtual address range. */
	/*sbi->virt_addr = objms_ioremap(sbi, sbi->phys_addr, initsize);
	if (!sbi->virt_addr) {
		printk(KERN_ERR "ioremap of the objms image failed(3)\n");
		goto out;
	}
*/
	super = objms_get_super(sbi);

	if (objms_journal_soft_init(sbi)) {
		retval = -EINVAL;
		printk(KERN_ERR "Journal initialization failed\n");
		goto out;
	}
	if (objms_recover_journal(sbi)) {
		retval = -EINVAL;
		printk(KERN_ERR "Journal recovery failed\n");
		goto out;
	}

	if (objms_check_integrity(sbi, super) == 0) {
		/*objms_dbg("Memory contains invalid objms %x:%x\n",
				le16_to_cpu(super->s_magic), OBJMS_SUPER_MAGIC);*/
		goto out;
	}

	blocksize = le32_to_cpu(super->s_blocksize);
	objms_set_blocksize(sbi, blocksize);

	//objms_dbg_verbose("blocksize %lu\n", blocksize);

	/* Set it all up.. */
setup_sb:

  printk(KERN_ERR "@objms_fill_super: address=%p,cpus=%d,per_node_blocks=%d,sizeof(txn)=%d\n",
      super, sbi->cpus, sbi->per_node_blocks, sizeof(objms_transaction_t));
	objms_recover_truncate_list(sbi);
	/* If the FS was not formatted on this mount, scan the meta-data after
	 * truncate list has been processed */
	if ((sbi->s_mount_opt & OBJMS_MOUNT_FORMAT) == 0)
		objms_setup_blocknode_map(sbi);

	//if (!(sbi->s_flags & MS_RDONLY)) {//FIXME: do we need s_flags in sbi?
	//	u64 mnt_write_time;
		/* update mount time and write time atomically. */
	/*	mnt_write_time = (get_seconds() & 0xFFFFFFFF);
		mnt_write_time = mnt_write_time | (mnt_write_time << 32);

		objms_memunlock_range(sbi, &super->s_mtime, 8);
		objms_memcpy_atomic(&super->s_mtime, &mnt_write_time, 8);
		objms_memlock_range(sbi, &super->s_mtime, 8);

		objms_flush_buffer(&super->s_mtime, 8, false);
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
	}*/

	clear_opt(sbi->s_mount_opt, MOUNTING);
	retval = 0;
#ifdef OBJMS_ENABLE_DEBUG
  sbi->wasted_les = 0;
  sbi->commit_time = 0;
  sbi->total_flushed_bytes = 0;
  sbi->forward_flushed_bytes = 0;
  sbi->backward_flushed_bytes = 0;
  sbi->forward_flushed_entries = 0;
  sbi->backward_flushed_entries = 0;
  sbi->wakeup_invalid = 0;
  sbi->wakeup_success = 0;
  sbi->wakeup_fail = 0;
  sbi->flushed_times = 0;
  sbi->flushing_times = 0;
  sbi->flushable_times = 0;
  int i;
  for (i = 0; i < sbi->cpus; i++){
    sbi->run_cpus[i] = 0;
  }
  sbi->obj_wakeup1 = 0;
  sbi->obj_wakeup2 = 0;
  sbi->obj_wakeup3 = 0;
#endif
#ifdef OBJMS_CLFLUSH_TIME
  sbi->flush_success = 0;
  sbi->flush_fail = 0;
#endif
	return retval;
out:
	/*if (sbi->virt_addr) {
		objms_iounmap(sbi->virt_addr, initsize, objms_is_wprotected(sbi));
		release_mem_region(sbi->phys_addr, initsize);
	}*/

	kfree(sbi);
	return retval;
}
/*
 * TODO: provide a system call to show the status of objms
int objms_statfs(struct objms_sb_info *sbi, struct kstatfs *buf){
	unsigned long count = 0;

	buf->f_type = OBJMS_SUPER_MAGIC;
	buf->f_bsize = sbi->blocksize;

	count = sbi->block_end;
	buf->f_blocks = sbi->block_end;
	buf->f_bfree = buf->f_bavail = objms_count_free_blocks(sbi);
	buf->f_files = (sbi->s_inodes_count);
	buf->f_ffree = (sbi->s_free_inodes_count);
	//buf->f_namelen = OBJMS_NAME_LEN;
	return 0;
}
*/
//FIXME: test_opt?
/*static int objms_show_options(struct seq_file *seq, struct objms_sb_info *sbi){
	seq_printf(seq, ",physaddr=0x%016llx", (u64)sbi->phys_addr);
	if (sbi->initsize)
		seq_printf(seq, ",init=%luk", sbi->initsize >> 10);
	if (sbi->blocksize)
		seq_printf(seq, ",bs=%lu", sbi->blocksize);
	if (sbi->bpi)
		seq_printf(seq, ",bpi=%lu", sbi->bpi);
  //FIXME
	if (sbi->num_inodes)
		seq_printf(seq, ",N=%lu", sbi->num_inodes);
	if (sbi->mode != (S_IRWXUGO | S_ISVTX))
		seq_printf(seq, ",mode=%03o", sbi->mode);
	if (uid_valid(sbi->uid))
		seq_printf(seq, ",uid=%u", from_kuid(&init_user_ns, sbi->uid));
	if (gid_valid(sbi->gid))
		seq_printf(seq, ",gid=%u", from_kgid(&init_user_ns, sbi->gid));
	if (test_opt(root->d_sb, ERRORS_RO))
		seq_puts(seq, ",errors=remount-ro");
	if (test_opt(root->d_sb, ERRORS_PANIC))
		seq_puts(seq, ",errors=panic");
*/	/* memory protection disabled by default */
/*	if (test_opt(root->d_sb, PROTECT))
		seq_puts(seq, ",wprotect");
	if (test_opt(root->d_sb, HUGEMMAP))
		seq_puts(seq, ",hugemmap");
	if (test_opt(root->d_sb, HUGEIOREMAP))
		seq_puts(seq, ",hugeioremap");
*/	/* xip not enabled by default */
/*	if (test_opt(root->d_sb, XIP))
		seq_puts(seq, ",xip");

	return 0;
}*/

int objms_remount(struct objms_sb_info *sbi, int *mntflags, char *data){
	unsigned long old_sb_flags;
	unsigned long old_mount_opt;
	//struct objms_super_block *super;
	int ret = -EINVAL;

	/* Store the old options */
	mutex_lock(&sbi->s_lock);
	old_sb_flags = sbi->s_flags;//FIXME: s_flags?
	old_mount_opt = sbi->s_mount_opt;

	if (objms_parse_options(data, sbi, 1))
		goto restore_opt;

	sbi->s_flags = (sbi->s_flags & ~MS_POSIXACL) |
		      ((sbi->s_mount_opt & OBJMS_MOUNT_POSIX_ACL) ? MS_POSIXACL : 0);

	//if ((*mntflags & MS_RDONLY) != (sbi->s_flags & MS_RDONLY)) {
	//	u64 mnt_write_time;
	//	super = objms_get_super(sbi);
		/* update mount time and write time atomically. */
	/*	mnt_write_time = (get_seconds() & 0xFFFFFFFF);
		mnt_write_time = mnt_write_time | (mnt_write_time << 32);

		objms_memunlock_range(sbi, &super->s_mtime, 8);
		objms_memcpy_atomic(&super->s_mtime, &mnt_write_time, 8);
		objms_memlock_range(sbi, &super->s_mtime, 8);

		objms_flush_buffer(&super->s_mtime, 8, false);
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
	}
*/
	mutex_unlock(&sbi->s_lock);
	ret = 0;
	return ret;

restore_opt:
	sbi->s_flags = old_sb_flags;
	sbi->s_mount_opt = old_mount_opt;
	mutex_unlock(&sbi->s_lock);
	return ret;
}

static void objms_put_super(struct objms_sb_info *sbi){
	struct objms_super_block *super = objms_get_super(sbi);
	u64 size = le64_to_cpu(super->s_size);
	struct objms_blocknode *i;
	struct list_head *head = &(sbi->free_block_head);//@ayu: FIXME, BUG

#ifdef OBJMS_ENABLE_DEBUG
  printk(KERN_ERR "@objms: total_flushed_bytes=%lu,forward_flushed_bytes=%lu,entries=%lu, backward_flushed_bytes=%lu,entries=%lu\n",
      sbi->total_flushed_bytes, sbi->forward_flushed_bytes,
      sbi->forward_flushed_entries, sbi->backward_flushed_bytes, sbi->backward_flushed_entries);
  printk(KERN_ERR "@objms: num_txns=%d,wakeup_invalid=%lu,wakeup_success=%lu,wakeup_fail=%lu\n", atomic_read(&sbi->num_txns), sbi->wakeup_invalid, sbi->wakeup_success, sbi->wakeup_fail);
  //printk(KERN_ERR "@objms: flushed_times=%lu,flushing_times=%lu,flushable_times=%lu\n", sbi->flushed_times, sbi->flushing_times, sbi->flushable_times);
  printk(KERN_ERR "@objms: obj_wakeup1=%lu,obj_wakeup2=%lu,obj_wakeup3=%lu\n",
      sbi->obj_wakeup1, sbi->obj_wakeup2, sbi->obj_wakeup3);
  
  //@ayu: FIXME
  printk(KERN_ERR "@objms: wasted_les=%lu, commit_time=%lu\n",
      sbi->wasted_les, sbi->commit_time);
  objms_flusher_thread_t *flusher_thread;
  int j;
  printk(KERN_ERR "@objms: flusher_thread statics:\n");
  for (j = 0; j < sbi->cpus; j++){
    flusher_thread = &(sbi->log_flusher_threads[j]);
    if (flusher_thread->num_txns){
      printk(KERN_ERR "@objms_flusher_thread[%d]:num_txns=%lu,flushed_bytes=%lu,clean_time=%lu\n",
          j, flusher_thread->num_txns, flusher_thread->flushed_bytes, flusher_thread->clean_time);
      int k;
      for (k = 0; k < sbi->cpus; k++){
        if (flusher_thread->run_cpus[k]){
          printk(KERN_ERR "objms_flusher_thread_cpus[%d]:%lu,", k, flusher_thread->run_cpus[k]);
        }
      }
    }
  }
  for (j = 0; j < sbi->cpus; j++){
    if (sbi->run_cpus[j]){
      printk(KERN_ERR "@objms_run_cpus[%d]=%lu,", j, sbi->run_cpus[j]);
    }
  }
#endif
#ifdef OBJMS_CLFLUSH_TIME
  printk(KERN_ERR "@objms: flush_success=%lu,flush_fail=%lu\n",
      sbi->flush_success, sbi->flush_fail);
#endif
  return;
#ifdef CONFIG_OBJMS_TEST
	if (first_objms_super == sbi->virt_addr)
		first_objms_super = NULL;
#endif

	/* It's unmount time, so unmap the objms memory */
	if (sbi->virt_addr) {
		objms_save_blocknode_mappings(sbi);
		objms_journal_uninit(sbi);
		//objms_iounmap(sbi->virt_addr, size, objms_is_wprotected(sbi));
		//release_mem_region(sbi->phys_addr, size);
		sbi->virt_addr = NULL;
	}

	/* Free all the objms_blocknodes */
	while (!list_empty(head)) {
		i = list_first_entry(head, struct objms_blocknode, link);
		list_del(&i->link);
		objms_free_blocknode(sbi, i);
	}
	objms_dbgmask = 0;
	kfree(sbi);
}

inline void objms_free_ole(objms_logentry_info_t *ole){
	kmem_cache_free(objms_ole_cachep, ole);
}

inline void objms_free_olock(struct olock *ol){
	kmem_cache_free(objms_olock_cachep, ol);
}

inline void objms_free_transaction(objms_transaction_t *trans){
	kmem_cache_free(objms_transaction_cachep, trans);
}

void __objms_free_blocknode(struct objms_blocknode *bnode){
	kmem_cache_free(objms_blocknode_cachep, bnode);
}

void objms_free_blocknode(struct objms_sb_info *sbi, struct objms_blocknode *bnode){
	sbi->num_blocknode_allocated--;
	__objms_free_blocknode(bnode);
}

#ifdef OBJMS_DYNAMIC_OLE
inline objms_logentry_info_t *objms_alloc_ole(void){
  objms_flusher_thread_t *flusher_thread =
    &(objms_sbi->log_flusher_threads[smp_processor_id() % objms_sbi->cpus]);
  if (!list_empty(&flusher_thread->ole_free)){
    spin_lock(&flusher_thread->ole_list_lock);
    if (!list_empty(&flusher_thread->ole_free)){
      objms_logentry_info_t *ole;
      ole = list_first_entry(&flusher_thread->ole_free, objms_logentry_info_t, link);
      list_del(&ole->link);
      spin_unlock(&flusher_thread->ole_list_lock);
      return ole;
    }
    spin_unlock(&flusher_thread->ole_list_lock);
  }
  return (objms_logentry_info_t *)
    kmem_cache_alloc(objms_ole_cachep, GFP_NOFS);
}
#endif

inline struct olock *objms_alloc_olock(void){
	return (struct olock *)
		kmem_cache_alloc(objms_olock_cachep, GFP_NOFS);
}

inline objms_transaction_t *objms_alloc_transaction(void){
  /*if (!list_empty(&objms_sbi->txn_free)){
    objms_transaction_t *trans;
    spin_lock(&objms_sbi->txn_free_list_lock);
    trans = list_first_entry(&objms_sbi->txn_free, objms_transaction_t, txn_list);
    list_del(&trans->txn_list);
    spin_unlock(&objms_sbi->txn_free_list_lock);
    return trans;
  } else {*/
    return (objms_transaction_t *)
      kmem_cache_alloc(objms_transaction_cachep, GFP_NOFS);
  //}
}

struct objms_blocknode *objms_alloc_blocknode(struct objms_sb_info *sbi){
	struct objms_blocknode *p;
	p = (struct objms_blocknode *)
		kmem_cache_alloc(objms_blocknode_cachep, GFP_NOFS);
	if (p) {
		sbi->num_blocknode_allocated++;
	}
	return p;
}

//will be called in inode.c
struct objms_inode_info *objms_alloc_inode(){
  struct objms_inode_info *inode;

  inode = kmem_cache_alloc(objms_inode_cachep, GFP_KERNEL);
  if (!inode){
    return NULL;
  }
  //init inode info
  atomic_set(&inode->i_count, 1);
  spin_lock_init(&inode->i_lock);
  mutex_init(&inode->i_mutex);
  //mutex_init(&inode->i_lock_mutex);
  inode->i_state = 0;
  return inode;
}

//FIXME: what is rcu?
/*static void objms_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	kmem_cache_free(objms_inode_cachep, inode);
}*/

//FIXME: do we need rcu?
void objms_destroy_inode(struct objms_inode_info *inode){
	//call_rcu(&inode->i_rcu, objms_i_callback);
	kmem_cache_free(objms_inode_cachep, inode);
}

static void init_once(void *foo){
	struct objms_inode_info *inode = (struct objms_inode_info *)foo;
  memset(inode, 0, sizeof(struct objms_inode_info));

  INIT_HLIST_NODE(&inode->i_hash);
	INIT_LIST_HEAD(&inode->i_truncated);
#ifdef OBJMS_FINE_LOCK
	INIT_LIST_HEAD(&inode->i_lock_head);
#endif
  //mutex_init(&inode->i_mutex);//do this in alloc_inode
}

static int __init init_blocknode_cache(void){
	objms_blocknode_cachep = kmem_cache_create("objms_blocknode_cache",
					sizeof(struct objms_blocknode),
					0, (SLAB_RECLAIM_ACCOUNT |
                                        SLAB_MEM_SPREAD), NULL);
	if (objms_blocknode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static int __init init_inode_cache(void){
	objms_inode_cachep = kmem_cache_create("objms_inode_cache",
					       sizeof(struct objms_inode_info),
					       0, (SLAB_RECLAIM_ACCOUNT | SLAB_PANIC
						   | SLAB_MEM_SPREAD), init_once);
	if (objms_inode_cachep == NULL){
    printk(KERN_ERR "@objms: init_inode_cache(): objms_inode_cachep = NULL!\n");
		return -ENOMEM;
  }
  return init_inode_hashtable();
}

static int __init init_transaction_cache(void){
	objms_transaction_cachep = kmem_cache_create("objms_journal_transaction",
			sizeof(objms_transaction_t), 0, (SLAB_RECLAIM_ACCOUNT |
			SLAB_MEM_SPREAD), NULL);
	if (objms_transaction_cachep == NULL) {
		return -ENOMEM;
	}
	return 0;
}

static int __init init_olock_cache(void){
	objms_olock_cachep = kmem_cache_create("objms_olock_cachep",
			sizeof(struct olock), 0, (SLAB_RECLAIM_ACCOUNT |
			SLAB_MEM_SPREAD), NULL);
	if (objms_olock_cachep == NULL) {
		return -ENOMEM;
	}
	return 0;
}

#ifdef OBJMS_DYNAMIC_OLE
static int __init init_ole_cache(void){
	objms_ole_cachep = kmem_cache_create("objms_ole_cachep",
			sizeof(objms_logentry_info_t), 0, (SLAB_RECLAIM_ACCOUNT |
			SLAB_MEM_SPREAD), NULL);
	if (objms_ole_cachep == NULL) {
		return -ENOMEM;
	}
	return 0;
}

static void destroy_ole_cache(void){
	if (objms_ole_cachep)
		kmem_cache_destroy(objms_ole_cachep);
	objms_ole_cachep = NULL;
}
#endif

static void destroy_olock_cache(void){
	if (objms_olock_cachep)
		kmem_cache_destroy(objms_olock_cachep);
	objms_olock_cachep = NULL;
}

static void destroy_transaction_cache(void){
	if (objms_transaction_cachep)
		kmem_cache_destroy(objms_transaction_cachep);
	objms_transaction_cachep = NULL;
}

static void destroy_inode_cache(void){
	kmem_cache_destroy(objms_inode_cachep);
}

static void destroy_blocknode_cache(void){
	kmem_cache_destroy(objms_blocknode_cachep);
}

static int __init init_objms(void){
	int rc = 0;

	rc = init_blocknode_cache();
	if (rc){
    printk(KERN_ERR "@objms: init_blocknode_cache() failed!\n");
		return rc;
  }

	rc = init_transaction_cache();
	if (rc)
		goto out1;

	rc = init_inode_cache();
	if (rc)
		goto out2;

	rc = init_olock_cache();
	if (rc)
		goto out3;

#ifdef OBJMS_DYNAMIC_OLE
	rc = init_ole_cache();
	if (rc)
		goto out4;
#endif

    printk(KERN_ERR "@objms: init succeed!\n");
	return 0;

#ifdef OBJMS_DYNAMIC_OLE
  destroy_ole_cache();
out4:
#endif
	destroy_olock_cache();
out3:
	destroy_inode_cache();
out2:
	destroy_transaction_cache();
out1:
	destroy_blocknode_cache();
	return rc;
}

static void __exit exit_objms(void){
	destroy_inode_cache();
	destroy_blocknode_cache();
	destroy_transaction_cache();
}
//objms mount syscall
SYSCALL_DEFINE2(objms_mount, void __user *, data, char __user *, name){
  int ret;
  struct filename *kernel_name;
  unsigned long data_page;

  printk(KERN_ERR "@objms_mount begin\n");
  kernel_name = getname(name);
  if (IS_ERR(kernel_name)){
    ret = PTR_ERR(kernel_name);
    goto out_name;
  }
  
  ret = copy_mount_options(data, &data_page);
  if (ret < 0){
    goto out_data;
  }

  ret = objms_fill_super((void *)data_page, kernel_name->name);

  free_page(data_page);
  printk(KERN_ERR "@objms: mount succeed!\n");
out_data:
  putname(kernel_name);
out_name:
  return ret;
}
//objms umount syscall
SYSCALL_DEFINE0(objms_umount){
  objms_put_super(objms_sbi);
  printk(KERN_ERR "@objms: umount succeed!\n");
  return 0;
}

MODULE_AUTHOR("Ayu");
MODULE_DESCRIPTION("Object Storage Management System");
MODULE_LICENSE("GPL");

module_init(init_objms)
module_exit(exit_objms)
