/*
 * FILE NAME include/linux/objms_fs.h
 *
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
#ifndef __OBJMS_DEF_H
#define __OBJMS_DEF_H

#include <linux/types.h>
#include <linux/obj.h>

/*
 * The OBJMS constants/structures
 */
#define OBJMS_SUPER_MAGIC 0x2015

/*
 * Mount flags
 */
#define OBJMS_MOUNT_PROTECT 0x000001            /* wprotect CR0.WP */
#define OBJMS_MOUNT_XATTR_USER 0x000002         /* Extended user attributes */
#define OBJMS_MOUNT_POSIX_ACL 0x000004          /* POSIX Access Control Lists */
#define OBJMS_MOUNT_ERRORS_CONT 0x000010        /* Continue on errors */
#define OBJMS_MOUNT_ERRORS_RO 0x000020          /* Remount fs ro on errors */
#define OBJMS_MOUNT_ERRORS_PANIC 0x000040       /* Panic on errors */
#define OBJMS_MOUNT_HUGEMMAP 0x000080           /* Huge mappings with mmap */
#define OBJMS_MOUNT_HUGEIOREMAP 0x000100        /* Huge mappings with ioremap */
#define OBJMS_MOUNT_PROTECT_OLD 0x000200        /* wprotect PAGE RW Bit */
#define OBJMS_MOUNT_FORMAT      0x000400        /* was FS formatted on mount? */
#define OBJMS_MOUNT_MOUNTING    0x000800        /* FS currently being mounted */

#define OBJMS_DEF_BLOCK_SIZE_4K 4096

#define OBJMS_INODE_SIZE  256    /* must be power of two */
#define OBJMS_INODE_BITS  8
//#define OBJMS_REVERSE_TXN_MODE_MASK (1UL << 60)

/* OBJMS supported data blocks */
//#define OBJMS_BLOCK_TYPE_4K     0
//#define OBJMS_BLOCK_TYPE_2M     1
//#define OBJMS_BLOCK_TYPE_1G     2
//#define OBJMS_BLOCK_TYPE_MAX    3

#define META_BLK_SHIFT 9

/*
 * Play with this knob to change the default block type.
 * By changing the OBJMS_DEFAULT_BLOCK_TYPE to 2M or 1G,
 * we should get pretty good coverage in testing.
 */
//#define OBJMS_DEFAULT_BLOCK_TYPE OBJMS_BLOCK_TYPE_4K

/*
 * Structure of an inode in OBJMS. Things to keep in mind when modifying it.
 * 1) Keep the inode size to within 48 bytes if possible. This is because
 *    a 64 byte log-entry can store 48 bytes of data and we would like
 *    to log an inode using only 1 log-entries
 * 2) root must be immediately after the qw containing height because we update
 *    root and height atomically using cmpxchg16b in objms_decrease_btree_height 
 * 3) i_size, i_ctime, and i_mtime must be in that order and i_size must be at
 *    16 byte aligned offset from the start of the inode. We use cmpxchg16b to
 *    update these three fields atomically.
 */
//i_flags can determina whether an onode is valid
//64 bytes:  a logentry can hold 48 bytes, so we need 2les/inode
struct objms_inode {
  //first 48 bytes
	//__le16	i_rsvd;         /* reserved. used to be checksum */
  __le16  i_mode; //TODO: UGO style permission, maybe we can merge it with i_flags?
	u8	    height;         /* height of data b-tree; max 3 for now */
	u8	    i_blk_type;     /* data block size this inode uses */
	__le32	i_flags;            /* Inode flags */
	__le64	root;               /* btree root. must be below qw w/ height */
	__le64	i_blocks;           /* Blocks count */
	__le64	i_size;             /* Size of data in bytes */
	__le32	i_ctime;            /* Inode and attributes modification time */
	__le32	i_mtime;            /* Inode b-tree (data) Modification time */
	__le32	i_attrsize; //Extended attributes size 
	__le32 i_pattern;     /* access pattern: 0-storage object, 1-memory object */

  //second 48 bytes
	//__le64	i_attr;    /* Extended attribute block(linked by list) *///FIXME: remove this
  __le32  i_uid;
  __le32  i_gid;
	__le32	i_dtime;  //TODO: Deletion Time, we use it to find the oldest inode to wear-leveling 
	__le32	i_atime;            /* Access time */

  //Extended attributes
};

//64B
#define OBJMS_INODE_XATTR_START sizeof(struct objms_inode)
//8B for attribute pages pointer
//184B
#define OBJMS_INODE_XATTR_LEN (OBJMS_INODE_SIZE - OBJMS_INODE_XATTR_START - 8)
//#define OBJMS_MAX_XATTR_SIZE (OBJMS_INODE_XATTR_LEN + OBJMS_DEF_BLOCK_SIZE_4K)

/* This is a per-inode structure and follows immediately after the 
 * struct objms_inode. It is used to implement the truncate linked list and is 
 * by objms_truncate_add(), objms_truncate_del(), and objms_recover_truncate_list()
 * functions to manage the truncate list */
struct objms_inode_truncate_item {
	__le64	i_truncatesize;     /* Size of truncated inode */
	__le64  i_next_truncate;    /* inode num of the next truncated inode */
};

/* #define OBJMS_SB_SIZE 128 */ /* must be power of two */
#define OBJMS_SB_SIZE 1024       /* must be power of two */

typedef struct objms_journal {
	__le64     journal_base;  //journal space base
	__le32     journal_size;  //journal(log entries)size
  //TODO: head and tail is to speed up journal recovery and transaction allocation
  //to something to fast journal recovery
	__le16     redo_logging;
	__le16     padding;
} objms_journal_t;


/*
 * Structure of the super block in OBJMS
 * The fields are partitioned into static and dynamic fields. The static fields
 * never change after file system creation. This was primarily done because
 * objms_get_block() returns NULL if the block offset is 0 (helps in catching
 * bugs). So if we modify any field using journaling (for consistency), we 
 * will have to modify s_sum which is at offset 0. So journaling code fails.
 * This (static+dynamic fields) is a temporary solution and can be avoided
 * once the file system becomes stable and objms_get_block() returns correct
 * pointers even for offset 0.
 */
//totally 2 logentries
struct objms_super_block {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below */
	__le16		s_sum;              /* checksum of this sb */
	__le16		s_magic;            /* magic signature */
	__le32		s_blocksize;        /* blocksize in bytes */
	__le64		s_size;             /* total size of fs in bytes */
	char		s_volume_name[16];  /* volume name */
  //__le64  s_objsystem_offset; //points to the location of struct obj_system_type
	/* points to the location of objms_journal_t */
	__le64          s_journal_offset;
	/* points to the location of struct objms_inode for the inode table */
	__le64    s_inode_table_offset;

  //next 48 bytes
	__le64    s_start_dynamic; 

	/* all the dynamic fields should go here */
	/* s_mtime and s_wtime should be together and their order should not be
	 * changed. we use an 8 byte write to update both of them atomically */
	__le32		s_mtime;            /* mount time */
	__le32		s_wtime;            /* write time */
	/* fields for fast mount support. Always keep them together */
	__le64		s_num_blocknode_allocated;
	__le64		s_num_free_blocks;
	__le32		s_inodes_count;
	__le32		s_free_inodes_count;
//	__le32		s_inodes_used_count;
	__le32		s_free_inode_hint;
  __le32  padding;
};

#define OBJMS_SB_STATIC_SIZE(ps) ((u64)&ps->s_start_dynamic - (u64)ps)

/* the above fast mount fields take total 32 bytes in the super block */
#define OBJMS_FAST_MOUNT_FIELD_SIZE  (32)
//inode 0 is reserved
/* The root inode follows immediately after the redundant super block */
#define OBJMS_ROOT_INO (OBJMS_INODE_SIZE)
//TODO: root inode stores the naming object
//#define OBJMS_ROOT_INO 0
//
#define OBJMS_BLOCKNODE_IN0 (OBJMS_ROOT_INO + OBJMS_INODE_SIZE)
//#define OBJMS_BLOCKNODE_IN0 (OBJMS_INODE_SIZE)

/* INODE HINT  START at 3 */ 
#define OBJMS_FREE_INODE_HINT_START      (3)

#endif /* _OBJMS_DEF_H */
