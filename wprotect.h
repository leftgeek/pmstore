/*
 * BRIEF DESCRIPTION
 *
 * Memory protection definitions for the OBJMS filesystem.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2010-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef __WPROTECT_H
#define __WPROTECT_H

#include "objms_def.h"
#include <linux/fs.h>

/* objms_memunlock_super() before calling! */
static inline void objms_sync_super(struct objms_super_block *ps)
{
	u16 crc = 0;

	//ps->s_wtime = cpu_to_le32(get_seconds());
	ps->s_sum = 0;
	crc = crc16(~0, (__u8 *)ps + sizeof(__le16),
			OBJMS_SB_STATIC_SIZE(ps) - sizeof(__le16));
	ps->s_sum = cpu_to_le16(crc);
	/* Keep sync redundant super block */
	memcpy((void *)ps + OBJMS_SB_SIZE, (void *)ps,
		sizeof(struct objms_super_block));
}

#if 0
/* objms_memunlock_inode() before calling! */
static inline void objms_sync_inode(struct objms_inode *pi)
{
	u16 crc = 0;

	pi->i_sum = 0;
	crc = crc16(~0, (__u8 *)pi + sizeof(__le16), OBJMS_INODE_SIZE -
		    sizeof(__le16));
	pi->i_sum = cpu_to_le16(crc);
}
#endif
/*
extern int objms_writeable(void *vaddr, unsigned long size, int rw);
extern int objms_xip_mem_protect(struct objms_sb_info *sbi,
				 void *vaddr, unsigned long size, int rw);
*/
static inline int objms_is_protected(struct objms_sb_info *sbi)
{
	return sbi->s_mount_opt & OBJMS_MOUNT_PROTECT;
}

static inline int objms_is_wprotected(struct objms_sb_info *sbi)
{
	return objms_is_protected(sbi);
}

static inline void
__objms_memunlock_range(void *p, unsigned long len)
{
	/*
	 * NOTE: Ideally we should lock all the kernel to be memory safe
	 * and avoid to write in the protected memory,
	 * obviously it's not possible, so we only serialize
	 * the operations at fs level. We can't disable the interrupts
	 * because we could have a deadlock in this path.
	 */
	//objms_writeable(p, len, 1);
}

static inline void
__objms_memlock_range(void *p, unsigned long len)
{
	//objms_writeable(p, len, 0);
}

static inline void objms_memunlock_range(struct objms_sb_info *sbi, void *p,
					 unsigned long len)
{
	if (objms_is_protected(sbi))
		__objms_memunlock_range(p, len);
}

static inline void objms_memlock_range(struct objms_sb_info *sbi, void *p,
				       unsigned long len)
{
	if (objms_is_protected(sbi))
		__objms_memlock_range(p, len);
}

static inline void objms_memunlock_super(struct objms_sb_info *sbi,
					 struct objms_super_block *ps)
{
	if (objms_is_protected(sbi))
		__objms_memunlock_range(ps, OBJMS_SB_SIZE);
}

static inline void objms_memlock_super(struct objms_sb_info *sbi,
				       struct objms_super_block *ps)
{
	objms_sync_super(ps);
	if (objms_is_protected(sbi))
		__objms_memlock_range(ps, OBJMS_SB_SIZE);
}

static inline void objms_memunlock_inode(struct objms_sb_info *sbi,
					 struct objms_inode *pi)
{
	if (objms_is_protected(sbi))
		__objms_memunlock_range(pi, OBJMS_SB_SIZE);
}

static inline void objms_memlock_inode(struct objms_sb_info *sbi,
				       struct objms_inode *pi)
{
	/* objms_sync_inode(pi); */
	if (objms_is_protected(sbi))
		__objms_memlock_range(pi, OBJMS_SB_SIZE);
}

static inline void objms_memunlock_block(struct objms_sb_info *sbi, void *bp)
{
	if (objms_is_protected(sbi))
		__objms_memunlock_range(bp, sbi->blocksize);
}

static inline void objms_memlock_block(struct objms_sb_info *sbi, void *bp)
{
	if (objms_is_protected(sbi))
		__objms_memlock_range(bp, sbi->blocksize);
}

#endif
