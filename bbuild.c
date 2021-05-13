/*
 * OBJMS emulated persistence. This file contains code to 
 * handle data blocks of various sizes efficiently.
 *
 * Persistent Memory File System
 * Copyright (c) 2012-2013, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/fs.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include "objms.h"

struct scan_bitmap {
	unsigned long bitmap_4k_size;
	unsigned long bitmap_2M_size;
	unsigned long bitmap_1G_size;
	unsigned long *bitmap_4k;
	unsigned long *bitmap_2M;
	unsigned long *bitmap_1G;
};

static void objms_clear_datablock_inode(struct objms_sb_info *sbi)
{
	struct objms_inode *pi =  objms_get_inode(OBJMS_BLOCKNODE_IN0);
	objms_transaction_t *trans;
  unsigned long tid;
  int ret;

	/* 1 log entry for inode */
	tid = sys_objms_new_txn(OBJMS_XSTRONG);
  trans = objms_current_transaction(tid);
	ret = objms_alloc_logentries(trans, 1);
  if (ret){
    return;
  }
  objms_add_logentry(trans, pi, MAX_DATA_PER_LENTRY, false);

	objms_memunlock_inode(sbi, pi);
	memset(pi, 0, MAX_DATA_PER_LENTRY);
	objms_memlock_inode(sbi, pi);
  objms_add_logentry_info(trans, pi, MAX_DATA_PER_LENTRY);

	/* commit the transaction */
	sys_objms_commit_txn(tid);
}

static void objms_init_blockmap_from_inode(struct objms_sb_info *sbi)
{
	struct objms_inode *pi =  objms_get_inode(OBJMS_BLOCKNODE_IN0);
	struct objms_blocknode_lowhigh *p = NULL;
	struct objms_blocknode *blknode;
	unsigned long index;
	unsigned long blocknr;
	unsigned long i;
	unsigned long num_blocknode;
	u64 bp;

	num_blocknode = sbi->num_blocknode_allocated;
	sbi->num_blocknode_allocated = 0;
	for (i=0; i<num_blocknode; i++) {
		index = i & 0xFF;
		if (index == 0) {
			/* Find and get new data block */
			blocknr = i >> 8; /* 256 Entries in a block */
			bp = __objms_find_data_block(pi, blocknr);
			p = objms_get_block(bp);
		}
		OBJMS_ASSERT(p);
		blknode = objms_alloc_blocknode(sbi);
		if (blknode == NULL)
                	OBJMS_ASSERT(0);
		blknode->block_low = le64_to_cpu(p[index].block_low);
		blknode->block_high = le64_to_cpu(p[index].block_high);
		list_add_tail(&blknode->link, &sbi->free_block_head);//@ayu: FIXME, BUG
	}
}

static bool objms_can_skip_full_scan(struct objms_sb_info *sbi)
{
	struct objms_inode *pi =  objms_get_inode(OBJMS_BLOCKNODE_IN0);
	struct objms_super_block *super = objms_get_super(sbi);
	__le64 root;
	unsigned int height, btype;
	unsigned long last_blocknr;

	if (!pi->root)
		return false;

	sbi->num_blocknode_allocated =
		le64_to_cpu(super->s_num_blocknode_allocated);
	sbi->num_free_blocks = le64_to_cpu(super->s_num_free_blocks);
	sbi->s_inodes_count = le32_to_cpu(super->s_inodes_count);
	sbi->s_free_inodes_count = le32_to_cpu(super->s_free_inodes_count);
	//sbi->s_inodes_used_count = le32_to_cpu(super->s_inodes_used_count);
	sbi->s_free_inode_hint = le32_to_cpu(super->s_free_inode_hint);

	objms_init_blockmap_from_inode(sbi);

	root = pi->root;
	height = pi->height;
	btype = pi->i_blk_type;
	/* pi->i_size can not be zero */
	last_blocknr = (le64_to_cpu(pi->i_size) - 1) >>
					objms_inode_blk_shift(pi);

	/* Clearing the datablock inode */
	objms_clear_datablock_inode(sbi);

	objms_free_inode_subtree(NULL, root, height, btype, last_blocknr);

	return true;
}


static int objms_allocate_datablock_block_inode(objms_transaction_t *trans,
	struct objms_sb_info *sbi, struct objms_inode *pi, unsigned long num_blocks)
{
	int errval;
	
	objms_memunlock_inode(sbi, pi);
	//pi->i_links_count = cpu_to_le16(1);
	pi->i_blk_type = OBJMS_BLOCK_TYPE_4K;
	pi->i_flags = OBJMS_INODE_INUSE;
	pi->height = 0;
	//pi->i_dtime = 0; 
	pi->i_size = cpu_to_le64(num_blocks << sbi->blocksize_bits);
	objms_memlock_inode(sbi, pi);

	errval = __objms_alloc_blocks(trans, pi, 0, num_blocks, false);

	return errval;
}
//FIXME: maybe we don't need this
void objms_save_blocknode_mappings(struct objms_sb_info *sbi)
{
	unsigned long num_blocks, blocknr;
	struct objms_inode *pi =  objms_get_inode(OBJMS_BLOCKNODE_IN0);
	struct objms_blocknode_lowhigh *p;
	struct list_head *head = &(sbi->free_block_head);//@ayu: FIXME, BUG
	struct objms_blocknode *i;
	struct objms_super_block *super = objms_get_super(sbi);
	objms_transaction_t *trans;
	u64 bp;
	int j, k;
	int errval;
  unsigned long tid;
	
	num_blocks = ((sbi->num_blocknode_allocated * sizeof(struct 
		objms_blocknode_lowhigh) - 1) >> sbi->blocksize_bits) + 1;

	/* 1 log entry for inode, 2 lentry for super-block */
  //printk(KERN_ERR "@objms_save_blocknode_mappings: sys_objms_new_transaction begin\n");
  tid = sys_objms_new_txn(OBJMS_XSTRONG);
  trans = objms_current_transaction(tid);
	errval = objms_alloc_logentries(trans, MAX_INODE_LENTRIES + MAX_SB_LENTRIES);
  if (errval){
    return;
  }

	objms_add_logentry(trans, pi, MAX_DATA_PER_LENTRY, false);

	errval = objms_allocate_datablock_block_inode(trans, sbi, pi, num_blocks);
	objms_add_logentry_info(trans, pi, MAX_DATA_PER_LENTRY);

	if (errval != 0) {
		//objms_dbg("Error saving the blocknode mappings: %d\n", errval);
		sys_objms_abort_txn(tid);
		return;
	}

	j = 0;
	k = 0;
	p = NULL;
	list_for_each_entry(i, head, link) {
		blocknr = k >> 8;
		if (j == 0) {
			/* Find, get and unlock new data block */
			bp = __objms_find_data_block(pi, blocknr);
			p = objms_get_block(bp); 
			objms_memunlock_block(sbi, p);
		}
		p[j].block_low = cpu_to_le64(i->block_low);
		p[j].block_high = cpu_to_le64(i->block_high);
		j++;

		if (j == 256) {
			j = 0;
			/* Lock the data block */
			objms_memlock_block(sbi, p);
			objms_flush_buffer(p, 4096, false);
		}
		
		k++;
	}
	
	/* Lock the block */	
	if (j) {
		objms_flush_buffer(p, j << 4, false);
		objms_memlock_block(sbi, p);	
	}	

	/* 
	 * save the total allocated blocknode mappings 
	 * in super block
	 */
	objms_add_logentry(trans, &super->s_num_blocknode_allocated,
			OBJMS_FAST_MOUNT_FIELD_SIZE, false);

	objms_memunlock_range(sbi, &super->s_num_blocknode_allocated, OBJMS_FAST_MOUNT_FIELD_SIZE);

	//super->s_wtime = cpu_to_le32(get_seconds());
	super->s_num_blocknode_allocated = 
			cpu_to_le64(sbi->num_blocknode_allocated);
	super->s_num_free_blocks = cpu_to_le64(sbi->num_free_blocks);
	super->s_inodes_count = cpu_to_le32(sbi->s_inodes_count);
	super->s_free_inodes_count = cpu_to_le32(sbi->s_free_inodes_count);
	//super->s_inodes_used_count = cpu_to_le32(sbi->s_inodes_used_count);
	super->s_free_inode_hint = cpu_to_le32(sbi->s_free_inode_hint);

	objms_memlock_range(sbi, &super->s_num_blocknode_allocated, OBJMS_FAST_MOUNT_FIELD_SIZE);
	objms_add_logentry_info(trans, &super->s_num_blocknode_allocated,
			OBJMS_FAST_MOUNT_FIELD_SIZE);
	/* commit the transaction */
	sys_objms_commit_txn(tid);
}

static void objms_inode_crawl_recursive(struct objms_sb_info *sbi,
				struct scan_bitmap *bm, unsigned long block,
				u32 height, u8 btype)
{
	__le64 *node;
	unsigned int i;

	if (height == 0) {
		/* This is the data block */
		if (btype == OBJMS_BLOCK_TYPE_4K) {
			set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
		} else if (btype == OBJMS_BLOCK_TYPE_2M) {
			set_bit(block >> PAGE_SHIFT_2M, bm->bitmap_2M);
		} else {
			set_bit(block >> PAGE_SHIFT_1G, bm->bitmap_1G);
		}
		return;
	}

	node = objms_get_block(block);
	set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
	for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
		if (node[i] == 0)
			continue;
		objms_inode_crawl_recursive(sbi, bm,
			le64_to_cpu(node[i]), height - 1, btype);
	}
}

static inline void objms_inode_crawl(struct objms_sb_info *sbi,
				struct scan_bitmap *bm, struct objms_inode *pi)
{
	if (pi->root == 0)
		return;
	objms_inode_crawl_recursive(sbi, bm, le64_to_cpu(pi->root), pi->height,
					pi->i_blk_type);
}

static void objms_inode_table_crawl_recursive(struct objms_sb_info *sbi,
				struct scan_bitmap *bm, unsigned long block,
				u32 height, u32 btype)
{
	__le64 *node;
	unsigned int i;
	struct objms_inode *pi;
	
	node = objms_get_block(block);

	if (height == 0) {
		unsigned int inodes_per_block = INODES_PER_BLOCK(btype);
		if (likely(btype == OBJMS_BLOCK_TYPE_2M))
			set_bit(block >> PAGE_SHIFT_2M, bm->bitmap_2M);
		else
			set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);

		sbi->s_inodes_count += inodes_per_block;
    sbi->s_free_inodes_count += inodes_per_block;
		for (i = 0; i < inodes_per_block; i++) {
			pi = (struct objms_inode *)((void *)node +
                                                        OBJMS_INODE_SIZE * i);
			if (le16_to_cpu(pi->i_flags) == 0){
          //|| le32_to_cpu(pi->i_dtime)) {
					/* Empty inode */
					continue;
			}
			//sbi->s_inodes_used_count++;
			sbi->s_free_inodes_count--;
			objms_inode_crawl(sbi, bm, pi);
		}
		return;
	}

	set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
	for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
		if (node[i] == 0)
			continue;
		objms_inode_table_crawl_recursive(sbi, bm,
			le64_to_cpu(node[i]), height - 1, btype);
	}
}

static int objms_alloc_insert_blocknode_map(struct objms_sb_info *sbi,
	unsigned long low, unsigned long high)
{
	struct list_head *head = &(sbi->free_block_head);//@ayu: FIXME, BUG
	struct objms_blocknode *i, *next_i;
	struct objms_blocknode *free_blocknode= NULL;
	unsigned long num_blocks = 0;
	struct objms_blocknode *curr_node;
	int errval = 0;
	bool found = 0;
	unsigned long next_block_low;
	unsigned long new_block_low;
	unsigned long new_block_high;

	//num_blocks = objms_get_numblocks(btype);

	new_block_low = low;
	new_block_high = high;
	num_blocks = high - low + 1;

	list_for_each_entry(i, head, link) {
		if (i->link.next == head) {
			next_i = NULL;
			next_block_low = sbi->block_end;
		} else {
			next_i = list_entry(i->link.next, typeof(*i), link);
			next_block_low = next_i->block_low;
		}


		if (new_block_high >= next_block_low) {
			/* Does not fit - skip to next blocknode */
			continue;
		}

		if ((new_block_low == (i->block_high + 1)) &&
			(new_block_high == (next_block_low - 1)))
		{
			/* Fill the gap completely */
			if (next_i) {
				i->block_high = next_i->block_high;
				list_del(&next_i->link);
				free_blocknode = next_i;
			} else {
				i->block_high = new_block_high;
			}
			found = 1;
			break;
		}

		if ((new_block_low == (i->block_high + 1)) &&
			(new_block_high < (next_block_low - 1))) {
			/* Aligns to left */
			i->block_high = new_block_high;
			found = 1;
			break;
		}

		if ((new_block_low > (i->block_high + 1)) &&
			(new_block_high == (next_block_low - 1))) {
			/* Aligns to right */
			if (next_i) {
				/* right node exist */
				next_i->block_low = new_block_low;
			} else {
				/* right node does NOT exist */
				curr_node = objms_alloc_blocknode(sbi);
				OBJMS_ASSERT(curr_node);
				if (curr_node == NULL) {
					errval = -ENOSPC;
					break;
				}
				curr_node->block_low = new_block_low;
				curr_node->block_high = new_block_high;
				list_add(&curr_node->link, &i->link);
			}
			found = 1;
			break;
		}

		if ((new_block_low > (i->block_high + 1)) &&
			(new_block_high < (next_block_low - 1))) {
			/* Aligns somewhere in the middle */
			curr_node = objms_alloc_blocknode(sbi);
			OBJMS_ASSERT(curr_node);
			if (curr_node == NULL) {
				errval = -ENOSPC;
				break;
			}
			curr_node->block_low = new_block_low;
			curr_node->block_high = new_block_high;
			list_add(&curr_node->link, &i->link);
			found = 1;
			break;
		}
	}
	
	if (found == 1) {
		sbi->num_free_blocks -= num_blocks;
	}	

	if (free_blocknode)
		objms_free_blocknode(sbi, free_blocknode);

	if (found == 0) {
		return -ENOSPC;
	}


	return errval;
}

static int __objms_build_blocknode_map(struct objms_sb_info *sbi,
	unsigned long *bitmap, unsigned long bsize, unsigned long scale)
{
	unsigned long next = 1;
	unsigned long low = 0;

	while (1) {
		next = find_next_bit(bitmap, bsize, next);
		if (next == bsize)
			break;
		low = next;
		next = find_next_zero_bit(bitmap, bsize, next);
		if (objms_alloc_insert_blocknode_map(sbi, low << scale ,
				(next << scale) - 1)) {
			printk("OBJMS: Error could not insert 0x%lx-0x%lx\n",
				low << scale, ((next << scale) - 1));
		}
		if (next == bsize)
			break;
	}
	return 0;
}
	
static void objms_build_blocknode_map(struct objms_sb_info *sbi,
							struct scan_bitmap *bm)
{
	__objms_build_blocknode_map(sbi, bm->bitmap_4k, bm->bitmap_4k_size * 8,
		PAGE_SHIFT - 12);
	__objms_build_blocknode_map(sbi, bm->bitmap_2M, bm->bitmap_2M_size * 8,
		PAGE_SHIFT_2M - 12);
	__objms_build_blocknode_map(sbi, bm->bitmap_1G, bm->bitmap_1G_size * 8,
		PAGE_SHIFT_1G - 12);
}

int objms_setup_blocknode_map(struct objms_sb_info *sbi)
{
	struct objms_super_block *super = objms_get_super(sbi);
	struct objms_inode *pi = objms_get_inode_table(sbi);
	objms_journal_t *journal = objms_get_journal(sbi);
	struct scan_bitmap bm;
	unsigned long initsize = le64_to_cpu(super->s_size);
	bool value = false;

	mutex_init(&sbi->inode_table_mutex);
	sbi->block_start = (unsigned long)0;
	sbi->block_end = ((unsigned long)(initsize) >> PAGE_SHIFT);
	
	value = objms_can_skip_full_scan(sbi);
	if (value) {
		//objms_dbg_verbose("OBJMS: Skipping full scan of inodes...\n");
		return 0;
	}

	bm.bitmap_4k_size = (initsize >> (PAGE_SHIFT + 0x3)) + 1;
	bm.bitmap_2M_size = (initsize >> (PAGE_SHIFT_2M + 0x3)) + 1;
	bm.bitmap_1G_size = (initsize >> (PAGE_SHIFT_1G + 0x3)) + 1;

	/* Alloc memory to hold the block alloc bitmap */
	bm.bitmap_4k = kzalloc(bm.bitmap_4k_size, GFP_KERNEL);
	bm.bitmap_2M = kzalloc(bm.bitmap_2M_size, GFP_KERNEL);
	bm.bitmap_1G = kzalloc(bm.bitmap_1G_size, GFP_KERNEL);

	if (!bm.bitmap_4k || !bm.bitmap_2M || !bm.bitmap_1G)
		goto skip;
	
	/* Clearing the datablock inode */
	objms_clear_datablock_inode(sbi);

	objms_inode_table_crawl_recursive(sbi, &bm, le64_to_cpu(pi->root),
						pi->height, pi->i_blk_type);

	/* Reserving three inodes - Inode 0, naming object, and Inode for datablock */
	//sbi->s_free_inodes_count = sbi->s_inodes_count -  
	//	(sbi->s_inodes_used_count + 2);
	sbi->s_free_inodes_count -= 3;  
	
	/* set the block 0 as this is used */
	sbi->s_free_inode_hint = OBJMS_FREE_INODE_HINT_START;

	/* initialize the num_free_blocks to */
	sbi->num_free_blocks = ((unsigned long)(initsize) >> PAGE_SHIFT);
	objms_init_blockmap(sbi, le64_to_cpu(journal->journal_base) + sbi->jsize);

	objms_build_blocknode_map(sbi, &bm);

skip:
	
	kfree(bm.bitmap_4k);
	kfree(bm.bitmap_2M);
	kfree(bm.bitmap_1G);

	return 0;
}
