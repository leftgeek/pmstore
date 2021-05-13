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
#include "objms.h"

void objms_init_blockmap(struct objms_sb_info *sbi, unsigned long init_used_size){
	unsigned long num_used_block;

	num_used_block = (init_used_size + sbi->blocksize - 1) >>
		sbi->blocksize_bits;

	sbi->block_start += num_used_block;
  //sbi->per_node_blocks = (sbi->block_end - sbi->block_start) / sbi->cpus;
  sbi->per_node_blocks = sbi->block_end / sbi->cpus;
}

static inline struct list_head *objms_get_blockhead(unsigned long blocknr){
  objms_flusher_thread_t *flusher_thread;
  struct list_head *head;
  //int cpu = (blocknr - objms_sbi->block_start) / objms_sbi->per_node_blocks;
  int cpu = blocknr / objms_sbi->per_node_blocks;

  flusher_thread = &(objms_sbi->log_flusher_threads[cpu]);
  head = &(flusher_thread->free_block_head);

  return head;
}
//get the block head of a resource node
static struct objms_blocknode *objms_next_blocknode(struct objms_blocknode *i,
						  struct list_head *head){
	if (list_is_last(&i->link, head))
		return NULL;
	return list_first_entry(&i->link, typeof(*i), link);
}

/* Caller must hold the super_block lock.  If start_hint is provided, it is
 * only valid until the caller releases the super_block lock. */
void __objms_free_block(struct objms_sb_info *sbi,
    objms_flusher_thread_t *flusher_thread, unsigned long blocknr,
		      unsigned long num_blocks, struct objms_blocknode **start_hint){
	struct list_head *head = &(flusher_thread->free_block_head);
	unsigned long new_block_low;
	unsigned long new_block_high;
	struct objms_blocknode *i;
	struct objms_blocknode *free_blocknode= NULL;
	struct objms_blocknode *curr_node;

	new_block_low = blocknr;
	new_block_high = blocknr + num_blocks - 1;
  if (list_empty(head)){
    curr_node = objms_alloc_blocknode(sbi);
    OBJMS_ASSERT(curr_node);
    if (curr_node == NULL) {
      /* returning without freeing the block*/
      goto block_found;
    }
    curr_node->block_low = new_block_low;
    curr_node->block_high = new_block_high;
    list_add_tail(&curr_node->link, head);
    flusher_thread->num_free_blocks += num_blocks;
    goto block_found;
  }

  //TODO: start_hint is used for what?
	/*if (start_hint && *start_hint &&
	    new_block_low >= (*start_hint)->block_low)
		i = *start_hint;
	else*/
		i = list_first_entry(head, typeof(*i), link);

	list_for_each_entry_from(i, head, link) {
    if (new_block_low < i->block_low){
      if (new_block_high + 1 == i->block_low){
        i->block_low -= num_blocks;
        flusher_thread->num_free_blocks += num_blocks;
      } else {
        curr_node = objms_alloc_blocknode(sbi);
        OBJMS_ASSERT(curr_node);
        if (curr_node == NULL) {
          /* returning without freeing the block*/
          goto block_found;
        }
        curr_node->block_low = new_block_low;
        curr_node->block_high = new_block_high;
        list_add(&curr_node->link, &i->link);
        flusher_thread->num_free_blocks += num_blocks;
        //if (start_hint)
        //  *start_hint = curr_node;
      }
      goto block_found;
    } else {
      struct objms_blocknode *next_i = NULL;
      if (i->link.next != head){//i is not the last entry
        next_i = list_entry(i->link.next, typeof(*i), link);
      }
      if (new_block_low == i->block_high + 1){//merge after i
        i->block_high += num_blocks;
        if (next_i && (i->block_high + 1 == next_i->block_low)){
          //merge i and next_i by removing i
          next_i->block_low = i->block_low;
          free_blocknode = i;
          list_del(&i->link);
        }
        flusher_thread->num_free_blocks += num_blocks;
        goto block_found;
      } else if (!next_i){//insert after i
        curr_node = objms_alloc_blocknode(sbi);
        OBJMS_ASSERT(curr_node);
        if (curr_node == NULL) {
          /* returning without freeing the block*/
          goto block_found;
        }
        curr_node->block_low = new_block_low;
        curr_node->block_high = new_block_high;
        list_add_tail(&curr_node->link, head);
        flusher_thread->num_free_blocks += num_blocks;
        //if (start_hint)
        //  *start_hint = curr_node;
        goto block_found;
      }
    }
	}

block_found:

	if (free_blocknode)
		__objms_free_blocknode(free_blocknode);
}

inline void objms_free_block(struct objms_sb_info *sbi, unsigned long blocknr,
		      unsigned short btype){
  //int cpu = (blocknr - sbi->block_start) / sbi->per_node_blocks;
  int cpu = blocknr / sbi->per_node_blocks;
  objms_flusher_thread_t *flusher_thread = &(sbi->log_flusher_threads[cpu]);

  spin_lock(&flusher_thread->block_list_lock);
  //mutex_lock(&flusher_thread->block_list_lock);
	__objms_free_block(sbi, flusher_thread, blocknr, objms_get_numblocks(btype), NULL);
  spin_unlock(&flusher_thread->block_list_lock);
  //mutex_unlock(&flusher_thread->block_list_lock);
}

inline void objms_free_num_blocks(struct objms_sb_info *sbi, unsigned long blocknr,
		      unsigned long num_blocks){
  //int cpu = (blocknr - sbi->block_start) / sbi->per_node_blocks;
  int cpu = blocknr / sbi->per_node_blocks;
  objms_flusher_thread_t *flusher_thread = &(sbi->log_flusher_threads[cpu]);
  /*int cpu2 = (blocknr + num_blocks - 1) / sbi->per_node_blocks;
  if (cpu != cpu2){
    printk(KERN_ERR "@objms_free_num_blocks: cpu1=%d,cpu2=%d\n", cpu, cpu2);
  }*/

  spin_lock(&flusher_thread->block_list_lock);
  //mutex_lock(&flusher_thread->block_list_lock);
	__objms_free_block(sbi, flusher_thread, blocknr, num_blocks, NULL);
  spin_unlock(&flusher_thread->block_list_lock);
  //mutex_unlock(&flusher_thread->block_list_lock);
}

//will not increase the i_blocks of the inode
int objms_new_block(objms_transaction_t *trans, unsigned long *blocknr,
	unsigned short btype, int zero){
  struct objms_sb_info *sbi = objms_sbi;
	struct objms_blocknode *bn;
	struct objms_blocknode *free_blocknode= NULL;
	void *bp;
	unsigned long num_blocks = 0;
	int errval = 0;
	bool found = 0;
	unsigned long new_block_low, new_block_high;
#ifdef OBJMS_CPU_ROUND_ROBIN
  static int cpu = 0;
#else
  //int cpu = 0;
  int cpu = smp_processor_id() % sbi->cpus;
#endif
  objms_flusher_thread_t *flusher_thread = &(sbi->log_flusher_threads[cpu % sbi->cpus]);
#ifdef OBJMS_CPU_ROUND_ROBIN
  cpu = (cpu + 1) % sbi->cpus;
#endif

	num_blocks = objms_get_numblocks(btype);//@ayu:num_blocks=(block_size/4k)(1, 512, 0x40000)

retry_alloc:
  spin_lock(&flusher_thread->block_list_lock);
  //mutex_lock(&flusher_thread->block_list_lock);
  //@ayu: alloc blocks from other flusher_threads
  if (unlikely(!flusher_thread->num_free_blocks)){
    spin_unlock(&flusher_thread->block_list_lock);
    //mutex_unlock(&flusher_thread->block_list_lock);
    //wakeup_log_cleaner(sbi);//@ayu: FIXME
    cond_resched();
    cpu = (cpu + 1) % sbi->cpus;
    flusher_thread = &(sbi->log_flusher_threads[cpu]);
    goto retry_alloc;
  }
	struct list_head *head = &(flusher_thread->free_block_head);
  
  list_for_each_entry(bn, head, link){
    //new_block_low = bn->block_low;//@ayu: FIXME, we removed aligned
    //inode table是大页2MB
    new_block_low = (bn->block_low + num_blocks - 1) & ~(num_blocks - 1);//page-aligned
    new_block_high = new_block_low + num_blocks - 1;
    //@ayu:一定得从new_block_low开始分配！
    if (new_block_low == bn->block_low){
      if (new_block_high < bn->block_high){
        bn->block_low += num_blocks;
        found = 1;
        break;
      } else if (new_block_high == bn->block_high){
        list_del(&bn->link);
        free_blocknode = bn;
        found = 1;
        break;
      }
    } else {
      if (new_block_high < bn->block_high){
        //split the bn into two parts!
        //head part:bn->block_low ~ new_block_low - 1
        struct objms_blocknode *newbn = objms_alloc_blocknode(objms_sbi);
        newbn->block_low = bn->block_low;
        newbn->block_high = new_block_low - 1;
        list_add(&newbn->link, &bn->link);

        //tail part: new_block_high + 1 ~ bn->block_high
        bn->block_low = new_block_high + 1;
        found = 1;
        break;
      } else if (new_block_high == bn->block_high){
        bn->block_high = new_block_low - 1;
        found = 1;
        break;
      }
    }
  }
	
	if (found == 1) {
		flusher_thread->num_free_blocks -= num_blocks;
	}	

  //printk(KERN_ERR "@objms_new_block:block_low=%lu,num=%u,flusher_thread[%d]-left=%d\n",
  //    new_block_low, num_blocks, cpu, flusher_thread->num_free_blocks);
  spin_unlock(&flusher_thread->block_list_lock);
  //mutex_unlock(&flusher_thread->block_list_lock);

	if (free_blocknode)
		__objms_free_blocknode(free_blocknode);

	if (found == 0) {
		return -ENOSPC;
	}
clear_blk:
	if (zero) {
		size_t size;
		bp = objms_get_block(objms_get_block_off(new_block_low));
		objms_memunlock_block(sbi, bp); //TBDTBD: Need to fix this
		if (btype == OBJMS_BLOCK_TYPE_4K)
			size = 0x1 << 12;
		else if (btype == OBJMS_BLOCK_TYPE_2M)
			size = 0x1 << 21;
		else
			size = 0x1 << 30;
    /*if (btype == OBJMS_BLOCK_TYPE_2M){
      printk(KERN_ERR "@objms_new_block: btype=2mb,bp=%p,blocknr=%lu,num=%u\n",
          bp, new_block_low, num_blocks);
    }*/
		memset_nt(bp, 0, size);
		objms_memlock_block(sbi, bp);
	}
	*blocknr = new_block_low;
  //printk(KERN_ERR "@objms_new_block:block_low=%lu,num=%u\n",
  //    new_block_low, num_blocks);

	return errval;
}
//@ayu: FIXME, TODO
//allocate continuous blocks for memory objects
//return number of blocks left
//if *blocknr != 0, then allocate from *blocknr
int objms_new_extent_block(objms_transaction_t *trans, unsigned long *blocknr,
	unsigned int count, int zero){
  struct objms_sb_info *sbi = objms_sbi;
	struct objms_blocknode *i;
	struct objms_blocknode *free_blocknode= NULL;
	void *bp;
	unsigned long num_blocks = 0;//actually allocated block count
	unsigned long new_block_low;
	unsigned long new_block_high;
  unsigned long start_hint = *blocknr;
	int left;
	bool found = 0;
#ifdef OBJMS_CPU_ROUND_ROBIN
  static int cpu = 0;
#else
  //int cpu = 0;
  int cpu = smp_processor_id() % sbi->cpus;
#endif
  objms_flusher_thread_t *flusher_thread = &(sbi->log_flusher_threads[cpu % sbi->cpus]);
#ifdef OBJMS_CPU_ROUND_ROBIN
  cpu = (cpu + 1) % sbi->cpus;
#endif

	num_blocks = count;
  left = count;

retry_alloc:
  spin_lock(&flusher_thread->block_list_lock);
  //mutex_lock(&flusher_thread->block_list_lock);
  //@ayu: alloc blocks from other flusher_threads
  if (unlikely(!flusher_thread->num_free_blocks)){
    spin_unlock(&flusher_thread->block_list_lock);
    //mutex_unlock(&flusher_thread->block_list_lock);
    //wakeup_log_cleaner(sbi);//@ayu: FIXME
    cond_resched();
    cpu = (cpu + 1) % sbi->cpus;
    flusher_thread = &(sbi->log_flusher_threads[cpu]);
    goto retry_alloc;
  }
	struct list_head *head = &(flusher_thread->free_block_head);//TODO: if *blocknr=0

	list_for_each_entry(i, head, link) {
    //if the start_hint is set, try to fulfill it
    if (unlikely(start_hint > 0)){
      if (start_hint < i->block_low){
        //printk(KERN_ERR "@objms_new_extent_block: start_hint is not available:%lu,bl=%lu,bh=%lu\n", 
        //    start_hint, i->block_low, i->block_high);
        spin_unlock(&flusher_thread->block_list_lock);
        //mutex_unlock(&flusher_thread->block_list_lock);
        return left;//@ayu: FIXME, TODO: if start_hint failed, return -ENOSPC
      }
      if (start_hint > i->block_high){
        continue;
      }
      //now we can allocate from the start_hint
      new_block_low = start_hint;
      new_block_high = new_block_low + num_blocks - 1;

      if (new_block_high >= i->block_high){
        left = new_block_high - i->block_high;
        if (new_block_low == i->block_low){
          list_del(&i->link);
          free_blocknode = i;
        } else {
          i->block_high = new_block_low - 1;
        }
        found = 1;
        break;
      } else {
        left = 0;
        if (new_block_low == i->block_low){
          i->block_low += num_blocks;
        } else {
          //entry is is split into two entries
          struct objms_blocknode *curr_node = objms_alloc_blocknode(sbi);
          curr_node->block_low = i->block_low;
          curr_node->block_high = new_block_low - 1;
          list_add(&curr_node->link, &i->link);

          i->block_low = new_block_high + 1;
        }
        found = 1;
        break;
      }
    } else {
      //allocate from the lowest available block
      new_block_low = i->block_low;
      new_block_high = new_block_low + num_blocks - 1;

      //FIXME, TODO: we need to consider if an allocation is not enough
      //strategy 2: best suitable alocation
      /*if (new_block_high > i->block_high) {
        continue;
      }*/
      //strategy 1: first part available allocation
      if (new_block_high >= i->block_high){
        left = new_block_high - i->block_high;
        list_del(&i->link);
        free_blocknode = i;
        found = 1;
        break;
      } else {
        i->block_low += num_blocks;
        left = 0;
        found = 1;
        break;
      }
    }
	}
	
	if (found == 1) {
		flusher_thread->num_free_blocks -= num_blocks - left;
	}	

  //printk(KERN_ERR "@objms_new_extent_block:block_low=%lu,num=%u,flusher_thread[%d]-left=%d\n",
  //    new_block_low, num_blocks - left, cpu, flusher_thread->num_free_blocks);
  spin_unlock(&flusher_thread->block_list_lock);
  //mutex_unlock(&flusher_thread->block_list_lock);

	if (free_blocknode)
		__objms_free_blocknode(free_blocknode);

	if (found == 0) {
		return -ENOSPC;
	}
clear_blk:
	if (zero) {
		size_t size;
		bp = objms_get_block(objms_get_block_off(new_block_low));
		objms_memunlock_block(sbi, bp); //TBDTBD: Need to fix this
		/*if (btype == OBJMS_BLOCK_TYPE_4K)
			size = 0x1 << 12;
		else if (btype == OBJMS_BLOCK_TYPE_2M)
			size = 0x1 << 21;
		else
			size = 0x1 << 30;*/
    size = (num_blocks - left) << PAGE_SHIFT;
		memset_nt(bp, 0, size);
		objms_memlock_block(sbi, bp);
	}
	*blocknr = new_block_low;
  //printk(KERN_ERR "@objms_new_extent_block:block_low=%lu,num=%u,flusher_thread[%d]-left=%d\n",
  //    new_block_low, num_blocks - left, flusher_thread->num_free_blocks);

	return left;
}



unsigned long objms_count_free_blocks(struct objms_sb_info *sbi){
  objms_flusher_thread_t *flusher_thread;
  unsigned long num_free_blocks = 0;
  int cpu;

  for (cpu = 0; cpu < sbi->cpus; cpu++){
    flusher_thread = &(sbi->log_flusher_threads[cpu]);
    num_free_blocks += flusher_thread->num_free_blocks;
  }
	return num_free_blocks; 
}
