/*
 * BRIEF DESCRIPTION
 *
 * Inode methods (allocate/free/read/write).
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

#include <linux/fs.h>
#include <linux/bootmem.h>
#include <linux/aio.h>
#include <linux/sched.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include <linux/syscalls.h>
#include <linux/hash.h>
#include "objms.h"

#define OBJMS_I_HASHBITS  objms_i_hash_shift
#define OBJMS_I_HASHMASK  objms_i_hash_mask

static unsigned int objms_i_hash_mask __read_mostly;
static unsigned int objms_i_hash_shift __read_mostly;

struct hlist_head *objms_inode_hashtable __read_mostly;
static __initdata unsigned long objms_ihash_entries = 0;

//a simple spinlock to protect the list manipulations
//also protects i_state
DEFINE_SPINLOCK(objms_inode_lock);

unsigned int blk_type_to_shift[OBJMS_BLOCK_TYPE_MAX] = {12, 21, 30};
uint32_t blk_type_to_size[OBJMS_BLOCK_TYPE_MAX] = {0x1000, 0x200000, 0x40000000};

static inline void objms_wait_on_inode(struct objms_inode_info *inode){
  might_sleep();
  //wait for a bit to be cleared
  //__I_NEW=3,I_NEW=1<<__I_NEW
  wait_on_bit(&inode->i_state, __I_NEW, TASK_UNINTERRUPTIBLE);
}
/*
static void objms_wake_up_inode(struct objms_inode_info *inode){
  smp_mb();
  wake_up_bit(&inode->i_state, __I_NEW);
}*/
//inode->i_lock must be held
static inline void __objms_iget(struct objms_inode_info *inode){
  atomic_inc(&inode->i_count);
}

static inline unsigned long objms_hash(unsigned long hashval){
  unsigned long tmp;
  tmp = (hashval * (unsigned long)objms_sbi) ^ (GOLDEN_RATIO_PRIME + hashval)
    / L1_CACHE_BYTES;
  tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> OBJMS_I_HASHBITS);
  return tmp & OBJMS_I_HASHMASK;
  //return (hashval >> OBJMS_INODE_BITS) & OBJMS_I_HASHMASK;
}

int __init init_inode_hashtable(void){
  int loop;

  /*objms_inode_cachep = kmem_cache_create("objms_inode_cache",
      sizeof(struct objms_inode_info),
      0,
      (SLAB_RECLAIM_ACCOUNT | SLAB_PANIC | SLAB_MEM_SPREAD),
      init_once);
  if (objms_inode_cachep == NULL){
    printk(KERN_ERR "#objms: objms_inode_init: objms_inode_cache init failed!\n");
    return -ENOMEM;
  }*/

  /*if (hashdist){
    objms_inode_hashtable = objms_alloc_large_system_hash("objms-inode-cache",//we can't use this function because it's used in bootmem
        sizeof(struct hlist_head),
        objms_ihash_entries,
        14,
        0,
        &objms_i_hash_shift,
        &objms_i_hash_mask,
        4096);
  } else {*/
    objms_inode_hashtable = alloc_large_system_hash("objms-inode-cache",//FIXME: this function is in mm/page_alloc.c
        sizeof(struct hlist_head),
        objms_ihash_entries,
        14,
        0,//HASH_EARLY,
        &objms_i_hash_shift,
        &objms_i_hash_mask,
        0, 0);
  //}

  if (objms_inode_hashtable == NULL){
    printk(KERN_ERR "#objms: objms_inode_init: objms_inode_hashtable init failed!\n");
    return -ENOMEM;
  }
  for (loop = 0; loop < (1U << objms_i_hash_shift); loop++){
    INIT_HLIST_HEAD(&objms_inode_hashtable[loop]);
  }
  return 0;
}

void __objms_insert_inode_hash(struct objms_inode_info *inode, unsigned long hashval){
  struct hlist_head *head = objms_inode_hashtable + objms_hash(hashval);
  spin_lock(&objms_inode_lock);
  spin_lock(&inode->i_lock);
  hlist_add_head(&inode->i_hash, head);
  spin_unlock(&inode->i_lock);
  spin_unlock(&objms_inode_lock);
}

static inline void objms_insert_inode_hash(struct objms_inode_info *inode){
  __objms_insert_inode_hash(inode, inode->i_ino);
}

//remove an inode from the hash
void __objms_remove_inode_hash(struct objms_inode_info *inode){
  spin_lock(&objms_inode_lock);
  spin_lock(&inode->i_lock);
  hlist_del_init(&inode->i_hash);
  spin_unlock(&inode->i_lock);
  spin_unlock(&objms_inode_lock);
}

static inline int objms_inode_unhashed(struct objms_inode_info *inode){
  return hlist_unhashed(&inode->i_hash);
}

void objms_remove_inode_hash(struct objms_inode_info *inode){
  if (!objms_inode_unhashed(inode)){
    __objms_remove_inode_hash(inode);
  }
}
//caller hold inode->i_lock
//FIXME
//释放inode空间，可能需要删除其对应的对象
static void objms_iput_final(objms_transaction_t *trans, struct objms_inode_info *inode){
  int drop;
  
  drop = (inode->pi->i_flags & OBJMS_INODE_BEFREE) || objms_inode_unhashed(inode);

  if (!drop){//no need to drop
    if (objms_sbi->s_flags & MS_ACTIVE){
      spin_unlock(&inode->i_lock);
      return;
    }
    //FIXME:if fs is shutting down, do the following...
    WARN_ON(inode->i_state & I_NEW);
  }

  inode->i_state |= I_FREEING;
  spin_unlock(&inode->i_lock);
  //free inode->pi
  objms_evict_inode(trans, inode);//FIXME: not finished yet
  //clear inode
  inode->i_state = I_FREEING | I_CLEAR;

  //free inode_info
  objms_remove_inode_hash(inode);
  spin_lock(&inode->i_lock);
  wake_up_bit(&inode->i_state, __I_NEW);
  spin_unlock(&inode->i_lock);

  objms_destroy_inode(inode);

}

inline void objms_iput(objms_transaction_t *trans, struct objms_inode_info *inode){
  if (inode){
    //BUG_ON(inode->i_state & I_CLEAR);
    if (atomic_dec_and_lock(&inode->i_count, &inode->i_lock)){
      objms_iput_final(trans, inode);
    }
  }
}

void objms_make_bad_inode(struct objms_inode_info *inode){
  objms_remove_inode_hash(inode);
  //set inode field NULL
}

void objms_unlock_new_inode(struct objms_inode_info *inode){
  spin_lock(&inode->i_lock);
  inode->i_state &= ~I_NEW;
  wake_up_bit(&inode->i_state, __I_NEW);
  spin_unlock(&inode->i_lock);
}

void objms_iget_failed(objms_transaction_t *trans, struct objms_inode_info *inode){
  objms_make_bad_inode(inode);
  objms_unlock_new_inode(inode);
  objms_iput(trans, inode);
}

/*
 * allocate a data block for inode and return it's absolute blocknr.
 * Zeroes out the block if zero set. Increments inode->i_blocks.
 */
//will increase the i_blocks of the inode
//以对象的实际块大小为单位分配一个数据块
static int objms_new_data_block(objms_transaction_t *trans, struct objms_inode *pi,
    unsigned long *blocknr, int zero)
{
  unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];

  int errval = objms_new_block(trans, blocknr, pi->i_blk_type, zero);
/*
 * FIXME: moved to __objms_alloc_blocks()
  if (!errval) {
    objms_memunlock_inode(objms_sbi, pi);
    le64_add_cpu(&pi->i_blocks,
        (1 << (data_bits - objms_sbi->blocksize_bits)));
    objms_memlock_inode(objms_sbi, pi);
  }
*/
  return errval;
}
//will increase the i_blocks of the inode
//we allow allocated <= count
static int objms_new_memory_block(objms_transaction_t *trans, struct objms_inode *pi,
    unsigned long *blocknr, unsigned int count, int zero){
  //unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
  int errval = objms_new_extent_block(trans, blocknr, count, zero);
/*
  if (errval >= 0) {
    objms_memunlock_inode(objms_sbi, pi);
    le64_add_cpu(&pi->i_blocks, count - errval);
    objms_memlock_inode(objms_sbi, pi);
  }*/
  return errval;
}

/*
 * find the offset to the block represented by the given inode's file
 * relative block number.
 */
//file_blocknr is 4K unit, __objms_find_data_block is actual blocksize unit
u64 objms_find_data_block(struct objms_sb_info *sbi, struct objms_inode *pi,
    unsigned long file_blocknr){
  u32 blk_shift;
  unsigned long blk_offset, blocknr = file_blocknr;
  unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];//@ayu:12, 21, 30
  unsigned int meta_bits = META_BLK_SHIFT;
  u64 bp;

  /* convert the 4K blocks into the actual blocks the inode is using */
  blk_shift = data_bits - sbi->blocksize_bits;
  blk_offset = file_blocknr & ((1 << blk_shift) - 1);
  blocknr = file_blocknr >> blk_shift;

  if (blocknr >= (1UL << (pi->height * meta_bits))){//@ayu:height <= 3
    return 0;
  }
#ifdef OBJMS_MEMORY_OBJECT
  if (likely(!pi->i_pattern)){
    bp = __objms_find_data_block(pi, blocknr);
  } else {
    bp = __objms_find_memory_data_block(pi, blocknr);
  }
#else
    bp = __objms_find_data_block(pi, blocknr);
#endif
  if (bp == 0)
    return 0;
  return bp + (blk_offset << sbi->blocksize_bits);
}

/* recursive_find_region: recursively search the btree to find hole or data
 * in the specified range
 * Input:
 * block: points to the root of the b-tree
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * @data_found: indicates whether data blocks were found
 * @hole_found: indicates whether a hole was found
 * hole: whether we are looking for a hole or data
 */
static int recursive_find_region(struct objms_sb_info *sbi, __le64 block,
    u32 height, unsigned long first_blocknr, unsigned long last_blocknr,
    int *data_found, int *hole_found, int hole)
{
  unsigned int meta_bits = META_BLK_SHIFT;
  __le64 *node;
  unsigned long first_blk, last_blk, node_bits, blocks = 0;
  unsigned int first_index, last_index, i;

  node_bits = (height - 1) * meta_bits;

  first_index = first_blocknr >> node_bits;
  last_index = last_blocknr >> node_bits;

  node = objms_get_block(le64_to_cpu(block));

  for (i = first_index; i <= last_index; i++) {
    if (height == 1 || node[i] == 0) {
      if (node[i]) {
        *data_found = 1;
        if (!hole)
          goto done;
      } else {
        *hole_found = 1;
      }

      if (!*hole_found || !hole)
        blocks += (1UL << node_bits);
    } else {
      first_blk = (i == first_index) ?  (first_blocknr &
          ((1 << node_bits) - 1)) : 0;

      last_blk = (i == last_index) ? (last_blocknr &
          ((1 << node_bits) - 1)) : (1 << node_bits) - 1;

      blocks += recursive_find_region(sbi, node[i], height - 1,
          first_blk, last_blk, data_found, hole_found,
          hole);
      if (!hole && *data_found)
        goto done;
      /* cond_resched(); */
    }
  }
done:
  return blocks;
}

/*
 * find the file offset for SEEK_DATA/SEEK_HOLE
 */
unsigned long objms_find_region(struct objms_sb_info *sbi,
    struct objms_inode *pi, loff_t *offset, int hole){
  unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
  unsigned long first_blocknr, last_blocknr;
  unsigned long blocks = 0, offset_in_block;
  int data_found = 0, hole_found = 0;

  if (*offset >= pi->i_size)
    return -ENXIO;

  if (!pi->i_blocks || !pi->root) {
    if (hole)
      return pi->i_size;
    else
      return -ENXIO;
  }

  offset_in_block = *offset & ((1UL << data_bits) - 1);

  if (pi->height == 0) {
    data_found = 1;
    goto out;
  }

  first_blocknr = *offset >> data_bits;
  last_blocknr = pi->i_size >> data_bits;

  blocks = recursive_find_region(sbi, pi->root, pi->height,
      first_blocknr, last_blocknr, &data_found, &hole_found, hole);

out:
  /* Searching data but only hole found till the end */
  if (!hole && !data_found && hole_found)
    return -ENXIO;

  if (data_found && !hole_found) {
    /* Searching data but we are already into them */
    if (hole)
      /* Searching hole but only data found, go to the end */
      *offset = pi->i_size;
    return 0;
  }

  /* Searching for hole, hole found and starting inside an hole */
  if (hole && hole_found && !blocks) {
    /* we found data after it */
    if (!data_found)
      /* last hole */
      *offset = pi->i_size;
    return 0;
  }

  if (offset_in_block) {
    blocks--;
    *offset += (blocks << data_bits) +
      ((1 << data_bits) - offset_in_block);
  } else {
    *offset += blocks << data_bits;
  }

  return 0;
}

/* examine the meta-data block node up to the end_idx for any non-null
 * pointers. if found return false, else return true.
 * required to determine if a meta-data block contains no pointers and hence
 * can be freed.
 */
static inline bool is_empty_meta_block(__le64 *node, unsigned int start_idx,
    unsigned int end_idx)
{
  int i, last_idx = (1 << META_BLK_SHIFT) - 1;
  for (i = 0; i < start_idx; i++)
    if (unlikely(node[i]))
      return false;
  for (i = end_idx + 1; i <= last_idx; i++)
    if (unlikely(node[i]))
      return false;
  return true;
}

/* recursive_truncate_blocks: recursively deallocate a range of blocks from
 * first_blocknr to last_blocknr in the inode's btree.
 * Input:
 * block: points to the root of the b-tree where the blocks need to be allocated
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * end: last byte offset of the range
 */
static int recursive_truncate_blocks(objms_transaction_t *trans, __le64 block,
    u32 height, u32 btype, unsigned long first_blocknr,
    unsigned long last_blocknr, bool *meta_empty)
{
  unsigned long blocknr, first_blk, last_blk;
  unsigned int node_bits, first_index, last_index, i;
  __le64 *node;
  unsigned int freed = 0, bzero;
  int start, end;
  bool mpty, all_range_freed = true;

  node = objms_get_block(le64_to_cpu(block));

  node_bits = (height - 1) * META_BLK_SHIFT;

  start = first_index = first_blocknr >> node_bits;
  end = last_index = last_blocknr >> node_bits;

  if (height == 1) {
    //struct objms_blocknode *start_hint = NULL;
    //mutex_lock(&sbi->s_lock);
    for (i = first_index; i <= last_index; i++) {
      if (unlikely(!node[i]))
        continue;
      
      //FIXME: free extent blocks at once
      /*unsigned long start_bnr = objms_get_blocknr(node[i]);
      unsigned int num_bnrs = 1, j;
      unsigned long next_bnr;
      for (j = i + 1; j <= last_index; j++){
        if (likely(node[j])){//only non-zero block need to be freed
          next_bnr = objms_get_blocknr(le64_to_cpu(node[j]));
          if (next_bnr == start_bnr + num_bnrs){
            num_bnrs++;
          } else {
            //FIXME: cowblk_list will not be redundant
            //num_bnrs << objms_get_numblocks(pi->i_blk_type));
            objms_add_cowblk_list(trans, start_bnr, num_bnrs);
            freed += num_bnrs;
            start_bnr = next_bnr;
            num_bnrs = 1;
          }
        }
      }
      objms_add_cowblk_list(trans, start_bnr, num_bnrs);
      freed += num_bnrs;
      i = j;*/
      unsigned long start_bnr = objms_get_blocknr(le64_to_cpu(node[i]));
      //objms_free_block(objms_sbi, start_bnr, btype);
      objms_add_cowblk_list(trans, start_bnr, objms_get_numblocks(btype));
      freed += objms_get_numblocks(btype);
    }
    //mutex_unlock(&sbi->s_lock);
  } else {
    for (i = first_index; i <= last_index; i++) {
      if (unlikely(!node[i]))
        continue;
      first_blk = (i == first_index) ? (first_blocknr &
          ((1 << node_bits) - 1)) : 0;

      last_blk = (i == last_index) ? (last_blocknr &
          ((1 << node_bits) - 1)) : (1 << node_bits) - 1;

      freed += recursive_truncate_blocks(trans, node[i],
          height - 1, btype, first_blk, last_blk, &mpty);
      /* cond_resched(); */
      if (mpty) {
        /* Freeing the meta-data block */
        blocknr = objms_get_blocknr(le64_to_cpu(node[i]));
        //objms_free_block(objms_sbi, blocknr,OBJMS_BLOCK_TYPE_4K);
        objms_add_cowblk_list(trans, blocknr, 1);
      } else {
        if (i == first_index)
          start++;
        else if (i == last_index)
          end--;
        all_range_freed = false;
      }
    }
  }
  if (all_range_freed &&
      is_empty_meta_block(node, first_index, last_index)) {
    *meta_empty = true;
  } else {
    /* Zero-out the freed range if the meta-block in not empty */
    if (start <= end) {
      bzero = (end - start + 1) * sizeof(u64);
      objms_memunlock_block(objms_sbi, node);
      memset(&node[start], 0, bzero);
      objms_memlock_block(objms_sbi, node);
      objms_flush_buffer(&node[start], bzero, false);
    }
    *meta_empty = false;
  }
  return freed;
}

unsigned int objms_free_inode_subtree(objms_transaction_t *trans,
    __le64 root, u32 height, u32 btype, unsigned long last_blocknr)
{
  unsigned long first_blocknr;
  unsigned int freed;
  bool mpty;

  if (!root){
    //printk(KERN_ERR "@objms_free_inode_subtree: root = null\n");
    return 0;
  }

  //@ayu: FIXME
  /*if (!trans){
    printk(KERN_ERR "@objms_free_inode_subtree: null trans 1\n");
    trans = objms_current_txn();
    if (!trans){
      printk(KERN_ERR "@objms_free_inode_subtree: null trans 2\n");
    }
  }*/
  if (height == 0) {
    first_blocknr = objms_get_blocknr(le64_to_cpu(root));
    //objms_free_block(objms_sbi, first_blocknr, btype);
    objms_add_cowblk_list(trans, first_blocknr, objms_get_numblocks(btype));
    freed = objms_get_numblocks(btype);
  } else {
    first_blocknr = 0;

    freed = recursive_truncate_blocks(trans, root, height, btype,
        first_blocknr, last_blocknr, &mpty);
    BUG_ON(!mpty);
    first_blocknr = objms_get_blocknr(le64_to_cpu(root));
    //objms_free_block(objms_sbi, first_blocknr, OBJMS_BLOCK_TYPE_4K);
    objms_add_cowblk_list(trans, first_blocknr, 1);
  }
  return freed;
}

static void objms_decrease_btree_height(struct objms_sb_info *sbi,
    struct objms_inode *pi, unsigned long newsize, __le64 newroot)
{
  unsigned int height = pi->height, new_height = 0;
  unsigned long blocknr, last_blocknr;
  __le64 *root;
  char b[8];

  if (pi->i_blocks == 0 || newsize == 0) {
    /* root must be NULL */
    BUG_ON(newroot != 0);
    goto update_root_and_height;
  }

  last_blocknr = ((newsize + objms_inode_blk_size(pi) - 1) >>
      objms_inode_blk_shift(pi)) - 1;
  while (last_blocknr > 0) {
    last_blocknr = last_blocknr >> META_BLK_SHIFT;
    new_height++;
  }
  if (height == new_height)
    return;
  //objms_dbg_verbose("reducing tree height %x->%x\n", height, new_height);
  while (height > new_height) {
    /* freeing the meta block */
    root = objms_get_block(le64_to_cpu(newroot));
    blocknr = objms_get_blocknr(le64_to_cpu(newroot));
    newroot = root[0];
    objms_free_block(sbi, blocknr, OBJMS_BLOCK_TYPE_4K);
    height--;
  }
update_root_and_height:
  /* pi->height and pi->root need to be atomically updated. use
   * cmpxchg16 here. The following is dependent on a specific layout of
   * inode fields */
  *(u64 *)b = *(u64 *)pi;
  /* pi->height is at offset 2 from pi */
  b[2] = (u8)new_height;
  /* TODO: the following function assumes cmpxchg16b instruction writes
   * 16 bytes atomically. Confirm if it is really true. */
  cmpxchg_double_local((u64 *)pi, &pi->root, *(u64 *)pi, pi->root,
      *(u64 *)b, newroot);
}

static unsigned long objms_inode_count_iblocks_recursive(struct objms_sb_info *sbi,
    __le64 block, u32 height)
{
  __le64 *node;
  unsigned int i;
  unsigned long i_blocks = 0;

  if (height == 0)
    return 1;
  node = objms_get_block(le64_to_cpu(block));
  for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
    if (node[i] == 0)
      continue;
    i_blocks += objms_inode_count_iblocks_recursive(sbi, node[i],
        height - 1);
  }
  return i_blocks;
}

static inline unsigned long objms_inode_count_iblocks (struct objms_sb_info *sbi,
    struct objms_inode *pi, __le64 root)
{
  unsigned long iblocks;
  if (root == 0)
    return 0;
  iblocks = objms_inode_count_iblocks_recursive(sbi, root, pi->height);
  return (iblocks << (objms_inode_blk_shift(pi) - sbi->blocksize_bits));
}

/* Support for sparse files: even though pi->i_size may indicate a certain
 * last_blocknr, it may not be true for sparse files. Specifically, last_blocknr
 * can not be more than the maximum allowed by the inode's tree height.
 */
static inline unsigned long objms_sparse_last_blocknr(unsigned int height,
    unsigned long last_blocknr)
{
  if (last_blocknr >= (1UL << (height * META_BLK_SHIFT)))
    last_blocknr = (1UL << (height * META_BLK_SHIFT)) - 1;
  return last_blocknr;
}

/*
 * Free data blocks from inode in the range start <=> end
 */
//@ayu: FIXME, currently it will not be called
//TODO: add blocks to cowblk_list instead of freeing it
static void __objms_truncate_blocks(objms_transaction_t *trans, struct objms_sb_info *sbi,
    struct objms_inode *pi, loff_t start, loff_t end){
  unsigned long first_blocknr, last_blocknr;
  __le64 root;
  unsigned int freed = 0;
  unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
  unsigned int meta_bits = META_BLK_SHIFT;
  bool mpty;
  //struct timespec i_mtime;

  if (!pi->root)
    goto end_truncate_blocks;

  first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

  if (pi->i_flags & cpu_to_le32(OBJMS_EOFBLOCKS_FL)) {
    last_blocknr = (1UL << (pi->height * meta_bits)) - 1;
  } else {
    if (end == 0)
      goto end_truncate_blocks;
    last_blocknr = (end - 1) >> data_bits;
    last_blocknr = objms_sparse_last_blocknr(pi->height,
        last_blocknr);
  }

  if (first_blocknr > last_blocknr)
    goto end_truncate_blocks;
  root = pi->root;

  if (pi->height == 0) {
    first_blocknr = objms_get_blocknr(le64_to_cpu(root));
    objms_free_block(sbi, first_blocknr, pi->i_blk_type);
    root = 0;
    freed = 1;
  } else {
    freed = recursive_truncate_blocks(trans, root, pi->height,
        pi->i_blk_type, first_blocknr, last_blocknr, &mpty);
    if (mpty) {
      first_blocknr = objms_get_blocknr(le64_to_cpu(root));
      objms_free_block(sbi, first_blocknr, OBJMS_BLOCK_TYPE_4K);
      root = 0;
    }
  }
  /* if we are called during mount, a power/system failure had happened.
   * Don't trust inode->i_blocks; recalculate it by rescanning the inode
   */
  objms_memunlock_inode(sbi, pi);
  if (objms_is_mounting(sbi))
    pi->i_blocks = objms_inode_count_iblocks(sbi, pi, root);
  else
    pi->i_blocks -= (freed * (1 << (data_bits -
            sbi->blocksize_bits)));

  //pi->i_blocks = cpu_to_le64(pi->i_blocks);
  //i_mtime = CURRENT_TIME_SEC;
  //pi->i_mtime = cpu_to_le32(i_mtime.tv_sec);
  //pi->i_ctime = cpu_to_le32(i_mtime.tv_sec);
  objms_decrease_btree_height(sbi, pi, start, root);
  /* Check for the flag EOFBLOCKS is still valid after the set size */
  check_eof_blocks(sbi, pi, pi->i_size);
  objms_memlock_inode(sbi, pi);
  /* now flush the inode's first cacheline which was modified */
  objms_flush_buffer(pi, 1, false);
  return;
end_truncate_blocks:
  /* we still need to update ctime and mtime */
  //objms_update_time(sbi, pi);
  objms_flush_buffer(pi, 1, false);
}

static int objms_increase_btree_height(objms_transaction_t *trans,
    struct objms_inode *pi, u32 new_height)
{
  u32 height = pi->height;
  __le64 *root, prev_root = pi->root;
  unsigned long blocknr;
  int errval = 0;

  //objms_dbg_verbose("increasing tree height %x:%x\n", height, new_height);
  while (height < new_height) {
    /* allocate the meta block */
    errval = objms_new_block(trans, &blocknr, OBJMS_BLOCK_TYPE_4K, 1);
    if (errval) {
      break;
    }
    blocknr = objms_get_block_off(blocknr);
    root = objms_get_block(blocknr);
    objms_memunlock_block(objms_sbi, root);
    root[0] = prev_root;
    objms_memlock_block(objms_sbi, root);
    objms_flush_buffer(root, sizeof(*root), false);
    prev_root = cpu_to_le64(blocknr);
    height++;
  }
  objms_memunlock_inode(objms_sbi, pi);
  pi->root = prev_root;
  pi->height = height;
  objms_memlock_inode(objms_sbi, pi);
  return errval;
}

/* recursive_alloc_blocks: recursively allocate a range of blocks from
 * first_blocknr to last_blocknr in the inode's btree.
 * Input:
 * block: points to the root of the b-tree where the blocks need to be allocated
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * zero: whether to zero-out the allocated block(s)
 */
//new_node: whether the block parameter is a newly allocated,
//only already alocated block will using log
#ifdef OBJMS_WEAK_XMODE
static int recursive_alloc_blocks(objms_transaction_t *trans,
    struct objms_sb_info *sbi, struct objms_inode *pi, __le64 block, u32 height,
    unsigned long first_blocknr, unsigned long last_blocknr, bool new_node,
    bool zero)
{
  int i, errval;
  unsigned int meta_bits = META_BLK_SHIFT, node_bits;
  __le64 *node;
  bool journal_saved = 0;
  unsigned long blocknr, first_blk, last_blk;
  unsigned int first_index, last_index;
  unsigned int flush_bytes;

  node = objms_get_block(le64_to_cpu(block));

  node_bits = (height - 1) * meta_bits;

  first_index = first_blocknr >> node_bits;
  last_index = last_blocknr >> node_bits;

  if (height == 1) {
    for (i = first_index; i <= last_index; i++) {
      if (node[i] == 0) {
        int j = i;
        //try to allocate all blocks in a time
        while (node[j + 1] == 0 && j < last_index){
          j++;
        }
        if (i < j){
          blocknr = 0;
          //printk(KERN_ERR "@recursive_alloc_blocks: objms_new_memory_block:i=%d,j=%d\n", i, j);
          //FIXME, TODO, objms_new_memory_block does not handle freed blocks and larger blocks
          errval = objms_new_memory_block(trans, pi, &blocknr, j + 1 - i, zero);
          if (errval > 0){
            //some blocks left
            j -= errval;
          }
        } else {
          errval = objms_new_data_block(trans, pi, &blocknr, zero);
          if (errval) {
            /* For later recovery in truncate... */
            objms_memunlock_inode(sbi, pi);
            pi->i_flags |= cpu_to_le32(OBJMS_EOFBLOCKS_FL);
            objms_memlock_inode(sbi, pi);
            return errval;
          }
        }
        /* save the meta-data into the journal before
         * modifying */
        if (new_node == 0 && journal_saved == 0) {
          int le_size = (last_index - i + 1) << 3;
          objms_add_logentry(trans, &node[i], le_size, true);
          journal_saved = 1;
        }
        objms_memunlock_block(sbi, node);
        while (i <= j){
          node[i++] = cpu_to_le64(objms_get_block_off(blocknr++));
        }
        i--;
        objms_memlock_block(sbi, node);
      }
    }
  } else {
    for (i = first_index; i <= last_index; i++) {
      if (node[i] == 0) {
        /* allocate the meta block */
        errval = objms_new_block(trans, &blocknr,
            OBJMS_BLOCK_TYPE_4K, 1);
        if (errval) {
          goto fail;
        }
        /* save the meta-data into the journal before
         * modifying */
        if (new_node == 0 && journal_saved == 0) {
          int le_size = (last_index - i + 1) << 3;
          objms_add_logentry(trans, &node[i], le_size, true);
          journal_saved = 1;
        }
        objms_memunlock_block(sbi, node);
        node[i] = cpu_to_le64(objms_get_block_off(blocknr));
        objms_memlock_block(sbi, node);
        new_node = 1;
      }

      first_blk = (i == first_index) ? (first_blocknr &
          ((1 << node_bits) - 1)) : 0;

      last_blk = (i == last_index) ? (last_blocknr &
          ((1 << node_bits) - 1)) : (1 << node_bits) - 1;

      errval = recursive_alloc_blocks(trans, sbi, pi, node[i],
          height - 1, first_blk, last_blk, new_node, zero);
      if (errval < 0)
        goto fail;
    }
  }
  if (new_node) {
    /* if the changes were not logged, flush the cachelines we may
     * have modified */
    flush_bytes = (last_index - first_index + 1) * sizeof(node[0]);
    objms_flush_buffer(&node[first_index], flush_bytes, false);
  }
  errval = 0;
fail:
  return errval;
}
#endif

#ifdef OBJMS_MEMORY_OBJECT
//@ayu: FIXME
//return number blocks left
static int recursive_alloc_memory_blocks(objms_transaction_t *trans,
    struct objms_sb_info *sbi, struct objms_inode *pi, __le64 block, u32 height,
    unsigned long file_blocknr, unsigned int count, bool new_node,
    bool zero, bool expand)
{
  int i, left = 0, errval;
  struct objms_extent_meta_entry *ext_me;
  struct objms_extent_leaf_entry *ext_le;
  bool journal_saved = 0;
  unsigned long blocknr;
  //bool expand = true;
  //unsigned int first_index, last_index;
  //unsigned int flush_bytes;

  if (height == 1) {
    i = 0;
    ext_le = objms_get_block(le64_to_cpu(block));
    //locate last unoccupied entry
    if (ext_le->count != 0){
      do {
        i++;
        ext_le = ext_le + 1;
      }while (i < 256 && ext_le->count != 0);
      if (expand){
        //if the leaf entry can expand, locate the last occupied leaf entry,
        //else locate the first unoccupied leaf entry
        i--;
        ext_le = ext_le - 1;
        //now ext_le point to last occupied entry, try to extend it
        //FIXME: TODO, we need to identify whether the file_blocknr equals the last block
        blocknr = objms_get_blocknr(le64_to_cpu(ext_le->poff)) + le64_to_cpu(ext_le->count);
        //allocate blocks from given position
        left = objms_new_memory_block(trans, pi, &blocknr, count, zero);

        if (left < count){
          //FIXME: log the leaf entry, le_size?
          objms_add_logentry(trans, ext_le, sizeof(*ext_le), true);
          //update the page count of the last occupied ext entry
          ext_le->count += count - left;
          count = left;
          journal_saved = 1;
        }
        //move ext_le to next unoccupied entry
        i++;
        ext_le = ext_le + 1;
      }
    }
    //now ext_le points to last unoccupied entry, try to allocate it
    while (count && i < 256){
      if (!journal_saved){//FIXME: since we do not know the number of modified leaf entry, we may need to alocate more loe entries
        //log the leaf entry
        objms_add_logentry(trans, ext_le + 1, sizeof(*ext_le), true);
        journal_saved = 1;
      }
      blocknr = 0;
      //try to allocate as many blocks as possible
      left = objms_new_memory_block(trans, pi, &blocknr, count, zero); 
      ext_le->poff = cpu_to_le64(objms_get_block_off(blocknr));
      ext_le->count = cpu_to_le64(count - left);

      count = left;
      i++;
      ext_le = ext_le + 1;
    }
  } else {
    i = 0;
    ext_me = objms_get_block(le64_to_cpu(block));
    //bypass occupied meta entry that cannot be expanded
    if (ext_me->poff){
      do {
        i++;
        ext_me = ext_me + 1;
      } while (i < 256 && ext_me->poff);
      if (expand){
        //if the meta entry can expand, locate the last occupied meta entry,
        //else locate the first unoccupied meta entry
        i--;
        ext_me = ext_me - 1;
      }
    }
    for (; i < 256; i++){
      //allocate block for meta node
      if (!ext_me->poff){
        errval = objms_new_block(trans, &blocknr,
            OBJMS_BLOCK_TYPE_4K, 1);//TODO: allocate meta block in another place so the data block is always continuous
        if (errval) {
          goto fail;
        }
        /* allocate the meta block */
        /* save the meta-data into the journal before
         * modifying */
        if (new_node == 0 && journal_saved == 0) {
          int le_size = 8;//FIXME
          //@ayu: FIXME, TODO, use page-logging for large region
          objms_add_logentry(trans, ext_me, le_size, true);
          journal_saved = 1;
        }
        objms_memunlock_block(sbi, ext_me);
        ext_me->poff = cpu_to_le64(objms_get_block_off(blocknr));
        ext_me->lpn = cpu_to_le64(file_blocknr);
        objms_memlock_block(sbi, ext_me);
        new_node = 1;//the meta node is newly-created, then we do not need to log it
      }

      left = recursive_alloc_memory_blocks(trans, sbi, pi, ext_me->poff,
          height - 1, file_blocknr, count, new_node, zero, expand);
      if (left <= 0){//stop when finished or err
        break;
      }
      //move to next meta entry
      ext_me = ext_me + 1;
      file_blocknr += count - left;
    }
  }
  return left;
  //FIXME: do we need to flush?
  //if (new_node) {
    /* if the changes were not logged, flush the cachelines we may
     * have modified */
  //  flush_bytes = (last_index - first_index + 1) * sizeof(node[0]);
  //  objms_flush_buffer(&node[first_index], flush_bytes, false);
  //}
fail:
  return errval;
}
#endif
//@ayu: FIXME, TODO
//whether a given blockpointer has been logged
//index is the bp entry index within the height
//TODO: we use blocknode to store the logical index instead of the physical block number
//if we can use physical block number, we can speed up abort operations
//can be merged with add_cowblk_list
//if set is 0, means only check without add
//if set is 1, means check and add

//add a range of blocks to the block list in order
static inline int objms_add_block_extents(struct list_head *head,
    unsigned long blknr, unsigned long num_blocks){
  struct objms_blocknode *newbn;
  if (!list_empty(head)){
    struct objms_blocknode *bn;
    list_for_each_entry(bn, head, link){
      if (blknr == bn->block_high + 1){
        bn->block_high += num_blocks;
        return 0;
      } else if (blknr == bn->block_low - num_blocks){
        bn->block_low -= num_blocks;
        return 0;
      } else if (blknr > bn->block_high + 1){
        continue;//find next block_node
      } else if (blknr < bn->block_low - num_blocks){
        //alloc a new block_node and insert in the head
        struct objms_blocknode *newbn = objms_alloc_blocknode(objms_sbi);
        newbn->block_low = blknr;
        newbn->block_high = blknr + num_blocks - 1;
        list_add(&newbn->link, &bn->link); 
        return 0;
      } else {//a previously cow-ed block
        return 1;//the blocks are already exist!
      }
    }
  }
  //alloc a new block_node and insert in the tail
  newbn = objms_alloc_blocknode(objms_sbi);
  newbn->block_low = blknr;
  newbn->block_high = blknr + num_blocks - 1;
  list_add_tail(&newbn->link, head);
  return 0;
}
//@ayu: add a range of blocknr to the txn->cowblk_list
//4KB granularity
//return: 0-success, 1-already exist
int objms_add_cowblk_list(objms_transaction_t *trans,
    unsigned long blknr, unsigned long num_blocks){
  return objms_add_block_extents(&trans->cowblk_list, blknr, num_blocks);
}
//add a range of blocks to be flushed
/*int objms_add_flusherblk_list(pid_t pid,
    unsigned long blknr, unsigned long num_blocks){
  return objms_add_block_extents(&objms_sbi->block_commit, blknr, num_blocks);
}*/

//do cow for a block pointer, will not be called in small write
static int objms_cow_page(objms_transaction_t *trans,
    __le64 *blockp, int offset, int len, bool zero){
  unsigned long new_blknr;
  void *old_blkp = objms_get_block(*blockp);
  void *new_blkp;
  int end_offset = offset + len;
  int errval;
  //create new meta block for parent pointer
  errval = objms_new_block(trans, &new_blknr,
      OBJMS_BLOCK_TYPE_4K, zero);
  *blockp = objms_get_block_off(new_blknr);
  new_blkp = objms_get_block(*blockp);
  //next copy old data to new cow-ed page
  //old: ----------
  //new: --+++++---
  if (offset > 0){
    //objms_add_logentry_info(trans, new_blkp, offset);
    memcpy(new_blkp, old_blkp, offset);
    objms_flush_buffer(new_blkp, offset, false);
  }
  if (end_offset < 4096){
    //objms_add_logentry_info(trans, (char *)new_blkp + end_offset, 4096 - end_offset);
    memcpy((char *)new_blkp + end_offset,
        (char *)old_blkp + end_offset, 4096 - end_offset);
    objms_flush_buffer((char *)new_blkp + end_offset,
        4096 - end_offset, false);
  }
  return errval;
}

//COW version of recursive_alloc_blocks
//new_node: 指父节点被记录日志没
//is_bplogged(): 指当前节点被记录日志没
//bp_logged: 最终是否需要记录当前节点的日志
//block_allocated: 最后是否需要把块指针单独刷回
static int recursive_alloc_blocks_cow(objms_transaction_t *trans,
    struct objms_inode *pi, __le64 *blockp, u32 height,
    unsigned long first_blocknr, unsigned long last_blocknr, bool new_node,
    bool zero, unsigned long parent_index)
{
  int i, errval;
  unsigned int meta_bits = META_BLK_SHIFT, node_bits;
  __le64 *node;
  //bool journal_saved = 0, block_allocated = 0;
  unsigned long blocknr, first_blk, last_blk, freeblknr;
  unsigned int first_index, last_index;
  unsigned int first_flush_index;
  unsigned int j, flush_bytes;

  //node = objms_get_block(le64_to_cpu(*blockp));
  node = objms_get_block(le64_to_cpup(blockp));

  node_bits = (height - 1) * meta_bits;

  first_index = first_blocknr >> node_bits;
  last_index = last_blocknr >> node_bits;
  first_flush_index = last_index + 1;//first set the first_flush_index to an invalid value

  printk(KERN_ERR "@recursive_alloc_blocks_cow: begin,trans=%p,blockp=%lx,height=%u,first_blocknr=%lu,last_blocknr=%lu,new_node=%d,zero=%d,parent_index=%lu\n",
      trans, *blockp, height, first_blocknr, last_blocknr, new_node, zero, parent_index);
  if (height == 1) {
    //@ayu: FIXME,假定不存在i/o hole，或者只有部分数据块被记录日志的情况
    //即要么都没被记录日志，要么都被记录了日志
    i = first_index;
    //step1: bypass block pointers that have already been logged
    if (new_node && (!trans)){
      printk(KERN_ERR "@recursive_alloc_blocks_cow: trans=null\n");
    }
    if (new_node && ((le64_to_cpu(*blockp) != trans->old_btree_root))){//the parent pointer is logged
      if (node[i] && (le64_to_cpu(node[i]) == trans->old_btree_root)){
        //特殊情况：原始的btree_height=0,但是btree_root指向一个数据块，此时
        //该数据块需要进行cow，但是不用对该数据块作日志因为它已经在inode中
        //做了日志,即需要对该块进行块分配和刷回，但是不用记录日志
        objms_add_cowblk_list(trans, objms_get_blocknr(le64_to_cpu(node[i])),
            objms_get_numblocks(pi->i_blk_type));
        //这种情况只会出现一次，后面再对该块进行写就不再需要进行COW了
        //直接当作该块是已经新分配的
        trans->old_btree_root = 0;
      } else {
        while (node[i] && (i <= last_index)){
          i++;
        }
      }
      //from i ~ last_index we need alloc new blocks
    } else {
      //parent pointer is not logged, check if child block pointers
      //bypass individual block pointers that have been logged
      //add i~last_index to bp_logged
      for (j = i; j <= last_index; j++){
        //add cowed blocks to cowblk_list
        if (node[j]){
          objms_add_cowblk_list(trans, objms_get_blocknr(le64_to_cpu(node[j])),
              objms_get_numblocks(pi->i_blk_type));
        }
      }
      //step2: log the old block pointers
      //i~last_index needs to be logged
      if (i <= last_index){
        flush_bytes = (last_index - i + 1) << 3;
        objms_add_logentry(trans, &node[i], flush_bytes, false);
      }
    }
    if (i <= last_index){
      first_flush_index = i;
      flush_bytes = (last_index - first_flush_index + 1) << 3;
      //step3: alloc new blocks
      //allocate blocks for node[i]~node[last_index]
      for (; i <= last_index; i++){
        //try to allocate continuous blocks
        j = last_index;
        if (i < j){
          blocknr = 0;
          //printk(KERN_ERR "@recursive_alloc_blocks: objms_new_memory_block:i=%d,j=%d\n", i, j);
          //FIXME, TODO, objms_new_memory_block does not handle freed blocks and larger blocks
          errval = objms_new_memory_block(trans, pi, &blocknr, j + 1 - i, zero);
          if (errval > 0){
            //some blocks left
            j -= errval;
            //@ayu: FIXME, free old blocks here (j - i)
            //printk(KERN_ERR "@recursive_alloc_blocks_cow: errval=%d\n", errval);
          } else if (errval < 0){//@ayu: FIXME
            printk(KERN_ERR "@recursive_alloc_blocks_cow1: no blocks left1,trans=%p\n", trans);
            goto fail;
          }
        } else {
          errval = objms_new_data_block(trans, pi, &blocknr, zero);
          if (errval) {
            printk(KERN_ERR "@recursive_alloc_blocks_cow2: no blocks left2,trans=%p\n", trans);
            goto fail;
          }
        }
        objms_memunlock_block(objms_sbi, node);
        while (i <= j){
          node[i++] = cpu_to_le64(objms_get_block_off(blocknr++));
        }
        i--;
        objms_memlock_block(objms_sbi, node);
      }
      //step4: flush block pointers
      objms_add_logentry_info(trans, &node[first_flush_index], flush_bytes);
    }
  } else {
    //currently we do not do cow for middle b-tree pointers
    //step1: bypass the block pointers that do not need to be logged
    for (i = first_index; i <= last_index; i++) {
      if (node[i] == 0){
        break;
      }
    }
    //we assume i~last_index is all zero block pointers 
    if (i <= last_index){
      bool bp_logged = new_node && ((le64_to_cpu(*blockp) != trans->old_btree_root));
      /* save the meta-data into the journal before
       *        * modifying */
      first_flush_index = i;
      flush_bytes = (last_index - first_flush_index + 1) << 3;
      //step2: log the zero block pointers
      if (bp_logged == 0) {
        objms_add_logentry(trans, &node[first_flush_index], flush_bytes, false);
      }
      //step3: alloc new blocks for zero block pointers
      for (; i <= last_index; i++){
        //try to allocate continuous blocks
        j = last_index;
        if (i < j){
          blocknr = 0;
          //printk(KERN_ERR "@recursive_alloc_blocks: objms_new_memory_block:i=%d,j=%d\n", i, j);
          //FIXME, TODO, objms_new_memory_block does not handle freed blocks and larger blocks
          errval = objms_new_memory_block(trans, pi, &blocknr, j + 1 - i, 1);
          if (errval > 0){
            //some blocks left
            j -= errval;
            //@ayu: FIXME, free old blocks here (j - i)
            //printk(KERN_ERR "@recursive_alloc_blocks_cow: errval=%d\n", errval);
          } else if (errval < 0){//@ayu: FIXME
            printk(KERN_ERR "@recursive_alloc_blocks_cow3: no meta blocks left1,errval=%d\n", errval);
            goto fail;
          }
        } else {
          errval = objms_new_block(trans, &blocknr, OBJMS_BLOCK_TYPE_4K, 1);
          if (errval) {
            printk(KERN_ERR "@recursive_alloc_blocks_cow4: no meta blocks left2,errval=%d\n", errval);
            goto fail;
          }
        }
        objms_memunlock_block(objms_sbi, node);
        while (i <= j){
          if (likely(!node[i])){
            node[i++] = cpu_to_le64(objms_get_block_off(blocknr++));
          } else {//if the node[i] is not empty, free the blocknr
            //that is allocated for node[i]
            objms_add_cowblk_list(trans, blocknr, 1);
            i++;
            blocknr++;
          }
        }
        i--;
        objms_memlock_block(objms_sbi, node);
      }
      //step4: flush block pointers
      objms_add_logentry_info(trans, &node[first_flush_index], flush_bytes);
    }

    for (i = first_index; i <= last_index; i++) {
      bool bp_logged = new_node && ((le64_to_cpu(*blockp) != trans->old_btree_root));
      //目前暂不对B树中间节点指针作COW
      //FIXME:对于元数据块指针，is_bplogged只能用在准备Log时，即node[i]=0时
      /*if (node[i] == 0) {
        //first_flush_index only change once
        if (!block_allocated){
          first_flush_index = i;
        }
        // save the meta-data into the journal before
        //  modifying
        if (bp_logged == 0 && journal_saved == 0) {
          int le_size = (last_index - i + 1) << 3;
          objms_add_logentry(trans, &node[i], le_size, false);//flush together later
          journal_saved = 1;
        }

        block_allocated = 1;
        errval = objms_new_block(trans, &blocknr,
            OBJMS_BLOCK_TYPE_4K, 1);
        if (errval) {
          goto fail;
        }
        objms_memunlock_block(objms_sbi, node);
        node[i] = cpu_to_le64(objms_get_block_off(blocknr));
        objms_memlock_block(objms_sbi, node);
        bp_logged = true;
      }*/
      //because node[first_flush_index ~ last_index] has been allocated new blocks
      if (i >= first_flush_index){
        bp_logged = true;
      }

      first_blk = (i == first_index) ? (first_blocknr &
          ((1 << node_bits) - 1)) : 0;

      last_blk = (i == last_index) ? (last_blocknr &
          ((1 << node_bits) - 1)) : (1 << node_bits) - 1;

      errval = recursive_alloc_blocks_cow(trans, pi, &node[i],
          height - 1, first_blk, last_blk, bp_logged, zero, (parent_index << meta_bits) + i);
      if (errval < 0)
        goto fail;
    }
  }
/*  //if blocks allocated, and they have not been added to log,
  //we need to flush the block pointer
  //刷回新分配的B树指针块
  //之所以需要block_allocated是因为在事务进行多次写情况下
  //new_node代表本节点所在的块是新分配的（由于父指针cow或新创建）
  //可能在上一次事务中就已经刷回了，但是对于这次来说就没有必要再刷了
  //有些块指针没有被记录日志，但是由于分配新数据块而修改，所以需要单独刷回
  if (block_allocated && (first_flush_index <= last_index)) {
    // if the changes were not logged, flush the cachelines we may
    // have modified
    flush_bytes = (last_index - first_flush_index + 1) * sizeof(node[0]);
    //printk(KERN_ERR "@recursive_alloc_blocks_cow: flush nodes, height=%d,start=%u,count=%u\n",
    //    height, first_flush_index, flush_bytes >> 3);
    //TODO: do not flush it here?
    //objms_flush_buffer(&node[first_index], flush_bytes, false);

    //FIXME: the meaning of new_node is changed!
    //add a ole to the le_list
    objms_add_logentry_info(trans, &node[first_flush_index], flush_bytes);
  }*/
  errval = 0;
fail:
  return errval;
}

//此处的num是以4KB为单位的！
//只要出现file_blocknr的地方，都说明参数是以4KB为单位！
//FIXME, TODO:将更新pi->i_blocks的操作放在此处而不是分散到objms_alloc_data_block()
int __objms_alloc_blocks(objms_transaction_t *trans, struct objms_inode *pi,
    unsigned long file_blocknr, unsigned int num, bool zero)
{
  struct objms_sb_info *sbi = objms_sbi;
  int errval;
  unsigned long max_blocks;
  unsigned int height;
  unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
  unsigned int blk_shift, meta_bits = META_BLK_SHIFT;
  unsigned long blocknr, first_blocknr, last_blocknr, total_blocks;
  /* convert the 4K blocks into the actual blocks the inode is using */
  blk_shift = data_bits - sbi->blocksize_bits;

  first_blocknr = file_blocknr >> blk_shift;
  last_blocknr = (file_blocknr + num - 1) >> blk_shift;

  height = pi->height;

  blk_shift = height * meta_bits;

  max_blocks = 0x1UL << blk_shift;

  if (last_blocknr > max_blocks - 1) {
    /* B-tree height increases as a result of this allocation */
    total_blocks = last_blocknr >> blk_shift;
    while (total_blocks > 0) {
      total_blocks = total_blocks >> meta_bits;
      height++;
    }
    if (height > 3) {
      errval = -ENOSPC;
      goto fail;
    }
  }
  //@ayu: FIXME, modify pi->i_blocks!
  if ((file_blocknr + num) > pi->i_blocks){
    objms_memunlock_inode(objms_sbi, pi);
    pi->i_blocks = file_blocknr + num;
    objms_memlock_inode(objms_sbi, pi);
  }

  if (!pi->root) {
    if (height == 0) {
      __le64 root;
      errval = objms_new_data_block(trans, pi, &blocknr, zero);
      if (errval) {
        goto fail;
      }
      root = cpu_to_le64(objms_get_block_off(blocknr));
      objms_memunlock_inode(sbi, pi);
      pi->root = root;
      pi->height = height;
      objms_memlock_inode(sbi, pi);
    } else {
      errval = objms_increase_btree_height(trans, pi, height);
      if (errval) {
        goto fail;
      }
#ifdef OBJMS_WEAK_XMODE
      if (trans->flags & OBJMS_XSTRONG){//cow mode
        errval = recursive_alloc_blocks_cow(trans, pi, &pi->root,
            pi->height, first_blocknr, last_blocknr, 1, zero, 0);
      } else {
        errval = recursive_alloc_blocks(trans, sbi, pi, pi->root,
            pi->height, first_blocknr, last_blocknr, 1, zero);
      }
#else
      errval = recursive_alloc_blocks_cow(trans, pi, &pi->root,
          pi->height, first_blocknr, last_blocknr, 1, zero, 0);
#endif
      if (errval < 0)
        goto fail;
    }
  } else {
    bool is_root_logged = false;
    /* Go forward only if the height of the tree is non-zero. */
    if (height == 0) {
      blocknr = 0;
      objms_add_cowblk_list(trans, objms_get_blocknr(le64_to_cpu(pi->root)),
          objms_get_numblocks(pi->i_blk_type));
      errval = objms_new_data_block(trans, pi, &blocknr, zero);
      objms_memunlock_block(objms_sbi, pi);
      pi->root = cpu_to_le64(objms_get_block_off(blocknr));
      objms_memlock_block(objms_sbi, pi);

      return 0;
    }

    if (height > pi->height) {
      //@ayu: when btree height increase, new root is also logged
      if (!trans->old_btree_root){
        trans->old_btree_root = pi->root;
      }
      is_root_logged = true;
      
      errval = objms_increase_btree_height(trans, pi, height);
      if (errval) {
        goto fail;
      }
    }
#ifdef OBJMS_WEAK_XMODE
    if (trans->flags & OBJMS_XSTRONG){//cow mode
      errval = recursive_alloc_blocks_cow(trans, pi, &pi->root, height,
          first_blocknr, last_blocknr, is_root_logged, zero, 0);
    } else {
      errval = recursive_alloc_blocks(trans, sbi, pi, pi->root, height,
          first_blocknr, last_blocknr, 0, zero);
    }
#else
    errval = recursive_alloc_blocks_cow(trans, pi, &pi->root, height,
        first_blocknr, last_blocknr,
        is_root_logged,
        zero, 0);
#endif
    if (errval < 0)
      goto fail;
  }
  return 0;
fail:
  return errval;
}

#ifdef OBJMS_MEMORY_OBJECT
//@ayu: FIXME
//alloc blocks for memory objects
//extent-tree
int __objms_alloc_memory_blocks(objms_transaction_t *trans, struct objms_inode *pi,
    unsigned long file_blocknr, unsigned int count, bool zero)
{
  struct objms_sb_info *sbi = objms_sbi;
  int errval, left = 0;
  unsigned int height;
  //unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
  //unsigned int blk_shift, meta_bits = META_BLK_SHIFT;
  unsigned long blocknr;
  struct objms_extent_meta_entry *ext_me;
  struct objms_extent_leaf_entry *ext_le;
  bool expand = true;
  /* convert the 4K blocks into the actual blocks the inode is using */
  //blk_shift = data_bits - sbi->blocksize_bits;

  height = pi->height;

  if (!pi->root){
    count += file_blocknr;//the file_blocknr must be start from 0
    blocknr = file_blocknr = 0;
    //try to allocate as many blocks as possible
    left = objms_new_memory_block(trans, pi, &blocknr, count, 0); 
    pi->root = cpu_to_le64(objms_get_block_off(blocknr));
    if (!left){
      return 0;
    }
    expand = false;
    file_blocknr += count - left;
    count = left;
  }
  //now the root directly points to the extent pages
  if (!height){
    if (expand){
      if (file_blocknr > pi->i_blocks){
        count += file_blocknr - pi->i_blocks;
      } else {
        count -= pi->i_blocks - file_blocknr;
      }
      file_blocknr = pi->i_blocks;
      blocknr = objms_get_blocknr(le64_to_cpu(pi->root)) + pi->i_blocks;
      //try to expand the root extent
      left = objms_new_memory_block(trans, pi, &blocknr, count, 0); 
      if (!left){
        return 0;
      }
      expand = false;
      file_blocknr += count - left;
      count = left;
    }
    //increase the extent-tree hight to 1
    errval = objms_increase_btree_height(trans, pi, 1);
    if (errval) {
      goto fail;
    }
    ext_le = objms_get_block(le64_to_cpu(pi->root));
    //update the first leaf entry of the new root
    //ext_le->poff = pi->root;//old root has already been set in increase btree height
    ext_le->count = pi->i_blocks;
  }
  //pi->height > 0
  //find the last occupied extent tree meta node
  for (height = pi->height; height <= 3; height++){
    left = recursive_alloc_memory_blocks(trans, sbi, pi, pi->root, height,
        file_blocknr, count, 0, zero, expand);
    if (left <= 0){
      break;
    }
    expand = false;
    file_blocknr += count - left;
    count = left;

    //now increase the extent-tree height: height must <= 3
    errval = objms_increase_btree_height(trans, pi, height + 1);
    if (errval) {
      goto fail;
    }
  }
  return left;
fail:
  return errval;
}
#endif
/*
 * Allocate num data blocks for inode, starting at given file-relative
 * block number.
 */
//此处的num是以4KB为单位的！
inline int objms_alloc_blocks(objms_transaction_t *trans, struct objms_inode *pi,
    unsigned long file_blocknr, unsigned int num, bool zero){
  int errval;
#ifdef OBJMS_MEMORY_OBJECT
  if (!pi->i_pattern){
    errval = __objms_alloc_blocks(trans, pi, file_blocknr, num, zero);
  } else {
    //alloc blocks for memory object
    errval = __objms_alloc_memory_blocks(trans, pi, file_blocknr, num, zero);
  }
#else
    errval = __objms_alloc_blocks(trans, pi, file_blocknr, num, zero);
#endif

  return errval;
}

/* Initialize the inode table. The objms_inode struct corresponding to the
 * inode table has already been zero'd out */
int objms_init_inode_table(struct objms_sb_info *sbi){
  struct objms_inode *pi = objms_get_inode_table(sbi);
  unsigned long num_blocks = 0, init_inode_table_size;
  int errval;

  if (sbi->s_inodes_count == 0) {//num_inodes = s_inodes_count
    /* initial inode table size was not specified. */
    if (sbi->initsize >= OBJMS_LARGE_INODE_TABLE_THREASHOLD)
      //init_inode_table_size = OBJMS_LARGE_INODE_TABLE_SIZE;
      init_inode_table_size = OBJMS_DEF_BLOCK_SIZE_4K;//@ayu: FIXME
    else
      init_inode_table_size = OBJMS_DEF_BLOCK_SIZE_4K;
  } else {
    init_inode_table_size = sbi->s_inodes_count << OBJMS_INODE_BITS;
  }

  objms_memunlock_inode(sbi, pi);
  pi->i_flags = 0;
  pi->height = 0;
  //pi->i_dtime = 0;
  if (init_inode_table_size >= OBJMS_LARGE_INODE_TABLE_SIZE)
    pi->i_blk_type = OBJMS_BLOCK_TYPE_2M;
  else
    pi->i_blk_type = OBJMS_BLOCK_TYPE_4K;

  num_blocks = (init_inode_table_size + objms_inode_blk_size(pi) - 1) >>
    objms_inode_blk_shift(pi);//@ayu:(4k + 4k - 1) >> 4k = 1

  pi->i_size = cpu_to_le64(num_blocks << objms_inode_blk_shift(pi));//@ayu:1<<4k=4k
  /* objms_sync_inode(pi); */
  objms_memlock_inode(sbi, pi);

  sbi->s_inodes_count = num_blocks <<
    (objms_inode_blk_shift(pi) - OBJMS_INODE_BITS);//@ayu:total inode count = 1 << (12 - 7)
  /* calculate num_blocks in terms of 4k blocksize */
  num_blocks = num_blocks << (objms_inode_blk_shift(pi) -
      sbi->blocksize_bits);
  errval = __objms_alloc_blocks(NULL, pi, 0, num_blocks, true);//为inode table预分配一段空间

  if (errval != 0) {
    return errval;
  }

  /* inode 0 is considered invalid and hence never used */
  sbi->s_free_inodes_count =
    (sbi->s_inodes_count - OBJMS_FREE_INODE_HINT_START);
  sbi->s_free_inode_hint = (OBJMS_FREE_INODE_HINT_START);

  return 0;
}
/*
bool objms_obj_capable(struct objms_inode *pi, int cap){
  struct user_namespace *ns = current_user_ns();
  return ns_capable(ns, cap) && kuid_has_mapping(ns, pi->i_uid);
}*/
//FIXME
int objms_obj_permission(struct objms_inode *pi, int mask){
/*  if (mask == MAY_READ){
    if (objms_obj_capable(pi, CAP_DAC_READ_SEARCH)){
      return 0;
    }
  }
*/
  return 0;
}
/*
static int objms_read_inode(struct objms_inode_info *inode, struct objms_inode *pi, u64 ino){
  int ret = -EIO;

  //FIXME: checksum error
#if 0
  if (objms_calc_checksum((u8 *)pi, OBJMS_INODE_SIZE)) {//FIXME: do we need sbi here?
    objms_err(objms_sbi, "checksum error in inode %lx\n",
        (u64)inode->i_ino);
    goto bad_inode;
  }
#endif

  inode->i_ino = ino;
  inode->pi = pi;
  return 0;

bad_inode:
  objms_make_bad_inode(inode);
  return ret;
}
*/
static inline void objms_update_inode(struct objms_inode_info *inode, struct objms_inode *pi){
  //do nothing because everything is in memory
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 */
//FIXME: caller log the inode
static int objms_free_inode(struct objms_sb_info *sbi,
    struct objms_inode *pi, unsigned long inode_nr){
  int err = 0;
#ifdef OBJMS_CPU_ROUND_ROBIN
  static int cpu = 0;
#else
  int cpu = smp_processor_id() % sbi->cpus;
#endif
  objms_flusher_thread_t *flusher_thread = &(sbi->log_flusher_threads[cpu % sbi->cpus]);
	struct list_head *head = &(flusher_thread->free_ino_list);
#ifdef OBJMS_CPU_ROUND_ROBIN
  cpu = (cpu + 1) % sbi->cpus;
#endif
  bool ino_freed = false;


  objms_memunlock_inode(sbi, pi);
  pi->i_flags = 0;
  pi->root = 0;
  pi->i_size = 0;
  //pi->i_attr = 0;//FIXME
  pi->i_attrsize = 0;
  //pi->i_dtime = cpu_to_le32(get_seconds());
  objms_memlock_inode(sbi, pi);

  /* increment s_free_inodes_count */
  //@ayu: TODO:使用更高效的inode空闲块记录方式：
  //可在每个inode块的第一个Inode中记录该空闲块中首个空闲inode
  //的偏移，以加速空闲inode的查找
  //而对该信息的修改可以放松一致性要求，因为这只是个参考
  //可在系统崩溃后重建
  //if (inode_nr < (sbi->s_free_inode_hint))
  //  sbi->s_free_inode_hint = (inode_nr);
  mutex_lock(&sbi->inode_table_mutex);
  if (inode_nr == (sbi->s_free_inode_hint - 1)){
    sbi->s_free_inode_hint = inode_nr;
    ino_freed = true;

    sbi->s_free_inodes_count += 1;

    if ((sbi->s_free_inodes_count) ==
        (sbi->s_inodes_count) - OBJMS_FREE_INODE_HINT_START) {
      // filesystem is empty
      sbi->s_free_inode_hint = (OBJMS_FREE_INODE_HINT_START);
    }
  }

//out:
  mutex_unlock(&sbi->inode_table_mutex);

  if (!ino_freed){
    struct objms_blocknode *bn, *tailbn;
    mutex_lock(&flusher_thread->ino_list_lock);
    if (!list_empty(head)){
      //bn = list_first_entry(head, struct objms_blocknode, link);
      tailbn = list_entry(head->prev, struct objms_blocknode, link);
      if (!tailbn->block_low){
        tailbn->block_low = inode_nr;
        ino_freed = true;
      } else if (!tailbn->block_high){
        tailbn->block_high = inode_nr;
        ino_freed = true;
      }
    }
    if (!ino_freed){
      bn = objms_alloc_blocknode(objms_sbi);
      bn->block_low = inode_nr;
      bn->block_high = 0;
      list_add_tail(&bn->link, head);
    }
    mutex_unlock(&flusher_thread->ino_list_lock);
  }
  return err;
}

static void __wait_on_freeing_inode(struct objms_inode_info *inode){
  wait_queue_head_t *wq;
  DEFINE_WAIT_BIT(wait, &inode->i_state, __I_NEW);
  wq = bit_waitqueue(&inode->i_state, __I_NEW);
  prepare_to_wait(wq, &wait.wait, TASK_UNINTERRUPTIBLE);
  spin_unlock(&inode->i_lock);
  spin_unlock(&objms_inode_lock);
  schedule();
  finish_wait(wq, &wait.wait);
  spin_lock(&objms_inode_lock);
}

static struct objms_inode_info *find_inode_fast(struct hlist_head *head,
    unsigned long ino){
  struct objms_inode_info *inode = NULL;

repeat:
  hlist_for_each_entry(inode, head, i_hash){
    spin_lock(&inode->i_lock);
    if (inode->i_ino != ino){
      spin_unlock(&inode->i_lock);
      continue;
    }
    if (inode->i_state & I_FREEING){//do not need I_WILL_FREE
      __wait_on_freeing_inode(inode);//FIXME: do we need this?
      goto repeat;
    }
    __objms_iget(inode);
    spin_unlock(&inode->i_lock);
    return inode;
  }
  return NULL;
}

static inline struct objms_inode_info *objms_iget_locked(unsigned long ino){
  struct hlist_head *head = objms_inode_hashtable + objms_hash(ino);//FIXME
  struct objms_inode_info *inode;

  spin_lock(&objms_inode_lock);
  inode = find_inode_fast(head, ino);
  spin_unlock(&objms_inode_lock);
  if (likely(inode)){
    objms_wait_on_inode(inode);
    return inode;
  }
  
  inode = objms_alloc_inode();
  if (likely(inode)){
    struct objms_inode_info *old;

    spin_lock(&objms_inode_lock);
    //we release the lock, so somebody may creat an inode with the same inode,
    //so search again
    old = find_inode_fast(head, ino);
    if (!old){
      inode->i_ino = ino;
      spin_lock(&inode->i_lock);
      inode->i_state = I_NEW;
      hlist_add_head(&inode->i_hash, head);
      spin_unlock(&inode->i_lock);
      spin_unlock(&objms_inode_lock);

      //return the locked inode
      return inode;
    }

    //somebody else create the same inode under us
    spin_unlock(&objms_inode_lock);
    objms_destroy_inode(inode);
    inode = old;
    objms_wait_on_inode(inode);
  }
  return inode;
}
//FIXME
struct objms_inode_info *objms_iget(unsigned long ino){
  struct objms_inode_info *inode;
  struct objms_inode *pi;
  int err;

  inode = objms_iget_locked(ino);
  if (unlikely(!inode)){
    //printk(KERN_ERR "@objms_iget: iget_locked failed\n");
    return ERR_PTR(-ENOMEM);
  }
  if (!(inode->i_state & I_NEW)){
    return inode;
  }

  //a newly created inode
  pi = objms_get_inode(ino);
  if (unlikely(!pi)) {
    //printk(KERN_ERR "@objms_iget: objms_get_inode failed, ino=%lu\n", ino);
    err = -EACCES;
    goto fail;
  }
  //connect the in-memory inode with in-SCM inode
  inode->pi = pi;

  objms_unlock_new_inode(inode);
  return inode;
fail:
  //printk(KERN_ERR "@objms_iget: objms_iget_failed,ino=%lu\n", ino);
  objms_iget_failed(NULL, inode);
  return ERR_PTR(err);
}

static inline void objms_free_inode_xattrs(struct objms_inode *pi){
  unsigned long current_blkoff, next_blkoff;
  //current_blkoff = pi->i_attr;//FIXME
  current_blkoff = 0;
  while (current_blkoff){
    u8 *bp = objms_get_block(current_blkoff);
    next_blkoff = *(unsigned long *)(bp + 4088);
    objms_free_block(objms_sbi, objms_get_blocknr(current_blkoff),
        OBJMS_BLOCK_TYPE_4K);
    current_blkoff = next_blkoff;
  }
}
//FIXME
void objms_evict_inode(objms_transaction_t *trans, struct objms_inode_info *inode){
  struct objms_inode *pi = inode->pi;
  __le64 root;
  unsigned long last_blocknr;
  unsigned int height, btype;
  int err = 0;

  if (pi->i_flags & OBJMS_INODE_BEFREE){//the inode is free(only when the object is deleted)
    root = pi->root;
    height = pi->height;
    btype = pi->i_blk_type;
    //printk(KERN_ERR "@objms_evict_inode: ino=%lu\n", inode->i_ino >> OBJMS_INODE_BITS);


    if (pi->i_flags & cpu_to_le32(OBJMS_EOFBLOCKS_FL)) {
      last_blocknr = (1UL << (pi->height * META_BLK_SHIFT))
        - 1;
    } else {
      if (likely(pi->i_size))
        last_blocknr = (pi->i_size - 1) >>
          objms_inode_blk_shift(pi);
      else
        last_blocknr = 0;
      last_blocknr = objms_sparse_last_blocknr(pi->height,
          last_blocknr);
    }
    //printk(KERN_ERR "@objms_evict_inode: ino=%lu,i_size=%lu,root=%lx,height=%u,last_blocknr=%lu\n",
    //    inode->i_ino >> OBJMS_INODE_BITS, pi->i_size, root, height, last_blocknr);

    //free the inode's xattr blocks!
    objms_free_inode_xattrs(pi);  
    /* first free the inode */
    err = objms_free_inode(objms_sbi, pi, inode->i_ino >> OBJMS_INODE_BITS);
    if (err)
      goto out;
    //@ayu: FIXME:TODO:此处的pi虽然状态被清空了,但是不能真正释放,
    //因为事务还没有提交,应该把它加入到事务的free_inode_list中,
    //在事务清理时进行释放!
    //the pi needs to be flushed!
    objms_add_logentry_info(trans, pi, MAX_DATA_PER_LENTRY);
    pi = NULL; /* we no longer own the objms_inode */

    /* then free the blocks from the inode's b-tree */
    err = objms_free_inode_subtree(trans, root, height, btype, last_blocknr);
    //printk(KERN_ERR "@objms_evict_inode: objms_free_inode_subtree: freed=%d\n", err);
  }
out:
  //printk(KERN_ERR "@objms_evict_inode: out\n");
  return;
  /* now it is safe to remove the inode from the truncate list */
  //objms_truncate_del(sbi, inode);//FIXME: since we didn't call truncate_add while unlink(delete inode)
}
//FIXME: there may have bug since we add a trans
static int objms_increase_inode_table_size(objms_transaction_t *trans,
    struct objms_sb_info *sbi){
  struct objms_inode *pi = objms_get_inode_table(sbi);
  int errval;

  /* 1 log entry for inode-table inode, 1 lentry for inode-table b-tree */
  errval = objms_alloc_logentries(trans, MAX_INODE_LENTRIES);
	if (errval) {
    return errval;
	}

  objms_add_logentry(trans, pi, MAX_DATA_PER_LENTRY, false);

  errval = __objms_alloc_blocks(trans, pi,
      le64_to_cpup(&pi->i_size) >> sbi->blocksize_bits,
      //1, true);
      //objms_get_numblocks(pi->i_blk_type), true);
      objms_get_numblocks(pi->i_blk_type), 0);
  //@ayu:此处并不需要将inode块进行清零操作,因为我们只需要把inode块
  //中的每个inode的i_flags清零就行,所以对于每个inode所占据的256B中,
  //只需要清零64B

  if (errval == 0) {
    u64 i_size = le64_to_cpu(pi->i_size);

    sbi->s_free_inode_hint = i_size >> OBJMS_INODE_BITS;
    i_size += objms_inode_blk_size(pi);

    objms_memunlock_inode(sbi, pi);
    pi->i_size = cpu_to_le64(i_size);
    objms_memlock_inode(sbi, pi);

    sbi->s_free_inodes_count += INODES_PER_BLOCK(pi->i_blk_type);
    sbi->s_inodes_count = i_size >> OBJMS_INODE_BITS;
  }// else
    //objms_dbg_verbose("no space left to inc inode table!\n");
  objms_add_logentry_info(trans, pi, MAX_DATA_PER_LENTRY);
  return errval;
}

static int objms_insert_inode_locked(objms_transaction_t *trans, struct objms_inode_info *inode){
  unsigned long ino = inode->i_ino;
  struct hlist_head *head = objms_inode_hashtable + objms_hash(ino);

  while (1){
    struct objms_inode_info *old = NULL;
    spin_lock(&objms_inode_lock);
    hlist_for_each_entry(old, head, i_hash){
      if (old->i_ino != ino){
        continue;
      }
      spin_lock(&old->i_lock);
      if (old->i_state & I_FREEING){//no I_WILL_FREE
        spin_unlock(&old->i_lock);
        continue;
      }
      break;
    }
    if (likely(!old)){
      spin_lock(&inode->i_lock);
      inode->i_state |= I_NEW;
      hlist_add_head(&inode->i_hash, head);
      spin_unlock(&inode->i_lock);
      spin_unlock(&objms_inode_lock);
      return 0;
    }
    __objms_iget(old);
    spin_unlock(&old->i_lock);
    spin_unlock(&objms_inode_lock);
    objms_wait_on_inode(old);
    if (unlikely(!objms_inode_unhashed(old))){
      objms_iput(trans, old);
      return -EBUSY;
    }
    objms_iput(trans, old);
  }
}

struct objms_inode_info *objms_new_inode(objms_transaction_t *trans,
    umode_t mode, unsigned long objno){
  struct objms_sb_info *sbi = objms_sbi;
	struct objms_super_block *super = objms_get_super(sbi);
  struct objms_inode_info *inode;
  struct objms_inode *pi = NULL, *inode_table;
  int i = 0, errval = 0;
  u32 num_inodes, inodes_per_block;
  unsigned long ino = 0;
  struct timespec i_mtime;
  static int cpu = 0;
  bool free_ino_list_hit = false;
  //int cpu = 0;
  //int cpu = task_cpu(current) % sbi->cpus;
  objms_flusher_thread_t *flusher_thread = &(sbi->log_flusher_threads[cpu % sbi->cpus]);
	struct list_head *head = &(flusher_thread->free_ino_list);
  cpu = (cpu + 1) % sbi->cpus;

  inode = objms_alloc_inode();//instead of vfs new_inode
  if (unlikely(!inode)){
    return ERR_PTR(-ENOMEM);
  }

  inode_table = objms_get_inode_table(sbi);
  //allocate from free_ino_list first
  mutex_lock(&flusher_thread->ino_list_lock);
  if (!list_empty(head)){
    struct objms_blocknode *bn;
    bn = list_first_entry(head, struct objms_blocknode, link);
    if (bn->block_low){
      i = bn->block_low;
      bn->block_low = 0;
    } else if (bn->block_high){
      i = bn->block_high;
      bn->block_high = 0;
    }
    if ((!bn->block_low) && (!bn->block_high)){
      list_del(&bn->link);
      //__objms_free_blocknode(bn);
      objms_free_blocknode(sbi, bn);
    }
  }
  mutex_unlock(&flusher_thread->ino_list_lock);
  if (i){
    pi = objms_get_inode(i << OBJMS_INODE_BITS);
    free_ino_list_hit = true;
    goto found_free_ino;
  }

  inode_table = objms_get_inode_table(sbi);
  mutex_lock(&sbi->inode_table_mutex);

  if (!sbi->s_free_inodes_count){
    errval = objms_increase_inode_table_size(trans, sbi);
    //人为地将新分配的inode块中的每个inode标志位清零
    i = (sbi->s_free_inode_hint);
    pi = objms_get_inode(i << OBJMS_INODE_BITS);
    for (i = 0; i < INODES_PER_BLOCK(pi->i_blk_type); i++){
      memset_nt(pi, 0, sizeof(struct objms_inode));
      pi = (struct objms_inode *)((void *)pi + OBJMS_INODE_SIZE);

/*#ifdef OBJMS_ENABLE_ASYNC_FLUSH
      i++;
      memset(pi, 0, sizeof(struct objms_inode));
      objms_add_logentry_info(trans, pi, sizeof(struct objms_inode));
      pi = (struct objms_inode *)((void *)pi + OBJMS_INODE_SIZE);
#endif*/
    }
  }
  if (likely(!objno)){
    //TODO: find the oldest unused objms inode
    i = (sbi->s_free_inode_hint);
    pi = objms_get_inode(i << OBJMS_INODE_BITS);
    if (le32_to_cpu(pi->i_flags) != 0){
      goto fail1;//impossible
    }
//    inodes_per_block = INODES_PER_BLOCK(inode_table->i_blk_type);
/*retry:
    num_inodes = (sbi->s_inodes_count);
    while (i < num_inodes) {//FIXME: 循环查找空闲inode的方式效率太低
      u32 end_ino;
      end_ino = i + (inodes_per_block - (i & (inodes_per_block - 1)));
      ino = i <<  OBJMS_INODE_BITS;
      pi = objms_get_inode(ino);
      for (; i < end_ino; i++) {
        // check if the inode is active.
        if (le32_to_cpu(pi->i_flags) == 0){
          //|| le32_to_cpu(pi->i_dtime))
          break;
        }
        //printk(KERN_ERR "@objms_new_inode:pi=%p,i=%u,i_flags=%x,i_size=%lu,i_mode=%o,i_attrsize=%u\n",
        //    pi, i, pi->i_flags, pi->i_size, pi->i_mode, pi->i_attrsize);
        pi = (struct objms_inode *)((void *)pi + OBJMS_INODE_SIZE);
      }
      // found a free inode
      if (i < end_ino){
      printk(KERN_ERR "@objms_new_inode: ino=%d\n", i);
        break;
      }
    }
    if (unlikely(i >= num_inodes)) {
      printk(KERN_ERR "@objms_new_inode: objms_increase_inode_table_size\n");
      errval = objms_increase_inode_table_size(trans, sbi);
      if (errval == 0)
        goto retry;
      mutex_unlock(&sbi->inode_table_mutex);
      //printk(KERN_ERR "@objms_new_inode: increase inode table size failed\n");
      //objms_dbg("OBJMS: could not find a free inode\n");
      goto fail1;
    }*/
  } else {//new inode with specific objno
    //@ayu: FIXME, TODO: 如果objno不存在,还要让inode table
    //增大，可能会造成inode table的空洞
    i = objno;
    pi = objms_get_inode(objno << OBJMS_INODE_BITS);
    if (le32_to_cpu(pi->i_flags) != 0){
      mutex_unlock(&sbi->inode_table_mutex);
      goto fail1;
    }
  }
  sbi->s_free_inodes_count -= 1;
  sbi->s_free_inode_hint = i + 1;
  mutex_unlock(&sbi->inode_table_mutex);

found_free_ino:
  ino = i << OBJMS_INODE_BITS;//need "<<" here

  /* chosen inode is in ino */
  inode->i_ino = ino;
  inode->pi = pi;
  //objms_add_logentry(trans, pi, sizeof(*pi));
  //@ayu: FIXME, we only need to log the first 48B(with i_flags)
  objms_add_logentry(trans, pi, MAX_DATA_PER_LENTRY, false);

  //init objms_inode
  objms_memunlock_inode(sbi, pi);
  pi->i_blk_type = OBJMS_DEFAULT_BLOCK_TYPE;//blocktype can be modified in new_obj
  //pi->i_flags = objms_mask_flags(mode, diri->i_flags);//FIXME
  pi->i_flags = OBJMS_INODE_INUSE;//set the inode's used flag
  pi->height = 0;
  pi->root = 0;
  //pi->i_dtime = 0;
  pi->i_blocks = pi->i_size = 0;
  i_mtime = CURRENT_TIME;
  pi->i_mtime = pi->i_atime = pi->i_ctime = i_mtime.tv_sec;//FIXME
  //pi->i_attr = 0;
  pi->i_attrsize = 0;
  pi->i_uid = current_fsuid().val;//FIXME: i_uid_read is from vfs
  pi->i_gid = current_fsgid().val;
  pi->i_mode = mode;
  pi->i_pattern = 0;
  objms_memlock_inode(sbi, pi);

  //objms_update_inode(inode, pi);

  //objms_set_inode_flags(inode, pi);

  if (objms_insert_inode_locked(trans, inode) < 0) {
    printk(KERN_ERR "@objms_new_inode: failed to insert ino %lu\n", ino >> OBJMS_INODE_BITS);
    //objms_err(sbi, "objms_new_inode failed ino %lx\n", inode->i_ino);
    errval = -EINVAL;
    goto fail1;
  }

  return inode;
fail1:
  objms_make_bad_inode(inode);
  objms_iput(trans, inode);
  return ERR_PTR(errval);
}
//clear the inode's inuse flag
inline void objms_clear_inode_inuse(struct objms_sb_info *sbi,
    struct objms_inode *pi){
  objms_memunlock_inode(sbi, pi);
  pi->i_flags &= ~OBJMS_INODE_INUSE;
  objms_memlock_inode(sbi, pi);
}

/*inline void objms_update_nlink(struct objms_sb_info *sbi,
    struct objms_inode *pi, unsigned int nlink){
  objms_memunlock_inode(sbi, pi);
  pi->i_links_count = cpu_to_le16(nlink);
  objms_memlock_inode(sbi, pi);
}*/

inline void objms_update_isize(struct objms_sb_info *sbi,
    struct objms_inode *pi, unsigned int size){
  objms_memunlock_inode(sbi, pi);
  pi->i_size = cpu_to_le64(size);
  objms_memlock_inode(sbi, pi);
}

inline void objms_update_atime(struct objms_sb_info *sbi, struct objms_inode *pi){
  struct timespec mtime = CURRENT_TIME_SEC;
  objms_memunlock_inode(sbi, pi);
  pi->i_atime = cpu_to_le32(mtime.tv_sec);
  objms_memlock_inode(sbi, pi);
  //objms_flush_buffer(&pi->i_atime, 4, false);
}

inline void objms_update_time(struct objms_sb_info *sbi, struct objms_inode *pi){
  struct timespec mtime = CURRENT_TIME_SEC;
  objms_memunlock_inode(sbi, pi);
  pi->i_ctime = cpu_to_le32(mtime.tv_sec);
  pi->i_mtime = cpu_to_le32(mtime.tv_sec);
  objms_memlock_inode(sbi, pi);
}

/* This function checks if VFS's inode and OBJMS's inode are not in sync */
/*static bool objms_is_inode_dirty(struct objms_inode_info *inode, struct objms_inode *pi){
  if (inode->i_ctime.tv_sec != le32_to_cpu(pi->i_ctime) ||
    inode->i_mtime.tv_sec != le32_to_cpu(pi->i_mtime) ||
    inode->i_size != le64_to_cpu(pi->i_size) ||
    inode->i_mode != le16_to_cpu(pi->i_mode) ||
    i_uid_read(inode) != le32_to_cpu(pi->i_uid) ||
    i_gid_read(inode) != le32_to_cpu(pi->i_gid) ||
    inode->i_nlink != le16_to_cpu(pi->i_links_count) ||
    inode->i_blocks != le64_to_cpu(pi->i_blocks) ||
    inode->i_atime.tv_sec != le32_to_cpu(pi->i_atime))
    return true;
  return false;//we are always in sync
}
*/
/*
 * dirty_inode() is called from mark_inode_dirty_sync()
 * usually dirty_inode should not be called because OBJMS always keeps its inodes
 * clean. Only exception is touch_atime which calls dirty_inode to update the
 * i_atime field.
 */
void objms_dirty_inode(struct objms_inode_info *inode, int flags){
  //do nothing
}

/*
 * Called to zeros out a single block. It's used in the "resize"
 * to avoid to keep data in case the file grow up again.
 */
/* Make sure to zero out just a single 4K page in case of 2M or 1G blocks */
static void objms_block_truncate_page(struct objms_sb_info *sbi,
    struct objms_inode *pi, loff_t newsize){
  unsigned long offset = newsize & (sbi->blocksize - 1);
  unsigned long blocknr, length;
  u64 blockoff;
  char *bp;

  /* Block boundary or extending ? */
  if (!offset || newsize > pi->i_size)
    return;

  length = sbi->blocksize - offset;
  blocknr = newsize >> sbi->blocksize_bits;

  blockoff = objms_find_data_block(sbi, pi, blocknr);

  /* Hole ? */
  if (!blockoff)
    return;

  bp = objms_get_block(blockoff);
  if (!bp)
    return;
  objms_memunlock_block(sbi, bp);
  memset(bp + offset, 0, length);
  objms_memlock_block(sbi, bp);
  objms_flush_buffer(bp + offset, length, false);
}
//FIXME: hold the freed blocks of an object before committing the txn
//works similar to add_cowblk_list
//when truncating a file, we don't want to return the freed blocks to the free list
//until the whole truncate operation is complete
void objms_truncate_del(struct objms_sb_info *sbi, struct objms_inode_info *inode){
  struct list_head *prev;
  struct objms_inode_truncate_item *head = objms_get_truncate_list_head(sbi);
  struct objms_inode_truncate_item *li;
  unsigned long ino_next;

  mutex_lock(&sbi->s_truncate_lock);
  if (list_empty(&inode->i_truncated))
    goto out;
  /* Make sure all truncate operation is persistent before removing the
   * inode from the truncate list */
  PERSISTENT_MARK();

  li = objms_get_truncate_item(sbi, inode->pi);

  ino_next = le64_to_cpu(li->i_next_truncate);
  prev = inode->i_truncated.prev;

  list_del_init(&inode->i_truncated);
  PERSISTENT_BARRIER();

  /* Atomically delete the inode from the truncate list */
  if (prev == &sbi->s_truncate) {
    objms_memunlock_range(sbi, head, sizeof(*head));
    head->i_next_truncate = cpu_to_le64(ino_next);
    objms_memlock_range(sbi, head, sizeof(*head));
    objms_flush_buffer(&head->i_next_truncate,
        sizeof(head->i_next_truncate), false);
  } else {
    struct objms_inode_info *i_prv = list_entry(prev,
        struct objms_inode_info, i_truncated);
    struct objms_inode_truncate_item *li_prv = 
      objms_get_truncate_item(sbi, i_prv->pi);
    objms_memunlock_range(sbi, li_prv, sizeof(*li_prv));
    li_prv->i_next_truncate = cpu_to_le64(ino_next);
    objms_memlock_range(sbi, li_prv, sizeof(*li_prv));
    objms_flush_buffer(&li_prv->i_next_truncate,
        sizeof(li_prv->i_next_truncate), false);
  }
  PERSISTENT_MARK();
  PERSISTENT_BARRIER();
out:
  mutex_unlock(&sbi->s_truncate_lock);
}

/* OBJMS maintains a so-called truncate list, which is a linked list of inodes
 * which require further processing in case of a power failure. Currently, OBJMS
 * uses the truncate list for two purposes.
 * 1) When removing a file, if the i_links_count becomes zero (i.e., the file
 * is not referenced by any directory entry), the inode needs to be freed.
 * However, if the file is currently in use (e.g., opened) it can't be freed
 * until all references are closed. Hence OBJMS adds the inode to the truncate
 * list during directory entry removal, and removes it from the truncate list
 * when VFS calls evict_inode. If a power failure happens before evict_inode,
 * the inode is freed during the next mount when we recover the truncate list
 * 2) When truncating a file (reducing the file size and freeing the blocks),
 * we don't want to return the freed blocks to the free list until the whole
 * truncate operation is complete. So we add the inode to the truncate list with
 * the specified truncate_size. Now we can return freed blocks to the free list
 * even before the transaction is complete. Because if a power failure happens
 * before freeing of all the blocks is complete, OBJMS will free the remaining
 * blocks during the next mount when we recover the truncate list */
//FIXME
void objms_truncate_add(struct objms_sb_info *sbi, struct objms_inode_info *inode, u64 truncate_size){
  struct objms_inode_truncate_item *head = objms_get_truncate_list_head(sbi);
  struct objms_inode_truncate_item *li;

  mutex_lock(&sbi->s_truncate_lock);
  if (!list_empty(&inode->i_truncated))
    goto out_unlock;

  li = objms_get_truncate_item(sbi, inode->pi);

  objms_memunlock_range(sbi, li, sizeof(*li));
  li->i_next_truncate = head->i_next_truncate;
  li->i_truncatesize = cpu_to_le64(truncate_size);
  objms_memlock_range(sbi, li, sizeof(*li));
  objms_flush_buffer(li, sizeof(*li), false);
  /* make sure above is persistent before changing the head pointer */
  PERSISTENT_MARK();
  PERSISTENT_BARRIER();
  /* Atomically insert this inode at the head of the truncate list. */
  objms_memunlock_range(sbi, head, sizeof(*head));
  head->i_next_truncate = cpu_to_le64(inode->i_ino);
  objms_memlock_range(sbi, head, sizeof(*head));
  objms_flush_buffer(&head->i_next_truncate,
      sizeof(head->i_next_truncate), false);
  /* No need to make the head persistent here if we are called from
   * within a transaction, because the transaction will provide a
   * subsequent persistent barrier */
  /*if (objms_current_transaction() == NULL) {
    PERSISTENT_MARK();
    PERSISTENT_BARRIER();
  }*/
  list_add(&inode->i_truncated, &sbi->s_truncate);

out_unlock:
  mutex_unlock(&sbi->s_truncate_lock);
}
//@ayu: FIXME
//currently it won't be called
void objms_setsize(struct objms_sb_info *sbi,
    struct objms_inode *pi, loff_t newsize){
  loff_t oldsize = pi->i_size;

  if (newsize != oldsize) {
    objms_block_truncate_page(sbi, pi, newsize);
    //i_size_write(pi, newsize);//FIXME
  }
  /* FIXME: we should make sure that there is nobody reading the inode
   * before truncating it. Also we need to munmap the truncated range
   * from application address space, if mmapped. */
  /* synchronize_rcu(); */
  __objms_truncate_blocks(NULL, sbi, pi, newsize, oldsize);
  /* No need to make the b-tree persistent here if we are called from
   * within a transaction, because the transaction will provide a
   * subsequent persistent barrier */
  /*if (objms_current_transaction() == NULL) {
    PERSISTENT_MARK();
    PERSISTENT_BARRIER();
  }*/
}

static inline int objms_can_set_blocksize_hint(struct objms_inode *pi,
					       loff_t new_size)
{
	/* Currently, we don't deallocate data blocks till the file is deleted.
	 * So no changing blocksize hints once allocation is done. */
	if (le64_to_cpu(pi->root))
		return 0;
	return 1;
}

int objms_set_blocksize_hint(struct objms_sb_info *sbi, struct objms_inode *pi,
		loff_t new_size)
{
	unsigned short block_type;

	if (!objms_can_set_blocksize_hint(pi, new_size))
		return 0;

	if (new_size >= 0x40000000) {   /* 1G */
		block_type = OBJMS_BLOCK_TYPE_1G;
		goto hint_set;
	}

	if (new_size >= 0x200000) {     /* 2M */
		block_type = OBJMS_BLOCK_TYPE_2M;
		goto hint_set;
	}

	/* defaulting to 4K */
	block_type = OBJMS_BLOCK_TYPE_4K;

hint_set:
	/*objms_dbg_verbose(
		"Hint: new_size 0x%llx, i_size 0x%llx, root 0x%llx\n",
		new_size, pi->i_size, le64_to_cpu(pi->root));
	objms_dbg_verbose("Setting the hint to 0x%x\n", block_type);*/
	objms_memunlock_inode(sbi, pi);
	pi->i_blk_type = block_type;
	objms_memlock_inode(sbi, pi);
	return 0;
}


