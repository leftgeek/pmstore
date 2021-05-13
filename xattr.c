#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/obj.h>
#include "objms.h"

SYSCALL_DEFINE5(objms_setxattr, unsigned long, tid, unsigned long, objno,
    const void __user *, value, loff_t, offset, size_t, size){
  struct objms_sb_info *sbi = objms_sbi;
  struct objms_inode_info *inode;
  struct objms_inode *pi;
  unsigned int max_les = 0, pos, len, count, left, current_blkoff, log_size = 0;
  ssize_t ret = 0;
  unsigned long i_attrblock;
  bool end_blk = false;
  bool need_log_pi = false;
  //bool need_flush_pi = false;
  int pageoff;

  objms_transaction_t *trans = objms_current_transaction(tid);
  if (unlikely(!trans)){
    return -1;
  }
  if (unlikely(!size)){
    return 0;
  }

  inode = objms_iget(objno << OBJMS_INODE_BITS);
  if (unlikely(IS_ERR(inode))){//invalid objno
    return -EINVAL;
  }
  
  //printk(KERN_ERR "@objms_setxattr:objno=%lu,offset=%u,size=%u\n",
  //    objno, offset, size);
  mutex_lock(&inode->i_mutex);
  if (unlikely(!access_ok(VERIFY_READ, value, size))){
    ret = -EFAULT;
    goto out;
  }

  //calculate attributes count within OBJMS_INODE_XATTR_LEN
  if ((offset + size) < OBJMS_INODE_XATTR_LEN){
    count = size;
  } else if (offset < OBJMS_INODE_XATTR_LEN){
    count = OBJMS_INODE_XATTR_LEN - offset;
  } else {
    count = 0;//count whthin OBJMS_INODE_XATTR_LEN = 0
  }

  pi = inode->pi;
  //@ayu: FIXME, allocate one more le to link next le
  //only necessary for normal commit mode
  /*if (!(trans->flags & OBJMS_XAUTO)){
    max_les++;
  }*/
  if (objms_need_log_inode(trans, pi, MAX_DATA_PER_LENTRY)){
    max_les++;//one more le for pi 
    need_log_pi = true;
  }
  //printk(KERN_ERR "@set_xattr: objno=%lu,attrsize=%lu,pos=%lu,len=%lu\n",
  //    objno, pi->i_attrsize, offset, size);
  //first: log the OBJMS_INODE_XATTR_LEN space
  if (offset < pi->i_attrsize){
    //We only need to log the space within [0, i_attrsize]
    log_size = min_t(uint32_t, pi->i_attrsize - offset, count);
    max_les += (log_size + MAX_DATA_PER_LENTRY - 1) / MAX_DATA_PER_LENTRY;
  }
  objms_alloc_logentries(trans, max_les);
  //FIXME: the first 48B or second 48B of the pi?
  //if the second 48B, then xattr within second + 48B can share the log
  if (need_log_pi){
    objms_add_logentry(trans, pi, MAX_DATA_PER_LENTRY, false);//log the inode
    objms_update_time(sbi, pi);
    objms_add_logentry_info(trans, pi, MAX_DATA_PER_LENTRY);
  }
  //update time and iattrsize
  //if (need_log_pi)
  //  objms_update_time(sbi, pi);
  //  create/rename
  //  @ayu: FIXME, 将need_log_pi 和need_flush_pi分开
  if (offset + size > pi->i_attrsize){
    pi->i_attrsize = offset + size;
    //since we modify the inode, it needs to be flushed
    //add the trans->pi_buf to ole_list
    if (!need_log_pi){
      objms_add_logentry_info(trans, trans->pi_buf, trans->pi_buf_len);
    }
  }

  //log the space within [offset, OBJMS_INODE_XATTR_LEN]
  if (log_size){
    objms_add_logentry(trans,
        (char *)pi + OBJMS_INODE_XATTR_START + offset, log_size, false);
  }

  //start updating attributes
  //attributes within OBJMS_INODE_XATTR_LEN
  if (count){
//#ifdef OBJMS_ENABLE_ASYNC_FLUSH
    left = __copy_from_user((char *)pi + OBJMS_INODE_XATTR_START + offset,
        value, count);
    objms_add_logentry_info(trans,
        (char *)pi + OBJMS_INODE_XATTR_START + offset, count);

/*#else
    left = objms_memcpy_to_scm_nocache(
        (char *)pi + OBJMS_INODE_XATTR_START + offset,
        value, count);*/
//#endif
  }

  //attributes beyond OBJMS_INODE_XATTR_LEN
  left = size - count;
  if (unlikely(left)){
    i_attrblock = objms_get_attrblock(pi);
    if (!i_attrblock){
      unsigned long attr_blocknr;
      ret = objms_new_block(trans, &attr_blocknr, pi->i_blk_type, 0);
      i_attrblock = objms_get_block_off(attr_blocknr);
      objms_set_attrblock(pi, i_attrblock);
      end_blk = true;
      if (ret){
        ret = -EFAULT;
        goto out;
      }
    }

    //count: witten count, pos: pos in user buffer, len: copy len, pageoff: offset within a 4088 page
    current_blkoff = i_attrblock;
    pos = count;
    if (offset > OBJMS_INODE_XATTR_LEN){
      offset -= OBJMS_INODE_XATTR_LEN;//offset start from 4088 pages
    } else {
      offset = 0;
    }
    pageoff = offset % 4088;//offset within a 4088 page

    while (left){
      u8 *bp;
      bp = objms_get_block(current_blkoff);
      if (offset < 4088){//read current_blk
        len = min_t(unsigned long, left, 4088 - pageoff);//lenth of attr need to copy in current_blk
        //add to log if this block is not newly-allocated
        if (!end_blk){
          objms_add_logentry(trans, bp + pageoff, len, false);
        }
        ret = __copy_from_user(bp + pageoff, (char __user *)value + pos, len);
        objms_add_logentry_info(trans, bp + pageoff, len);

        pageoff = offset = 0;
        pos += len;
        left -= len;
      } else {
        offset -= 4088;
      }

      if (end_blk){//set the end block's next block_off to zero
        *(unsigned long *)(bp + 4088) = 0;
      }
      if (left){
        unsigned long *next_blkoffp = (unsigned long *)(bp + 4088);
        if (*next_blkoffp == 0){
          //allocate a new block
          unsigned long attr_blocknr;
          ret = objms_new_block(trans, &attr_blocknr, OBJMS_BLOCK_TYPE_4K, 0);
          *next_blkoffp = objms_get_block_off(attr_blocknr);
          end_blk = true;
        }
        current_blkoff = *next_blkoffp;
      }
    }
  }

  ret = size;
  //@ayu: FIXME, auto_commit mode test
  if (trans->flags & OBJMS_XAUTO){
    objms_auto_commit_txn(trans);
  }

out:
  mutex_unlock(&inode->i_mutex);
  objms_iput(trans, inode);
  return ret;
}

SYSCALL_DEFINE5(objms_getxattr, unsigned long, tid, unsigned long, objno,
    void __user *, value, loff_t, offset, size_t, size){
  //struct objms_sb_info *sbi = objms_sbi;
  //unsigned long ino = objno << OBJMS_INODE_BITS;
  struct objms_inode_info *inode;
  struct objms_inode *pi;
  unsigned long pos, len, count, left, current_blkoff;
  ssize_t ret = 0;
  int pageoff;

  if (unlikely(!size)){
    return 0;
  }
  inode = objms_iget(objno << OBJMS_INODE_BITS);
  if (IS_ERR(inode)){//invalid objno
    //printk(KERN_ERR "@objms_getxattr: bad inode\n");
    return -EINVAL;
  }

  if (!access_ok(VERIFY_WRITE, value, size)){
    //printk(KERN_ERR "@objms_getxattr: !access_ok()\n");
    ret = -EFAULT;
    goto out;
  }
  //printk(KERN_ERR "@objms_getxattr: objno=%lu,offset=%lu,size=%lu\n",
  //    objno, offset, size);
  pi = inode->pi;
  if (offset > pi->i_attrsize){
    ret = -EFAULT;
    goto out;
  } else if (offset + size > pi->i_attrsize){
    size = pi->i_attrsize - offset;
    //goto out;
  }

  if ((offset + size) < OBJMS_INODE_XATTR_LEN){
    count = size;
  } else if (offset < OBJMS_INODE_XATTR_LEN){
    count = OBJMS_INODE_XATTR_LEN - offset;
  } else {
    count = 0;
  }

  if (count){
    left = __copy_to_user((char __user *)value,
        (char *)pi + OBJMS_INODE_XATTR_START + offset, count);
    if (unlikely(left)){
      ret = -EFAULT;
      goto out;
    }
  }
/*
  if (count < size){
    u8 *bp = objms_get_block(sbi, pi->i_attr);
    left = __copy_to_user((char __user *)value + count, bp, size - count);
    if (unlikely(left)){
      ret = -EFAULT;
      goto out;
    }
  }*/
  //attributes beyond OBJMS_INODE_XATTR_LEN
  //count: read count, pos: pos in user buffer, len: copy len
  left = size - count;
  if (unlikely(left)){
    current_blkoff = objms_get_attrblock(pi);
    pos = count;
    if (offset > OBJMS_INODE_XATTR_LEN){
      offset -= OBJMS_INODE_XATTR_LEN;//offset start from 4088 pages
    } else {
      offset = 0;
    }
    pageoff = offset % 4088;
    while (left){
      u8 *bp;
      bp = objms_get_block(current_blkoff);
      if (offset < 4088){
        len = min_t(unsigned long, left, 4088 - pageoff);
        ret = __copy_to_user((char __user *)value + pos, bp + pageoff, len);
        pageoff = offset = 0;
        pos += len;
        left -= len;
      } else {
        offset -= 4088;
      }

      if (left){
        current_blkoff = *(unsigned long *)(bp + 4088);
        if (current_blkoff == 0){
          printk(KERN_ERR "@objms_getxattr: bad block\n");
          goto out;
        }
      }
    }
  }
  ret = size;

out:
  objms_iput(NULL, inode);
  return ret;
}
