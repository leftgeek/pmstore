#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <asm/uaccess.h>
#include <linux/syscalls.h>
#include <linux/obj.h>
#include "objms.h"
/*
static struct obj_system_type *objms_get_objsystem(struct objms_sb_info *sbi,
    const char *name){
  struct obj_system_type *op;
  int i;

  op = objms_get_first_objsystem(sbi);
  for (i = 0; i < OBJ_SYSTEM_MAX; i++){
    if (op->magic == OBJ_SYSTEM_MAGIC
        && strncmp(op->name, name, strlen(name)) == 0){
      return op;
    }
    op = objms_get_next_objsystem(op);
  }
  return NULL;
}*/
//get an object id by its name
SYSCALL_DEFINE1(objms_get_objno, const char __user *, name){
  struct objms_sb_info *sbi = objms_sbi;
  struct filename *tmpname;
  //struct objms_inode_info *inode;
	struct objms_inode *pi;
  unsigned long objno = 0;
  struct objms_name_info *oni;
  void *blkaddr;
  unsigned long blknr, offset, blkend, content_size;
  struct objms_name_entry *one;
  u64 bp;

  tmpname = getname(name);
  if (unlikely(IS_ERR(tmpname))){
    return 0;
  }
  if (strlen(tmpname->name) >= 23){//max name len is 23
    goto out;
  }
  
  pi = objms_get_naming_object(sbi);
  oni = (struct objms_name_info *)((char *)pi + OBJMS_INODE_XATTR_START);
  /*inode = objms_iget(OBJMS_ROOT_INO);
  if (!inode){
    printk(KERN_ERR "@objms_get_objno: objms_iget failed\n");
    return -EINVAL;
  }*/

  content_size = oni->end_entry_index << 5;
  for (blknr = 0; blknr < pi->i_blocks; blknr++){
    bp = __objms_find_data_block(pi, blknr);
    blkaddr = objms_get_block(bp);

    blkend = min_t(unsigned long, objms_inode_blk_size(pi),
        content_size - (blknr << objms_inode_blk_shift(pi)));
    for (offset = 0; offset < blkend;
        offset += sizeof(struct objms_name_entry)){
      one = (struct objms_name_entry *)(blkaddr + offset); 
      if (!strncmp(one->name, tmpname->name, strlen(tmpname->name))
          && one->objno){//found
        objno = one->objno;
        goto out;
      }
    }
  }

out:
  putname(tmpname);
  //objms_iput(inode);
  return objno;
}

//delete an object's name by its id
SYSCALL_DEFINE2(objms_delete_name, unsigned long, tid, unsigned long, objno){
  struct objms_sb_info *sbi = objms_sbi;
  //struct objms_inode_info *inode;
	struct objms_inode *pi;
  struct objms_name_info *oni;
  void *blkaddr;
  unsigned long blknr, offset, blkend, content_size;
  struct objms_name_entry *one;
  u64 bp;
  int ret = -1;
  unsigned int found_entry_index = 0;

/*  if (unlikely(!objno)){
    return 0;
  }*/
  pi = objms_get_naming_object(sbi);
  oni = (struct objms_name_info *)((char *)pi + OBJMS_INODE_XATTR_START);
  //TODO: check the write permission to the object
  //if (objms_obj_permission(pi, mask))
  /*inode = objms_iget(OBJMS_ROOT_INO);
  if (!inode){
    printk(KERN_ERR "@objms_delete_name: objms_iget failed\n");
    return -EINVAL;
  }*/

  content_size = oni->end_entry_index << 5;
  for (blknr = 0; blknr < pi->i_blocks; blknr++){
    bp = __objms_find_data_block(pi, blknr);
    blkaddr = objms_get_block(bp);

    blkend = min_t(unsigned long, objms_inode_blk_size(pi),
        content_size - (blknr << objms_inode_blk_shift(pi)));
    for (offset = 0; offset < blkend;
        offset += sizeof(struct objms_name_entry)){
      one = (struct objms_name_entry *)(blkaddr + offset); 
      if (one->objno == objno){//found
        one->objno = 0;
        ret = 0;

        if (found_entry_index < oni->free_entry_hint){
          oni->free_entry_hint = found_entry_index;
        }
        if (found_entry_index == oni->end_entry_index - 1){
          oni->end_entry_index--;
        }
        oni->free_entries_count++;
        goto out;
      }
      found_entry_index++;
    }
  }

out:
  //objms_iput(inode);
  return 0;
}
//set an object's name
SYSCALL_DEFINE3(objms_set_name, unsigned long, tid,
    unsigned long, objno, const char __user *, name){
  struct objms_sb_info *sbi = objms_sbi;
  struct filename *tmpname;
  //struct objms_inode_info *inode;
	struct objms_inode *pi;
  struct objms_name_info *oni;
  void *blkaddr;
  unsigned long blknr, offset, blkend, content_size;
  struct objms_name_entry *one;
  int namelen;
  int ret = 0;
  u64 bp;

  objms_transaction_t *trans = objms_current_transaction(tid);
  if (unlikely(!trans)){
    return -1;
  }
/*  if (!objno){
    return 0;
  }*/
  tmpname = getname(name);
  if (unlikely(IS_ERR(tmpname))){
    return 1;
  }
  namelen = strlen(tmpname->name);
  if (namelen >= 24){//max name len is 23
    ret = 1;
    goto out;
  }

  pi = objms_get_naming_object(sbi);
  oni = (struct objms_name_info *)((char *)pi + OBJMS_INODE_XATTR_START);
  //TODO: check the write permission to the object
  //if (objms_obj_permission(pi, mask))
  /*inode = objms_iget(OBJMS_ROOT_INO);
  if (!inode){
    printk(KERN_ERR "@objms_set_name: objms_iget failed\n");
    return -EINVAL;
  }*/
  //find if the name is already used or if the obj already has a name
  content_size = oni->end_entry_index << 5;
  for (blknr = 0; blknr < pi->i_blocks; blknr++){
    bp = __objms_find_data_block(pi, blknr);
    blkaddr = objms_get_block(bp);

    blkend = min_t(unsigned long, objms_inode_blk_size(pi),
        content_size - (blknr << objms_inode_blk_shift(pi)));
    for (offset = 0; offset < blkend;
        offset += sizeof(struct objms_name_entry)){
      one = (struct objms_name_entry *)(blkaddr + offset); 
      if (one->objno &&
          !strncmp(one->name, tmpname->name, namelen)){//found a conflict name
        ret = 1;
        goto out;
      }
      if (one->objno == objno){//found the same objno
        strncpy(one->name, tmpname->name, namelen);
        one->name[namelen] = '\0';
        goto out;
      }
    }
  }
  //good, now find a free entry
  //object name info is stored as xattr of naming object
  //begin searching from the hint
  //blknr = (oni->free_entry_hint * sizeof(struct objms_name_entry)) / objms_inode_blk_size(pi);
  blknr = (oni->free_entry_hint << 5) >> objms_inode_blk_shift(pi);
  //offset = (oni->free_entry_hint * sizeof(struct objms_name_entry)) % objms_inode_blk_size(pi);
  offset = (oni->free_entry_hint << 5) % objms_inode_blk_size(pi);

  if (!oni->free_entries_count){
    ret = objms_alloc_logentries(trans, 1);
    if (ret){
      goto out;
    }
    objms_add_logentry(trans, pi, MAX_DATA_PER_LENTRY, false); //only the first 48 bytes of inode will be modified

    objms_alloc_blocks(trans, pi, blknr, 1, true);//FIXME
    objms_update_isize(sbi, pi, pi->i_size + objms_inode_blk_size(pi));
    objms_add_logentry_info(trans, pi, MAX_DATA_PER_LENTRY);
    //oni->free_entries_count = objms_inode_blk_size(pi) / sizeof(struct objms_name_entry);
    oni->free_entries_count = objms_inode_blk_size(pi) >> 5;
    //oni->end_entry_index++;
  }
  //search a new free entry from free_entry_hint
  for (; blknr < pi->i_blocks; blknr++){
    bp = __objms_find_data_block(pi, blknr);
    blkaddr = objms_get_block(bp);

    blkend = min_t(unsigned long, objms_inode_blk_size(pi),
        content_size - (blknr << objms_inode_blk_shift(pi)));
    for (; offset <= blkend;
        offset += sizeof(struct objms_name_entry)){
      one = (struct objms_name_entry *)((char *)blkaddr + offset); 
      if (!one->objno){//found a free entry
        strncpy(one->name, tmpname->name, namelen);
        one->name[namelen] = '\0';
        one->objno = objno;

        if (oni->free_entry_hint == oni->end_entry_index){
          oni->end_entry_index++;
        }
        oni->free_entries_count--;
        oni->free_entry_hint++;
        goto out;
      }
      oni->free_entry_hint++;
    }
    offset = 0;
  }
/*  if (oni->free_entry_hint == oni->end_entry_index){
    oni->end_entry_index++;
  }
  oni->free_entries_count--;
  oni->free_entry_hint++;//FIXME: the next entry may not be free

  bp = __objms_find_data_block(pi, blknr);
  blkaddr = objms_get_block(bp);

  one = (struct objms_name_entry *)(blkaddr + offset); 
  strncpy(one->name, tmpname->name, namelen);
  one->name[namelen] = '\0';
  one->objno = objno;
 */ 
out:
  putname(tmpname);
  //objms_iput(inode);
  return ret;
}
/*
//find a objsystem by its name and return it's start_objno
SYSCALL_DEFINE1(objms_find_objsystem, const char __user *, name){
  struct objms_sb_info *sbi = objms_sbi;
  struct obj_system_type *op;
  struct filename *tmpname;
  unsigned long start_objno = 0;

  tmpname = getname(name);
  if (unlikely(IS_ERR(tmpname))){
    return 0;
  }
  op = objms_get_objsystem(sbi, tmpname->name);
  if (op){
    start_objno = le64_to_cpu(op->start_objno);
  }

  putname(tmpname);
  return start_objno;
}*/
/*
//register a new objsystem and create an initial object id for it(and return)
SYSCALL_DEFINE2(objms_register_objsystem, const char __user *, name,
    size_t, size){
  struct objms_sb_info *sbi = objms_sbi;
  int i;
  struct obj_system_type *op;
  struct objms_super_block *super = objms_get_super(sbi);
  struct filename *tmpname;
  unsigned long start_objno = 0;

  tmpname = getname(name);
  if (IS_ERR(tmpname)){
    return 0;
  }
  mutex_lock(&sbi->s_lock);
  op = objms_get_objsystem(sbi, tmpname->name);
  if (op || super->s_objsystem_count == OBJ_SYSTEM_MAX){
    //printk(KERN_ERR "@objms_register_objsystem: objsystem full\n");
    start_objno = 0;
    goto finish;
  }
  //create a initial object for obj_system & store objid in objsys
  start_objno = sys_objms_create(NULL, 0640);
  if (!start_objno){//failed
    //printk(KERN_ERR "@objms_register_objsystem: new_obj failed\n");
    goto finish;
  }

  //find a free objsystem item and fill it with the new objsystem
  op = objms_get_first_objsystem(sbi);
  for (i = 0; i < OBJ_SYSTEM_MAX; i++){
    if (op->magic != OBJ_SYSTEM_MAGIC){
      objms_memunlock_range(sbi, op, sizeof(*op));
      op->magic = OBJ_SYSTEM_MAGIC;
      strcpy(op->name, tmpname->name);
      op->start_objno = start_objno;
      //op->c_time = CURRENT_TIME;//FIXME
      objms_memlock_range(sbi, op, sizeof(*op));
      objms_memunlock_super(sbi, super);
      super->s_objsystem_count++;
      objms_memlock_super(sbi, super);
      break;
    }
    op = objms_get_next_objsystem(op);
  }

finish:
  mutex_unlock(&sbi->s_lock);
  putname(tmpname);
  return start_objno;
}*/
/*
//FIXME: use trans
SYSCALL_DEFINE1(objms_unregister_objsystem, const char __user *, name){
  struct objms_sb_info *sbi = objms_sbi;
  int ret = -1;
  struct obj_system_type *op;
  struct filename *tmpname;

  tmpname = getname(name);
  if (unlikely(IS_ERR(tmpname))){
    return PTR_ERR(tmpname);
  }
  
  op = objms_get_objsystem(sbi, tmpname->name);
  if (op){
    objms_memunlock_range(sbi, op, sizeof(*op));
    op->magic = 0;
    objms_memlock_range(sbi, op, sizeof(*op));
    ret = 0;
  }

  putname(tmpname);
  return ret;
}*/
//pre-allocate: FIXME: need fix
SYSCALL_DEFINE5(objms_allocate, unsigned long, tid, unsigned long, objno,
    int, mode, loff_t,  offset, size_t, len){
	struct objms_sb_info *sbi = objms_sbi;
  unsigned long ino = objno << OBJMS_INODE_BITS;
	struct objms_inode_info *inode;
	long ret = 0;
	unsigned long blocknr, blockoff;
	int num_blocks, blocksize_mask;
	struct objms_inode *pi;
	loff_t new_size;
  struct timespec i_mtime;

  objms_transaction_t *trans = objms_current_transaction(tid);
  if (unlikely(!trans)){
    return -1;
  }
/*  if (unlikely(!objno)){
    //printk(KERN_ERR "@objms_allocate_obj: objno=0\n");
    return -1;
  }*/
  if (unlikely(!len)){
    return 0;
  }

  inode = objms_iget(ino);
  if (!inode){
    //printk(KERN_ERR "@objms_allocate_obj: objms_iget failed\n");
    return -EINVAL;
  }

	/* We only support the FALLOC_FL_KEEP_SIZE mode */
	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	mutex_lock(&inode->i_mutex);
  pi = inode->pi;
  //printk(KERN_ERR "@objms_allocate_before, objno=%lu,offset=%lu,len=%lu,orig_len=%lu\n",
  //    objno, offset, len, pi->i_size);

	new_size = len + offset;
  //for large page size, only expand when new_size > orig_size
  if (new_size <= pi->i_size){
    //printk(KERN_ERR "@objms_allocate: new_size <= i_size\n");
    goto out;
  }
  //FIXME: align the offset and size
  unsigned int blk_size = objms_inode_blk_size(pi);
  new_size = (new_size + blk_size - 1) & ~(blk_size - 1);
  offset = pi->i_size;
  len = new_size - pi->i_size;
  //printk(KERN_ERR "@objms_allocate_after: offset=%lu,len=%lu\n",
  //    offset, len); 
	/*if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > pi->i_size) {
		ret = inode_newsize_ok(inode, new_size);//FIXME: unfinished
		if (ret)
			goto out;
	}*/
	
  //ret = objms_alloc_logentries(trans, MAX_INODE_LENTRIES + MAX_METABLOCK_LENTRIES);//FIXME, we do not have to allocate so many log entries
  ret = objms_alloc_logentries(trans, MAX_INODE_LENTRIES);
	if (unlikely(ret)){
		goto out;
	}
	objms_add_logentry(trans, pi, MAX_DATA_PER_LENTRY, false);

	/* Set the block size hint */
  printk(KERN_ERR "@objms_allocate:old_size=%lu,new_size=%lu\n",pi->i_size, new_size);
	objms_set_blocksize_hint(sbi, pi, new_size);

	blocksize_mask = sbi->blocksize - 1;
	blocknr = offset >> sbi->blocksize_bits;
	blockoff = offset & blocksize_mask;
	num_blocks = (blockoff + len + blocksize_mask) >> sbi->blocksize_bits;
	ret = objms_alloc_blocks(trans, pi, blocknr, num_blocks, true);

	i_mtime = CURRENT_TIME_SEC;

	objms_memunlock_inode(sbi, pi);
	if (ret || (mode & FALLOC_FL_KEEP_SIZE)) {
		pi->i_flags |= cpu_to_le32(OBJMS_EOFBLOCKS_FL);
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > pi->i_size) {
		pi->i_size = cpu_to_le64(new_size);
	}
	pi->i_mtime = cpu_to_le32(i_mtime.tv_sec);
	pi->i_ctime = cpu_to_le32(i_mtime.tv_sec);
	objms_memlock_inode(sbi, pi);
	objms_add_logentry_info(trans, pi, MAX_DATA_PER_LENTRY);

  //@ayu: FIXME, auto_commit mode test
  if (trans->flags & OBJMS_XAUTO){
    objms_auto_commit_txn(trans);
  }
out:
	mutex_unlock(&inode->i_mutex);
  objms_iput(trans, inode);
	return ret;
}

//like the fs's create() syscall
//create an object node of initial size size and return its number/id
//TODO: maybe we can pass a obj_stat structure pointer?
//SYSCALL_DEFINE2(objms_new_obj, int, blktype, umode_t, mode){
SYSCALL_DEFINE3(objms_create, unsigned long, tid,
   struct obj_stat __user *, statbuf, umode_t, mode){
  int ret = 0;
  unsigned int max_les = MAX_INODE_LENTRIES - 1;
  unsigned long objno = 0;
  int blk_type = OBJMS_BLOCK_TYPE_4K;
  struct objms_sb_info *sbi = objms_sbi;
  struct objms_inode_info *inode;

  objms_transaction_t *trans = objms_current_transaction(tid);
  if (!trans){
    return 0;
  }

  //@ayu: FIXME, allocate one more le to link next le
  //only necessary for normal commit mode
  /*if (!(trans->flags & OBJMS_XAUTO)){
    max_les++;
  }*/
  max_les = 3;//FIXME:create a file needs 3 les
  //allocate 2 log entry for new inode
  ret = objms_alloc_logentries(trans, max_les);
	if (unlikely(ret)){
    //printk(KERN_ERR "@objms_new_obj: alloc_logentries failed\n");
		goto out_err;
	}
  
  if (unlikely(statbuf)){//TODO: fill the object with user-defined initial values
    struct obj_stat ostat;
    ret = __copy_from_user(&ostat, statbuf, sizeof(ostat));
    if (ostat.st_objno > 0){
      objno = ostat.st_objno;
    }
    switch (ostat.st_blksize){
      case 1 << PAGE_SHIFT_2M:
        objms_memunlock_inode(sbi, inode->pi);
        blk_type = OBJMS_BLOCK_TYPE_2M;
        objms_memlock_inode(sbi, inode->pi);
        break;
      case 1 << PAGE_SHIFT_1G:
        objms_memunlock_inode(sbi, inode->pi);
        blk_type = OBJMS_BLOCK_TYPE_1G;
        objms_memlock_inode(sbi, inode->pi);
        break;
      default:
        //4K
        break;
    }
  }
  //create the object maybe with specific objno
  inode = objms_new_inode(trans, mode, objno);
  if (unlikely(statbuf)){//TODO: fill the object with user-defined initial values
    inode->pi->i_blk_type = blk_type;
    //inode->pi->i_pattern = ostat.st_pattern;
  }
  if (unlikely(IS_ERR(inode))){
    //printk(KERN_ERR "@objms_new_obj: new_inode failed\n");
    goto out_err;
  }
  objms_unlock_new_inode(inode);
  //the relationship between objno and the ino used inside objms is:
  objno = inode->i_ino >> OBJMS_INODE_BITS;
  //printk(KERN_ERR "@objms_create: objno=%lu\n", objno);

  //the whole inode needs to be flushed
  objms_need_log_inode(trans, inode->pi, sizeof(struct objms_inode));//the inode is logged
  //@ayu: FIXME, auto_commit mode test
  if (trans->flags & OBJMS_XAUTO){
    objms_auto_commit_txn(trans);
  }
	return objno;
out_err:
	return 0;
}

//FIXME: unfinished, can copy from objms_unlink
SYSCALL_DEFINE2(objms_delete, unsigned long, tid, unsigned long, objno){
  //struct objms_sb_info *sbi = objms_sbi;
  int ret = 0;
  //unsigned int max_les = MAX_INODE_LENTRIES - 1;
  unsigned int max_les = 0;
  unsigned long ino = objno << OBJMS_INODE_BITS;
  struct objms_inode_info *inode;
  struct objms_inode *pi;
  bool need_log_pi = false;

  objms_transaction_t *trans = objms_current_transaction(tid);
  if (unlikely(!trans)){
    return -1;
  }

  //printk(KERN_ERR "@objms_delete: objno=%lu\n", objno);
/*  if (unlikely(!objno)){
    //printk(KERN_ERR "@objms_delete_obj: objno=0\n");
    return -1;
  }*/
  inode = objms_iget(ino);
  if (unlikely(!inode)){
    //printk(KERN_ERR "@objms_delete_obj: objms_iget failed\n");
    return -EINVAL;
  }

  mutex_lock(&inode->i_mutex);
  pi = inode->pi;

  //@ayu: FIXME, allocate one more le to link next le
  //only necessary for normal commit mode
  /*if (!(trans->flags & OBJMS_XAUTO)){
    max_les++;
  }*/
  //FIXME:delete a file needs 3 les,
  //2 has been allocated in set_xattr()
  if (objms_need_log_inode(trans, pi, MAX_DATA_PER_LENTRY)){
    max_les++;//one more le for pi 
    need_log_pi = true;
  }
  ret = objms_alloc_logentries(trans, max_les);
	if (unlikely(ret)) {
    objms_iput(trans, inode);
    return ret;
	}
  if (need_log_pi){
    objms_add_logentry(trans, pi, MAX_DATA_PER_LENTRY, false);
  }
  //clear inode's inuse flag(so when i_count reaches 0 we can delete it)
  //objms_clear_inode_inuse(sbi, pi);
  pi->i_flags |= OBJMS_INODE_BEFREE;
  //objms_remove_inode_hash(inode);//FIXME

  //decrease inodes->i_count, it will be deleted on disk because INODE_IN_USE is cleared
  spin_lock(&inode->i_lock);
  atomic_set(&inode->i_count, 1);
  inode->i_state |= I_FREEING;
  spin_unlock(&inode->i_lock);
  //objms_remove_inode_hash(inode);//FIXME
  mutex_unlock(&inode->i_mutex);

  objms_iput(trans, inode);
  //@ayu: FIXME, auto_commit mode test
  if (trans->flags & OBJMS_XAUTO){
    objms_auto_commit_txn(trans);
  }

  //TODO:
/*
  objms_truncate_add(sbi, inode, inode->pi->i_size);//FIXME
  objms_clear_inode_inuse(sbi, inode->pi);
  objms_evict_inode(sbi, inode);//FIXME: we should clear_nlink first!
*/
  return ret;
}

static ssize_t objms_direct_read(struct objms_inode *pi,
    char __user *buf, size_t len, loff_t pos){
  int progress = 0, hole = 0;
  ssize_t retval = 0;
  unsigned long blocknr, blockoff;
  unsigned int num_blocks;
  loff_t size, offset;
  struct objms_sb_info *sbi = objms_sbi;

  rcu_read_lock();
  size = le64_to_cpu(pi->i_size);
  if (pos + len > size){
    len = size - pos;
  }

  //find starting block number to access
  blocknr = pos >> sbi->blocksize_bits;
  //find starting offset within starting block
  blockoff = pos & (sbi->blocksize - 1);
  //find number of blocks to access
  num_blocks = (blockoff + len + sbi->blocksize - 1)
    >> sbi->blocksize_bits;

  offset = 0;
  do {
    int count;
    u8 *bp = NULL;
    u64 block = objms_find_data_block(sbi, pi, blocknr);
    if (unlikely(!block)){
      hole = 1;
      goto hole;
    }
    bp = (u8 *)objms_get_block(block);
    if (unlikely(!bp)){
      retval = -EACCES;
      goto out;
    }
hole:
    ++blocknr;
    count = blockoff + len > sbi->blocksize ?
      sbi->blocksize - blockoff : len;//how many I should read

    if (unlikely(hole)){
      retval = __clear_user(buf + offset, count);//memset user space zero
    } else {
      retval = __copy_to_user(buf + offset, bp + blockoff, count);
    }
    if (unlikely(retval)){
      retval = -EFAULT;
      goto out;
    }

    progress += count;
    offset += count;
    len -= count;
    blockoff = 0;
    hole = 0;
  } while (len);

  retval = progress;
out:
  rcu_read_unlock();
  return retval;
}
//read data from an object to user space
//copy from generic_file_aio_read()
SYSCALL_DEFINE5(objms_read, unsigned long, tid, unsigned long, objno,
    char __user *, buf, size_t, len, loff_t, pos){
  ssize_t retval = 0;
  loff_t size;
  //unsigned long ino = objno << OBJMS_INODE_BITS;
  struct objms_inode_info *inode = NULL;
  objms_transaction_t *trans = objms_current_transaction(tid);

  if (unlikely(!len)){
    return 0;
  }
  inode = objms_iget(objno << OBJMS_INODE_BITS);
  if (unlikely(IS_ERR(inode))){//invalid objno
    //printk(KERN_ERR "@objms_read_obj: bad inode\n");
    return -EINVAL;
  }

  if (unlikely(!access_ok(VERIFY_WRITE, buf, len))){
    //printk(KERN_ERR "@objms_read_obj: !access_ok()\n");
    retval = -EFAULT;
    goto out;
  }
  //printk(KERN_ERR "@objms_read: objno=%lu,i_size=%lu,len=%lu, pos=%lu\n",
  //    objno, inode->pi->i_size, len, pos);
  size = inode->pi->i_size;
  //if (likely(pos < size)){
  if (pos < size){
    retval = objms_direct_read(inode->pi, buf, len, pos);
/*    if (retval <= 0){
      printk(KERN_ERR "@objms_read_obj: objms_direct_read failed, retval = %ld\n", retval);
    }*/
  }/* else {
    printk(KERN_ERR "@objms_read_obj: pos(%lld) >= size(%lld)\n",
        pos, size);
  }*/

      //printk(KERN_ERR "@read: objno=%lu,read=%lu,offset=%lu,len=%lu\n",
      //    objno, retval, pos, len);
  //modify the access time
  objms_update_atime(objms_sbi, inode->pi);
out:
  objms_iput(NULL, inode);
  return retval;
}
//FIXME: latency calculation is wrong if flush_buffer is called
//however, in iozone test the flush_buffer won't be executed
static inline void objms_flush_edge_cachelines(loff_t pos,
    ssize_t len, void *start_addr){
  /*if (unlikely(pos & 0x7)){
    objms_flush_buffer(start_addr, 1, false);
    printk(KERN_ERR "@pos & 0x7\n");
  }
  if (unlikely(((pos + len) & 0x7) && ((pos & (CACHELINE_SIZE - 1))
          != ((pos + len) & (CACHELINE_SIZE - 1))))){
    objms_flush_buffer(start_addr + len, 1, false);
    printk(KERN_ERR "@pos + len & 0x7\n");
  }*/
#ifdef PCM_EMULATE_LATENCY
  //int extra_latency = (int)len * (1 - (float)PCM_BANDWIDTH_MB / DRAM_BANDWIDTH_MB)
  //  / (((float)PCM_BANDWIDTH_MB) / 1000);
  emulate_latency_ns(len);//FIXME
#endif
}

/* optimized path for file write that doesn't require a transaction. In this
 * path we don't need to allocate any new data blocks. So the only meta-data
 * modified in path is inode's i_size, i_ctime, and i_mtime fields */
/*static ssize_t objms_write_fast(struct objms_inode *pi,
    const char __user *buf, size_t count, loff_t pos, u64 block){
	u8 *bp = objms_get_block(block);
	size_t offset = pos & (objms_sbi->blocksize - 1);
	size_t copied, left;
  ssize_t retval = 0;
  struct timespec mtime = CURRENT_TIME_SEC;

  left = __copy_from_user_inatomic_nocache(bp + offset, buf, count);
  copied = count - left;
  objms_flush_edge_cachelines(pos, copied, bp + offset);

  if (unlikely(copied != count)){
    return -EFAULT;
  }

  pos += copied;
  if (pos > pi->i_size){
    //make sure written data is persistent before updating time and size
    PERSISTENT_MARK();
    PERSISTENT_BARRIER();
    //objms_update_isize(objms_sbi, pi, pos);
    //objms_update_time(objms_sbi, pi);
    //FIXME: we should use cmpxchg_double_local
    objms_memunlock_inode(objms_sbi, pi);
    //pi->i_size = cpu_to_le64(size);
    //pi->i_mtime = cpu_to_le32(mtime.tv_sec);
    //pi->i_size, pi->i_mtime need to be atomically updated
    __le32 words[2];
    words[0] = pi->i_ctime;
    words[1] = cpu_to_le32(mtime.tv_sec);
    cmpxchg_double_local(&pi->i_size, (u64 *)&pi->i_ctime, pi->i_size,
        *(u64 *)&pi->i_ctime, size, *(u64 *)words);
    objms_memlock_inode(objms_sbi, pi);
  } else {
    //objms_update_time(objms_sbi, pi);
    objms_memunlock_inode(objms_sbi, pi);
    pi->i_mtime = cpu_to_le32(mtime.tv_sec);
    objms_memlock_inode(objms_sbi, pi);
  }
  objms_flush_buffer(pi, 1, false);
	
  retval = copied;
	return retval;
}
*/
//only clear edge block for new_blk(start or end)
/*static inline void objms_clear_edge_blk(struct objms_sb_info *sbi,
    struct objms_inode *oi, unsigned long block,
    size_t blk_off, bool is_end_blk){
  void *ptr;
  size_t count;
  unsigned long blknr;

  blknr = block >> (objms_inode_blk_shift(oi) - sbi->blocksize_bits);
  ptr = objms_get_block(__objms_find_data_block(oi, blknr));
  if (ptr != NULL){
    if (is_end_blk){
      ptr = ptr + blk_off - (blk_off % 8);
      count = objms_inode_blk_size(oi) - blk_off + (blk_off % 8);
    } else {
      count = blk_off + (8 - (blk_off % 8));
    }
    objms_memunlock_range(sbi, ptr, objms_inode_blk_size(oi));
    memset_nt(ptr, 0, count);
    objms_memlock_range(sbi, ptr, objms_inode_blk_size(oi));
  }
}*/
//there may be hole in object's data pages,
//some pages is not allocated yet,
//version for write_obj, create = 1
inline u64 objms_find_and_alloc_blocks(objms_transaction_t *trans, struct objms_inode *pi,
    sector_t iblock){
	u64 block = objms_find_data_block(objms_sbi, pi, iblock);

  if (unlikely(!block)) {//it seldom never comes here, this may be useful for objms_objmap_fault
    //the trans could not be NULL
    //printk(KERN_ERR "@objms_find_and_alloc_blocks: pi=%p,trans=%p\n",
    //    pi, trans);
    if (objms_alloc_blocks(trans, pi, iblock, 1, true)){
      //bad block
      return 0;
    }
		block = objms_find_data_block(objms_sbi, pi, iblock);
		return block;
	} else {
    return block;
  }
}

static ssize_t objms_direct_write(objms_transaction_t *trans, struct objms_inode *pi,
    const char __user *buf, size_t count, loff_t pos){
  ssize_t written = 0;
  size_t bytes, copied, left, retval = 0;
  unsigned long index, offset;
  int begin, end;

  do {
    u8 *bp;
    sector_t block;
    offset = (pos & (objms_sbi->blocksize - 1));//within page
    index = pos >> objms_sbi->blocksize_bits;
    bytes = objms_sbi->blocksize - offset;
    if (bytes > count){
      bytes = count;
    }
    block = objms_find_and_alloc_blocks(trans, pi, index);
    if (unlikely(!block)){
      break;
    }
    bp = objms_get_block(block);

    begin = 0;
    end = bytes;
#ifdef OBJMS_ENABLE_ASYNC_FLUSH
    //FIXME: old-ver: only for auto-commit mode txn
    //if ((trans->flags & OBJMS_XAUTO) && trans->flusher_cpup){
#ifdef OBJMS_DATA_ASYNC
        //&& (trans->backward_ole->status & OLE_FLUSHED)){//500ns
      int ratio_son = 1, ratio_mom = 2;//ratio的分子分母

/*#ifdef OBJMS_ENABLE_DEBUG
      ratio_son = 0;
      if (trans->backward_ole->status & OLE_FLUSHED){
        objms_sbi->flushed_times++;
      } else if (trans->backward_ole->status & OLE_FLUSHING){
        objms_sbi->flushing_times++;
      } else {
        objms_sbi->flushable_times++;
      }
#endif*/

      //150ns
      //old: 1/2, 1/2, 1/3
#ifdef OBJMS_DYNAMIC_OLE
      if (trans->backward_ole){
        if (trans->backward_ole->status & OLE_FLUSHED){
          ratio_son = 2;
          ratio_mom = 3;
#ifdef OBJMS_ENABLE_DEBUG
          //objms_sbi->obj_wakeup1++;
#endif
        } else if (trans->backward_ole->status & OLE_FLUSHING){
          ratio_son = 1;
          ratio_mom = 2;
#ifdef OBJMS_ENABLE_DEBUG
          //objms_sbi->obj_wakeup2++;
#endif
        } else {
          ratio_son = 1;
          ratio_mom = 2;
          //ratio_son = 0;
#ifdef OBJMS_ENABLE_DEBUG
          //objms_sbi->obj_wakeup3++;
#endif
        }
      } else {
        ratio_son = 1;
        ratio_mom = 2;
      }
#else
      if (objms_has_empty_flusher_entry(trans)){
        if (trans->fe_count){
          if (trans->flusher_entries[trans->fe_tail].status & OLE_FLUSHED){
            ratio_son = 2;
            ratio_mom = 3;
#ifdef OBJMS_ENABLE_DEBUG
            //objms_sbi->obj_wakeup1++;
#endif
          } else if (trans->flusher_entries[trans->fe_tail].status & OLE_FLUSHING){
            ratio_son = 1;
            ratio_mom = 2;
#ifdef OBJMS_ENABLE_DEBUG
            //objms_sbi->obj_wakeup2++;
#endif
          } else {
            ratio_son = 1;
            ratio_mom = 2;
            //ratio_son = 0;
#ifdef OBJMS_ENABLE_DEBUG
            //objms_sbi->obj_wakeup3++;
#endif
          }
        } else {
          ratio_son = 1;
          ratio_mom = 2;
        }
      } else {
        ratio_son = 0;
      }
#endif
/*
      //500ns
      if (trans->backward_ole->status & OLE_FLUSHED){
        ratio_son = 2;
        ratio_mom = 3;
      } else if (trans->backward_ole->status & OLE_FLUSHING){
        ratio_mom = 2;
      }

      //1000ns
      ratio_mom = 3;
      if (trans->backward_ole->status & OLE_FLUSHED){
        ratio_son = 2;
        ratio_mom = 3;
      } else if (trans->backward_ole->status & OLE_FLUSHING){
        ratio_mom = 2;
      }
*/
      begin = offset & (~(CACHELINE_SIZE - 1));
      end = (offset + bytes + CACHELINE_SIZE - 1) & (~(CACHELINE_SIZE - 1));
      int region_size = (end - begin) >> CLINE_SHIFT;
      int separator = ((region_size) * ratio_son / ratio_mom) << CLINE_SHIFT;//3/4 part of the region bytes
      if (separator){
        //begin: begin bytes, end: end bytes
        begin = begin + separator - offset;
        end = bytes - begin;
        //if metadata is flushed out before data
        //use asynchronous flush for data
        left = __copy_from_user(bp + offset, buf, begin);
        objms_add_logentry_info(trans, bp + offset, begin);

        //printk(KERN_ERR "@objms_direct_write: backwards write,offset=%lu,begin=%d,end=%d\n",
        //    offset, begin, end);
      } else {
        begin = 0;
        end = bytes;
      }
#endif
#endif
    //as we use asynchronous flush...
    left = objms_memcpy_to_scm_nocache(bp + offset + begin, buf + begin, end);
    //left = __copy_from_user(bp + offset + begin, buf + begin, end);
    copied = bytes - left;
    //objms_flush_edge_cachelines(pos, end, bp + offset + begin);

    if (unlikely(copied != bytes)){
      retval = -EFAULT;
      goto out;
    }
    written += copied;
    count -= copied;
    pos += copied;
    buf += copied;
  }while (count);
  retval = written;
/*
  if (pos > pi->i_size){
    objms_update_isize(objms_sbi, pi, pos);
  }*/
out:
  return retval;
}

//FIXME: 大页写目前只支持COW, tokyocabinet测试可能会有问题
//优化：如果allocate一段空间但是并没有清零，则往该空间写直接覆盖就行
static ssize_t objms_write_obj_safe(objms_transaction_t *trans,
    struct objms_inode_info *inode, const char __user *buf, size_t count, loff_t pos,
    bool fine_lock){
  struct objms_inode *pi = inode->pi;
  ssize_t written = 0;
  u64 old_sblk;
  //bool new_sblk = false, new_eblk = false;
  size_t sblk_offset, eblk_len, eblk_overwrite_len, old_sblk_len, old_eblk_len, ret;
  unsigned long start_blk, end_blk, num_blocks;
  void *old_sblkptr = NULL, *old_eblkptr = NULL;
  unsigned int max_les = 0;
  bool need_log_pi = false, log_sameblk = false, log_sblk = false, log_eblk = false;
  size_t left, len;

  //num_blocks in 4KB block
  num_blocks = (((pos & (objms_sbi->blocksize - 1))
        + count +  - 1) >> objms_sbi->blocksize_bits) + 1;
  //offset in the actual block size block
  sblk_offset = pos & (objms_inode_blk_size(pi) - 1);
  start_blk = pos >> objms_sbi->blocksize_bits;
  end_blk = start_blk + num_blocks - 1;

  old_sblk = objms_find_data_block(objms_sbi, pi, start_blk);

  //for append write
  if (pos >= pi->i_size){
    if (old_sblk){
      start_blk++;//no need to re-allocate block for start_blk
      num_blocks--;
    }
    max_les = 1;//就算不进行cow,也需要对为0的旧数据块指针做日志
    //目前只分配1个,不够再补
    goto alloc_les;
  } else {
    //old_sblk already exists!
    //save the old start block address
    old_sblkptr = objms_get_block(old_sblk);

    //save the old end block address
    u64 old_eblk = objms_find_data_block(objms_sbi, pi, end_blk);
    if (old_eblk){
      old_eblkptr = objms_get_block(old_eblk);
    }

    //old_eblk_len: valid data len in old eblk
    //eblk_len: valid data len (to be written) in new eblk
    //last modified block is the last block of pi
    if (end_blk == pi->i_blocks - 1){
      old_eblk_len = pi->i_size & (objms_inode_blk_size(pi) - 1);
      if (old_eblk_len == 0){
        old_eblk_len = objms_inode_blk_size(pi);
      }
    } else {
      old_eblk_len = objms_inode_blk_size(pi);
    }

    eblk_len = (pos + count) & (objms_inode_blk_size(pi) - 1);
    if (eblk_len == 0){
      eblk_len = objms_inode_blk_size(pi);
    }

    //update a same_block, currently only support 4KB block
    if (num_blocks == 1){//(sblk_offset + count <= objms_inode_blk_size(pi))
      eblk_overwrite_len = (old_eblk_len <= eblk_len)? (old_eblk_len - sblk_offset): count;
      //use journaling for data
      if (eblk_overwrite_len <= COW2JOURNAL_LIMIT){
        //printk(KERN_ERR "@log_sameblk: pos=%lu,count=%lu\n", pos, count);
        max_les = (eblk_overwrite_len + MAX_DATA_PER_LENTRY - 1)
          / MAX_DATA_PER_LENTRY;
        log_sameblk = true;
        goto alloc_les;
      }
      //else do 2 cow copy for the same block
    } else {
      //not same block
      //decide whether we should use cow or undo logging
      //for data written to start_blk and end_blk
      //check cow for sblk
      if (start_blk == pi->i_blocks - 1){
        old_sblk_len = pi->i_size & (objms_inode_blk_size(pi) - 1);
        if (old_sblk_len == 0){
          old_sblk_len = objms_inode_blk_size(pi);
        }
      } else {
        old_sblk_len = objms_inode_blk_size(pi);
      }

      if ((old_sblk_len - sblk_offset) <= COW2JOURNAL_LIMIT){
        //data to be written <= COW2JOURNAL_LIMIT, use journaling
        max_les += (old_sblk_len - sblk_offset + MAX_DATA_PER_LENTRY - 1)
          / MAX_DATA_PER_LENTRY;
        start_blk++;//no need to re-allocate block for start_blk
        num_blocks--;
        log_sblk = true;
      }

      //check cow for eblk
      //use eblk_len!
      if (old_eblk){//there's an overwrite in eblk
        eblk_overwrite_len = (old_eblk_len <= eblk_len)? old_eblk_len: eblk_len;
        //printk(KERN_ERR "@end_blk-cow\n");
        if (eblk_overwrite_len <= COW2JOURNAL_LIMIT){
          max_les += (eblk_overwrite_len + MAX_DATA_PER_LENTRY - 1)
            / MAX_DATA_PER_LENTRY;
          num_blocks--;
          log_eblk = true;
        }
      }
    }

    max_les += (num_blocks + MAX_PTRS_PER_LENTRY - 1)
      / MAX_PTRS_PER_LENTRY;
  }

alloc_les:

  if (objms_need_log_inode(trans, pi, MAX_DATA_PER_LENTRY)){
    max_les++;//one more le for pi 
    need_log_pi = true;
  }
  
  ret = objms_alloc_logentries(trans, max_les);
  if (unlikely(ret)){
    goto out;
  }
  if (need_log_pi){
    //only the first 48 bytes of inode will be modified
    objms_add_logentry(trans, pi, MAX_DATA_PER_LENTRY, false);
    objms_update_time(objms_sbi, pi);
  }
  if (pos + count > pi->i_size){
    objms_update_isize(objms_sbi, pi, pos + count);
  }
  //here check if we can release the lock immediately
#ifdef OBJMS_FINE_LOCK
  if (fine_lock){
    mutex_unlock(&inode->i_mutex);
  }
#endif

//log_cow_data:
  if (unlikely(log_sameblk)){
    //flush the pi
    objms_add_logentry_info(trans, pi, MAX_DATA_PER_LENTRY);

    objms_add_logentry(trans, old_sblkptr + sblk_offset, eblk_overwrite_len, false);
    
#ifdef OBJMS_ENABLE_ASYNC_FLUSH
    left = __copy_from_user(old_sblkptr + sblk_offset, buf, count);
    //add_ole individually because count >= eblk_overwrite_len
    objms_add_logentry_info(trans, old_sblkptr + sblk_offset, count);
#else
    left = objms_memcpy_to_scm_nocache(old_sblkptr + sblk_offset, buf, count);
#endif
    ret = count;

    goto out;
  } else {
    //don't zero-out the allocated blocks
    if (num_blocks){
      objms_alloc_blocks(trans, pi, start_blk, num_blocks, false);
    }
    //flush the pi
    objms_add_logentry_info(trans, pi, MAX_DATA_PER_LENTRY);

    if (log_sblk){//use journaling instead of cow
      //@ayu: TODO:如果一块区域使用的是粗粒度日志，那么由于它使用的是non-temporal
      //拷贝，则对它记录日志后的更改也该使用non-temporal拷贝
      objms_add_logentry(trans, old_sblkptr + sblk_offset,
          old_sblk_len - sblk_offset, false);
      //printk(KERN_ERR "@objms_write_obj_safe: log_sblk,len=%u\n", old_sblk_len - sblk_offset);

#ifdef OBJMS_ENABLE_ASYNC_FLUSH
      left = __copy_from_user(old_sblkptr + sblk_offset,
          buf, objms_inode_blk_size(pi) - sblk_offset);
      //add_ole individually because objms_inode_blk_size(pi) >= old_sblk_len
      objms_add_logentry_info(trans, old_sblkptr + sblk_offset,
          objms_inode_blk_size(pi) - sblk_offset);
      written = objms_inode_blk_size(pi) - sblk_offset;
      count -= written;
      pos += written;
      buf += written;
#endif
    } else if (old_sblkptr && sblk_offset) {
      void *new_sblkptr = objms_get_block(
          objms_find_data_block(objms_sbi, pi, start_blk));
      //copy head part of the old start_blk that is not modified
      len = sblk_offset;
      //printk(KERN_ERR "@objms_write_obj_safe: sblk_cow,len=%u\n", len);
#ifdef OBJMS_ENABLE_ASYNC_FLUSH
      memcpy(new_sblkptr, old_sblkptr, len);
      objms_add_logentry_info(trans, new_sblkptr, len);
#else
      //其实objms_memcpy_to_scm_nocache就是__copy_from_user_inatomic_nocache
     left = objms_memcpy_to_scm_nocache(new_sblkptr, old_sblkptr, len);
#endif
    }
    if (log_eblk){//use journaling instead of cow
      objms_add_logentry(trans, old_eblkptr, eblk_overwrite_len, false);
      //printk(KERN_ERR "@objms_write_obj_safe: log_eblk,len=%u\n", eblk_overwrite_len);
#ifdef OBJMS_ENABLE_ASYNC_FLUSH
      left = __copy_from_user(old_eblkptr,
          buf + count - eblk_len, eblk_len);
      //add_ole individually because eblk_len >= eblk_overwrite_len
      objms_add_logentry_info(trans, old_eblkptr, eblk_len);
      
      written += eblk_len;
      count -= eblk_len;
#endif
    } else if (old_eblkptr && (old_eblk_len > eblk_len)){
      void *new_eblkptr = objms_get_block(
          objms_find_data_block(objms_sbi, pi, end_blk));
      //copy tail part of the old end_blk that is not modified
      len = old_eblk_len - eblk_len;
      //printk(KERN_ERR "@objms_write_obj_safe: eblk_cow,len=%u\n", len);
#ifdef OBJMS_ENABLE_ASYNC_FLUSH
      memcpy((char *)new_eblkptr + eblk_len,
          (char *)old_eblkptr + eblk_len, len);
      objms_add_logentry_info(trans, new_eblkptr + eblk_len, len);
#else
      left = objms_memcpy_to_scm_nocache((char *)new_eblkptr + eblk_len,
          (char *)old_eblkptr + eblk_len, len);
#endif
    }
  }

//do_write:
  written += objms_direct_write(trans, pi, buf, count, pos);
  ret = written;

out:
  return ret;
}


#ifdef OBJMS_WEAK_XMODE
static ssize_t objms_write_obj_unsafe(objms_transaction_t *trans,
    struct objms_inode_info *inode, const char __user *buf, size_t count, loff_t pos,
    bool fine_lock){
  struct objms_inode *pi = inode->pi;
  size_t offset, ret;
  unsigned long start_blk, end_blk, num_blocks;
  unsigned int max_les = 0;
  bool need_log_pi = false;
  
  offset = pos & (objms_sbi->blocksize - 1);
  num_blocks = ((count + offset - 1) >> objms_sbi->blocksize_bits) + 1;
  //offset in the actual block size block
  //offset = pos & (objms_inode_blk_size(pi) - 1);
  start_blk = pos >> objms_sbi->blocksize_bits;
  end_blk = start_blk + num_blocks - 1;

  //if there is no hole and it's an override, we don't have to log the metadata
  //currently do not consider hole
  //FIXME, TODO: we do not consider if the blocksize of pi is greater than 4KB!
  if (end_blk < pi->i_blocks){
    struct timespec mtime = CURRENT_TIME_SEC;
    //@ayu: FIXME, here check if we can release the lock immediately
    if (fine_lock){
      mutex_unlock(&inode->i_mutex);
    }
    ret = objms_direct_write(trans, pi, buf, count, pos);
    
    pos += ret;
    if (pos > pi->i_size){
      //__le32 words[2];
      //make sure written data is persistent before updating time and size
      PERSISTENT_MARK();
      PERSISTENT_BARRIER();
      //FIXME: we should use cmpxchg_double_local
      objms_memunlock_inode(objms_sbi, pi);
      pi->i_size = pos;
      pi->i_mtime = cpu_to_le32(mtime.tv_sec);
      //pi->i_size, pi->i_mtime need to be atomically updated
      //FIXME: the following will crash the system
      //words[0] = pi->i_ctime;
      //words[1] = cpu_to_le32(mtime.tv_sec);
      //cmpxchg_double_local(&pi->i_size, (u64 *)&pi->i_ctime, pi->i_size,
       //   *(u64 *)&pi->i_ctime, pos, *(u64 *)words);
      objms_memlock_inode(objms_sbi, pi);
    } else {
      //objms_update_time(objms_sbi, pi);
      objms_memunlock_inode(objms_sbi, pi);
      pi->i_mtime = cpu_to_le32(mtime.tv_sec);
      objms_memlock_inode(objms_sbi, pi);
    }
    objms_flush_buffer(pi, 1, false);

    goto out;
  } else if (pi->root){
    //if ((end_blk >= pi->i_blocks) && pi->root){
  //do not consider hole, calculate how many new data page we should allocate
      unsigned int num_to_alloc = end_blk + 1 - pi->i_blocks;
      unsigned int leaf_entry_left, root_entry_count;
      int shift;

      if (!(pi->i_blocks % 512)){
        leaf_entry_left = 0;
      } else {
        leaf_entry_left = 512 - pi->i_blocks % 512;//blocks count left in leaf b tree node
      }
      if (num_to_alloc <= leaf_entry_left){//no meta b tree page would allocate
        if ((num_to_alloc << 3) >= CACHELINE2PAGE_LIMIT){//will use log page for large journaling
          max_les = 1;
        } else {
          max_les = (num_to_alloc + MAX_PTRS_PER_LENTRY - 1) / MAX_PTRS_PER_LENTRY;
        }
      } else {
        if ((leaf_entry_left << 3) >= CACHELINE2PAGE_LIMIT){
          max_les = 1;
        } else {
          max_les = (leaf_entry_left + MAX_PTRS_PER_LENTRY - 1) / MAX_PTRS_PER_LENTRY;
        }
        num_to_alloc -= leaf_entry_left;
        if (pi->height == 1){//height would increase
          if (end_blk < (1 << 18)){//new height = 2
            shift = 512;
            root_entry_count = (num_to_alloc + shift - 1) / shift;//entry to log in level2(top)
            max_les += (root_entry_count + MAX_PTRS_PER_LENTRY - 1) / MAX_PTRS_PER_LENTRY;
          } else {//new height = 3
            shift = 1 << 18;
            root_entry_count = 511;//entry to log in level 2
            max_les += (root_entry_count + MAX_PTRS_PER_LENTRY - 1) / MAX_PTRS_PER_LENTRY;
            num_to_alloc -= root_entry_count << 9;
            root_entry_count = (num_to_alloc + shift - 1) / shift;//entry to log in level3(top)
            max_les += (root_entry_count + MAX_PTRS_PER_LENTRY - 1) / MAX_PTRS_PER_LENTRY;
          }
        } else if (pi->height == 2){//height may increase
          if (end_blk < (1 << 18)){//new height = 2
            shift = 512;
            root_entry_count = (num_to_alloc + shift - 1) / shift;//entry to log in level2(top)
            max_les += (root_entry_count + MAX_PTRS_PER_LENTRY - 1) / MAX_PTRS_PER_LENTRY;
          } else {//new height = 3
            shift = 1 << 18;
            root_entry_count = (shift - pi->i_blocks) / 512;//entry to log in level2
            max_les += (root_entry_count + MAX_PTRS_PER_LENTRY - 1) / MAX_PTRS_PER_LENTRY;
            num_to_alloc -= root_entry_count << 9;
            root_entry_count = (num_to_alloc + shift - 1) / shift;//entry to log in level3(top)
            max_les += (root_entry_count + MAX_PTRS_PER_LENTRY - 1) / MAX_PTRS_PER_LENTRY;
          }
        } else {//pi->height = 3, height would not increase
          shift = 1 << 18;
          root_entry_count = (num_to_alloc + shift - 1) / shift;//entry to log in level3(top)
          max_les += (root_entry_count + MAX_PTRS_PER_LENTRY - 1) / MAX_PTRS_PER_LENTRY;
        }
      }
    }

  //@ayu: FIXME, allocate one more le to link next le
  //only necessary for normal commit mode
  if (!(trans->flags & OBJMS_XAUTO)){
    max_les++;
  }
    if (objms_need_log_inode(trans, pi, MAX_DATA_PER_LENTRY)){
      max_les++;//one more le for pi 
      need_log_pi = true;
    }
    ret = objms_alloc_logentries(trans, max_les);
    if (unlikely(ret)){
      goto out;
    }
    if (need_log_pi){
      //only the first 48 bytes of inode will be modified
      objms_add_logentry(trans, pi, MAX_DATA_PER_LENTRY, true);
      objms_update_time(objms_sbi, pi);
    }

    if (num_blocks){
      objms_alloc_blocks(trans, pi, start_blk, num_blocks, false);
    }

    //@ayu: FIXME
    //asynchronous metadata flush
    //wakeup_log_flusher(trans);

    ret = objms_direct_write(trans, pi, buf, count, pos);
    pos += ret;
    if (pos > pi->i_size){
      objms_update_isize(objms_sbi, pi, pos);
    }
out:
    return ret;
}
#endif
SYSCALL_DEFINE5(objms_write, unsigned long, tid, unsigned long, objno,
    const char __user *, buf, size_t, len, loff_t, pos){
  //struct objms_sb_info *sbi = objms_sbi;
  struct objms_inode *pi;
  //ssize_t written = 0;
  size_t ret;
  //unsigned long ino = objno << OBJMS_INODE_BITS;
  struct objms_inode_info *inode;
  bool cow = false;//COW switch
  struct olock *newol = NULL;
  bool fine_lock = false, new_lock = true;

  objms_transaction_t *trans = objms_current_transaction(tid);
  if (unlikely(!trans)){
    return -1;
  }
  
  if (unlikely(!len)){
    return 0;
  }
  cow = trans->flags & OBJMS_XSTRONG;

re_lock:
  inode = objms_iget(objno << OBJMS_INODE_BITS);
  if (unlikely(IS_ERR(inode))){//invalid objno
    printk(KERN_ERR "@objms_write_obj: bad inode, objno=%lu\n", objno);
    return -EINVAL;
  }

  mutex_lock(&inode->i_mutex);
  if (unlikely(!access_ok(VERIFY_READ, buf, len))){
    ret = -EFAULT;
    goto out;
  }
  pi = inode->pi;
  //if (pos < pi->i_size)
  //printk(KERN_ERR "@objms_write_obj: objno=%lu,isize=%lu,offset=%lu,len=%lu,iblocks=%lu\n",
  //    objno, pi->i_size, pos, len, pi->i_blocks);
#ifdef OBJMS_FINE_LOCK
  //currently only allow concurrent write for rewrite operation
  if (pos + len <= pi->i_size){
    struct olock *ol;
    bool is_conflict = false;
    pid_t current_pid = current->pid;
    //printk(KERN_ERR "@fine_lock begin\n");
    //check olock list, do not merge!
    list_for_each_entry(ol, &inode->i_lock_head, l_list) {
      if (pos + len <= ol->l_start
          || pos >= ol->l_start + ol->l_len){
        continue;
      } else if (ol->l_pid != current_pid){
        //conflict
        is_conflict = true;
        break;
      } else {
        //the thread has created a global lock before
        if ((pos >= ol->l_start)
            && (pos + len <= ol->l_start + ol->l_len)
            && (ol->l_type == 1)){
          //only if the new lock is smaller than the previous lock
          //and previous lock is stronger than the new lock
          //old:------------------
          //new:   +++++++++++
          new_lock = false;//do not need to create a new lock
          break;
        }
      }
    }
    if (is_conflict){
      mutex_unlock(&inode->i_mutex);
      goto re_lock;//try again
    }
    fine_lock = true;
    if (new_lock){
      newol = objms_alloc_olock();
      newol->l_type = 1;//write
      newol->l_pid = current_pid;
      newol->l_start = pos;
      newol->l_len = len;
      list_add(&newol->l_list, &inode->i_lock_head);
    }
  }
#endif

#ifdef OBJMS_WEAK_XMODE
  if (!cow){
    ret = objms_write_obj_unsafe(trans, inode, buf, len, pos, fine_lock);
  } else {
    ret = objms_write_obj_safe(trans, inode, buf, len, pos, fine_lock);
  }
#else
    ret = objms_write_obj_safe(trans, inode, buf, len, pos, fine_lock);
#endif
  //auto_commit mode
  if (trans->flags & OBJMS_XAUTO){
    objms_auto_commit_txn(trans);
  }

out:
#ifdef OBJMS_FINE_LOCK
  if (newol){
    //the lock is created in this operation, so release it on finish
    mutex_lock(&inode->i_mutex);
    list_del(&newol->l_list);
    mutex_unlock(&inode->i_mutex);
    objms_free_olock(newol);
  } else {
    mutex_unlock(&inode->i_mutex);
  }
#else
    mutex_unlock(&inode->i_mutex);
#endif
  objms_iput(trans, inode);
  return ret;
}

static int objms_direct_log(objms_transaction_t *trans,
    struct objms_inode *pi, loff_t pos, size_t len, bool is_flush, bool add_ole){
  unsigned long blocknr, blockoff;
  unsigned int num_blocks;
  loff_t size, offset;
  struct objms_sb_info *sbi = objms_sbi;
  int retval = 0;

  size = le64_to_cpu(pi->i_size);
  if (pos + len > size){
    len = size - pos;
  }

  //find starting block number to access
  blocknr = pos >> sbi->blocksize_bits;
  //find starting offset within starting block
  blockoff = pos & (sbi->blocksize - 1);
  //find number of blocks to access
  num_blocks = (blockoff + len + sbi->blocksize - 1)
    >> sbi->blocksize_bits;

  offset = 0;
  do {
    int count;
    u8 *bp = NULL;
    u64 block = objms_find_data_block(sbi, pi, blocknr);
    if (unlikely(!block)){
      retval = -EFAULT;
      goto out;
    }
    bp = (u8 *)objms_get_block(block);

    ++blocknr;
    count = blockoff + len > sbi->blocksize ?
      sbi->blocksize - blockoff : len;//how many I should read

    if (is_flush){
      objms_add_logentry_info(trans, bp + blockoff, count);
      //trans->backward_ole->status |= OLE_FLUSHABLE;
      //wakeup_log_flusher(trans);
    } else {
      objms_add_logentry(trans, bp + blockoff, count, add_ole);
    }

    offset += count;
    len -= count;
    blockoff = 0;
  } while (len);

out:
  return retval;
}
//mark an region to be modified
//begin write to a memory object, logging a memory object's content
//do not add remapping and cow, just let user call write_obj instead
//@ayu: TODO: objms_omark()
//flags: 0 - mark, 1 - flush immediately
//FIXME: what if the page mapping hasn't been built yet?
SYSCALL_DEFINE5(objms_omark, unsigned long, tid, unsigned long, objno,
    unsigned long, addr, size_t, len, int, flags){
  struct objms_sb_info *sbi = objms_sbi;
  struct objms_inode_info *inode;
  size_t count = 0, ret = 0;
  unsigned int max_logentries;
  int i;
  bool cow;
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
  unsigned long offset;//offset within the object

  //printk(KERN_ERR "@objms_omark, tid=%lu,objno=%lu,addr=%lx,len=%lu,flags=%x\n",
  //    tid, objno, addr, len, flags);
  objms_transaction_t *trans = objms_current_transaction(tid);
  if (unlikely(!trans)){
    //printk(KERN_ERR "@objms_omark, trans = null\n");
    return -1;
  }
  //cow = trans->flags & OBJMS_XSTRONG;
  if (unlikely(!len)){//FIXME
    return 0;
  }

  inode = objms_iget(objno << OBJMS_INODE_BITS);
  if (unlikely(IS_ERR(inode))){//invalid objno
    return -EINVAL;
  }
  
  vma = find_vma(mm, addr);

  offset = (vma->vm_pgoff << PAGE_SHIFT) + (addr - vma->vm_start);
  //printk(KERN_ERR "@objms_omark: objno=%lu,vm_start=%lx,vm_end=%lx,vm_pgoff=%lu,offset=%lu,len,flags=%d\n",
  //    objno, vma->vm_start, vma->vm_end, vma->vm_pgoff, offset, len, flags);
  //printk(KERN_ERR "@objms_omark: objno=%lu,tid=%lu,addr=%lu,offset=%lu,len=%lu,flags=%d\n",
  //    objno, tid, addr, offset, len, flags);

  //@ayu: FIXME, when adding a new ole, the previous is flushable,
  //this should not be true for omark, but we allow it here.
  //FIXME: do not log the space exceeds i_size
  if (flags & OBJMS_OMARK_LOG){//only log the region
    //since we do not add ole, we should mark previous ole as flushable actively
    /*if (trans->backward_ole && (!(trans->backward_ole->status & OLE_FLUSHABLE))){
      trans->backward_ole->status |= OLE_FLUSHABLE;
      wakeup_log_flusher(trans);
    }*/
    objms_direct_log(trans, inode->pi, offset, len, false, false);
  } else if (flags & OBJMS_OMARK_FLUSH){//just flush the region
    //@ayu: FIXME
    /*if (trans->backward_ole && (!(trans->backward_ole->status & OLE_FLUSHABLE))){
      trans->backward_ole->status |= OLE_FLUSHABLE;
      wakeup_log_flusher(trans);
    }*/
    objms_direct_log(trans, inode->pi, offset, len, true, false);
    /*if (trans->flags & OBJMS_XAUTO){
      //for auto-commit mode, flush the region immediately
      objms_flush_buffer((void *)addr, len, false);//FIXME: wrong addr
    } else {
      //mark the last-marked region as flushable
      if (((unsigned long)trans->backward_ole->addr == addr)
          && (trans->backward_ole->size == len)){
        trans->backward_ole->status |= OLE_FLUSHABLE;
        wakeup_log_flusher(trans);
      } else {
        //add a new region that needs to be flushed
        objms_direct_log(trans, inode->pi, offset, len, true, false);
      }
    }*/
  } else {//default: log the region, add it to ole (not flushable)
     //TODO: first check if we can merge to a existing region
    //if data=journal, log the area to be modified
    //the marked region has been aligned to CACHELINE_SIZE
    //allocate logentries
    //count = len;
    //let the add_logentry calculate the number of needed log entries
    /*max_logentries = (count + MAX_DATA_PER_LENTRY - 1) / MAX_DATA_PER_LENTRY;
      ret = objms_alloc_logentries(trans, max_logentries);
      if (unlikely(ret)){
      goto out;
      }*/
    //objms_add_logentry(trans, (void *)addr, len, true);
    /*if (flags & OBJMS_OMARK_FLUSH_PREV){
      //FIXME: previous omarked region can also be flushed
      //problem in multi-thread
      if (trans->backward_ole && (!(trans->backward_ole & OLE_FLUSHABLE))){
        trans->backward_ole->status |= OLE_FLUSHABLE;
        wakeup_log_flusher(trans);
      }
    }*/
    //log the region and add it to ole
    objms_direct_log(trans, inode->pi, offset, len, false, true);
  }
out:
  return ret;
}

static void objms_fillattr(struct objms_inode_info *inode, struct obj_stat *stat){
  stat->st_objno = inode->i_ino >> OBJMS_INODE_BITS;
  stat->st_uid = le32_to_cpu(inode->pi->i_uid);
  stat->st_gid = le32_to_cpu(inode->pi->i_gid);
  stat->st_mode = le16_to_cpu(inode->pi->i_mode);
  stat->st_blksize = objms_inode_blk_size(inode->pi);
  stat->st_blocks = le64_to_cpu(inode->pi->i_blocks);
  stat->st_pattern = le32_to_cpu(inode->pi->i_pattern);
  stat->st_size = le64_to_cpu(inode->pi->i_size);
  stat->st_attrsize = le32_to_cpu(inode->pi->i_attrsize);
  stat->st_atime = le32_to_cpu(inode->pi->i_atime);
  stat->st_mtime = le32_to_cpu(inode->pi->i_mtime);
  stat->st_ctime = le32_to_cpu(inode->pi->i_ctime);
  //printk(KERN_ERR "@objms_fillattr: objno=%lu,mode=%o,blocks=%lu,size=%lu\n",
  //    stat->st_objno, stat->st_mode, stat->st_blocks, stat->st_size);
}

SYSCALL_DEFINE2(objms_obj_stat, unsigned long, objno,
    struct obj_stat __user *, statbuf){
  //struct objms_sb_info *sbi = objms_sbi;
  unsigned long ino = objno << OBJMS_INODE_BITS;
  struct objms_inode_info *inode;
  struct obj_stat tmp;

/*  if (unlikely(!objno)){
    //printk(KERN_ERR "@objms_obj_stat: objno=0\n");
    return -1;
  }*/
  inode = objms_iget(ino);
  if (unlikely(IS_ERR(inode))){//invalid objno
    //printk(KERN_ERR "@objms_obj_stat: bad inode\n");
    return -EINVAL;
  }

  objms_fillattr(inode, &tmp);

  objms_iput(NULL, inode);
  return __copy_to_user(statbuf, &tmp, sizeof(tmp))? -EFAULT: 0;
}
//get an object's block address by its blknr
const void *objms_block_address(unsigned long objno, unsigned long blocknr){
  //struct objms_sb_info *sbi = objms_sbi;
  struct objms_inode *pi;
  unsigned long ino = objno << OBJMS_INODE_BITS;
  struct objms_inode_info *inode;
  u64 bp;

/*  if (unlikely(!objno)){
    //printk(KERN_ERR "@objms_block_address: objno=0\n");
    return NULL;
  }*/
  inode = objms_iget(ino);
  if (unlikely(IS_ERR(inode))){//invalid objno
    //printk(KERN_ERR "@objms_block_address: bad inode\n");
    return NULL;
  }
  pi = inode->pi;

  objms_iput(NULL, inode);
  bp = __objms_find_data_block(pi, blocknr);
  return objms_get_block( bp);
}
EXPORT_SYMBOL(objms_block_address);

//get an object's onode address by its blknr(default0)
//当blocknr为0时表示从onode的起始地址
//否则就是扩展属性页的地址
const void *objms_onode_address(unsigned long objno, unsigned long blocknr){
  //struct objms_sb_info *sbi = objms_sbi;
  struct objms_inode *pi;
  unsigned long ino = objno << OBJMS_INODE_BITS;
  struct objms_inode_info *inode;
  u64 bp;

/*  if (unlikely(!objno)){
    //printk(KERN_ERR "@objms_block_address: objno=0\n");
    return NULL;
  }*/
  inode = objms_iget(ino);
  if (unlikely(IS_ERR(inode))){//invalid objno
    //printk(KERN_ERR "@objms_block_address: bad inode\n");
    return NULL;
  }
  pi = inode->pi;

  objms_iput(NULL, inode);
  bp = (const void *)pi;
  return bp;
}
EXPORT_SYMBOL(objms_onode_address);
