#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <asm/uaccess.h>
#include <linux/syscalls.h>
#include <linux/obj.h>
#include "objms.h"
//lock a region of an object
//return 0 if succeed, 1 if failed
SYSCALL_DEFINE5(objms_olock, unsigned long, tid, unsigned long, objno,
    loff_t, offset, size_t, len, int, type){
  struct objms_inode_info *inode;
  struct olock *ol, *newol;
  bool is_conflict = false;
  pid_t current_pid = current->pid;
  int retval = 0;

#ifdef OBJMS_FINE_LOCK
  inode = objms_iget(objno << OBJMS_INODE_BITS);
  if (unlikely(IS_ERR(inode))){//invalid objno
    return -EINVAL;
  }
  //check olock list, do not merge!
  mutex_lock(&inode->i_mutex);
  list_for_each_entry(ol, &inode->i_lock_head, l_list) {
    if (offset + len <= ol->l_start
        || offset >= ol->l_start + ol->l_len){
      continue;
    } else if (ol->l_pid != current_pid){
      if (ol->l_type == 1 || type == 1){
        //if at least one of which is write lock, then conflict
        is_conflict = true;
        break;
      }
    } else {
      //the thread has created a global lock before
      //FIXME, TODO, what's the rule? 
      is_conflict = true;
      break;
    }
  }
  if (is_conflict){
    //printk(KERN_ERR "@fine_lock conflict,pid=%u,pos=%lu,len=%lu,o_pid=%u,o_start=%lu,o_len=%lu\n",
    //    current_pid, pos, len, ol->l_pid, ol->l_start, ol->l_len);
    retval = 1;
    goto out;
  }
  newol = objms_alloc_olock();
  newol->l_type = type;
  newol->l_pid = current_pid;
  newol->l_start = offset;
  newol->l_len = len;
  list_add(&newol->l_list, &inode->i_lock_head);
  //printk(KERN_ERR "@fine_lock add,l_pid=%u,l_start=%lu,l_len=%lu\n",
  //    current_pid, offset, len);
out:
  mutex_unlock(&inode->i_mutex);
  objms_iput(NULL, inode);
#endif
  return retval;
}

//unlock a region of an object
//do we need lock type?
//TODO: must be in a txn!
SYSCALL_DEFINE5(objms_ounlock, unsigned long, tid, unsigned long, objno,
    loff_t, offset, size_t, len, int, type){
  struct objms_inode_info *inode;
  struct olock *ol;
  pid_t current_pid = current->pid;

#ifdef OBJMS_FINE_LOCK
  inode = objms_iget(objno << OBJMS_INODE_BITS);
  if (unlikely(IS_ERR(inode))){//invalid objno
    return -EINVAL;
  }

  mutex_lock(&inode->i_mutex);
  list_for_each_entry(ol, &inode->i_lock_head, l_list) {
    if ((ol->l_pid == current_pid)
        && (offset == ol->l_start)
            && (len == ol->l_len)){
      list_del(&ol->l_list);
      mutex_unlock(&inode->i_mutex);
      objms_free_olock(ol);
      return 0;
    }
  }
  mutex_unlock(&inode->i_mutex);
  objms_iput(NULL, inode);
#endif
  return 1;
}
