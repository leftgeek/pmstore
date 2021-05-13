/*
 * OBJMS journaling facility. This file contains code to log changes to objms
 * meta-data to facilitate consistent meta-data updates against arbitrary
 * power and system failures.
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

#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <asm/tlbflush.h>
#include <linux/mmu_notifier.h>
#include "objms.h"

//get a log entry by its offset(offset starts from LOGENTRY_SIZE
static inline objms_logentry_t *get_log_entry(struct objms_sb_info *sbi, uint32_t le_off){
  return (objms_logentry_t *)(sbi->journal_base_addr + le_off - LOGENTRY_SIZE);
}

static inline u32 objms_get_log_entry_off(struct objms_sb_info *sbi,
    objms_logentry_t *le){
  return (((char *)le - (char *)sbi->journal_base_addr) + LOGENTRY_SIZE);
}

/* Undo a valid log entry */
static inline void objms_undo_logentry(struct objms_sb_info *sbi,
	objms_logentry_t *le){
	char *data;

	if (le->size > 0) {
		data = objms_get_block(le64_to_cpu(le->addr_offset));
		/* Undo changes by flushing the log entry to objms */
		objms_memunlock_range(sbi, data, le->size);
		memcpy(data, le->data, le->size);
		objms_memlock_range(sbi, data, le->size);
		objms_flush_buffer(data, le->size, false);
	}
}

static void objms_undo_transaction_recursively(struct objms_sb_info *sbi,
  objms_logentry_t *le){
  if (le->status & LE_INUSE){
    if (le->next_offset){
      le = get_log_entry(sbi, le32_to_cpu(le->next_offset));
      objms_undo_transaction_recursively(sbi, le);
    } else {
      objms_undo_logentry(sbi, le);
    }
  }
}

/* can be called during journal recovery or transaction abort */
/* We need to Undo in the reverse order */
//non-recursive version
static void objms_undo_transaction(struct objms_sb_info *sbi,
		objms_transaction_t *trans){
	//objms_logentry_t *le;
	//int i, j;

  //non-recursive version: too slow
  /*for (i = le32_to_cpu(te->num_used) - 1; i >= 0; i--){
    le = trans->start_addr;
    for (j = 0; j < i; j++){
      le = get_log_entry(sbi, le32_to_cpu(le->next_offset));
    }
    if (le->status == LE_INUSE){//FIXME: do we need this if?
      objms_undo_logentry(sbi, le);
    }
  }*/
  //recursively version
  objms_undo_transaction_recursively(sbi, trans->start_addr);
}

/* can be called by either during log cleaning or during journal recovery */
//flush the new content of all les of a transaction
/*#ifndef OBJMS_ENABLE_ASYNC_FLUSH
static void objms_flush_txn(objms_transaction_t *trans){
  objms_logentry_info_t *ole;
  list_for_each_entry(ole, &trans->ole_list, link){
    objms_flush_buffer(ole->addr, ole->size, false);
  }
}
#endif*/
/* can be called by either during log cleaning or during journal recovery */
/*
static void objms_redo_transaction(struct objms_sb_info *sbi,
		objms_transaction_t *trans, bool recover){
	objms_logentry_t *te = trans->start_addr;
	objms_logentry_t *le = trans->start_addr;
	int i;
	char *data;

	for (i = 0; i < trans->num_used; i++) {
		if (le->status && le->size > 0) {
			data = objms_get_block(le64_to_cpu(le->addr_offset));
*/			/* flush data if we are called during recovery */
/*			if (recover) {
				objms_memunlock_range(sbi, data, le->size);
				memcpy(data, le->data, le->size);
				objms_memlock_range(sbi, data, le->size);
			}
			objms_flush_buffer(data, le->size, false);
		}
    le = get_log_entry(sbi, le32_to_cpu(le->next_offset));
	}
}
*/

#ifdef OBJMS_DYNAMIC_OLE
static void objms_flush_log_backwards(objms_transaction_t *trans){
  objms_logentry_info_t *head_ole = list_first_entry(&trans->ole_list,
      objms_logentry_info_t, link);

flush_prev:
  if (trans->backward_ole->status & OLE_FLUSHED){
    //wait until the flusher thread finish
    return;
  } else if (trans->backward_ole->status & OLE_FLUSHING){
    //wait until ole has been flushed
    //schedule();
    cond_resched();
    goto flush_prev;
    //return;//FIXME
  } else {
    spin_lock(&trans->ole_lock);
    if (trans->backward_ole->status & OLE_FLUSHING){
      spin_unlock(&trans->ole_lock);
      goto flush_prev;
    }
    //we prepare to flush the ole
    trans->backward_ole->status |= OLE_FLUSHING;
    spin_unlock(&trans->ole_lock);
    //flush the le
    objms_flush_buffer(trans->backward_ole->addr, trans->backward_ole->size, false);
#ifdef OBJMS_ENABLE_DEBUG
    //objms_sbi->backward_flushed_entries++;
    objms_sbi->backward_flushed_bytes += trans->backward_ole->size;
    //trans->backward_flushed_bytes += trans->backward_ole->size;
    trans->backward_flushed_bytes++;
#endif
    trans->backward_ole->status |= OLE_FLUSHED;

    if (trans->backward_ole != head_ole){
      trans->backward_ole = list_entry(trans->backward_ole->link.prev,
          objms_logentry_info_t, link);
      goto flush_prev;
    }
  }
}
static void objms_flush_log(objms_flusher_thread_t *flusher_thread){
  int i;
  objms_transaction_t *trans;
  objms_logentry_info_t *ole;

  bool need_stop = false;
  //while (flusher_thread->bit_mask && (time--)){
  while (flusher_thread->bit_mask && (!need_stop)){
    for (i = 0; i < QUEUE_PER_FLUSHER; i++){
      //clear the bit_mask of the txn
      //flusher_thread->bit_mask &= ~(1 << i);//FIXME
      trans = flusher_thread->current_trans[i];

      if (!trans || !trans->flusher_cpup){
        continue;
      }

      ole = trans->backward_ole;
      //if we reach the end of the txn
      if (!ole || (ole->status & OLE_FLUSHING)){
        continue;
      }

      ole = trans->forward_ole;
      if (ole == NULL){//pick the first entry
        ole = list_first_entry(&trans->ole_list,
            objms_logentry_info_t, link);
      } else {
        ole = list_entry(ole->link.next,
            objms_logentry_info_t, link);
      }

      spin_lock(&trans->ole_lock);
      if (ole->status & OLE_FLUSHING){
        //the ole is being (has been) flushed by backwards
        spin_unlock(&trans->ole_lock);
        continue;
      } else {
        ole->status |= OLE_FLUSHING;
        spin_unlock(&trans->ole_lock);
      }

flush_next:
      trans->forward_ole = ole;

#ifdef OBJMS_ENABLE_DEBUG
      //printk(KERN_ERR "@objms_flush_log: trans=%p, addr=%lx,size=%u\n",
      //    trans, ole->addr, ole->size);
      flusher_thread->run_cpus[task_cpu(current)]++;
      //objms_sbi->forward_flushed_entries++;
      objms_sbi->forward_flushed_bytes += ole->size;
      //trans->forward_flushed_bytes += ole->size;
      trans->forward_flushed_bytes++;
      flusher_thread->flushed_bytes += ole->size;
#endif
#ifdef OBJMS_CLFLUSH_TIME
      objms_flush_buffer_async(ole->addr, ole->size, false);
#else
      objms_flush_buffer(ole->addr, ole->size, false);
#endif
      //before set the status to OLE_FLUSHED, compare if we reach the end
      //because after set OLE_FLUSHED, backwards thread
      //may return and set forward_ole and backward_ole to NULL
      //if (!trans->backward_ole || ole == trans->backward_ole){
      if (ole == trans->backward_ole){
        ole->status |= OLE_FLUSHED;
        continue;
      } else {
        ole->status |= OLE_FLUSHED;
      }

      ole = list_entry(ole->link.next,
          objms_logentry_info_t, link);

      spin_lock(&trans->ole_lock);
      if (ole->status & OLE_FLUSHING){
        spin_unlock(&trans->ole_lock);
        continue;
      } else {
        ole->status |= OLE_FLUSHING;
        spin_unlock(&trans->ole_lock);
        goto flush_next;
      }
    }
    //wake_up_process((objms_sbi->log_flusher_threads[(task_cpu(current) + 1) % objms_sbi->cpus]).flusher_thread);
    //current->state = TASK_INTERRUPTIBLE;
    //schedule();
    //@ayu: TODO
    //当flusher thread空闲时,判断其所属SOCKET上有无运行的事务
    //如果没有,则停止当前flusher thread,否则继续循环
/*#ifndef OBJMS_ASYNC_STOP
    need_stop = true;
    if (!list_empty(&objms_sbi->txn_running)){
      struct task_struct *task;
      objms_transaction_t *t;
      int flusher_cpu_low, flusher_cpu_high;
      int cpu;
      cpu = task_cpu(current);
      flusher_cpu_low = cpu & (~(OBJMS_PER_SOCKET_CORES - 1));
      if (flusher_cpu_low >= OBJMS_CORES){
        flusher_cpu_low -= OBJMS_CORES;
      }
      flusher_cpu_high = flusher_cpu_low + OBJMS_PER_SOCKET_CORES - 1;

      spin_lock(&objms_sbi->txn_list_lock);
      list_for_each_entry(t, &objms_sbi->txn_running, txn_list){
        task = find_task_by_vpid(t->pid);
        cpu = task_cpu(task);
        //事务与flusher thread在同一个SOCKET上运行
        if ((cpu >= flusher_cpu_low && cpu <= flusher_cpu_high)
            || ((cpu >= flusher_cpu_low + OBJMS_CORES)
              && (cpu <= flusher_cpu_high + OBJMS_CORES))){
          spin_unlock(&objms_sbi->txn_list_lock);
          need_stop = false;
#ifdef OBJMS_ENABLE_DEBUG
          objms_sbi->obj_wakeup1++;
#endif
          break;
        }
      }
      if (need_stop){
#ifdef OBJMS_ENABLE_DEBUG
        objms_sbi->obj_wakeup2++;
#endif
        spin_unlock(&objms_sbi->txn_list_lock);
      }
    }
#endif*/
    if (!need_stop){
      cond_resched();
    }
  }
}
#else
static void objms_flush_log_backwards(objms_transaction_t *trans){
  int flush_index = trans->fe_tail;
  objms_logentry_info_t *ole = &(trans->flusher_entries[flush_index]);

flush_prev:
  if (ole->status & OLE_FLUSHED){
    //wait until the flusher thread finish
    return;
  } else if (ole->status & OLE_FLUSHING){
    //wait until ole has been flushed
    //schedule();
    cond_resched();
    goto flush_prev;
  } else {
    //prepare to flush the ole
    ole->status |= OLE_FLUSHING;
    //check if the ole has been flushed by flusher thread
    //during this time
    if (ole->status & OLE_FLUSHED){
      goto flush_prev;
    } else {
      ole->status |= OLE_FLUSHED;
    }
    //flush the ole
    objms_flush_buffer(ole->addr, ole->size, false);
#ifdef OBJMS_ENABLE_DEBUG
    //objms_sbi->backward_flushed_entries++;
    objms_sbi->backward_flushed_bytes += ole->size;
    //trans->backward_flushed_bytes += ole->size;
    trans->backward_flushed_bytes++;
#endif

    if (flush_index != trans->fe_head){
      flush_index = (flush_index + FLUSHER_ENTRY_PER_TXN - 1) % FLUSHER_ENTRY_PER_TXN;
      ole = &(trans->flusher_entries[flush_index]);
      goto flush_prev;
    }
  }
}
//@ayu: FIXME, TODO
//flush the cacheline of logs
//run until a txn commit, else sleep
static void objms_flush_log(objms_flusher_thread_t *flusher_thread){
  int i;
  objms_transaction_t *trans;
  objms_logentry_info_t *ole;

  bool need_stop = false;
  //while (flusher_thread->bit_mask && (time--)){
  while (flusher_thread->bit_mask && (!need_stop)){
    for (i = 0; i < QUEUE_PER_FLUSHER; i++){
      //clear the bit_mask of the txn
      //flusher_thread->bit_mask &= ~(1 << i);//FIXME
      trans = flusher_thread->current_trans[i];

      if (!trans || !trans->fe_count || !trans->flusher_cpup){
        continue;
      }
      if (trans->current_index == FLUSHER_ENTRY_PER_TXN){
        trans->current_index = trans->fe_head;
      }

flush_current:
      ole = &(trans->flusher_entries[trans->current_index]);
      //if ((!(ole->status & OLE_FLUSHABLE)) || (ole->status & OLE_FLUSHING)){
      if (ole->status & OLE_FLUSHING){
        //this one is been flushed
        //or this one is not flushable
        //continue;
        goto flush_next;
      }
      //prepare to flush
      ole->status |= OLE_FLUSHING;
      //check if the current_ole has been flushed by txn thread
      //during this time
      if (ole->status & OLE_FLUSHED){
        continue;
      }
 #ifdef OBJMS_ENABLE_DEBUG
      //printk(KERN_ERR "@objms_flush_log: trans=%p, addr=%lx,size=%u\n",
      //    trans, ole->addr, ole->size);
      flusher_thread->run_cpus[task_cpu(current)]++;
      //objms_sbi->forward_flushed_entries++;
      objms_sbi->forward_flushed_bytes += ole->size;
      //trans->forward_flushed_bytes += ole->size;
      trans->forward_flushed_bytes++;
      flusher_thread->flushed_bytes += ole->size;
#endif
#ifdef OBJMS_CLFLUSH_TIME
      objms_flush_buffer_async(ole->addr, ole->size, false);
#else
      objms_flush_buffer(ole->addr, ole->size, false);
#endif
      //一旦一个ole被设置为OLE_FLUSHED,它就可以会被回收,成为新的tail
      ole->status |= OLE_FLUSHED;
      //do we reach the end?
flush_next:
      if (trans->current_index == trans->fe_tail){
        continue;
      }
      trans->current_index = (trans->current_index + 1) % FLUSHER_ENTRY_PER_TXN;
      goto flush_current;

      //before set the status to OLE_FLUSHED, compare if we reach the end
      //because after set OLE_FLUSHED, backwards thread
      //may return and set forward_ole and backward_ole to NULL
    }
    //wake_up_process((objms_sbi->log_flusher_threads[(task_cpu(current) + 1) % objms_sbi->cpus]).flusher_thread);
    //current->state = TASK_INTERRUPTIBLE;
    //schedule();
    //@ayu: TODO
    //当flusher thread空闲时,判断其所属SOCKET上有无运行的事务
    //如果没有,则停止当前flusher thread,否则继续循环
/*#ifndef OBJMS_ASYNC_STOP
    need_stop = true;
    if (!list_empty(&objms_sbi->txn_running)){
      struct task_struct *task;
      objms_transaction_t *t;
      int flusher_cpu_low, flusher_cpu_high;
      int cpu;
      cpu = task_cpu(current);
      flusher_cpu_low = cpu & (~(OBJMS_PER_SOCKET_CORES - 1));
      if (flusher_cpu_low >= OBJMS_CORES){
        flusher_cpu_low -= OBJMS_CORES;
      }
      flusher_cpu_high = flusher_cpu_low + OBJMS_PER_SOCKET_CORES - 1;

      spin_lock(&objms_sbi->txn_list_lock);
      list_for_each_entry(t, &objms_sbi->txn_running, txn_list){
        task = find_task_by_vpid(t->pid);
        cpu = task_cpu(task);
        //事务与flusher thread在同一个SOCKET上运行
        if ((cpu >= flusher_cpu_low && cpu <= flusher_cpu_high)
            || ((cpu >= flusher_cpu_low + OBJMS_CORES)
              && (cpu <= flusher_cpu_high + OBJMS_CORES))){
          spin_unlock(&objms_sbi->txn_list_lock);
          need_stop = false;
#ifdef OBJMS_ENABLE_DEBUG
          objms_sbi->obj_wakeup1++;
#endif
          break;
        }
      }
      if (need_stop){
#ifdef OBJMS_ENABLE_DEBUG
        objms_sbi->obj_wakeup2++;
#endif
        spin_unlock(&objms_sbi->txn_list_lock);
      }
    }
#endif*/
    if (!need_stop){
      cond_resched();
      //schedule();
    }
  }
}
#endif
static void log_flusher_try_sleeping(objms_flusher_thread_t *flusher_thread)
{
	DEFINE_WAIT(wait2);
	prepare_to_wait(&flusher_thread->flusher_wait, &wait2, TASK_INTERRUPTIBLE);
	schedule();
	finish_wait(&flusher_thread->flusher_wait, &wait2);
}

static int objms_log_flusher(void *arg)
{
  objms_flusher_thread_t *flusher_thread = &(objms_sbi->log_flusher_threads[(unsigned long)arg]);

	for ( ; ; ) {
		log_flusher_try_sleeping(flusher_thread);

		if (kthread_should_stop())
			break;
    objms_flush_log(flusher_thread);
	}
	objms_flush_log(flusher_thread);
	return 0;
}
//@ayu: FIXME
#ifdef OBJMS_LAZY_STOP
static void objms_stop_flusher_thread(unsigned long arg){
  int i;
  if (!arg){
    return;
  }
  objms_flusher_thread_t *flusher_thread = (objms_flusher_thread_t *)arg;

  for (i = 0; i < QUEUE_PER_FLUSHER; i++){
    if (flusher_thread->current_trans[i]){
      return;
    }
  }
  flusher_thread->bit_mask = 0;
}
#endif
//@ayu: FIXME, TODO, wakeup flusher thread according to the pid
static void wakeup_log_flusher(objms_transaction_t *trans)
{
  int i, j, flusher_cpu, free_flusher_cpu;
  struct objms_sb_info *sbi = objms_sbi;
  int num_flusher_threads;
  int current_cpu;// = task_cpu(current);
  int flusher_cpu_low, flusher_cpu_high;
  //int flusher_cpu_low2, flusher_cpu_high2;//hyper-threads
  //static int cpu = 0;
  //@ayu: FIXME: need test
  //num_flusher_threads = (atomic_read(&sbi->num_txns) + QUEUE_PER_FLUSHER - 1) / QUEUE_PER_FLUSHER;
  /*if (atomic_read(&sbi->num_txns) <= sbi->cpus / 4){//<=16
    num_flusher_threads = (atomic_read(&sbi->num_txns) + 1) / 2;
    //num_flusher_threads = atomic_read(&sbi->num_txns);
  } else {
    num_flusher_threads = (sbi->cpus / 16) + atomic_read(&sbi->num_txns) / 16;
  }*/
  //num_flusher_threads = 2;
  objms_flusher_thread_t *flusher_thread;
  
  if (!trans->flusher_cpup){
    //last choice: choose randomly
#ifdef OBJMS_FLUSHER_RANDOM
    num_flusher_threads = min_t(int, atomic_read(&sbi->num_txns), MAX_FLUSHERS);
    free_flusher_cpu = (task_cpu(current) + 1) % num_flusher_threads;
    //free_flusher_cpu = (task_cpu(current) + 1) % sbi->cpus;
    //first find a free flusher thread with bit_mask set
/*    for (i = 0; i < num_flusher_threads; i++){
      flusher_thread = &(sbi->log_flusher_threads[i]);
      if (flusher_thread->bit_mask){
        for (j = 0; j < QUEUE_PER_FLUSHER; j++){
          if (flusher_thread->current_trans[j]){
            break;
          }
        }
        if (j == QUEUE_PER_FLUSHER){
          free_flusher_cpu = i;
          break;
        }
      } else {
        //record a free flusher thread without bit_mask set
        free_flusher_cpu = i;
      }
    }*/
#endif

    /*if (current_cpu >= OBJMS_CORES){
      current_cpu -= OBJMS_CORES;
    }*/
    //flusher_cpu_low = current_cpu & (~OBJMS_PER_SOCKET_CORES);
#ifdef OBJMS_DEBUG_NUMA
    //map cpu2,cpu3 to cpu0, cpu1
    //best results for multi-threads
    current_cpu = task_cpu(current);
    if (current_cpu >= 16 && current_cpu <= 31){
      current_cpu -= 16;
    }
    if (current_cpu >= 48 && current_cpu <= 63){
      current_cpu -= 16;
    }
    //or map cpu0,cpu1 to cpu2,cpu3
    /*if (current_cpu >= 0 && current_cpu <= 15){
      current_cpu += 16;
    }
    if (current_cpu >= 32 && current_cpu <= 47){
      current_cpu += 16;
    }*/
    /*if (current_cpu >= 8 && current_cpu <= 15){
      current_cpu -= 8;
    }
    if (current_cpu >= 24 && current_cpu <= 31){
      current_cpu -= 8;
    }*/
    flusher_cpu_low = current_cpu & (~(OBJMS_PER_SOCKET_CORES - 1));
    flusher_cpu_high = flusher_cpu_low + OBJMS_PER_SOCKET_CORES - 1;
    free_flusher_cpu = current_cpu + 1;
    if (free_flusher_cpu > flusher_cpu_high){
      free_flusher_cpu = flusher_cpu_low;
    }
#else

#ifdef OBJMS_FLUSHER_SOCKET
    //1.先计算出所在的SOCKET的CPU范围,
    //int lock_index;
    //TODO:应该包括对应的超线程
retry_free_flusher:
    current_cpu = task_cpu(current);
    flusher_cpu_low = current_cpu & (~(OBJMS_PER_SOCKET_CORES - 1));
    if (flusher_cpu_low >= OBJMS_CORES){
      flusher_cpu_low -= OBJMS_CORES;
    }
    //计算num_flusher_threads
    //num_flusher_threads规定了free_flusher_cpu的范围为
    //[flusher_cpu_low, free_flusher_cpu + num_flusher_threads - 1]
#ifdef OBJMS_FLUSHER_TOTAL
    flusher_cpu_high = flusher_cpu_low + OBJMS_PER_SOCKET_CORES - 1;
    //统计方法1:全局的flusher thread数量
    //确保每个SOCKET至少有一个flusher thread
    j = 0;
    for (i = 0; i < OBJMS_CORES; i++){
      flusher_thread = &(sbi->log_flusher_threads[i]);
      if (i < flusher_cpu_low){
        if (flusher_thread->bit_mask){
          j++;
        }
      } else if (i > flusher_cpu_high){
        if (flusher_thread->bit_mask){
          j++;
        }
      }
    }
    if (j > MAX_FLUSHERS){
      j = MAX_FLUSHERS;
    }
    num_flusher_threads = min_t(int, atomic_read(&sbi->num_txns), MAX_FLUSHERS - j);
    if (num_flusher_threads == 0){
      //return;
      num_flusher_threads = 1;//min=1
    } else if (num_flusher_threads > OBJMS_PER_SOCKET_CORES){
      //<=8
      num_flusher_threads = OBJMS_PER_SOCKET_CORES;
    }
#else
    //统计方法2:per-SOCKET的flusher thread数量
    //FIXME:此处是读取所有的事务数量,实际上并没有太大意义
    num_flusher_threads = min_t(int,
        //atomic_read(&sbi->num_txns) / OBJMS_SOCKETS, MAX_FLUSHER_PER_SOCKET);
        atomic_read(&sbi->num_txns), MAX_FLUSHER_PER_SOCKET);
#endif  //OBJMS_FLUSHER_TOTAL
    if (num_flusher_threads == 0){
      num_flusher_threads = 1;
    }
    flusher_cpu_high = flusher_cpu_low + num_flusher_threads - 1;
    
    //default: random
    free_flusher_cpu = flusher_cpu_low + (current_cpu % num_flusher_threads);
    //如果没有开启OBJMS_ASYNC_STOP,就从空闲的running flusher中开始寻找
    //first find a free flusher thread with bit_mask set
    for (i = flusher_cpu_low; i <= flusher_cpu_high; i++){
      flusher_thread = &(sbi->log_flusher_threads[i]);
#ifdef OBJMS_ASYNC_STOP
      //找未运行的flusher thread
      if (!flusher_thread->bit_mask){
        free_flusher_cpu = i;
        break;
      }
#else
      //找正在运行的empty flusher thread
      if (flusher_thread->bit_mask){
        for (j = 0; j < QUEUE_PER_FLUSHER; j++){
          if (flusher_thread->current_trans[j]){
            break;
          }
        }
        if (j == QUEUE_PER_FLUSHER){
          free_flusher_cpu = i;
          break;
        }
      } else {
        //record a free flusher thread without bit_mask set
        free_flusher_cpu = i;
      }
#endif  //OBJMS_ASYNC_STOP
    }
    //如果分配好flusher cpu后当前进行运行的CPU又变了,
    //就重新进行分配
    if (unlikely(task_cpu(current) != current_cpu)){
      goto retry_free_flusher;
      //return;
    }
#endif  //OBJMS_FLUSHER_SOCKET
#endif  //OBJMS_DEBUG_NUMA

    flusher_cpu = free_flusher_cpu;
    //find a free flusher thread first end
retry_flusher:
    //flusher_cpu = flusher_cpup % sbi->cpus;
    //flusher_cpu = flusher_cpup % num_flusher_threads;
    flusher_thread = &(sbi->log_flusher_threads[flusher_cpu]);
    spin_lock(&flusher_thread->flusher_queue_lock);
    for (i = 0; i < QUEUE_PER_FLUSHER; i++){
      if (!flusher_thread->current_trans[i]){
#ifdef OBJMS_ENABLE_DEBUG
        flusher_thread->num_txns++;
#endif
        flusher_thread->current_trans[i] = trans;
        trans->flusher_cpup = flusher_cpu + 1;
        trans->flusher_index = i;
        //set the bit mask, send the need_flush message
        flusher_thread->bit_mask |= 1 << trans->flusher_index;
        break;
      }
    }
    spin_unlock(&flusher_thread->flusher_queue_lock);
    //如果默认的分配策略没有分配成功，就试图去分配下一个
    //如果全部遍历完又回到开始还是没有分配成功，则放弃
    /*if (unlikely(!trans->flusher_cpup)){
      int new_flusher_cpu = (flusher_cpu + 1) % num_flusher_threads;
      if (new_flusher_cpu == flusher_cpu){
        return;
      }
      goto retry_flusher;
    }*/
  } else {
    //flusher_cpu = trans->flusher_cpup % sbi->cpus;
    flusher_cpu = trans->flusher_cpup - 1;
    flusher_thread = &(sbi->log_flusher_threads[flusher_cpu]);
/*#ifdef OBJMS_ENABLE_DEBUG
    //检查当前事务是否切换了SOCKET
    current_cpu = task_cpu(current);
    flusher_cpu_low = current_cpu & (~(OBJMS_PER_SOCKET_CORES - 1));
    if (flusher_cpu_low >= OBJMS_CORES){
      flusher_cpu_low -= OBJMS_CORES;
    }
    if (flusher_cpu_low == (flusher_cpu & (~(OBJMS_PER_SOCKET_CORES - 1)))){
      sbi->obj_wakeup1++;
    } else {
      sbi->obj_wakeup2++;
    }
#endif*/
  }
#ifdef OBJMS_ENABLE_DEBUG
    sbi->run_cpus[task_cpu(current)]++;
#endif
  if (unlikely(!trans->flusher_cpup)){
#ifdef OBJMS_ENABLE_DEBUG
    sbi->wakeup_invalid++;
#endif
    return;
  }
  //printk(KERN_ERR "@task_cpu=%d, flusher_cpu=%d\n", task_cpu(current), flusher_cpu);
  //wakeup the wait queue that has the same cpu with the current thread
	if (!waitqueue_active(&flusher_thread->flusher_wait)){
#ifdef OBJMS_ENABLE_DEBUG
    sbi->wakeup_fail++;
#endif
		return;
  }
#ifdef OBJMS_ENABLE_DEBUG
    sbi->wakeup_success++;
#endif
	wake_up_interruptible(&flusher_thread->flusher_wait);
}

static int objms_log_flusher_run(struct objms_sb_info *sbi)
{
	int ret = 0;
  int j, journal_off, per_journal_size;
  unsigned long i;
  unsigned long block_start;
  objms_flusher_thread_t *flusher_thread;
  objms_logentry_t *le;

  sbi->log_flusher_threads = kzalloc(sbi->cpus * sizeof(objms_flusher_thread_t),
      GFP_KERNEL);

  //block_start = sbi->block_start;
  block_start = 0;
  per_journal_size = sbi->jsize / sbi->cpus;
  for (i = 0; i < sbi->cpus; i++){
    flusher_thread = &(sbi->log_flusher_threads[i]);
    flusher_thread->current_trans = kzalloc(QUEUE_PER_FLUSHER * sizeof(objms_transaction_t *),
        GFP_KERNEL);
    init_waitqueue_head(&flusher_thread->flusher_wait);
    flusher_thread->flusher_thread = kthread_create(objms_log_flusher, (void *)i, "log_flush_td");
    //flusher_thread->flusher_thread_shadow = kthread_create(objms_log_flusher, (void *)i, "log_flush_tsd");

    spin_lock_init(&flusher_thread->flusher_queue_lock);
    spin_lock_init(&flusher_thread->rle_list_lock);
    flusher_thread->reset_le_head = NULL;
    flusher_thread->reset_le_tail = NULL;
    flusher_thread->num_reset_logentries = 0;
#ifdef OBJMS_ENABLE_DEBUG
    flusher_thread->flushed_bytes = 0;
    flusher_thread->num_txns = 0;
    int k;
    for (k = 0; k < sbi->cpus; k++){
      flusher_thread->run_cpus[k] = 0;
    }
#endif

    spin_lock_init(&flusher_thread->le_list_lock);
    journal_off = i * per_journal_size;
    flusher_thread->free_le_head = get_log_entry(sbi, journal_off + LOGENTRY_SIZE);
    flusher_thread->free_le_tail = get_log_entry(sbi, journal_off + per_journal_size);
    flusher_thread->num_free_logentries = per_journal_size >> LESIZE_SHIFT;
    //link all free log entries
    for (j = journal_off + LOGENTRY_SIZE; j < journal_off + per_journal_size; j += LOGENTRY_SIZE){
      le = get_log_entry(sbi, j);
      le->next_offset = j + LOGENTRY_SIZE;
    }

    INIT_LIST_HEAD(&flusher_thread->ole_free);
    spin_lock_init(&flusher_thread->ole_list_lock);

    INIT_LIST_HEAD(&flusher_thread->txn_commit);
    spin_lock_init(&flusher_thread->txn_list_lock);

    INIT_LIST_HEAD(&flusher_thread->free_ino_list);
    mutex_init(&flusher_thread->ino_list_lock);
    //init resource pool for each flusher_thread
    INIT_LIST_HEAD(&flusher_thread->free_block_head);
    spin_lock_init(&flusher_thread->block_list_lock);
    //mutex_init(&flusher_thread->block_list_lock);
    struct objms_blocknode *blknode = objms_alloc_blocknode(sbi);

    //flusher_thread的块空间是将整个映射区按照CPU个数进行划分
    //包括已经被占用的超级块区，所以flusher_thread[0]的可用
    //块需要做调整，去掉被用掉的超级块区
    if (i == 0){
      flusher_thread->block_start = sbi->block_start;
      flusher_thread->block_end = block_start + sbi->per_node_blocks - 1;
      flusher_thread->num_free_blocks = sbi->per_node_blocks - sbi->block_start;
    } else {
      flusher_thread->block_start = block_start;
      flusher_thread->block_end = block_start + sbi->per_node_blocks - 1;
      flusher_thread->num_free_blocks = sbi->per_node_blocks;
    }

    blknode->block_low = flusher_thread->block_start;
    blknode->block_high = flusher_thread->block_end;
    list_add_tail(&blknode->link, &flusher_thread->free_block_head);

    block_start += sbi->per_node_blocks;

#ifdef OBJMS_FLUSHER_BIND_CPU
    kthread_bind(flusher_thread->flusher_thread, i);
#endif
#ifdef OBJMS_FLUSHER_BIND_SOCKET
    int flusher_cpu_low, flusher_cpu_high;
    flusher_cpu_low = i & (~(OBJMS_PER_SOCKET_CORES - 1));
    if (flusher_cpu_low >= OBJMS_CORES){
      flusher_cpu_low -= OBJMS_PER_SOCKET_CORES;
    }
    //flusher_cpu_low = (flusher_cpu_low + OBJMS_PER_SOCKET_CORES) % OBJMS_CORES;//@ayu: FIXME
    flusher_cpu_high = flusher_cpu_low + OBJMS_PER_SOCKET_CORES - 1;
    cpumask_t dst_mask = CPU_MASK_NONE;
    for (j = flusher_cpu_low; j <= flusher_cpu_high; j++){
      cpumask_set_cpu(j, &dst_mask);
    }
    for (j = flusher_cpu_low + OBJMS_CORES; j <= flusher_cpu_high + OBJMS_CORES; j++){
      cpumask_set_cpu(j, &dst_mask);
    }
    set_cpus_allowed_ptr(flusher_thread->flusher_thread, &dst_mask);
#endif
#ifdef OBJMS_ENABLE_ASYNC_FLUSH
    flusher_thread->bit_mask = 0;
    wake_up_process(flusher_thread->flusher_thread);
#endif
  }
/*  for (i = 0; i < OBJMS_SOCKETS; i++){
    spin_lock_init(&(sbi->fs_locks[i]));
  }
*/
	return ret;
}
//invalidate log entries
static inline void objms_reset_logentries(objms_logentry_t *le_head, int num){
  int i;
  unsigned int next_offset;
  objms_logentry_t *le;
  le = le_head;
  for (i = 0; i < num; i++){
    next_offset = le32_to_cpu(le->next_offset);
    le->size = 0;
    objms_flush_buffer(le, LOGENTRY_SIZE, false);
    le = get_log_entry(objms_sbi, next_offset);
  }
  //guarantee log entries are reset before thay are adding to the free list
  PERSISTENT_MARK();
  PERSISTENT_BARRIER();
}
//transactions related functions begin
//release a transaction's log entries
static void objms_clean_txn(struct objms_sb_info *sbi,
    objms_transaction_t *trans, objms_logentry_t *last_addr, int cpu){
  int i;
/*#ifdef OBJMS_CPU_ROUND_ROBIN
  static int cpu = 0;
  //int cpu = 0;
#else
  int cpu = smp_processor_id() % sbi->cpus;
#endif*/
  //objms_logentry_info_t *ole;
	struct objms_blocknode *bn;
  objms_flusher_thread_t *flusher_thread = &(sbi->log_flusher_threads[cpu]);
/*#ifdef OBJMS_CPU_ROUND_ROBIN
  cpu = (cpu + 1) % sbi->cpus;
#endif*/

  //@ayu: FIXME, TODO: clear all les before releasing them!
  //link all les of the txn to free_le_list
  if (last_addr){//in an auto-commit process
  spin_lock(&flusher_thread->rle_list_lock);
    if (!flusher_thread->reset_le_head){
      flusher_thread->reset_le_head = trans->start_addr;
    } else {
      flusher_thread->reset_le_tail->next_offset = objms_get_log_entry_off(sbi, trans->start_addr);
    }
    flusher_thread->reset_le_tail = last_addr;
    flusher_thread->num_reset_logentries += trans->num_used;
    /*flusher_thread->free_le_tail->next_offset = objms_get_log_entry_off(sbi, trans->start_addr);
    flusher_thread->free_le_tail = last_addr;
    flusher_thread->num_free_logentries += trans->num_used;*/
  spin_unlock(&flusher_thread->rle_list_lock);
  } else if (trans->num_entries){
    //first reset log entries
    if (trans->num_used){
      objms_reset_logentries(trans->start_addr, trans->num_used);
    }
  spin_lock(&flusher_thread->le_list_lock);
    flusher_thread->free_le_tail->next_offset = objms_get_log_entry_off(sbi, trans->start_addr);
    flusher_thread->free_le_tail = trans->end_addr;
    flusher_thread->num_free_logentries += trans->num_entries;
  spin_unlock(&flusher_thread->le_list_lock);
  }
  //release the txn cowblk_list
  //FIXME,TODO:for committed txn, release all old cow pages,
  //while for aborted txn, release all new cow pages
  //normal txns*/
  
  if (!list_empty(&trans->cowblk_list)){
      //list_for_each_entry(bn, &trans->cowblk_list, link){
      while (!list_empty(&trans->cowblk_list)){
        bn = list_first_entry(&trans->cowblk_list, struct objms_blocknode, link);

        //printk(KERN_ERR "@objms_clean_txn: block_low=%lu,num=%lu\n",
        //    bn->block_low, bn->block_high - bn->block_low + 1);
        objms_free_num_blocks(sbi, bn->block_low,
            bn->block_high + 1 - bn->block_low);

        list_del(&bn->link);
        objms_free_blocknode(sbi, bn);
      }
    }
#ifdef OBJMS_DYNAMIC_OLE 
  //release the logentry_info list
  if (!list_empty(&trans->ole_list)){
    spin_lock(&flusher_thread->ole_list_lock);
    //move the ole_list to ole_free
    //list_splice_init(&trans->ole_list, &flusher_thread->ole_free);
    list_splice_tail(&trans->ole_list, &flusher_thread->ole_free);
    INIT_LIST_HEAD(&trans->ole_list);
    spin_unlock(&flusher_thread->ole_list_lock);
  }
  //another version: add the blocknode to the free list instead of free it
  /*while (!list_empty(&trans->ole_list)){
    ole = list_first_entry(&trans->ole_list, objms_logentry_info_t, link);
    list_del(&ole->link);
    objms_free_ole(ole);
  }*/
#endif
}
//FIXME
static void objms_clean_journal(struct objms_sb_info *sbi, bool unmount){
	//objms_journal_t *journal = objms_get_journal(sbi);
  objms_transaction_t *trans;
  objms_flusher_thread_t *flusher_thread;
  int cpu;
  int num_rles;
  objms_logentry_t *head_rle, *tail_rle;

	/* atomically read both tail and gen_id of journal. Normally use of
	 * volatile is prohibited in kernel code but since we use volatile
	 * to write to journal's tail and gen_id atomically, we thought we
	 * should use volatile to read them simultaneously and avoid locking
	 * them. */
  //printk(KERN_ERR "@objms_clean_journal start\n");
  //we can support both undo and redo txn by this
  //clean committed and aborted transaction: 
  //we only allow a clean thread one time, we should modify this later...
  for (cpu = 0; cpu < sbi->cpus; cpu++){
    flusher_thread = &(sbi->log_flusher_threads[cpu]);
lock_txnlist:
    //clear reset_logentries
    if (flusher_thread->num_reset_logentries){
      spin_lock(&flusher_thread->rle_list_lock);
      num_rles = flusher_thread->num_reset_logentries;
      head_rle = flusher_thread->reset_le_head;
      tail_rle = flusher_thread->reset_le_tail;

      flusher_thread->num_reset_logentries = 0;
      flusher_thread->reset_le_head = NULL;
      flusher_thread->reset_le_tail = NULL;
      spin_unlock(&flusher_thread->rle_list_lock);
      objms_reset_logentries(head_rle, num_rles);
      //free reset_logentries
      spin_lock(&flusher_thread->le_list_lock);
      flusher_thread->free_le_tail->next_offset = objms_get_log_entry_off(sbi, head_rle);
      flusher_thread->free_le_tail = tail_rle;
      flusher_thread->num_free_logentries += num_rles;
      spin_unlock(&flusher_thread->le_list_lock);
    }
    if (!list_empty(&flusher_thread->txn_commit)){
      spin_lock(&flusher_thread->txn_list_lock);//TODO: we should use mutex here
      trans = list_first_entry(&flusher_thread->txn_commit, objms_transaction_t, txn_list);
      list_del(&trans->txn_list);
      spin_unlock(&flusher_thread->txn_list_lock);
      //clean the non-empty trans
      if (trans->num_entries || (!list_empty(&trans->cowblk_list))){
      //if (trans->num_entries){
        objms_clean_txn(sbi, trans, NULL, cpu);
      }
      //free the txn
      objms_free_transaction(trans);
      
      goto lock_txnlist;
    }
#ifndef OBJMS_ASYNC_STOP
    //stop the flusher_thread
    spin_lock(&flusher_thread->flusher_queue_lock);
    int i;
    for (i = 0; i < QUEUE_PER_FLUSHER; i++){
      if (flusher_thread->current_trans[i]){
        break;
      }
    }
    //only stop the empty flusher thread
    if (i == QUEUE_PER_FLUSHER){
      flusher_thread->bit_mask = 0;
    }
    spin_unlock(&flusher_thread->flusher_queue_lock);
#endif
  }
  
  PERSISTENT_MARK();
	PERSISTENT_BARRIER();

/*
 //TODO: check for stale trans
clean_stale_txn:
  if (!list_empty(&objms_sbi->txn_running)){
    struct task_struct *task;
    objms_transaction_t *t;
    spin_lock(&objms_sbi->txn_list_lock);
    list_for_each_entry(t, &objms_sbi->txn_running, txn_list){
      task = find_task_by_vpid(t->pid);
      //if (!task || task->exit_state == EXIT_DEAD){
      if (!task){
        printk(KERN_ERR "@objms_new_txn: stale txn=%lx,pid=%d,current_pid=%d,flags=%d,new_flags=%d,num_entries=%u\n",
            t, t->pid, current->pid, t->flags, flags, t->num_entries);
        spin_unlock(&objms_sbi->txn_list_lock);
        objms_abort_transaction(t);
        goto clean_stale_txn;
      }
    }
    spin_unlock(&objms_sbi->txn_list_lock);
  }*/
	if (unmount) {
	//	PERSISTENT_MARK();
/*		if (journal->txn_low != journal->txn_high)
			objms_dbg("OBJMS: umount but journal not empty %x:%x\n",
			le32_to_cpu(journal->txn_low), le32_to_cpu(journal->txn_high));
		PERSISTENT_BARRIER();*/
  del_timer(&sbi->jc_timer);
	}
}

static void log_cleaner_try_sleeping(struct  objms_sb_info *sbi)
{
	DEFINE_WAIT(wait);
	prepare_to_wait(&sbi->log_cleaner_wait, &wait, TASK_INTERRUPTIBLE);
	schedule();
	finish_wait(&sbi->log_cleaner_wait, &wait);
}

static int objms_log_cleaner(void *arg)
{
	struct objms_sb_info *sbi = (struct objms_sb_info *)arg;

	for ( ; ; ) {
		log_cleaner_try_sleeping(sbi);

		if (kthread_should_stop())
			break;
    objms_clean_journal(sbi, false);
	}
	objms_clean_journal(sbi, true);
	return 0;
}

void wakeup_log_cleaner(struct objms_sb_info *sbi)
{
	if (!waitqueue_active(&sbi->log_cleaner_wait))
		return;
	wake_up_interruptible(&sbi->log_cleaner_wait);
  mod_timer(&sbi->jc_timer, jiffies + JOURNAL_TIMER * HZ);
}

static void objms_journal_clean_timer(unsigned long arg){
  //when no running txn, clean the journal
  //if (objms_sbi->num_free_logentries < OBJMS_TOTAL_LE && !objms_sbi->num_txns){
  //if (!objms_sbi->num_txns){
    wakeup_log_cleaner(objms_sbi);
  //}
  //objms_sbi->jc_timer.data = 0;
}

static int objms_journal_cleaner_run(struct objms_sb_info *sbi)
{
	int ret = 0;

	init_waitqueue_head(&sbi->log_cleaner_wait);

	sbi->log_cleaner_thread = kthread_run(objms_log_cleaner, sbi,
			"objms_log_cleaner_0x%llx", sbi->phys_addr);
	if (IS_ERR(sbi->log_cleaner_thread)) {
		/* failure at boot is fatal */
		//objms_err(sbi, "Failed to start objms log cleaner thread\n");
		ret = -1;
	}
  //@ayu: add a timer
  init_timer(&sbi->jc_timer);
  sbi->jc_timer.data = 0;
  sbi->jc_timer.function = objms_journal_clean_timer;
  sbi->jc_timer.expires = jiffies + JOURNAL_TIMER * HZ;
  add_timer(&sbi->jc_timer);

#ifdef OBJMS_LAZY_STOP
  //@ayu: add a timer
  init_timer(&sbi->fs_timer);
  sbi->fs_timer.data = 0;
  sbi->fs_timer.function = objms_stop_flusher_thread;
  sbi->fs_timer.expires = jiffies + HZ / 10;
  add_timer(&sbi->fs_timer);
#endif
	return ret;
}

int objms_journal_soft_init(struct objms_sb_info *sbi){
	objms_journal_t *journal = objms_get_journal(sbi);

	sbi->journal_base_addr = objms_get_block(le64_to_cpu(journal->journal_base));
	sbi->jsize = le32_to_cpu(journal->journal_size);
  //sbi->free_le_head = get_log_entry(sbi, 0);
  //sbi->free_le_tail = get_log_entry(sbi, sbi->jsize - LOGENTRY_SIZE);
  //sbi->num_txns = 0;
  atomic_set(&sbi->num_txns, 0);
  //sbi->num_free_logentries = sbi->jsize >> LESIZE_SHIFT;
  //printk(KERN_ERR "@objms_journal_soft_init: free_log: %d\n",
  //    sbi->num_free_logentries);
  //init journal cleaner
	//mutex_init(&sbi->journal_mutex);

	sbi->redo_log = !!le16_to_cpu(journal->redo_logging);

	objms_journal_cleaner_run(sbi);


	return objms_log_flusher_run(sbi);
}

int objms_journal_hard_init(struct objms_sb_info *sbi,
    uint64_t journal_base, uint32_t journal_size){
	objms_journal_t *journal = objms_get_journal(sbi);

	objms_memunlock_range(sbi, journal, sizeof(*journal));
	journal->journal_base = cpu_to_le64(journal_base);
	journal->journal_size = cpu_to_le32(journal_size);
	/* lets do Undo logging for now */
	journal->redo_logging = 0;
	objms_memlock_range(sbi, journal, sizeof(*journal));

	sbi->journal_base_addr = objms_get_block(journal_base);
	objms_memunlock_range(sbi, sbi->journal_base_addr, journal_size);
	memset_nt(sbi->journal_base_addr, 0, journal_size);
  //FIXME: do we need flush all log entries?
	objms_memlock_range(sbi, sbi->journal_base_addr, journal_size);

	return objms_journal_soft_init(sbi);
}

int objms_journal_uninit(struct objms_sb_info *sbi)
{
  int i;
  objms_flusher_thread_t *flusher_thread;
	if (sbi->log_cleaner_thread)
		kthread_stop(sbi->log_cleaner_thread);
  for (i = 0; i < sbi->cpus; i++){
    flusher_thread = &(sbi->log_flusher_threads[i]);
    if (flusher_thread->flusher_thread)
      kthread_stop(flusher_thread->flusher_thread);
    //if (flusher_thread->flusher_thread_shadow)
    //  kthread_stop(flusher_thread->flusher_thread_shadow);
    kfree(flusher_thread->current_trans);
  }
  kfree(sbi->log_flusher_threads);
	return 0;
}

inline objms_transaction_t *objms_current_transaction(unsigned long tid)
{
	return (objms_transaction_t *)tid;
}
//current txn bind to the process
inline objms_transaction_t *objms_current_txn(void)
{
	return (objms_transaction_t *)current->objms_journal_info;
}
/*
static int objms_free_logentries(int max_log_entries)
{
	objms_dbg("objms_free_logentries: Not Implemented\n");
	return -ENOMEM;
}
*/
//dynamicly allocate log entries
//we support non-continuous log entry allocation
int objms_alloc_logentries(objms_transaction_t *trans,
    uint32_t num_log_entries){
  struct objms_sb_info *sbi = objms_sbi;
  objms_logentry_t *head_le, *tail_le;
  int i;
#ifdef OBJMS_CPU_ROUND_ROBIN
  static int cpu = 0;
#else
  int cpu = smp_processor_id() % sbi->cpus;
#endif
  objms_flusher_thread_t *flusher_thread = &(sbi->log_flusher_threads[cpu]);

  //calculate the actual number of log entries
  if (trans->start_addr){
    uint32_t free_le = trans->num_entries - trans->num_used;
    if (free_le < num_log_entries){
      num_log_entries -= free_le;
    } else {
      num_log_entries = 0;
    }
  }
  if (unlikely(!num_log_entries)){
    return 0;
  }
  //printk(KERN_ERR "@objms_alloc_logentries: trans=%p,num_log_entries=%d\n",
  //    trans, num_log_entries);
retry_alloc:
  //TODO: try to release the lock earlier
	spin_lock(&flusher_thread->le_list_lock);
  if (unlikely(num_log_entries > flusher_thread->num_free_logentries)){
    spin_unlock(&flusher_thread->le_list_lock);
    cpu = (cpu + 1) % sbi->cpus;
    flusher_thread = &(sbi->log_flusher_threads[cpu]);
    goto retry_alloc;
  }

  tail_le = head_le = flusher_thread->free_le_head;
  //find the last allocated le
  for (i = 0; i < num_log_entries - 1; i++){
    //@ayu: FIXME, TODO, clear the in_use bit, move it in a le cleaner thread!
    tail_le->status &= ~LE_INUSE;
    tail_le = get_log_entry(sbi, tail_le->next_offset);
  }
  //@ayu: FIXME, TODO, clear the in_use bit!
  tail_le->status &= ~LE_INUSE;
  //move the free_le_head
  flusher_thread->free_le_head = get_log_entry(sbi, tail_le->next_offset);

  flusher_thread->num_free_logentries -= num_log_entries;
	spin_unlock(&flusher_thread->le_list_lock);
#ifdef OBJMS_CPU_ROUND_ROBIN
  cpu = (cpu + 1) % sbi->cpus;
#endif

  //link les to the le list
  if (trans->num_entries == 0){//alloc for the first time
    trans->start_addr = head_le;
    trans->next_addr = head_le;

    objms_memunlock_range(sbi, head_le, sizeof(*head_le));
    head_le->status = TXN_RUNNING;
    objms_memlock_range(sbi, head_le, sizeof(*head_le));
    //We don't need to flush the head entry because it is still free,
    //and will be flushed in add_logentry
  } else {
    trans->end_addr->next_offset = objms_get_log_entry_off(sbi, head_le);
  }

  if (trans->next_addr == NULL){//when previously allocated les used up, next_addr=NULL
    trans->next_addr = head_le;
  }
  trans->end_addr = tail_le;
  trans->end_addr->next_offset = 0;//clear the next_offset of the end log entry

  trans->num_entries += num_log_entries;
  
	return 0;
journal_full://TODO: wait cleaner or free all logentries and return failed?
	spin_unlock(&flusher_thread->le_list_lock);
	//printk(KERN_ERR "@objms_alloc_logentries: journal_full, free_les=%d, request=%d\n",
  //    sbi->num_free_logentries, num_log_entries);
	wakeup_log_cleaner(sbi);
  //goto retry_alloc;
	return -EAGAIN;
}

//create a new transaction(currently no log entries connected)
SYSCALL_DEFINE1(objms_new_txn, int, flags){
  //struct objms_sb_info *sbi = objms_sbi;
	//objms_journal_t *journal = objms_get_journal(objms_sbi);
	objms_transaction_t *trans = objms_alloc_transaction();
	if (unlikely(!trans)){
    goto txn_full;
  }
	//memset(trans, 0, sizeof(*trans));

	trans->num_entries = 0;
	trans->num_used = 0;
  trans->flags = flags;
  trans->pid = current->pid;
  //trans->commit_time = 0;
#ifdef OBJMS_ENABLE_DEBUG
  trans->forward_flushed_bytes = 0;
  trans->backward_flushed_bytes = 0;
  trans->total_flushed_bytes = 0;
#endif
  trans->flusher_cpup = 0;
  trans->start_addr = NULL;
  trans->next_addr = NULL;
  trans->end_addr = NULL;
#ifdef OBJMS_DYNAMIC_OLE
  trans->forward_ole = NULL;
  trans->backward_ole = NULL;
  INIT_LIST_HEAD(&trans->ole_list);
  //mutex_init(&trans->ole_lock);
  spin_lock_init(&trans->ole_lock);
#else
  trans->fe_count = 0;
  trans->fe_head = trans->fe_tail = FLUSHER_ENTRY_PER_TXN;
  trans->current_index = FLUSHER_ENTRY_PER_TXN;
#endif
  trans->pi_buf = NULL;
  INIT_LIST_HEAD(&trans->cowblk_list);

  trans->old_btree_root = 0;

  //@ayu: TODO, for nested txns,
  //if this is a child txn, link it to the parent's
  //child list, the global txn_running list only
  //link all root txns of all txn trees.
  /*spin_lock(&objms_sbi->txn_list_lock);
  list_add_tail(&trans->txn_list, &objms_sbi->txn_running);
  spin_unlock(&objms_sbi->txn_list_lock);*/
	//trans->t_journal = journal;
  //printk(KERN_ERR "@objms_new_txn: trans=%p\n", trans);
  //connect the trans with the current process
	/*trans->parent = (objms_transaction_t *)current->objms_journal_info;
	current->objms_journal_info = trans;
  if (!trans->parent){
    //increase the num_txns
    //objms_sbi->num_txns++;
    atomic_inc(&objms_sbi->num_txns);
  }*/
  atomic_inc(&objms_sbi->num_txns);
	current->objms_journal_info = trans;
  
	return (unsigned long)trans;

txn_full:
  return -ENOMEM;
}
//change current transaction's properties
//currently we only support change current transaction's mode
//and return current transaction's state
SYSCALL_DEFINE3(objms_xcntl, unsigned long, tid, int, cmd, long, arg){
  int ret = 0;
	objms_transaction_t *trans = objms_current_transaction(tid);

	if (unlikely(!trans)){
		return -1;
  }
  switch (cmd){
    case OBJMS_XMODE_GET:
      return trans->flags;
      break;
    case OBJMS_XMODE_SET:
      //when a txn changed from normal to auto commit mode
      //will call auto_commit_txn to commit previous logged data
      if ((arg & OBJMS_XAUTO) && 
          !(trans->flags & OBJMS_XAUTO)){
        objms_auto_commit_txn(trans);
        //INIT_LIST_HEAD(&trans->block_clean);//FIXME:TODO,事务由normal转为auto时，不用释放其数据块，直接作为auto-commit方式释放就行
      }
      trans->flags = arg;
      break;
    default:
      break;
  }
  return ret;
}
#ifdef OBJMS_ENABLE_AUTO_COMMIT
//@ayu: FIXME,TODO: distinguish between normal_commit and auto_commit
//commit all log entries of a txn without freeing the txn
//in this mode, we do not record redundant logging information
int objms_auto_commit_txn(objms_transaction_t *trans){
  struct objms_sb_info *sbi = objms_sbi;
  objms_logentry_t *last_addr = get_log_entry(sbi, trans->backward_ole->le_off);
#ifdef OBJMS_ENABLE_DEBUG
  if (objms_current_txn() != trans){
    printk(KERN_ERR "@objms_auto_commit_txn: current_txn=%p,trans=%p\n",
        objms_current_txn(), trans);
  }
#endif
  //printk(KERN_ERR "@auto_commit_txn: trans=%p,num_used=%d,num_entries=%d\n",
  //    trans, trans->num_used, trans->num_entries);
  if (unlikely((!trans->num_entries) || (!trans->num_used))){
    return 0;
  }
  
  //when a txn changed from normal to auto commit mode, its pi_buf needs to be flushed
  if (trans->pi_buf){
    //printk(KERN_ERR "@objms_auto_commit_txn: pi_buf\n");
    objms_flush_buffer(trans->pi_buf, trans->pi_buf_len, false);
  }
#ifdef OBJMS_ENABLE_ASYNC_FLUSH
  if (!(trans->backward_ole->status & OLE_FLUSHED)){
    objms_flush_log_backwards(trans);
  }
#ifdef OBJMS_ENABLE_DEBUG
  if (trans->total_flushed_bytes !=
      (trans->forward_flushed_bytes + trans->backward_flushed_bytes)){
    printk(KERN_ERR "@objms_auto_commit_txn: total=%lu,forward=%lu,backward=%lu\n",
        trans->total_flushed_bytes, trans->forward_flushed_bytes,
        trans->backward_flushed_bytes);
  }
  trans->forward_flushed_bytes = 0;
  trans->backward_flushed_bytes = 0;
  trans->total_flushed_bytes = 0;
#endif
#else
  //flush the modified metadata and memory object content and modified data(too small to use cow)
  //objms_flush_txn(trans);
#endif
  //printk(KERN_ERR "@auto_commit_txn flush end\n");
  PERSISTENT_MARK();
  PERSISTENT_BARRIER();
  //@ayu: FIXME
#ifndef OBJMS_ASYNC_STOP
  if (trans->flusher_cpup){
    //if (++(trans->commit_time) % 10 == 0){
    sbi->log_flusher_threads[trans->flusher_cpup - 1].bit_mask &= ~(1 << trans->flusher_index);//FIXME: stop flusher thread
    //}
    sbi->log_flusher_threads[trans->flusher_cpup - 1].current_trans[trans->flusher_index] = NULL;
    trans->flusher_cpup = 0;
  }
#endif
  /* Atomically write the commit type */
  objms_memunlock_range(sbi, trans->start_addr, LOGENTRY_SIZE);
  trans->start_addr->status = TXN_COMMITTED;
  objms_memlock_range(sbi, trans->start_addr, LOGENTRY_SIZE);
  /* Atomically make the txn entry valid */
  objms_flush_buffer(&trans->start_addr->status, sizeof(trans->start_addr->status), true);

  //do not access head entry anymore becuse it has been evicted from the CPU cache
  //clean the txn
  //free all used log entries, cowlist, and loggedbp_list of the txn
  //@ayu: FIXME, TODO, do not clean txn in this critical path
  objms_clean_txn(sbi, trans, last_addr, smp_processor_id() % sbi->cpus);
  trans->num_entries -= trans->num_used;
  if (trans->num_entries){//still some les left
    //the next log entry becomes the new head log entry
    trans->start_addr = trans->next_addr;
    objms_memunlock_range(sbi, trans->start_addr, sizeof(*trans->start_addr));
    trans->start_addr->status = TXN_RUNNING;
    objms_memlock_range(sbi, trans->start_addr, sizeof(*trans->start_addr));
  } else {
    trans->start_addr = NULL;
    trans->next_addr = NULL;
    trans->end_addr = NULL;
  }
  trans->forward_ole = NULL;
  trans->backward_ole = NULL;
  trans->num_used = 0;
  trans->pi_buf = NULL;
  trans->old_btree_root = 0;
  return 0;
}
#else
int objms_auto_commit_txn(objms_transaction_t *trans){
  return 0;
}
#endif

//commit a transaction and add it to the txn_commit list
SYSCALL_DEFINE1(objms_commit_txn, unsigned long, tid){
  struct objms_sb_info *sbi = objms_sbi;
	objms_transaction_t *trans = objms_current_transaction(tid);
  objms_flusher_thread_t *flusher_thread;
#ifdef OBJMS_CPU_ROUND_ROBIN
  static int cpu = 0;
#else
  int cpu = smp_processor_id() % sbi->cpus;
#endif

#ifdef OBJMS_ENABLE_DEBUG
  if (objms_current_txn() != trans){
    printk(KERN_ERR "@objms_commit_txn: current_txn=%p,trans=%p\n",
        objms_current_txn(), trans);
  }
#endif
	if (unlikely(!trans)){
		return 0;
  }

  //if (!trans->parent){
    //decrease the num_txns
    //sbi->num_txns--;
    atomic_dec(&sbi->num_txns);
  //}
    //flush the onode(s) if we need to
    //TODO: there may be more than one onode,
    //use link list to support it
    /*if (trans->pi_buf){//@ayu: FIXME
      printk(KERN_ERR "@objms_commit_txn: pi_buf\n");
      objms_flush_buffer(trans->pi_buf, trans->pi_buf_len, false);
    }*/
#ifdef OBJMS_ENABLE_ASYNC_FLUSH
#ifdef OBJMS_DYNAMIC_OLE
    if (trans->backward_ole
        && (!(trans->backward_ole->status & OLE_FLUSHED))){
#else
    if (trans->fe_count
        && (!(trans->flusher_entries[trans->fe_tail].status & OLE_FLUSHED))){
#endif
      objms_flush_log_backwards(trans);
    }
#else
    //flush the modified metadata and memory object content and modified data(too small to use cow)
		//objms_flush_txn(trans);
#endif
    //make the data persistent
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
#ifdef OBJMS_ENABLE_ASYNC_FLUSH
    //remove current_trans from the flusher thread
    if (trans->flusher_cpup){
      flusher_thread = &(sbi->log_flusher_threads[trans->flusher_cpup - 1]);
#ifdef OBJMS_LAZY_STOP
      //stop the flusher thread in 1/10 s
      sbi->fs_timer.data = &sbi->log_flusher_threads[trans->flusher_cpup - 1];
      mod_timer(&sbi->fs_timer, jiffies + HZ / OBJMS_LAZY_STOP_TIMER);
#endif

#ifdef OBJMS_ASYNC_STOP
        //@ayu: FIXME
        spin_lock(&flusher_thread->flusher_queue_lock);
        flusher_thread->bit_mask &= ~(1 << trans->flusher_index);//FIXME: stop flusher thread
        spin_unlock(&flusher_thread->flusher_queue_lock);
#endif
      flusher_thread->current_trans[trans->flusher_index] = NULL;
      trans->flusher_cpup = 0;
    }
#endif
  //检查是否使用了日志项
    if (trans->num_used){
      /* Atomically write the commit type */
      objms_memunlock_range(sbi, trans->start_addr, LOGENTRY_SIZE);
      trans->start_addr->status = TXN_COMMITTED;
      objms_memlock_range(sbi, trans->start_addr, LOGENTRY_SIZE);
      /* Atomically make the txn entry valid */
      objms_flush_buffer(&trans->start_addr->status, sizeof(trans->start_addr->status), true);
    }

finish_txn:
  //printk(KERN_ERR "@objms_commit_txn: txn=%p, num_used=%u, wasted=%u, pi_buf=%p\n",
  //    trans, trans->num_used, trans->num_entries - trans->num_used, trans->pi_buf);
#ifndef OBJMS_DYNAMIC_OLE
  trans->fe_count = 0; 
#endif
#ifdef OBJMS_ENABLE_DEBUG
  //how many les are wasted?
  sbi->commit_time++;
  sbi->wasted_les += trans->num_entries - le16_to_cpu(trans->num_used);
#ifdef OBJMS_ENABLE_ASYNC_FLUSH
  //if (trans->total_flushed_bytes !=
  if (trans->total_flushed_bytes >
      (trans->forward_flushed_bytes + trans->backward_flushed_bytes)){
    printk(KERN_ERR "@objms_commit_txn:%p, total=%u,forward=%u,backward=%u\n",
        trans, trans->total_flushed_bytes, trans->forward_flushed_bytes,
        trans->backward_flushed_bytes);
  }
  trans->forward_flushed_bytes = 0;
  trans->backward_flushed_bytes = 0;
  trans->total_flushed_bytes = 0;
#endif
#endif
    //current->objms_journal_info = trans->parent;
    current->objms_journal_info = NULL;
    //TODO: first remove the trans from running txn list
    /*spin_lock(&sbi->txn_list_lock);
    list_del(&trans->txn_list);
    spin_unlock(&sbi->txn_list_lock);
    //add the transaction to commit transaction list
    if (!list_empty(&trans->txn_list)){//FIXME
      //printk(KERN_ERR "@txn_list =%p, num_entries=%d,num_used=%d\n",
      //    trans, trans->num_entries, trans->num_used);
      return 0;
    }*/
    flusher_thread = &(sbi->log_flusher_threads[cpu]);
#ifdef OBJMS_CPU_ROUND_ROBIN
    cpu = (cpu + 1) % sbi->cpus;
#endif
    spin_lock(&flusher_thread->txn_list_lock);
    list_add_tail(&trans->txn_list, &flusher_thread->txn_commit);
    spin_unlock(&flusher_thread->txn_list_lock);
  //printk(KERN_ERR "@objms_commit_transaction: end2\n");
	/* wake up the log cleaner if required */
	/*if (flusher_thread->num_free_logentries < OBJMS_FREE_LE_LIMIT){
    //num_free_logentries<3/4 && more than 2 txns running
    //printk(KERN_ERR "@objms_commit_transaction: free les: %d\n", sbi->num_free_logentries);
		wakeup_log_cleaner(sbi);
  }*/

	return 0;
}
#ifdef OBJMS_DYNAMIC_OLE
//@ayu: FIXME, currently we only support this situation
//merge le is in the granularity of byte,
//while merge ole is in the granularity of cacheline!
//如果合并相邻项，文件创建等小事务性能非常低，所以没有开启
static inline bool objms_can_merge_ole(objms_transaction_t *trans,
    unsigned long next_addr_start, uint16_t next_addr_len){
  unsigned long prev_addr_start = (unsigned long)trans->backward_ole->addr;
  unsigned long prev_addr_end = prev_addr_start + trans->backward_ole->size;
  unsigned long next_addr_end = next_addr_start + next_addr_len;

/*#ifdef OBJMS_ENABLE_ASYNC_FLUSH
  if ((next_addr_start >= prev_addr_start)
      && (next_addr_end <= prev_addr_end)){
    return true;
  } else {
    return false;
  }
#endif*/
  //return false;
  //useless when in auto_commit mode
  //if ((!(trans->flags & OBJMS_XAUTO))){
    if ((next_addr_start > prev_addr_end)
        || (next_addr_end < prev_addr_start)){
      return false;
    } else if (next_addr_start >= prev_addr_start){
      if (next_addr_end > prev_addr_end){//expand the previous size
        //printk(KERN_ERR "@objms_can_merge_ole1:ps=%lx,pe=%lx,ns=%lx,ne=%lx\n",
        //    prev_addr_start, prev_addr_end, next_addr_start, next_addr_end);
        //trans->backward_ole->addr = (void *)prev_addr_start;
        trans->backward_ole->size = next_addr_end - prev_addr_start;
      }//else next can be merged into previous
    } else {//next_addr_start < prev_addr_start
      if (next_addr_end >= prev_addr_end){//previous can be merged into next
        trans->backward_ole->addr = (void *)next_addr_start;
        trans->backward_ole->size = next_addr_len;
        //printk(KERN_ERR "@objms_can_merge_ole2:ps=%lx,pe=%lx,ns=%lx,ne=%lx\n",
        //    prev_addr_start, prev_addr_end, next_addr_start, next_addr_end);
      } else {//expand the previous addr
        //printk(KERN_ERR "@objms_can_merge_ole3:ps=%lx,pe=%lx,ns=%lx,ne=%lx\n",
        //    prev_addr_start, prev_addr_end, next_addr_start, next_addr_end);
        trans->backward_ole->addr = (void *)next_addr_start;
        trans->backward_ole->size = prev_addr_end - next_addr_start;
      }
    }
  //}
  return true;
}
#endif
//@ayu: TODO, breakdown large ole into small oles,
//so as to improve parallelism
void objms_add_logentry_info(objms_transaction_t *trans, void *addr, uint16_t size){
  objms_logentry_info_t *ole;
  unsigned long addr_start = ((unsigned long)addr) & CACHELINE_MASK;
  uint16_t addr_len = CACHELINE_ALIGN((unsigned long)addr + size) - addr_start;
#ifdef OBJMS_ENABLE_DEBUG
  objms_sbi->total_flushed_bytes += addr_len;
  //trans->total_flushed_bytes += addr_len;
  trans->total_flushed_bytes++;
#endif
  //printk(KERN_ERR "@objms_add_logentry_info: trans=%p,addr=%lu,size=%u\n",
  //    trans, addr_start, addr_len);
#ifndef OBJMS_ENABLE_ASYNC_FLUSH
  objms_flush_buffer(addr_start, addr_len, false);
#else
#ifdef OBJMS_OMIT_META_ASYNC
  if (addr_len < 256){//@ayu: FIXME
    objms_flush_buffer(addr_start, addr_len, false);
#ifdef OBJMS_ENABLE_DEBUG
    trans->backward_flushed_bytes++;
#endif
    return;
  }
#endif
#ifdef OBJMS_DYNAMIC_OLE
  if (trans->backward_ole){
    /*if (!trans->backward_ole->status){
      spin_lock(&trans->ole_lock);
      //note: only if previous ole has not been flushed can we merge
      if ((!trans->backward_ole->status)
          && objms_can_merge_ole(trans, addr_start, addr_len)){
        //printk(KERN_ERR "@objms_can_merge_ole: %p,%u,%p,%u\n",
        //    trans->backward_ole->addr, trans->backward_ole->size, addr, size);
        spin_unlock(&trans->ole_lock);
        return;
        //goto wakeup_flusher;
      }
      spin_unlock(&trans->ole_lock);
    }*/
    //如果前一个ole已经被刷回了,就直接利用它来存放下一个要添加的
    //ole信息,避免重新分配新的ole
    if (trans->backward_ole->status & OLE_FLUSHED){
      ole = list_first_entry(&trans->ole_list,
          objms_logentry_info_t, link);
      if (ole == trans->backward_ole){
        trans->forward_ole = NULL;
      } else {
        trans->forward_ole = list_entry(trans->backward_ole->link.prev,
            objms_logentry_info_t, link);
      }

      trans->backward_ole->addr = (void *)addr_start;
      trans->backward_ole->size = addr_len;
      trans->backward_ole->status = 0;
      goto wakeup_flusher;
    }/* else if (!trans->backward_ole->status){//@ayu: FIXME
      //if previous ole is not flushing, do not add ole
      //instead, flush newly ole immediately
      objms_flush_buffer(addr_start, addr_len, false);
      return;
    }*/
  }
  
  ole = objms_alloc_ole();
  ole->status = 0;
  ole->le_off = 0;
  ole->size = addr_len;
  ole->addr = (void *)addr_start;

  list_add_tail(&ole->link, &trans->ole_list);
  trans->backward_ole = ole;//backward_ole always point to the last ole until commit

#else
  //if the flusher entry queue is full
  uint16_t new_index;
  if (trans->fe_count < FLUSHER_ENTRY_PER_TXN){
    if (trans->fe_tail == FLUSHER_ENTRY_PER_TXN){
      //the queue is empty
      trans->fe_head = 0;
      trans->fe_tail = 0;
      new_index = 0;
    } else {
      new_index = (trans->fe_tail + 1) % FLUSHER_ENTRY_PER_TXN;
    }

    trans->fe_count++;
  } else {
    //try to reclaim 1 flushed entry
    if ((trans->flusher_entries[trans->fe_head].status & OLE_FLUSHED)
        && (trans->current_index != trans->fe_head)){
      //如果待回收的flusher entry不是刚刚被刷过的
      //防止少刷一圈
      //reclaim the head entry
      new_index = trans->fe_head;
      trans->fe_head = (trans->fe_head + 1) % FLUSHER_ENTRY_PER_TXN;
    } else {
      //no entry reclaimable, just flush immediately
      objms_flush_buffer((void *)addr_start, addr_len, false);
#ifdef OBJMS_ENABLE_DEBUG
      //trans->backward_flushed_bytes += addr_len;
      trans->backward_flushed_bytes++;
#endif
      return;
    }
  }
  trans->flusher_entries[new_index].status = 0;
  trans->flusher_entries[new_index].le_off = 0;
  trans->flusher_entries[new_index].size = addr_len;
  trans->flusher_entries[new_index].addr = (void *)addr_start;
  trans->fe_tail = new_index;
  //trans->flusher_entries[new_index].status |= OLE_FLUSHABLE;

#endif

wakeup_flusher:
  wakeup_log_flusher(trans);//FIXME
#endif
}

inline bool objms_has_empty_flusher_entry(objms_transaction_t *trans){
#ifdef OBJMS_EMPTY_FLUSHER_ENTRY
  if ((trans->fe_count < FLUSHER_ENTRY_PER_TXN)
      || ((trans->flusher_entries[trans->fe_head].status & OLE_FLUSHED)
        && (trans->current_index != trans->fe_head))){
    //there is empty flusher entry
    return true;
  } else {
    return false;
  }
#else
  return true;
#endif
}
//calculate and allocate log entries
//TODO: redundant log entry check
int objms_add_logentry(objms_transaction_t *trans, void *addr,
    uint16_t size, bool add_le_info){
  struct objms_sb_info *sbi = objms_sbi;
	objms_logentry_t *le;//currently available le
	int num_les = 0, i;
  uint32_t le_size;
	uint64_t le_start = objms_get_addr_off(sbi, addr);//data offset

	if (unlikely(!trans)){
		return -EINVAL;
  }
  //@ayu: remove redundant logging
  //FIXME, TODO: we need to reflush the log enry
  /*if (unlikely(objms_can_merge_le(trans, addr, size))){
    uint16_t log_size;
    le = get_log_entry(sbi, trans->backward_ole->le_off);
    log_size = min_t(uint16_t, MAX_DATA_PER_LENTRY - le->size, size);
    objms_memunlock_range(sbi, le, sizeof(*le));
    memcpy(le->data + le->size, addr, log_size);
    le->size = le->size + log_size;
    objms_memlock_range(sbi, le, sizeof(*le));

    size -= log_size;
    addr += log_size;
    le_start += log_size;
    //printk(KERN_ERR "@objms_can_merge_le called\n");
  }*/
  //for normal-commit txn, onode may be stored in pi_buf,
  //we do not flush it early, thus we do not add ole for it
  //if (add_le_info && (addr != trans->pi_buf)){
  if (add_le_info){//FIXME: for FS-txn only
    objms_add_logentry_info(trans, addr, size);
  }
  //printk(KERN_ERR "@objms_add_logentry: trans=%p,addr=%p,size=%u\n",
  //    trans, addr, size);

  //first try coarse-grained logging
  if (unlikely(size >= CACHELINE2PAGE_LIMIT)){//use page-logging
    objms_metalogentry_t *mle;//currently available le
    char *log_page_data;
    unsigned long blocknr = 0;

#ifdef OBJMS_ENABLE_DEBUG
    sbi->obj_wakeup1++;
#endif
    //printk(KERN_ERR "@cacheline 2 page limit: size=%d\n", size);
    num_les = (size + PAGE_SIZE - CACHELINE2PAGE_LIMIT) / PAGE_SIZE;
    if (unlikely(num_les > trans->num_entries - trans->num_used)){
      if (objms_alloc_logentries(trans, num_les)){//ohoh, allocation failed...
        return -ENOMEM;
      }
    }
    //printk(KERN_ERR "@objms_add_logentry1: size=%d, num_les=%d\n",
    //    size, num_les);
    mle = (objms_metalogentry_t *)trans->next_addr;
    for (i = 0; i < num_les; i++) {
      objms_new_block(trans, &blocknr, OBJMS_BLOCK_TYPE_4K, 0);
      //int left = objms_new_extent_block(sbi, &blocknr, count, 0);//FIXME: TODO
      //reuse the cowblk_list to store the log page number
      objms_add_cowblk_list(trans, blocknr, 1);

      mle->page_off = cpu_to_le64(objms_get_block_off(blocknr));
      objms_memunlock_range(sbi, mle, sizeof(*mle));
      mle->addr_offset = cpu_to_le64(le_start);
      le_size = min_t(uint16_t, PAGE_SIZE, size);
      mle->log_size = le_size;
      size -= le_size;
      //log the data
      log_page_data = objms_get_block(le64_to_cpu(mle->page_off));
      /*memcpy(log_page_data, addr, le_size);
      //flush the log page
      objms_flush_buffer(log_page_data, le_size, false);*/
      objms_memcpy_to_scm_nocache(log_page_data, addr, le_size);
      /* put a compile time barrier so that compiler doesn't reorder
       * the writes to the log entry */
      barrier();
      mle->status |= LE_META;
      objms_memlock_range(sbi, mle, sizeof(*mle));

      trans->next_addr = get_log_entry(sbi, le32_to_cpu(mle->next_offset));
      //flush the log entry
      objms_flush_buffer(mle, LOGENTRY_SIZE, false);

      //prepare for next log entry
      addr += le_size;
      le_start += le_size;
      mle = (objms_metalogentry_t *)trans->next_addr;
    }
    trans->num_used += num_les;
  }
	if (unlikely(!size)){
    return 0;
	}
  //next try fine-grained logging
  num_les = (size + MAX_DATA_PER_LENTRY - 1) / MAX_DATA_PER_LENTRY;
	if (unlikely(num_les > trans->num_entries - trans->num_used)){//transaction's free les is not enough, try allocate more
    if (objms_alloc_logentries(trans, num_les)){//ohoh, allocation failed...
      //dump_stack();
      return -ENOMEM;
    }
	}

  le = trans->next_addr;
	for (i = 0; i < num_les; i++) {
#ifdef OBJMS_ENABLE_DEBUG
    sbi->obj_wakeup2++;
#endif
    //printk(KERN_ERR "@objms_add_logentry: le=%u,le->next_offset=%u\n",
    //    objms_get_log_entry_off(sbi,le),le32_to_cpu(le->next_offset));
    objms_memunlock_range(sbi, le, sizeof(*le));
		le->addr_offset = cpu_to_le64(le_start);
		le_size = min_t(uint16_t, sizeof(le->data), size);
    le->size = le_size;
		size -= le_size;
    memcpy(le->data, addr, le_size);
		/* put a compile time barrier so that compiler doesn't reorder
		 * the writes to the log entry */
		barrier();
    le->status |= LE_DATA;
    objms_memlock_range(sbi, le, sizeof(*le));

		trans->next_addr = get_log_entry(sbi, le32_to_cpu(le->next_offset));
    //make the log entry persistent
		objms_flush_buffer(le, LOGENTRY_SIZE, false);

    //prepare for next log entry
		addr += le_size;
		le_start += le_size;
    le = trans->next_addr;
	}
  trans->num_used += num_les;
  if (trans->num_used == trans->num_entries){//les are used up
    trans->next_addr = NULL;
  }
//	if (!sbi->redo_log) {
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
//	}
	return 0;
}

SYSCALL_DEFINE1(objms_abort_txn, unsigned long, tid){
  struct objms_sb_info *sbi = objms_sbi;
  objms_logentry_t *te;
	objms_transaction_t *trans = objms_current_transaction(tid);
#ifdef OBJMS_CPU_ROUND_ROBIN
  static int cpu = 0;
#else
  int cpu = smp_processor_id() % sbi->cpus;
#endif
	if (unlikely(!trans)){
		return 0;
  }
  te = trans->start_addr;

  //if (!trans->parent){
    //decrease the num_txns
    //sbi->num_txns--;
    atomic_dec(&sbi->num_txns);
  //}
  if (unlikely(!trans->num_entries)){
    //current->objms_journal_info = trans->parent;
    current->objms_journal_info = NULL;
    objms_free_transaction(trans);
    return 0;
  }
//	if (!sbi->redo_log) {
		/* Undo Log */
		objms_undo_transaction(sbi, trans);//copy all les to it's original place and make them persistent(flush), so after make the txn persistent, the log cleaner can directly remove the txn
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
//	}
  //modify the transaction's status to TXN_ABORTED
  objms_memunlock_range(sbi, te, sizeof(*te));
  te->status = TXN_ABORTED;
  objms_memlock_range(sbi, te, sizeof(*te));

  objms_flush_buffer(&te->status, sizeof(te->status), false);

  //current->objms_journal_info = trans->parent;
  current->objms_journal_info = NULL;
  objms_flusher_thread_t *flusher_thread = &(sbi->log_flusher_threads[cpu]);
#ifdef OBJMS_CPU_ROUND_ROBIN
  cpu = (cpu + 1) % sbi->cpus;
#endif
  //first remove the trans from running txn list
  /*spin_lock(&sbi->txn_list_lock);
  list_del(&trans->txn_list);
  spin_unlock(&sbi->txn_list_lock);*/
  //add the transaction to abort transaction list
  spin_lock(&flusher_thread->txn_list_lock);
  list_add_tail(&trans->txn_list, &flusher_thread->txn_commit);
  spin_unlock(&flusher_thread->txn_list_lock);
	
	/* wake up the log cleaner if required */
	/*if (flusher_thread->num_free_logentries < OBJMS_FREE_LE_LIMIT){//num_free_logentries<3/4 && more than 2 txns running
  //printk(KERN_ERR "@objms_abort_transaction: free les: %d\n", sbi->num_free_logentries);
		wakeup_log_cleaner(sbi);
  }*/

	return 0;
}

/* we need to increase the gen_id to invalidate all the journal log
 * entries. This is because after the recovery, we may still have some
 * valid log entries beyond the tail (before power failure, they became
 * persistent before the journal tail could become persistent.
 * should gen_id and head be updated atomically? not necessarily? we
 * can update gen_id before journal head because gen_id and head are in
 * the same cacheline */
//TODO: reset the journal space
/*static void objms_reset_journal(struct objms_sb_info *sbi, objms_journal_t *journal){
  //objms_memunlock_range(sbi, journal, sizeof(*journal));
	//objms_memlock_range(sbi, journal, sizeof(*journal));
	//objms_flush_buffer(journal, sizeof(*journal), false);
  memset(sbi->journal_base_addr, 0, sbi->jsize);
  //reset the num_free_txnentries to max;
  //sbi->num_free_txnentries = sbi->tsize / TXNENTRY_SIZE;
}*/
//FIXME
//recover the journal area:
static int objms_recover_undo_journal(struct objms_sb_info *sbi){
	//objms_journal_t *journal = objms_get_journal(sbi);
  uint32_t i;
  objms_transaction_t trans;
  objms_logentry_t *le;

  for (i = 0; i < sbi->jsize; i += LOGENTRY_SIZE){//FIXME, wrong
    le = get_log_entry(sbi, i);
    //only TXN_RUNNING and its used need recover
    if ((le->status == TXN_RUNNING)
        && (le->status & LE_INUSE)){
      //find the first log entry
      trans.start_addr = le;
      //find the last log entry
      //trans.end_addr = get_log_entry(sbi, le32_to_cpu(le->end_offset));
      objms_undo_transaction(sbi, &trans);
      //no txn_mutex lock because we are the only one access it
      //objms_release_txnentry(sbi, le);
      //le->status = LE_FREE;
    }
  }

	//objms_reset_journal(sbi, journal);
  memset(sbi->journal_base_addr, 0, sbi->jsize);
	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	return 0;
}
/*
static int objms_recover_redo_journal(struct objms_sb_info *sbi){
	objms_journal_t *journal = objms_get_journal(sbi);
  uint32_t i;
	uint32_t txn_low = le32_to_cpu(journal->txn_low);
	uint32_t txn_high = le32_to_cpu(journal->txn_high);
  objms_transaction_t trans;
  objms_txnentry_t *te;

  for (i = txn_low; i < txn_high; i += TXNENTRY_SIZE){
    te = get_txn_entry(sbi, i);
    //only TXN_COMMITTED need recover (redo)
    if (te->status == TXN_COMMITTED){
      trans.te = te;
      //find the first log entry
      trans.start_addr = get_log_entry(sbi, le32_to_cpu(te->start_offset));
      //find the last log entry
      //trans.end_addr = get_log_entry(sbi, le32_to_cpu(te->end_offset));
      objms_redo_transaction(sbi, &trans, true);
      //no txn_mutex lock because we are the only one access it
      objms_release_txnentry(sbi, te);
    }
  }
	
	objms_forward_journal(sbi, journal);
	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	return 0;
}
*/
int objms_recover_journal(struct objms_sb_info *sbi)
{

	/* is the journal empty? true if unmounted properly. */
//	if (sbi->redo_log)
//		objms_recover_redo_journal(sbi);
//	else
		objms_recover_undo_journal(sbi);
	return 0;
}

