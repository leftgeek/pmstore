/*
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
#ifndef __OBJMS_JOURNAL_H
#define __OBJMS_JOURNAL_H
#include <linux/slab.h>
#include <linux/obj.h>

/* default objms journal size 64MB(1024*1024 les) */
#define OBJMS_DEFAULT_JOURNAL_SIZE  (64 << 20)
//#define OBJMS_PER_JOURNAL_SIZE  (OBJMS_DEFAULT_JOURNAL_SIZE / 24)
//total log entry count
//#define OBJMS_TOTAL_LE  524288
//3/4 of total log entries
//#define OBJMS_FREE_LE_LIMIT 393216
//#define OBJMS_FREE_LE_LIMIT 462252
//#define OBJMS_FREE_LE_LIMIT (OBJMS_PER_JOURNAL_SIZE * 3 / 256) 
/* minimum objms journal size 64KB */
#define OBJMS_MINIMUM_JOURNAL_SIZE  (1 << 16)
#define OBJMS_SOCKETS 4
#define OBJMS_PER_SOCKET_CORES 8
#define OBJMS_CORES (OBJMS_SOCKETS * OBJMS_PER_SOCKET_CORES)
#define OBJMS_PER_CORE_THREADS 2
#define OBJMS_THREADS (OBJMS_CORES * OBJMS_PER_CORE_THREADS)

#define CACHELINE_SIZE  (64)
#define CLINE_SHIFT		(6)
#define CACHELINE_MASK  (~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) (((addr)+CACHELINE_SIZE-1) & CACHELINE_MASK)

#define LOGENTRY_SIZE  CACHELINE_SIZE
#define LESIZE_SHIFT   CLINE_SHIFT

#define MAX_INODE_LENTRIES (2)
#define MAX_SB_LENTRIES (2)
/* 2 le for adding or removing the inode from truncate list. used to log
 * potential changes to inode table's i_next_truncate and i_sum */
//FIXME: 1 or 2?
#define MAX_TRUNCATE_LENTRIES (2)
#define MAX_DATA_PER_LENTRY  48
/* blocksize * max_btree_height */
#define MAX_METABLOCK_LENTRIES \
	((OBJMS_DEF_BLOCK_SIZE_4K * 3)/MAX_DATA_PER_LENTRY)

#define MAX_PTRS_PER_LENTRY (MAX_DATA_PER_LENTRY / sizeof(u64))

//|txn status(4bits)|le status(4bits)|
//log entry type
#define LE_FREE 0
#define LE_DATA 0x1
#define LE_META 0x2
#define LE_INUSE (LE_DATA | LE_META)
//when the txn bit is set, it means the le is a txn head le
#define TXN_RUNNING    0x10
#define TXN_COMMITTED  0x20
#define TXN_ABORTED    0x40
//logentry_info status
#define OLE_UNFLUSHED 0x0
#define OLE_FLUSHING 0x100
#define OLE_FLUSHED 0x200
//#define OLE_FLUSHABLE 0x400
//the length limit of use journaling instead of cow
//#define COW2JOURNAL_LIMIT 960
#define COW2JOURNAL_LIMIT 960
//the length limit of use page logging instead of cacheline logging
//#define CACHELINE2PAGE_LIMIT 240
//4 * 48 + 64 = 256
//4 * 64 = 256
#define CACHELINE2PAGE_LIMIT 192
//#define CACHELINE2PAGE_LIMIT 144

//#define QUEUE_PER_FLUSHER 32
#define QUEUE_PER_FLUSHER 4
//#define JOURNAL_TIMER 5
#define JOURNAL_TIMER 1

#undef OBJMS_ENABLE_AUTO_COMMIT
#undef OBJMS_ENABLE_ASYNC_FLUSH
//#define OBJMS_ENABLE_ASYNC_FLUSH 0x1
#undef OBJMS_DATA_ASYNC
//#define OBJMS_DATA_ASYNC 0x1
//去掉元数据的async,即小数据立即flush
#undef OBJMS_OMIT_META_ASYNC
//#define OBJMS_OMIT_META_ASYNC 0x1
#undef OBJMS_MEMORY_OBJECT
//#define OBJMS_MEMORY_OBJECT 0x1
#undef OBJMS_FINE_LOCK
//#define OBJMS_FINE_LOCK 0x1
#undef OBJMS_WEAK_XMODE
//#define OBJMS_WEAK_XMODE 0x1
#undef OBJMS_ENABLE_DEBUG
//#define OBJMS_ENABLE_DEBUG
#undef OBJMS_ASYNC_STOP
#define OBJMS_ASYNC_STOP 0x1
#undef OBJMS_LAZY_STOP
//#define OBJMS_LAZY_STOP 0x1
#define OBJMS_LAZY_STOP_TIMER 1000
#undef OBJMS_ASYNC_DIVIDE
//#define OBJMS_ASYNC_DIVIDE 0x1
#define MAX_FLUSHER_PER_SOCKET 8
#define MAX_FLUSHERS 16
//1.不绑定flusher thread,且完全随机分配
#undef OBJMS_FLUSHER_RANDOM
//#define OBJMS_FLUSHER_RANDOM 0x1
//2.绑定flusher thread到所在SOCKET上
//限制每个SOCKET的数量
//开启这个的时候要关闭OBJMS_ASYNC_STOP
#undef OBJMS_FLUSHER_SOCKET
#define OBJMS_FLUSHER_SOCKET 0x1
//3.绑定flusher thread到所在SOCKET上
//限制所有SOCKET的总flusher thread数量
//开启这个的时候最好开启OBJMS_ASYNC_STOP
#undef OBJMS_FLUSHER_TOTAL
//#define OBJMS_FLUSHER_TOTAL 0x1
#undef OBJMS_DYNAMIC_OLE
//#define OBJMS_DYNAMIC_OLE
//每个事务3个flusher entry
#define FLUSHER_ENTRY_PER_TXN 4
//是否允许判断空闲ole项,开启后
//add_ole会根据队列是否有空闲来选择是否开启data-async
#undef OBJMS_EMPTY_FLUSHER_ENTRY
//#define OBJMS_EMPTY_FLUSHER_ENTRY 0x1
#undef OBJMS_CPU_ROUND_ROBIN
#define OBJMS_CPU_ROUND_ROBIN 0x1
//FIXME: this will be removed if multi-socket problem has solved
#undef OBJMS_DEBUG_NUMA
//#define OBJMS_DEBUG_NUMA 0x1
#undef OBJMS_FLUSHER_BIND_CPU
//#define OBJMS_FLUSHER_BIND_CPU
#undef OBJMS_FLUSHER_BIND_SOCKET
#define OBJMS_FLUSHER_BIND_SOCKET

//@ayu: clflush time calculate
#undef OBJMS_CLFLUSH_TIME
//#define OBJMS_CLFLUSH_TIME

/* persistent data structure to describe a single log-entry */
/* every log entry is max CACHELINE_SIZE bytes in size */
typedef struct {
  u8  status; //| txn_status(4bits) | le_status(4bits)|
	u8       size;
	u16      padding;
  __le32   next_offset;  //next logentry's offset(of the journal space)
  //in the same transaction, start from sizeof(le) when 0 means terminate
	__le64   addr_offset;
	char     data[48];
} objms_logentry_t;

//meta log entry
typedef struct {
  u8  status; //LE_META
	u8       size;  //not used
	u16      padding;
  __le32   next_offset;
	__le64   addr_offset;
  __le64 page_off;//offset of the first page in a extent
  __le64 log_size;
  //extended log page information
  __le64 page_off2;
  __le64 log_size2;
  __le64 page_off3;
  __le64 log_size3;
} objms_metalogentry_t;
//@ayu: FIXME, TODO, head log entry
/*typedef struct {
  u8  status; //| txn_status(4bits) | le_status(4bits)|
	u8       size;
	u16      parent_id;//parent txn's id(a txn's id is its offset in DRAM cache/slab)
  //we do not store parent txn's head_log_entry offset because
  //it may have no log_entry
  __le32   next_offset;  //next logentry's offset(of the journal space)
  //in the same transaction, start from sizeof(le) when 0 means terminate
	__le64   addr_offset;
	char     data[48];
} objms_headlogentry_t;
*/
//in-memory data structure of log entry
typedef struct {
  uint16_t status;
  uint16_t size;
  uint32_t le_off;//FIXME: we do not need this
  void *addr;
#ifdef OBJMS_DYNAMIC_OLE
  struct list_head link;
#endif
} objms_logentry_info_t;
//pte node can be merged with logentry_info
typedef struct {
  unsigned long uaddr;
  void *addr;//kaddr
  struct list_head link;
} objms_ptenode_t;
//get a transaction entry by its offset
//in memory transaction structure
typedef struct objms_transaction{
	//objms_journal_t  *t_journal;
  uint16_t num_entries;
  uint16_t num_used;
  uint16_t pi_buf_len;//length of pi_buf
  //uint16_t num_flushed; 
  uint16_t flags;  //OBJMS_XAUTO, OBJMS_XSTRONG...
  //flusher_cpup - 1=flusher_cpu number
  uint16_t flusher_cpup;//flusher thread cpu bind to the trans, starts from 1(0 means invalid)
  uint16_t flusher_index;//flusher index(0-9)
  pid_t pid;
#ifdef OBJMS_ENABLE_DEBUG
  uint32_t forward_flushed_bytes;
  uint32_t backward_flushed_bytes;
  uint32_t total_flushed_bytes;
#endif
  //unsigned int commit_time;//FIXME
  objms_logentry_t *start_addr; //first log entry's address
	//objms_logentry_t *last_addr; //next-unused log entry's addr(next_addr to end_addr log entries are all unused)
	objms_logentry_t *next_addr; //next-unused log entry's addr(next_addr to end_addr log entries are all unused)
  objms_logentry_t *end_addr;
  //struct objms_transaction *parent;
  struct list_head txn_list;
  struct list_head cowblk_list;//old-block list
  //TODO: reduce its size, it is not available for auto_commit_mode

  unsigned long old_btree_root;//old btree root pointer(offset)，当increase_btree_height时记录前B树的快照，旧的B树根以下的块如果要被修改也需要被记录日志，此时新的btree root产生的new_node对它不起作用
  //for memory object cow txns
  struct objms_inode *pi_buf;//to reduce redundant inode logging
#ifdef OBJMS_DYNAMIC_OLE
  objms_logentry_info_t *forward_ole; //currently being-flushed log entry's address
  objms_logentry_info_t *backward_ole; //backward flush pointer
  struct list_head ole_list;//in-memory list of all les of a txn(ole_list)
  //struct mutex ole_lock;
  spinlock_t ole_lock;
#else
  objms_logentry_info_t flusher_entries[FLUSHER_ENTRY_PER_TXN];
  //此处直接用位域就行
  uint16_t fe_count;
  uint16_t current_index;
  uint16_t fe_head;
  uint16_t fe_tail;
#endif
} objms_transaction_t;

extern objms_transaction_t *objms_alloc_transaction(void);
extern void objms_free_transaction(objms_transaction_t *trans);

extern objms_transaction_t *objms_current_transaction(unsigned long tid);
extern int objms_add_logentry(objms_transaction_t *trans, void *addr,
    uint16_t size, bool add_le_info);
extern void objms_add_logentry_info(objms_transaction_t *trans, void *addr, uint16_t size);
extern bool objms_has_empty_flusher_entry(objms_transaction_t *trans);
extern int objms_alloc_logentries(objms_transaction_t *trans,
    uint32_t num_log_entries);
extern int objms_add_ptenode(objms_transaction_t *trans,
    unsigned long address);
extern int objms_auto_commit_txn(objms_transaction_t *trans);
//extern void wakeup_log_flusher(pid_t pid);
//extern void wakeup_log_flusher(objms_transaction_t *trans);

#endif    /* __OBJMS_JOURNAL_H */
