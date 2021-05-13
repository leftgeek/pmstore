#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/sched.h>
#include <asm/pgtable.h>
#include <linux/mman.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/sched/sysctl.h>
#include <linux/uprobes.h>
#include <linux/rbtree_augmented.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/file.h>
#include <asm/tlb.h>
#include "../../mm/internal.h"
#include "objms.h"
#include <linux/hugetlb.h>

static inline unsigned long round_hint_to_min(unsigned long hint)
{
	hint &= PAGE_MASK;
	if (((void *)hint != NULL) &&
	    (hint < mmap_min_addr))
		return PAGE_ALIGN(mmap_min_addr);
	return hint;
}

static int find_vma_links(struct mm_struct *mm, unsigned long addr,
		unsigned long end, struct vm_area_struct **pprev,
		struct rb_node ***rb_link, struct rb_node **rb_parent)
{
	struct rb_node **__rb_link, *__rb_parent, *rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;

	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			/* Fail if an existing vma overlaps the area */
			if (vma_tmp->vm_start < end)
				return -ENOMEM;
			__rb_link = &__rb_parent->rb_left;
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return 0;
}
/*
static void __vma_link_file(struct vm_area_struct *vma)
{
	struct file *file;

	file = vma->vm_file;
	if (file) {
		struct address_space *mapping = file->f_mapping;

		if (vma->vm_flags & VM_DENYWRITE)
			atomic_dec(&file_inode(file)->i_writecount);
		if (vma->vm_flags & VM_SHARED)
			mapping->i_mmap_writable++;

		flush_dcache_mmap_lock(mapping);
		if (unlikely(vma->vm_flags & VM_NONLINEAR))
			vma_nonlinear_insert(vma, &mapping->i_mmap_nonlinear);
		else
			vma_interval_tree_insert(vma, &mapping->i_mmap);
		flush_dcache_mmap_unlock(mapping);
	}
}

static void
__vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, struct rb_node **rb_link,
	struct rb_node *rb_parent)
{
	__vma_link_list(mm, vma, prev, rb_parent);
	__vma_link_rb(mm, vma, rb_link, rb_parent);
}*/
#ifdef CONFIG_DEBUG_VM_RB
static int browse_rb(struct rb_root *root)
{
	int i = 0, j, bug = 0;
	struct rb_node *nd, *pn = NULL;
	unsigned long prev = 0, pend = 0;

	for (nd = rb_first(root); nd; nd = rb_next(nd)) {
		struct vm_area_struct *vma;
		vma = rb_entry(nd, struct vm_area_struct, vm_rb);
		if (vma->vm_start < prev) {
			printk("vm_start %lx prev %lx\n", vma->vm_start, prev);
			bug = 1;
		}
		if (vma->vm_start < pend) {
			printk("vm_start %lx pend %lx\n", vma->vm_start, pend);
			bug = 1;
		}
		if (vma->vm_start > vma->vm_end) {
			printk("vm_end %lx < vm_start %lx\n",
				vma->vm_end, vma->vm_start);
			bug = 1;
		}
		if (vma->rb_subtree_gap != vma_compute_subtree_gap(vma)) {
			printk("free gap %lx, correct %lx\n",
			       vma->rb_subtree_gap,
			       vma_compute_subtree_gap(vma));
			bug = 1;
		}
		i++;
		pn = nd;
		prev = vma->vm_start;
		pend = vma->vm_end;
	}
	j = 0;
	for (nd = pn; nd; nd = rb_prev(nd))
		j++;
	if (i != j) {
		printk("backwards %d, forwards %d\n", j, i);
		bug = 1;
	}
	return bug ? -1 : i;
}

static void validate_mm_rb(struct rb_root *root, struct vm_area_struct *ignore)
{
	struct rb_node *nd;

	for (nd = rb_first(root); nd; nd = rb_next(nd)) {
		struct vm_area_struct *vma;
		vma = rb_entry(nd, struct vm_area_struct, vm_rb);
		BUG_ON(vma != ignore &&
		       vma->rb_subtree_gap != vma_compute_subtree_gap(vma));
	}
}
#else
#define validate_mm_rb(root, ignore) do { } while (0)
#define validate_mm(mm) do { } while (0)
#endif


//static void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
//			struct vm_area_struct *prev, struct rb_node **rb_link,
//			struct rb_node *rb_parent)
//{
/*  struct address_space *mapping = NULL;

	if (vma->vm_file)
		mapping = vma->vm_file->f_mapping;

	if (mapping)
		mutex_lock(&mapping->i_mmap_mutex);
*/
//	__vma_link(mm, vma, prev, rb_link, rb_parent);
//	__vma_link_file(vma);
/*
	if (mapping)
		mutex_unlock(&mapping->i_mmap_mutex);
*/
//	mm->map_count++;
//	validate_mm(mm);
//}


static unsigned long count_vma_pages_range(struct mm_struct *mm,
		unsigned long addr, unsigned long end)
{
	unsigned long nr_pages = 0;
	struct vm_area_struct *vma;

	/* Find first overlaping mapping */
	vma = find_vma_intersection(mm, addr, end);
	if (!vma)
		return 0;

	nr_pages = (min_t(unsigned long, end, vma->vm_end) -
		max(addr, vma->vm_start)) >> PAGE_SHIFT;

	/* Iterate over the rest of the overlaps */
	for (vma = vma->vm_next; vma; vma = vma->vm_next) {
		unsigned long overlap_len;

		if (vma->vm_start > end)
			break;

		overlap_len = min_t(unsigned long, end, vma->vm_end) - vma->vm_start;
		nr_pages += overlap_len >> PAGE_SHIFT;
	}

	return nr_pages;
}
//version for mmap
/*static int objms_find_and_alloc_blocks(struct objms_inode *pi,
    sector_t iblock, sector_t *data_block, int create){
  struct objms_sb_info *sbi = objms_sbi;
	int err = -EIO;
	u64 block;
	objms_transaction_t *trans;

	block = objms_find_data_block(sbi, pi, iblock);

  if (unlikely(!block)) {//it seldom never comes here, this may be useful for objms_objmap_fault
		if (!create) {
			err = -ENODATA;
			goto err;
		}

		trans = objms_current_transaction();
    err = objms_alloc_blocks(trans, pi, iblock, 1, true);
    if (err) {
      goto err;
    }
		block = objms_find_data_block(sbi, pi, iblock);
	}

	*data_block = block;
	err = 0;

err:
	return err;
}*/
//copy from filemap_fault
int objms_objmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf){
  struct objms_sb_info *sbi = objms_sbi;
  struct objms_inode *pi = (struct objms_inode *)vma->vm_file;
  pgoff_t offset = vmf->pgoff;
  pgoff_t size;
  int rc = 0;
  sector_t block = 0;
  //void *mem;
  unsigned long pfn;

  size = (le64_to_cpu(pi->i_size) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
  if (offset >= size){
    //so as to allow memory object extends as storage objects
    return VM_FAULT_SIGBUS;
  }

  printk(KERN_ERR "@objms_objmap_fault: offset=%lu\n", offset);
  //rc = objms_find_and_alloc_blocks(pi, offset, &block, 1);
  //@ayu: FIXME, BUG for null txn
  block = objms_find_and_alloc_blocks(NULL, pi, offset);
  if (unlikely(!block)){
    return -1;
  }
  printk(KERN_ERR "@objms_objmap_fault: block=%d\n", block);

  //mem = objms_get_block(sbi, block); 
  pfn = (sbi->phys_addr + block) >> PAGE_SHIFT;

  rc = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address, pfn);

  if (rc == -ENOMEM){
    return VM_FAULT_SIGBUS;
  }

  if (rc != -EBUSY){
    BUG_ON(rc);
  }
  return VM_FAULT_NOPAGE;
}

static pte_t objms_make_huge_pte(struct vm_area_struct *vma,
    unsigned long pfn, unsigned long sz, int writable){
  pte_t entry;
  if (writable){
    entry = pte_mkwrite(pte_mkdirty(pfn_pte(pfn, vma->vm_page_prot)));
  } else {
    entry = pte_wrprotect(pfn_pte(pfn, vma->vm_page_prot));
  }
  entry = pte_mkspecial(pte_mkyoung(entry));
  if (sz != PAGE_SIZE){
    entry = pte_mkhuge(entry);
  }
  return entry;
}

//@ayu: FIXME, TODO
int objms_objmap_hpage_fault(struct vm_area_struct *vma, struct vm_fault *vmf){
  struct objms_sb_info *sbi = objms_sbi;
  struct objms_inode *pi = (struct objms_inode *)vma->vm_file;
  pgoff_t offset = vmf->pgoff;
  pgoff_t size, block_sz;
  int rc = 0;
  sector_t block = 0;
  //void *mem;
  struct mm_struct *mm = vma->vm_mm;
  unsigned long pfn;
  pte_t *ptep, new_pte;
  unsigned long address = (unsigned long)vmf->virtual_address;

  size = (le64_to_cpu(pi->i_size) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
  if (offset >= size){
    //so as to allow memory object extends as storage objects
    return VM_FAULT_SIGBUS;
  }

  if (pi->i_blk_type == OBJMS_BLOCK_TYPE_2M){
    block_sz = PMD_SIZE;
  } else {
    block_sz = PUD_SIZE;
  }
  address &= ~(block_sz - 1);

  //printk(KERN_ERR "@objms_objmap_hpage_fault: offset=%lx\n", offset);
  //ptep = pte_alloc_pagesz(mm, address, block_sz);
  ptep = huge_pte_alloc(mm, address, block_sz);
  if (!ptep){
    return VM_FAULT_SIGBUS;
  }
  if (pte_none(*ptep)){
    //rc = objms_find_and_alloc_blocks(pi, offset, &block, 1);
    //@ayu: FIXME, BUG for null txn
    block = objms_find_and_alloc_blocks(NULL, pi, offset);
    if (unlikely(!block)){
      return -1;
    }

    //mem = objms_get_block(sbi, block); 
    pfn = objms_get_pfn(block);
    pfn <<= PAGE_SHIFT;
    pfn &= ~(block_sz - 1);
    pfn >>= PAGE_SHIFT;

    new_pte = objms_make_huge_pte(vma, pfn, block_sz,
        ((vma->vm_flags & VM_WRITE)
         && (vma->vm_flags & VM_SHARED)));
    set_pte_at(mm, address, ptep, new_pte);
    if (ptep_set_access_flags(vma, address, ptep, new_pte,
          vmf->flags & FAULT_FLAG_WRITE)){
      update_mmu_cache(vma, address, ptep);
    }
  }
  return VM_FAULT_NOPAGE;
}

unsigned long objms_get_unmapped_area(struct objms_inode *pi,
    unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags){
	unsigned long align_size;
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct vm_unmapped_area_info info;

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (pi->i_blk_type == OBJMS_BLOCK_TYPE_1G)
		align_size = PUD_SIZE;
	else if (pi->i_blk_type == OBJMS_BLOCK_TYPE_2M)
		align_size = PMD_SIZE;
	else
		align_size = PAGE_SIZE;

	if (flags & MAP_FIXED) {
		/* FIXME: We could use 4K mappings as fallback. */
		if (len & (align_size - 1))
			return -EINVAL;
		if (addr & (align_size - 1))
			return -EINVAL;
		return addr;
	}

	if (addr) {
		addr = ALIGN(addr, align_size);
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}

	/*
	 * FIXME: Using the following values for low_limit and high_limit
	 * implicitly disables ASLR. Awaiting a better way to have this fixed.
	 */
	info.flags = 0;
	info.length = len;
	info.low_limit = TASK_UNMAPPED_BASE;
	info.high_limit = TASK_SIZE;
	info.align_mask = align_size - 1;
	info.align_offset = 0;
	return vm_unmapped_area(&info);
}

static const struct vm_operations_struct objms_obj_vm_ops = {
  .fault = objms_objmap_fault,
};

static const struct vm_operations_struct objms_obj_hpage_vm_ops = {
  .fault = objms_objmap_hpage_fault,
};

static inline int objms_has_huge_mmap(void){
  return objms_sbi->s_mount_opt & OBJMS_MOUNT_HUGEMMAP;
}

unsigned long objms_omap_region(struct objms_inode *pi, unsigned long addr,
    unsigned long len, vm_flags_t vm_flags, unsigned long pgoff){
  struct mm_struct *mm = current->mm;
  struct vm_area_struct *vma, *prev;
  //int correct_wcount = 0;
  int error;
  struct rb_node **rb_link, *rb_parent;
  unsigned long charged = 0;

  //printk(KERN_ERR "@objms_omap_region: addr=%lx, len=%lu, pgoff=%lu, objsize=%lu\n",
  //    addr, len, pgoff, pi->i_size);
  //check against address space limit
  if (!may_expand_vm(mm, len >> PAGE_SHIFT)){
    unsigned long nr_pages;

    //MAP_FIXED may remove pages of mappings that intersects with
    //requested mapping. Account for the pages it would unmap
    if (!(vm_flags & MAP_FIXED)){
      return -ENOMEM;
    }

    nr_pages = count_vma_pages_range(mm, addr, addr + len);
    if (!may_expand_vm(mm, (len >> PAGE_SHIFT) - nr_pages)){
      return -ENOMEM;
    }
  }

  //clear old maps
munmap_back:
  if (find_vma_links(mm, addr, addr + len, &prev, &rb_link, &rb_parent)){
    if (do_munmap(mm, addr, len)){
      return -ENOMEM;
    }
    goto munmap_back;
  }

  if ((vm_flags & (VM_NORESERVE | VM_SHARED | VM_WRITE)) == VM_WRITE){
    charged = len >> PAGE_SHIFT;
    if (security_vm_enough_memory_mm(mm, charged)){
      return -ENOMEM;
    }
    vm_flags |= VM_ACCOUNT;
  }

  //can we just expand an old mapping?
  vma = vma_merge(mm, prev, addr, addr + len, vm_flags,
      NULL, NULL, pgoff, NULL, NULL_VM_UFFD_CTX);
  if (vma){
    goto out;
  }

  //determine the object being mapped and call the mapper
  vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
  if (!vma){
    error = -ENOMEM;
    goto unacct_error;
  }

  vma->vm_mm = mm;
  vma->vm_start = addr;
  vma->vm_end = addr + len;
  vma->vm_flags = vm_flags;
  vma->vm_page_prot = vm_get_page_prot(vm_flags);
  vma->vm_pgoff = pgoff;
  INIT_LIST_HEAD(&vma->anon_vma_chain);

  error = -EINVAL;  //when rejecting VM_GROWSDOWN | VM_GROWSUP

  //if (inode){
  //TODO: maybe we should increase inode's reference count?
  vma->vm_file = (struct file *)pi;//FIXME: store the object's inode->pi in vma->vm_file;
  //vma->vm_object = (void *)pi;//FIXME: store the object's inode->pi in vma->vm_object;
  //@ayu: hugemmap
  if (objms_has_huge_mmap()
      && (vma->vm_flags & VM_SHARED)
      && (pi->i_blk_type == OBJMS_BLOCK_TYPE_2M
        || pi->i_blk_type == OBJMS_BLOCK_TYPE_1G)){
    vma->vm_flags |= VM_OBJMS_HUGETLB;//FIXME
    vma->vm_ops = &objms_obj_hpage_vm_ops;
    //printk(KERN_ERR "@objms_omap: huge_mmap\n");
  } else {
    vma->vm_ops = &objms_obj_vm_ops;//connect the objms page fault handler with vma
    //printk(KERN_ERR "@objms_omap: mmap\n");
  }
  vma->vm_flags |= VM_MIXEDMAP;
  vm_flags = vma->vm_flags;

  //vma_link(mm, vma, prev, rb_link, rb_parent);
	__vma_link_list(mm, vma, prev, rb_parent);
	__vma_link_rb(mm, vma, rb_link, rb_parent);
	mm->map_count++;

out:
  perf_event_mmap(vma);
  vm_stat_account(mm, vm_flags, NULL, len >> PAGE_SHIFT);
  if (vm_flags & VM_LOCKED){
    if (!((vm_flags & VM_SPECIAL) || is_vm_hugetlb_page(vma)
          || vma == get_gate_vma(current->mm))){
      mm->locked_vm += (len >> PAGE_SHIFT);
    } else {
      vma->vm_flags &= ~VM_LOCKED;
    }
  }

  return addr;

//free_vma:
  kmem_cache_free(vm_area_cachep, vma);
unacct_error:
  if (charged){
    vm_unacct_memory(charged);
  }
  return error;
}

//copy from sys_mmap_pgoff
//flags is MAP_ANONYMOUS because there's no connection with file
//pgoff is the offset in page count
SYSCALL_DEFINE6(objms_omap, unsigned long, addr, unsigned long, len,
			unsigned long, prot, unsigned long, flags,
			unsigned long, objno, unsigned long, offset){
  //FIXME: should support MAP_HUGETLB
  struct mm_struct *mm = current->mm;
  vm_flags_t vm_flags;
  unsigned long ino = objno << OBJMS_INODE_BITS;
  struct objms_inode_info *inode;
  struct objms_inode *pi;
  unsigned long pgoff = offset >> PAGE_SHIFT;

  flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);

  //printk(KERN_ERR "@objms_omap: objno=%lu, addr=%lx,len=%d\n", objno, addr, len);
  inode = objms_iget(ino);
  if (!inode){
    //printk("@objms_omap: objms_iget failed\n");
    return -EINVAL;
  }
  pi = inode->pi;

  down_write(&mm->mmap_sem);

  if (!len){
    addr = -EINVAL;
    goto out;
  }

  if (!(flags & MAP_FIXED)){
    addr = round_hint_to_min(addr);
  }

  //careful about overflows
  len = PAGE_ALIGN(len);
  if (!len){
    addr = -ENOMEM;
    goto out;
  }

  //offset overflow?
  if ((pgoff + (len >> PAGE_SHIFT)) < pgoff){
    addr = -EOVERFLOW;
    goto out;
  }

  //too many mappings?
  if (mm->map_count > sysctl_max_map_count){
    addr = -ENOMEM;
    goto out;
  }

  //obtain the address to map to
  addr = objms_get_unmapped_area(pi, addr, len, pgoff, flags);
  if (addr & ~PAGE_MASK){
    goto out;
  }

  //do simple checking here so the lower-level routines won't have to
  vm_flags = calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags)
    | mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

  if (flags & MAP_LOCKED){
    if (!can_do_mlock()){
      addr = -EPERM;
      goto out;
    }
  }

  //mlock MCL_FUTURE?
  if (vm_flags & VM_LOCKED){
    unsigned long locked, lock_limit;
    locked = len >> PAGE_SHIFT;
    locked += mm->locked_vm;
    lock_limit = rlimit(RLIMIT_MEMLOCK);
    lock_limit >>= PAGE_SHIFT;
    if (locked > lock_limit && !capable(CAP_IPC_LOCK)){
      addr = -EAGAIN;
      goto out;
    }
  }

  switch (flags & MAP_TYPE){
    case MAP_SHARED:
      vm_flags |= VM_SHARED | VM_MAYSHARE;
      //fall through
    case MAP_PRIVATE:
      if (vm_flags & (VM_GROWSDOWN | VM_GROWSUP)){
        addr = -EINVAL;
        goto out;
      }
      break;
    default:
      addr = -EINVAL;
      goto out;
  }

  vm_flags |= VM_BPM;

  if (flags & MAP_NORESERVE){
    //we honor MAP_NORESERVE if allowed to overcommit
    if (sysctl_overcommit_memory != OVERCOMMIT_NEVER){
      vm_flags |= VM_NORESERVE;
    }
  }

  addr = objms_omap_region(pi, addr, len, vm_flags, pgoff);

out:
  up_write(&mm->mmap_sem);
  objms_iput(NULL, inode);
  return addr;
}

/*
 * Close a vm structure and free it, returning the next.
 */
static struct vm_area_struct *remove_vma(struct vm_area_struct *vma)
{
	struct vm_area_struct *next = vma->vm_next;

	might_sleep();
	if (vma->vm_ops && vma->vm_ops->close)
		vma->vm_ops->close(vma);
	//if (vma->vm_file)
	//	fput(vma->vm_file);
  mpol_put(vma_policy(vma));
	kmem_cache_free(vm_area_cachep, vma);
	return next;
}

static long vma_compute_subtree_gap(struct vm_area_struct *vma)
{
	unsigned long max, subtree_gap;
	max = vma->vm_start;
	if (vma->vm_prev)
		max -= vma->vm_prev->vm_end;
	if (vma->vm_rb.rb_left) {
		subtree_gap = rb_entry(vma->vm_rb.rb_left,
				struct vm_area_struct, vm_rb)->rb_subtree_gap;
		if (subtree_gap > max)
			max = subtree_gap;
	}
	if (vma->vm_rb.rb_right) {
		subtree_gap = rb_entry(vma->vm_rb.rb_right,
				struct vm_area_struct, vm_rb)->rb_subtree_gap;
		if (subtree_gap > max)
			max = subtree_gap;
	}
	return max;
}
RB_DECLARE_CALLBACKS(static, vma_gap_callbacks, struct vm_area_struct, vm_rb,
		     unsigned long, rb_subtree_gap, vma_compute_subtree_gap)

/*
 * Update augmented rbtree rb_subtree_gap values after vma->vm_start or
 * vma->vm_prev->vm_end values changed, without modifying the vma's position
 * in the rbtree.
 */
static void vma_gap_update(struct vm_area_struct *vma)
{
	/*
	 * As it turns out, RB_DECLARE_CALLBACKS() already created a callback
	 * function that does exacltly what we want.
	 */
	vma_gap_callbacks_propagate(&vma->vm_rb, NULL);
}

static void vma_rb_erase(struct vm_area_struct *vma, struct rb_root *root)
{
	/*
	 * All rb_subtree_gap values must be consistent prior to erase,
	 * with the possible exception of the vma being erased.
	 */
	validate_mm_rb(root, vma);

	/*
	 * Note rb_erase_augmented is a fairly large inline function,
	 * so make sure we instantiate it only once with our desired
	 * augmented rbtree callbacks.
	 */
	rb_erase_augmented(&vma->vm_rb, root, &vma_gap_callbacks);
}

/*
 * Ok - we have the memory areas we should free on the vma list,
 * so release them, and do the vma updates.
 *
 * Called with the mm semaphore held.
 */
static void remove_vma_list(struct mm_struct *mm, struct vm_area_struct *vma)
{
	unsigned long nr_accounted = 0;

	/* Update high watermark before we lower total_vm */
	update_hiwater_vm(mm);
	do {
		long nrpages = vma_pages(vma);

		if (vma->vm_flags & VM_ACCOUNT)
			nr_accounted += nrpages;
		vm_stat_account(mm, vma->vm_flags, vma->vm_file, -nrpages);
		vma = remove_vma(vma);
	} while (vma);
	vm_unacct_memory(nr_accounted);
	validate_mm(mm);
}

/*
 * Get rid of page table information in the indicated region.
 *
 * Called with the mm semaphore held.
 */
static void objms_unmap_region(struct mm_struct *mm,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		unsigned long start, unsigned long end)
{
	struct vm_area_struct *next = prev? prev->vm_next: mm->mmap;
	struct mmu_gather tlb;

	lru_add_drain();
	tlb_gather_mmu(&tlb, mm, start, end);
	update_hiwater_rss(mm);
	unmap_vmas(&tlb, vma, start, end);
	free_pgtables(&tlb, vma, prev ? prev->vm_end : FIRST_USER_ADDRESS,
				 next ? next->vm_start : USER_PGTABLES_CEILING);
	tlb_finish_mmu(&tlb, start, end);
}

/*
 * Create a list of vma's touched by the unmap, removing them from the mm's
 * vma list as we go..
 */
static void
detach_vmas_to_be_unmapped(struct mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, unsigned long end)
{
	struct vm_area_struct **insertion_point;
	struct vm_area_struct *tail_vma = NULL;

	insertion_point = (prev ? &prev->vm_next : &mm->mmap);
	vma->vm_prev = NULL;
	do {
		vma_rb_erase(vma, &mm->mm_rb);
		mm->map_count--;
		tail_vma = vma;
    tail_vma->vm_file = NULL;//this is important
		vma = vma->vm_next;
	} while (vma && vma->vm_start < end);
	*insertion_point = vma;
	if (vma) {
		vma->vm_prev = prev;
		vma_gap_update(vma);
	} else
		mm->highest_vm_end = prev ? prev->vm_end : 0;
	tail_vma->vm_next = NULL;
  
	vmacache_invalidate(mm);		/* Kill the cache. */
}

/*
 * __split_vma() bypasses sysctl_max_map_count checking.  We use this on the
 * munmap path where it doesn't make sense to fail.
 */
static int __split_vma(struct mm_struct * mm, struct vm_area_struct * vma,
	      unsigned long addr, int new_below)
{
	struct mempolicy *pol;
	struct vm_area_struct *new;
	int err = -ENOMEM;

	if (is_vm_hugetlb_page(vma) && (addr &
					~(huge_page_mask(hstate_vma(vma)))))
		return -EINVAL;

	new = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
	if (!new)
		goto out_err;

	/* most fields are the same, copy all, and then fixup */
	*new = *vma;

	INIT_LIST_HEAD(&new->anon_vma_chain);

	if (new_below)
		new->vm_end = addr;
	else {
		new->vm_start = addr;
		new->vm_pgoff += ((addr - vma->vm_start) >> PAGE_SHIFT);
	}

  err = vma_dup_policy(vma, new);
  if (err){
    goto out_free_vma;
  }

	if (anon_vma_clone(new, vma))
		goto out_free_mpol;

	if (new->vm_file){
		get_file(new->vm_file);
  }

	if (new->vm_ops && new->vm_ops->open)
		new->vm_ops->open(new);

	if (new_below)
		err = vma_adjust(vma, addr, vma->vm_end, vma->vm_pgoff +
			((addr - new->vm_start) >> PAGE_SHIFT), new);
	else
		err = vma_adjust(vma, vma->vm_start, addr, vma->vm_pgoff, new);

	/* Success. */
	if (!err)
		return 0;

	/* Clean everything up if vma_adjust failed. */
	if (new->vm_ops && new->vm_ops->close)
		new->vm_ops->close(new);
	if (new->vm_file)
		fput(new->vm_file);
	unlink_anon_vmas(new);
 out_free_mpol:
	mpol_put(pol);
 out_free_vma:
	kmem_cache_free(vm_area_cachep, new);
 out_err:
	return err;
}
//FIXME: unfinished
SYSCALL_DEFINE2(objms_ounmap, unsigned long, addr, size_t, len){
  int ret;
  unsigned long end;
  struct vm_area_struct *vma, *prev, *last;
  struct mm_struct *mm = current->mm;

  printk(KERN_ERR "@objms_ounmap: addr=%lx,len=%lu\n", addr, len);
  profile_munmap(addr);
  down_write(&mm->mmap_sem);
  
  if ((addr & ~PAGE_MASK) || addr > TASK_SIZE || len > TASK_SIZE - addr){
    ret = -EINVAL;
    goto out;
  }

  if ((len = PAGE_ALIGN(len)) == 0){
    ret = -EINVAL;
    goto out;
  }
  //find the first overlapping VMA
  vma = find_vma(mm, addr);
  if (!vma){
    ret = 0;
    goto out;
  }
  prev = vma->vm_prev;
  //we have addr < vma->vm_end

  //if it doesn't overlap, we have nothing
  end = addr + len;
  if (vma->vm_start >= end){
    ret = 0;
    goto out;
  }

  //if we need to split any vma, do it now to save pain later
  if (addr > vma->vm_start){
    int error;

    //make sure that map_count on return from munmap() will not exceed its limit
    if (end < vma->vm_end
        && mm->map_count >= sysctl_max_map_count){
      ret = -ENOMEM;
      goto out;
    }

    error = __split_vma(mm, vma, addr, 0);
    if (error){
      ret = error;
      goto out;
    }
    prev = vma;
  }

  //does it split the last one?
  last = find_vma(mm, end);
  if (last && end > last->vm_start){
    int error = __split_vma(mm, last, end, 1);
    if (error){
      ret = error;
      goto out;
    }
  }
  vma = prev? prev->vm_next: mm->mmap;

  //unlock any mlock()ed ranges before detaching vmas
  if (mm->locked_vm){
    struct vm_area_struct *tmp = vma;
    while (tmp && tmp->vm_start < end){
      if (tmp->vm_flags & VM_LOCKED){
        mm->locked_vm -= vma_pages(tmp);
        munlock_vma_pages_all(tmp);
      }
      tmp = tmp->vm_next;
    }
  }
  
  //FIXME: put the inode
  //maybe we should call objms_iput()?
  if (vma->vm_file){
    /*
    struct objms_inode_info *inode = (struct objms_inode_info *)vma->vm_file;
    objms_iput(inode);*/
    vma->vm_file = NULL;
  }

  //remove the vma's, and unmap the actual pages
  detach_vmas_to_be_unmapped(mm, vma, prev, end);
  objms_unmap_region(mm, vma, prev, addr, end);

  //fix up all other VM information
  remove_vma_list(mm, vma);
  ret = 0;

out:
  up_write(&mm->mmap_sem);
  return ret;
}
