/*
 *  First Class Virtual Address Spaces
 *  Copyright (c) 2016-2017, Hewlett Packard Enterprise
 *
 *  Code Authors:
 *     Marco A Benatto <marco.antonio.780@gmail.com>
 *     Till Smejkal <till.smejkal@gmail.com>
 */


#include <linux/vas.h>

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmu_context.h>
#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/rmap.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>
#include <linux/vmacache.h>

#include <asm/mman.h>
#include <asm/processor.h>

#include "internal.h"


/***
 * Internally used defines and macros
 ***/

/*
 * Make sure we are not overflowing the VAS sharing variable.
 */
#define VAS_MAX_SHARES U16_MAX

#define VAS_MAX_ID INT_MAX

/*
 * Masks and bits to implement sharing of VAS.
 */
#define VAS_SHARE_READABLE (1 << 0)
#define VAS_SHARE_WRITABLE (1 << 16)
#define VAS_SHARE_READ_MASK 0xffff
#define VAS_SHARE_WRITE_MASK 0xffff0000
#define VAS_SHARE_READ_WRITE_MASK (VAS_SHARE_READ_MASK | VAS_SHARE_WRITE_MASK)

/**
 * next_vma_safe() - Get the next vm_area of the VMA list in the memory map
 *		     safely.
 * @vma: The pointer to the vm_area we are currently at.
 *
 * Return: The pointer to next vm_area if any, NULL otherwise.
 */
#define next_vma_safe(vma) ((vma) ? (vma)->vm_next : NULL)

/**
 * access_type_str() - Get a string representation of the access type to a VAS.
 * @type: The access type to the VAS (rw/wo/ro).
 *
 * Return: A string representation of the given access type.
 */
#define access_type_str(type) ((type) & MAY_WRITE ?			\
			       ((type) & MAY_READ ? "rw" : "wo") : "ro")


/***
 * Debugging functions
 ***/

#ifdef CONFIG_VAS_DEBUG

/**
 * __dump_memory_map() - Dump the content of the given memory map.
 * @mm: The memory map which should be dumped.
 *
 * This function will acquire the semaphore of the memory map in read-mode.
 * Accordingly, if the memory map is already locked when this function is
 * called, this will produce a deadlock.
 */
static void __dump_memory_map(const char *title, struct mm_struct *mm)
{
	int count;
	struct vm_area_struct *vma;

	down_read(&mm->mmap_sem);

	/* Dump some general information. */
	pr_info("-- %s [%p] --\n"
		"> General information <\n"
		"  PGD value: %#lx\n"
		"  Task size: %#lx\n"
		"  Map count: %d\n"
		"  Last update: %lld\n"
		"  Code:  %#lx - %#lx\n"
		"  Data:  %#lx - %#lx\n"
		"  Heap:  %#lx - %#lx\n"
		"  Stack: %#lx\n"
		"  Args:  %#lx - %#lx\n"
		"  Env:   %#lx - %#lx\n",
		title, mm, pgd_val(*mm->pgd), mm->task_size, mm->map_count,
		mm->vas_last_update, mm->start_code, mm->end_code,
		mm->start_data, mm->end_data, mm->start_brk, mm->brk,
		mm->start_stack, mm->arg_start, mm->arg_end, mm->env_start,
		mm->env_end);

	/* Dump current RSS state counters of the memory map. */
	pr_cont("> RSS Counter <\n");
	for (count = 0; count < NR_MM_COUNTERS; ++count)
		pr_cont(" %d: %lu\n", count, get_mm_counter(mm, count));

	/* Dump the information for each region. */
	pr_cont("> Mapped Regions <\n");
	for (vma = mm->mmap, count = 0; vma; vma = vma->vm_next, ++count) {
		pr_cont("  VMA %3d: %#14lx - %#-14lx", count, vma->vm_start,
			vma->vm_end);

		if (is_exec_mapping(vma->vm_flags))
			pr_cont(" EXEC  ");
		else if (is_data_mapping(vma->vm_flags))
			pr_cont(" DATA  ");
		else if (is_stack_mapping(vma->vm_flags))
			pr_cont(" STACK ");
		else
			pr_cont(" OTHER ");

		pr_cont("%c%c%c%c [%c]",
			vma->vm_flags & VM_READ ? 'r' : '-',
			vma->vm_flags & VM_WRITE ? 'w' : '-',
			vma->vm_flags & VM_EXEC ? 'x' : '-',
			vma->vm_flags & VM_MAYSHARE ? 's' : 'p',
			vma->vas_reference ? 'v' : '-');

		if (vma->vm_file) {
			struct file *f = vma->vm_file;
			char *buf;

			buf = kmalloc(PATH_MAX, GFP_TEMPORARY);
			if (buf) {
				char *p;

				p = file_path(f, buf, PATH_MAX);
				if (IS_ERR(p))
					p = "?";

				pr_cont(" --> %s @%lu\n", p, vma->vm_pgoff);
				kfree(buf);
			} else {
				pr_cont(" --> NA @%lu\n", vma->vm_pgoff);
			}
		} else if (vma->vm_ops && vma->vm_ops->name) {
			pr_cont(" --> %s\n", vma->vm_ops->name(vma));
		} else {
			pr_cont(" ANON\n");
		}
	}
	if (count == 0)
		pr_cont("  EMPTY\n");

	up_read(&mm->mmap_sem);
}

#define pr_vas_debug(fmt, args...) pr_info("[VAS] %s - " fmt, __func__, ##args)
#define dump_memory_map(title, mm) __dump_memory_map(title, mm)

#else /* CONFIG_VAS_DEBUG */

#define pr_vas_debug(...) do {} while (0)
#define dump_memory_map(...) do {} while (0)

#endif /* CONFIG_VAS_DEBUG */

/***
 * Internally used variables
 ***/

/*
 * All SLAB caches used to improve allocation performance.
 */
static struct kmem_cache *vas_cachep;
static struct kmem_cache *att_vas_cachep;
static struct kmem_cache *vas_context_cachep;

/*
 * Global management data structures and their associated locks.
 */
static struct idr vases;
static spinlock_t vases_lock;

/*
 * The place holder variables that are used to identify to-be-deleted items in
 * our global management data structures.
 */
static struct vas *INVALID_VAS;

/*
 * Kernel 'ksets' where all objects will be managed.
 */
static struct kset *vases_kset;


/***
 * Constructors and destructors for the data structures.
 ***/
static inline struct vm_area_struct *new_vm_area(void)
{
	return kmem_cache_zalloc(vm_area_cachep, GFP_ATOMIC);
}

static inline void delete_vm_area(struct vm_area_struct *vma)
{
	kmem_cache_free(vm_area_cachep, vma);
}

static inline struct vas *new_vas(void)
{
	return kmem_cache_zalloc(vas_cachep, GFP_KERNEL);
}

static inline void delete_vas(struct vas *vas)
{
	WARN_ON(vas->att_count != 0);

	mutex_destroy(&vas->mtx);

	if (vas->mm)
		mmput_async(vas->mm);
	kmem_cache_free(vas_cachep, vas);
}

static inline void delete_vas_rcu(struct rcu_head *rp)
{
	struct vas *vas = container_of(rp, struct vas, rcu);

	delete_vas(vas);
}

static inline struct att_vas *new_att_vas(void)
{
	return kmem_cache_zalloc(att_vas_cachep, GFP_ATOMIC);
}

static inline void delete_att_vas(struct att_vas *avas)
{
	if (avas->mm)
		mmput_async(avas->mm);
	kmem_cache_free(att_vas_cachep, avas);
}

static inline struct vas_context *new_vas_context(void)
{
	return kmem_cache_zalloc(vas_context_cachep, GFP_KERNEL);
}

static inline void delete_vas_context(struct vas_context *ctx)
{
	WARN_ON(ctx->refcount != 0);

	kmem_cache_free(vas_context_cachep, ctx);
}

/***
 * Kobject management of data structures
 ***/

/**
 * __vas_get() - Increase the reference counter of a VAS data structure.
 * @vas: The VAS data structure for which the reference counter should be
 *	 increased.
 *
 * Return: The pointer to the VAS data structure with increased reference
 *	   counter on success, NULL otherwise.
 */
static inline struct vas *__vas_get(struct vas *vas)
{
	return container_of(kobject_get(&vas->kobj), struct vas, kobj);
}

/**
 * __vas_put() - Decrease the reference counter of a VAS data structure.
 * @vas: The VAS data structure for which the reference counter should be
 *	 decreased.
 *
 * After the call to this function, the given VAS data structure must not be
 * used anymore.
 */
static inline void __vas_put(struct vas *vas)
{
	kobject_put(&vas->kobj);
}

/*
 * The attribute structure to handle sysfs attributes of a VAS.
 */
struct vas_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct vas *vas, struct vas_sysfs_attr *vsattr,
			char *buf);
	ssize_t (*store)(struct vas *vas, struct vas_sysfs_attr *vsattr,
			 const char *buf, size_t count);
};

#define VAS_SYSFS_ATTR(NAME, MODE, SHOW, STORE)				\
static struct vas_sysfs_attr vas_sysfs_attr_##NAME =			\
	__ATTR(NAME, MODE, SHOW, STORE)

/*
 * Sysfs operations of a VAS.
 */
static ssize_t vas_sysfs_attr_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct vas *vas;
	struct vas_sysfs_attr *vsattr;

	vas = container_of(kobj, struct vas, kobj);
	vsattr = container_of(attr, struct vas_sysfs_attr, attr);

	if (!vsattr->show)
		return -EIO;

	return vsattr->show(vas, vsattr, buf);
}

static ssize_t vas_sysfs_attr_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buf, size_t count)
{
	struct vas *vas;
	struct vas_sysfs_attr *vsattr;

	vas = container_of(kobj, struct vas, kobj);
	vsattr = container_of(attr, struct vas_sysfs_attr, attr);

	if (!vsattr->store)
		return -EIO;

	return vsattr->store(vas, vsattr, buf, count);
}

static const struct sysfs_ops vas_sysfs_ops = {
	.show = vas_sysfs_attr_show,
	.store = vas_sysfs_attr_store,
};

/*
 * Default attributes of a VAS.
 */
static ssize_t show_vas_name(struct vas *vas, struct vas_sysfs_attr *vsattr,
			       char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s", vas->name);
}
VAS_SYSFS_ATTR(name, 0444, show_vas_name, NULL);

static ssize_t show_vas_mode(struct vas *vas, struct vas_sysfs_attr *vsattr,
			       char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%#03o", vas->mode);
}
VAS_SYSFS_ATTR(mode, 0444, show_vas_mode, NULL);

static ssize_t show_vas_user(struct vas *vas, struct vas_sysfs_attr *vsattr,
			       char *buf)
{
	struct user_namespace *ns = current_user_ns();

	return scnprintf(buf, PAGE_SIZE, "%d", from_kuid(ns, vas->uid));
}
VAS_SYSFS_ATTR(user, 0444, show_vas_user, NULL);

static ssize_t show_vas_group(struct vas *vas, struct vas_sysfs_attr *vsattr,
				char *buf)
{
	struct user_namespace *ns = current_user_ns();

	return scnprintf(buf, PAGE_SIZE, "%d", from_kgid(ns, vas->gid));
}
VAS_SYSFS_ATTR(group, 0444, show_vas_group, NULL);

static struct attribute *vas_default_attr[] = {
	&vas_sysfs_attr_name.attr,
	&vas_sysfs_attr_mode.attr,
	&vas_sysfs_attr_user.attr,
	&vas_sysfs_attr_group.attr,
	NULL
};

/**
 * vas_realease() - Properly free a VAS data structure after its kobject is
 *		    gone.
 * @kobj: The kobject that belonged to the corresponding VAS data structure.
 */
static void vas_release(struct kobject *kobj)
{
	struct vas *vas = container_of(kobj, struct vas, kobj);

	spin_lock(&vases_lock);
	idr_remove(&vases, vas->id);
	spin_unlock(&vases_lock);

	/*
	 * Wait for the full RCU grace period before actually deleting the VAS
	 * data structure since we haven't done it earlier.
	 */
	call_rcu(&vas->rcu, delete_vas_rcu);
}

/*
 * The ktype data structure representing a VAS.
 */
static struct kobj_type vas_ktype = {
	.sysfs_ops = &vas_sysfs_ops,
	.release = vas_release,
	.default_attrs = vas_default_attr,
};


/***
 * Internally visible functions
 ***/

/**
 * vas_remove() - Remove a VAS data structure from the global VAS list.
 * @vas: The VAS that should be removed.
 */
static void vas_remove(struct vas *vas)
{
	spin_lock(&vases_lock);

	/*
	 * Only put the to-be-deleted place holder in the IDR, the actual remove
	 * in the IDR and the freeing of the object  will be done when we
	 * release the kobject. We need to do it this way, to keep the ID
	 * reserved. Otherwise it can happen, that we try to create a new VAS
	 * with a reused ID in the sysfs before the current VAS is removed from
	 * the sysfs.
	 */
	idr_replace(&vases, INVALID_VAS, vas->id);
	spin_unlock(&vases_lock);

	/*
	 * No need to wait for the RCU period here, we will do it before
	 * actually deleting the VAS in the 'vas_release' function.
	 */
	__vas_put(vas);
}

/**
 * vas_insert() - Insert a VAS data structure in the global VAS list.
 * @vas: The VAS that should be inserted.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int vas_insert(struct vas *vas)
{
	int ret;

	/* Add the VAS in the IDR cache. */
	spin_lock(&vases_lock);

	ret = idr_alloc(&vases, vas, 1, VAS_MAX_ID, GFP_KERNEL);

	spin_unlock(&vases_lock);

	if (ret < 0) {
		delete_vas(vas);
		return ret;
	}

	/* Add the last data to the VAS' data structure. */
	vas->id = ret;
	vas->kobj.kset = vases_kset;

	/* Initialize the kobject and add it to the sysfs. */
	ret = kobject_init_and_add(&vas->kobj, &vas_ktype, NULL, "%d", vas->id);
	if (ret != 0) {
		vas_remove(vas);
		return ret;
	}

	/* The VAS is ready, trigger the corresponding UEVENT. */
	kobject_uevent(&vas->kobj, KOBJ_ADD);

	/*
	 * We don't put or get the VAS again, because its reference count will
	 * be initialized with '1'. This will be reduced to 0 when we remove the
	 * VAS again from the internal global management list.
	 */
	return 0;
}

/**
 * vas_lookup() - Lookup the VAS data structure with the given ID.
 * @id: The ID of the VAS of interest.
 *
 * This function will increase the reference counter of the found VAS data
 * structure before returning. Hence, it is necessary to use vas_put() on the
 * returned pointer before leaving the scope where the pointer is valid.
 *
 * Return: The pointer to the VAS if found, NULL otherwise.
 */
static struct vas *vas_lookup(int id)
{
	struct vas *vas;

	rcu_read_lock();

	vas = idr_find(&vases, id);
	if (vas == INVALID_VAS)
		vas = NULL;
	if (vas)
		vas = __vas_get(vas);

	rcu_read_unlock();

	return vas;
}

/**
 * vas_lookup_by_name() - Lookup the VAS data structure with the given name.
 * @name: The name of the VAS of interest.
 *
 * This function will increase the reference counter of the found VAS data
 * structure before returning. Hence, it is necessary to use vas_put() on the
 * returned pointer before leaving the scope where the pointer is valid.
 *
 * Return: The pointer to the VAS if found, NULL otherwise.
 */
static struct vas *vas_lookup_by_name(const char *name)
{
	struct vas *vas;
	int id;

	rcu_read_lock();

	idr_for_each_entry(&vases, vas, id) {
		if (vas == INVALID_VAS)
			continue;

		if (strcmp(vas->name, name) == 0)
			break;
	}

	if (vas)
		vas = __vas_get(vas);

	rcu_read_unlock();

	return vas;
}

/**
 * vas_take_share() - Try to acquire a sharing of a VAS with the given type.
 * @type: The type of sharing (rw/wo/ro).
 * @vas: The VAS for which a sharing should be acquired.
 *
 * Return: 0 on success, -1 otherwise.
 */
static int vas_take_share(int type, struct vas *vas)
{
	int ret;

	spin_lock(&vas->share_lock);
	if (type & MAY_WRITE) {
		if ((vas->sharing & VAS_SHARE_READ_WRITE_MASK) == 0) {
			vas->sharing += VAS_SHARE_WRITABLE;
			ret = 1;
		} else
			ret = 0;
	} else {
		if ((vas->sharing & VAS_SHARE_WRITE_MASK) == 0) {
			vas->sharing += VAS_SHARE_READABLE;
			ret = 1;
		} else
			ret = 0;
	}
	spin_unlock(&vas->share_lock);

	return ret;
}

/**
 * vas_take_share() - Release a sharing of a VAS with the given type.
 * @type: The type of the sharing (rw/wo/ro).
 * @vas: The VAS for which the sharing should be released.
 */
static void vas_put_share(int type, struct vas *vas)
{
	spin_lock(&vas->share_lock);
	if (type & MAY_WRITE)
		vas->sharing -= VAS_SHARE_WRITABLE;
	else
		vas->sharing -= VAS_SHARE_READABLE;
	spin_unlock(&vas->share_lock);
}

/**
 * init_vas_mm() - Initialize the memory map of a new VAS.
 * @vas: The VAS for which the memory map should be initialized.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int init_vas_mm(struct vas *vas)
{
	struct mm_struct *mm;

	mm = mm_allocate();
	if (!mm)
		return -ENOMEM;

	mm = mm_setup(mm);
	if (!mm)
		return -ENOMEM;

	arch_pick_mmap_layout(mm);

	vas->mm = mm;
	return 0;
}

/**
 * init_att_vas_mm() - Initialize the memory map of a new attached-VAS.
 * @avas: The attached-VAS for which the memory map should be initialized.
 * @owner: The task to which the attached-VAS belongs.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int init_att_vas_mm(struct att_vas *avas, struct task_struct *owner)
{
	struct mm_struct *mm, *orig_mm = owner->original_mm;

	mm = mm_allocate();
	if (!mm)
		return -ENOMEM;

	mm = mm_setup(mm);
	if (!mm)
		return -ENOMEM;

	mm = mm_set_task(mm, owner, orig_mm->user_ns);
	if (!mm)
		return -ENOMEM;

	arch_pick_mmap_layout(mm);

	/* Additional setup of the memory map. */
	set_mm_exe_file(mm, get_mm_exe_file(orig_mm));
	mm->vas_last_update = orig_mm->vas_last_update;

	avas->mm = mm;
	return 0;
}

/**
 * vas_find_reference() - Lookup the corresponding vm_area in the referenced
 *			  memory map.
 * @mm: The referenced memory map.
 * @vma: The vm_area to which the corresponding one should be find.
 *
 * The function is very similar to find_exact_vma(). However, it can also handle
 * cases where a VMA was resized while the referenced one wasn't or visa-versa.
 *
 * This function requires that the semaphore of the referenced memory map is
 * taken in read-mode.
 *
 * Return: The pointer to the corresponding vm_area on success, NULL otherwise.
 */
static struct vm_area_struct *vas_find_reference(struct mm_struct *mm,
						 struct vm_area_struct *vma)
{
	struct vm_area_struct *ref;

	ref = find_vma(mm, vma->vm_start);
	if (ref) {
		/*
		 * Ok we found VMA in the other memory map. So lets check
		 * whether this is really the VMA we are referencing to.
		 */
		if (ref->vm_start == vma->vm_start &&
		    ref->vm_end == vma->vm_end)
			/* This is an exact match. */
			return ref;

		if (ref->vm_start != vma->vm_start &&
		    ref->vm_end == vma->vm_end &&
		    vma->vm_flags & VM_GROWSDOWN)
			/* This might be the stack VMA. */
			return ref;
	}

	return NULL;
}

/**
 * build_vas_access_type() - Translate a bit field with O_* bits into a fs-like
 *			     bit field with MAY_* bits.
 * @acc_type: The bit field that should be converted.
 *
 * Return: The converted bit field on success, -1 otherwise.
 */
static inline int build_vas_access_type(int acc_type)
{
	/* We are only interested in access modes. */
	acc_type &= O_ACCMODE;

	if (acc_type == O_RDONLY)
		return MAY_READ;
	else if (acc_type == O_WRONLY)
		return MAY_WRITE;
	else if (acc_type == O_RDWR)
		return MAY_READ | MAY_WRITE;

	return -1;
}

/**
 * check_permission() - Check whether the requested access type is allowed with
 *			the given permissions.
 * @uid: The UID of the owning user.
 * @gid: The GID of the owning group.
 * @mode: The object's access permissions.
 * @type: The requested access type.
 *
 * Return: 0 if the access is valid, -ERRNO otherwise.
 */
static int check_permission(kuid_t uid, kgid_t gid, umode_t mode, int type)
{
	kuid_t cur_uid = current_uid();

	/* root can do anything with a VAS. */
	if (unlikely(uid_eq(cur_uid, GLOBAL_ROOT_UID)))
		return 0;

	if (likely(uid_eq(cur_uid, uid)))
		mode >>= 6;
	else if (in_group_p(gid))
		mode >>= 3;

	if ((type & ~mode & (MAY_READ | MAY_WRITE)) == 0)
		return 0;
	return -EACCES;
}

/**
 * copy_vm_area() - Copy a vm_area from one memory map into another one.
 * @src_mm: The memory map to which the vm_area belongs that should be copied.
 * @src_vma: The vm_area that should be copied.
 * @dst_mm: The memory map to which the vm_area should be copied.
 * @vm_flags: The vm_flags that should be used for the new vm_area.
 *
 * This function requires that the semaphores of the destination memory maps is
 * taken in write-mode and the one of the source memory map at least in
 * read-mode.
 *
 * Return: A pointer to the new vm_area on success, NULL otherwise.
 */
static struct vm_area_struct *copy_vm_area(struct mm_struct *src_mm,
					   struct vm_area_struct *src_vma,
					   struct mm_struct *dst_mm,
					   unsigned long vm_flags)
{
	struct vm_area_struct *vma, *prev;
	struct rb_node **rb_link, *rb_parent;
	int ret;

	pr_vas_debug("Copying VMA - addr: %#lx - %#lx - to %p\n",
		     src_vma->vm_start, src_vma->vm_end, dst_mm);

	ret = find_vma_links(dst_mm, src_vma->vm_start, src_vma->vm_end,
			     &prev, &rb_link, &rb_parent);
	if (ret != 0) {
		pr_vas_debug("Could not map VMA in the new memory map because of a conflict with a different mapping\n");
		return NULL;
	}

	vma = new_vm_area();
	*vma = *src_vma;

	INIT_LIST_HEAD(&vma->anon_vma_chain);
	ret = vma_dup_policy(src_vma, vma);
	if (ret != 0)
		goto out_free_vma;
	ret = anon_vma_clone(vma, src_vma);
	if (ret != 0)
		goto out_free_vma;
	vma->vm_mm = dst_mm;
	vma->vm_flags = vm_flags;
	vma_set_page_prot(vma);
	vma->vm_next = vma->vm_prev = NULL;
	if (vma->vm_file)
		get_file(vma->vm_file);
	if (vma->vm_ops && vma->vm_ops->open)
		vma->vm_ops->open(vma);
	vma->vas_last_update = src_vma->vas_last_update;

	vma_link(dst_mm, vma, prev, rb_link, rb_parent);

	vm_stat_account(dst_mm, vma->vm_flags, vma_pages(vma));
	if (unlikely(dup_page_range(dst_mm, vma, src_mm, src_vma)))
		pr_vas_debug("Failed to copy page table for VMA %p from %p\n",
			     vma, src_vma);

	return vma;

out_free_vma:
	delete_vm_area(vma);
	return NULL;
}

/**
 * remove_vm_area() - Remove a vm_area from a given memory map.
 * @mm: The memory map from which the vm_area should be removed.
 * @vma: The vm_area that should be removed.
 *
 * This function requires that the semaphores of the memory map is taken in
 * write-mode.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int remove_vm_area(struct mm_struct *mm, struct vm_area_struct *vma)
{
	pr_vas_debug("Removing VMA - addr: %#lx - %#lx - from %p\n",
		     vma->vm_start, vma->vm_end, mm);

	return do_munmap(mm, vma->vm_start, vma->vm_end - vma->vm_start);
}

/**
 * update_vm_area() - Update the information of a vm_area in one particular
 *		      memory map with the information of the corresponding one
 *		      from another memory map.
 * @src_mm: The memory map to which the vm_area belongs from which the
 *	    information should be copied.
 * @src_vma: The vm_area from which the information should be copied.
 * @dst_mm: The memory map to which the vm_area belongs to which the
 *	    information should be copied.
 * @dst_vma: The vm_area that should be updated if already known. This argument
 *	     can be NULL if the corresponding vm_area in the destination memory
 *	     map is not yet know. It this case the destination vm_area will be
 *	     looked up in the destination memory map.
 *
 * This function requires that the semaphores of both memory maps are taken in 
 * write-mode.
 *
 * Return: A pointer to the updated vm_area on success, NULL otherwise.
 */
static struct vm_area_struct *update_vm_area(struct mm_struct *src_mm,
					     struct vm_area_struct *src_vma,
					     struct mm_struct *dst_mm,
					     struct vm_area_struct *dst_vma)
{
	pr_vas_debug("Updating VMA - addr: %#lx - %#lx - in %p\n",
		     src_vma->vm_start, src_vma->vm_end, dst_mm);

	/* Lookup the destination vm_area if not yet known. */
	if (!dst_vma)
		dst_vma = vas_find_reference(dst_mm, src_vma);

	if (!dst_vma) {
		pr_vas_debug("Cannot find corresponding memory region in destination memory map -- Abort\n");
		dst_vma = NULL;
	} else if (ktime_compare(src_vma->vas_last_update,
				 dst_vma->vas_last_update) == 0) {
		pr_vas_debug("Memory region is unchanged -- Skip\n");
	} else if (ktime_compare(src_vma->vas_last_update,
				 dst_vma->vas_last_update) == -1) {
		pr_vas_debug("Memory region is stale (%lld vs %lld)-- Abort\n",
			     src_vma->vas_last_update,
			     dst_vma->vas_last_update);
		dst_vma = NULL;
	} else if (src_vma->vm_start != dst_vma->vm_start ||
		   src_vma->vm_end != dst_vma->vm_end) {
		/*
		 * The VMA changed completely. We have to represent this change
		 * in the destination memory region.
		 */
		struct mm_struct *orig_vas_ref = dst_vma->vas_reference;
		unsigned long orig_vm_flags = dst_vma->vm_flags;

		if (remove_vm_area(dst_mm, dst_vma) != 0) {
			dst_vma = NULL;
			goto out;
		}

		dst_vma = copy_vm_area(src_mm, src_vma, dst_mm, orig_vm_flags);
		if (!dst_vma)
			goto out;

		dst_vma->vas_reference = orig_vas_ref;
	} else {
		/*
		 * The VMA itself did not change. However, mappings might have
		 * changed. So at least update the page table entries belonging
		 * to the VMA in the destination memory region.
		 */
		if (unlikely(dup_page_range(dst_mm, dst_vma, src_mm, src_vma)))
			pr_vas_debug("Cannot update page table entries\n");

		dst_vma->vas_last_update = src_vma->vas_last_update;
	}

out:
	return dst_vma;
}

/**
 * vas_merge() - Merge VAS related parts into an attached-VAS memory map.
 * @avas: The pointer to the attached-VAS data structure that contains all the
 *	  information for this attachment.
 * @vas: The pointer to the VAS that should be attached.
 * @type: The type of attaching (rw/wo/ro) -- see vas_attach() for more
 *	  information.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int vas_merge(struct att_vas *avas, struct vas *vas, int type)
{
	struct vm_area_struct *vma, *new_vma;
	struct mm_struct *vas_mm, *avas_mm;
	int ret;

	vas_mm = vas->mm;
	avas_mm = avas->mm;

	dump_memory_map("Before VAS MM", vas_mm);

	if (down_write_killable(&avas_mm->mmap_sem))
		return -EINTR;
	down_read_nested(&vas_mm->mmap_sem, SINGLE_DEPTH_NESTING);

	/* Try to copy all VMAs of the VAS into the AS of the attached-VAS. */
	for (vma = vas_mm->mmap; vma; vma = vma->vm_next) {
		unsigned long merged_vm_flags = vma->vm_flags;

		pr_vas_debug("Merging a VAS memory region (%#lx - %#lx)\n",
			     vma->vm_start, vma->vm_end);

		/*
		 * Remove the writable bit from the vm_flags if the VAS is
		 * attached only readable.
		 */
		if (!(type & MAY_WRITE))
			merged_vm_flags &= ~(VM_WRITE | VM_MAYWRITE);

		new_vma = copy_vm_area(vas_mm, vma, avas_mm, merged_vm_flags);
		if (!new_vma) {
			pr_vas_debug("Failed to merge a VAS memory region (%#lx - %#lx)\n",
				     vma->vm_start, vma->vm_end);
			ret = -EFAULT;
			goto out_unlock;
		}

		/*
		 * Remember for the VMA that we just added it to the
		 * attached-VAS that it actually belongs to the VAS.
		 */
		new_vma->vas_reference = vas_mm;
	}

	ret = 0;

out_unlock:
	up_read(&vas_mm->mmap_sem);
	up_write(&avas_mm->mmap_sem);

	dump_memory_map("After VAS MM", vas_mm);
	dump_memory_map("After Attached-VAS MM", avas_mm);

	return ret;
}

/**
 * vas_unmerge() - Unmerge VAS related parts from an attached-VAS memory map
 * @avas: The pointer to the attached-VAS data structure that contains all the
 *	  information for this attachment.
 * @vas: The pointer to the VAS that should be detached.
 *
 * This function not only removes the VAS related parts of the memory map from
 * the attached-VAS but also updates the corresponding mappings in the VAS'
 * memory map.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int vas_unmerge(struct att_vas *avas, struct vas *vas)
{
	struct vm_area_struct *vma, *next;
	struct mm_struct *vas_mm, *avas_mm;
	int ret;

	vas_mm = vas->mm;
	avas_mm = avas->mm;

	dump_memory_map("Before Attached-VAS MM", avas_mm);
	dump_memory_map("Before VAS MM", vas_mm);

	if (down_write_killable(&avas_mm->mmap_sem))
		return -EINTR;
	down_write_nested(&vas_mm->mmap_sem, SINGLE_DEPTH_NESTING);

	/* Update all VMAs of the VAS if they changed in the attached-VAS. */
	for (vma = avas_mm->mmap, next = next_vma_safe(vma); vma;
	     vma = next, next = next_vma_safe(next)) {
		struct mm_struct *ref_mm = vma->vas_reference;

		if (!ref_mm) {
			struct vm_area_struct *new_vma;

			/*
			 * This is a VMA which was created while the VAS was
			 * attached to the process and which is not yet existent
			 * in the VAS. Copy it into the VAS' mm_struct.
			 */
			pr_vas_debug("Unmerging a new VAS memory region (%#lx - %#lx)\n",
				     vma->vm_start, vma->vm_end);

			new_vma = copy_vm_area(avas_mm, vma, vas_mm,
					       vma->vm_flags);
			if (!new_vma) {
				pr_vas_debug("Failed to unmerge a new VAS memory region (%#lx - %#lx)\n",
					     vma->vm_start, vma->vm_end);
				ret = -EFAULT;
				goto out_unlock;
			}

			new_vma->vas_reference = NULL;
		} else {
			struct vm_area_struct *upd_vma;

			/*
			 * This VMA was previously copied into the memory map
			 * when the VAS was attached to the process. So check if
			 * we need to update the corresponding VMA in the VAS'
			 * memory map.
			 */
			pr_vas_debug("Unmerging an existing VAS memory region (%#lx - %#lx)\n",
				     vma->vm_start, vma->vm_end);

			upd_vma = update_vm_area(avas_mm, vma, vas_mm, NULL);
			if (!upd_vma) {
				pr_vas_debug("Failed to unmerge a VAS memory region (%#lx - %#lx)\n",
					     vma->vm_start, vma->vm_end);
				ret = -EFAULT;
				goto out_unlock;
			}
		}

		/* Remove the current VMA from the attached-VAS memory map. */
		remove_vm_area(avas_mm, vma);
	}

	ret = 0;

out_unlock:
	up_write(&vas_mm->mmap_sem);
	up_write(&avas_mm->mmap_sem);

	dump_memory_map("After VAS MM", vas_mm);

	return ret;
}

/**
 * task_merge() - Merge task related parts into an attached-VAS memory map.
 * @avas: The pointer to the attached-VAS data structure that contains all the
 *	  information for this attachment.
 * @tsk: The pointer to the task to which the VAS will be attached.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int task_merge(struct att_vas *avas, struct task_struct *tsk)
{
	struct vm_area_struct *vma, *new_vma;
	struct mm_struct *avas_mm, *tsk_mm;
	int ret;

	tsk_mm = tsk->original_mm;
	avas_mm = avas->mm;

	dump_memory_map("Before Task MM", tsk_mm);
	dump_memory_map("Before Attached-VAS MM", avas_mm);

	if (down_write_killable(&avas_mm->mmap_sem))
		return -EINTR;
	down_read_nested(&tsk_mm->mmap_sem, SINGLE_DEPTH_NESTING);

	/*
	 * Try to copy all necessary memory regions from the task's memory
	 * map to the attached-VAS memory map.
	 */
	for (vma = tsk_mm->mmap; vma; vma = vma->vm_next) {
		pr_vas_debug("Merging a task memory region (%#lx - %#lx)\n",
			     vma->vm_start, vma->vm_end);

		new_vma = copy_vm_area(tsk_mm, vma, avas_mm, vma->vm_flags);
		if (!new_vma) {
			pr_vas_debug("Failed to merge a task memory region (%#lx - %#lx)\n",
				     vma->vm_start, vma->vm_end);
			ret = -EFAULT;
			goto out_unlock;
		}

		/*
		 * Remember for the VMA that we just added it to the
		 * attached-VAS that it actually belongs to the task.
		 */
		new_vma->vas_reference = tsk_mm;
	}

	ret = 0;

out_unlock:
	up_read(&tsk_mm->mmap_sem);
	up_write(&avas_mm->mmap_sem);

	dump_memory_map("After Task MM", tsk_mm);
	dump_memory_map("After Attached-VAS MM", avas_mm);

	return ret;
}

/**
 * task_unmerge() - Unmerge task related parts from an attached-VAS memory map.
 * @avas: The pointer to the attached-VAS data structure that contains all the
 *	  information for this attachment.
 * @tsk: The pointer to the task to which the VAS was attached.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int task_unmerge(struct att_vas *avas, struct task_struct *tsk)
{
	struct vm_area_struct *vma, *next;
	struct mm_struct *avas_mm, *tsk_mm;

	tsk_mm = tsk->original_mm;
	avas_mm = avas->mm;

	dump_memory_map("Before Task MM", tsk_mm);
	dump_memory_map("Before Attached-VAS MM", avas_mm);

	if (down_write_killable(&avas_mm->mmap_sem))
		return -EINTR;

	/*
	 * Since we are always syncing with the task's memory map at every
	 * switch, unmerging the task's memory regions basically just means
	 * removing them.
	 */
	for (vma = avas_mm->mmap, next = next_vma_safe(vma); vma;
	     vma = next, next = next_vma_safe(next)) {
		struct mm_struct *ref_mm = vma->vas_reference;

		if (ref_mm != tsk_mm) {
			pr_vas_debug("Skipping memory region (%#lx - %#lx) during task unmerging\n",
				     vma->vm_start, vma->vm_end);
			continue;
		}

		pr_vas_debug("Unmerging a task memory region (%#lx - %#lx)\n",
			     vma->vm_start, vma->vm_end);

		/* Remove the current VMA from the attached-VAS memory map. */
		remove_vm_area(avas_mm, vma);
	}

	up_write(&avas_mm->mmap_sem);

	dump_memory_map("After Task MM", tsk_mm);
	dump_memory_map("After Attached-VAS MM", avas_mm);

	return 0;
}

/**
 * __vas_attach() - Attach a VAS to a task -- update internal information.
 * @avas: The pointer to the attached-VAS data structure containing all the
 *	  information of this attaching.
 * @tsk: The pointer to the task to which the VAS should be attached.
 * @vas: The pointer to the VAS which should be attached.
 *
 * This function requires that the VAS is already locked.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int __vas_attach(struct att_vas *avas, struct task_struct *tsk,
			struct vas *vas)
{
	int ret;

	/* Before doing anything, synchronize the RSS-stat of the task. */
	sync_mm_rss(tsk->mm);

	/*
	 * Try to acquire the VAS share with the proper type. This will ensure
	 * that the different sharing possibilities of VAS are respected.
	 */
	if (!vas_take_share(avas->type, vas)) {
		pr_vas_debug("VAS is already attached exclusively\n");
		return -EBUSY;
	}

	ret = vas_merge(avas, vas, avas->type);
	if (ret != 0)
		goto out_put_share;

	ret = task_merge(avas, tsk);
	if (ret != 0)
		goto out_put_share;

	vas->att_count++;

	return 0;

out_put_share:
	vas_put_share(avas->type, vas);
	return ret;
}

/**
 * __vas_detach() - Detach a VAS from a task -- update internal information.
 * @avas: The pointer to the attached-VAS data structure containing all the
 *	  information of this attaching.
 * @tsk: The pointer to the task from which the VAS should be detached.
 * @vas: The pointer to the VAS which should be detached.
 *
 * This function requires that the VAS is already locked.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int __vas_detach(struct att_vas *avas, struct task_struct *tsk,
			struct vas *vas)
{
	int ret;

	/* Before detaching the VAS, synchronize the RSS-stat of the task. */
	sync_mm_rss(tsk->mm);

	ret = task_unmerge(avas, tsk);
	if (ret != 0)
		return ret;

	ret = vas_unmerge(avas, vas);
	if (ret != 0)
		return ret;

	vas->att_count--;

	/* We unlock the VAS here to ensure our sharing properties. */
	vas_put_share(avas->type, vas);

	return 0;
}

/**
 * sync_from_task() - Synchronize all task related parts of the memory map from
 *		      the task to the attached-VAS.
 * @avas_mm: The memory map of the attached-VAS.
 * @tsk_mm: The memory map of the task.
 *
 * This function requires that the semaphore of the attached-VAS memory map is
 * taken in write-mode and the semaphore of the task's memory map in read-mode.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int sync_from_task(struct mm_struct *avas_mm, struct mm_struct *tsk_mm)
{
	struct vm_area_struct *vma;
	int ret;

	ret = 0;
	for (vma = tsk_mm->mmap; vma; vma = vma->vm_next) {
		struct vm_area_struct *ref;

		ref = vas_find_reference(avas_mm, vma);
		if (!ref) {
			ref = copy_vm_area(tsk_mm, vma, avas_mm, vma->vm_flags);

			if (!ref) {
				pr_vas_debug("Failed to copy memory region (%#lx - %#lx) during task sync\n",
					     vma->vm_start, vma->vm_end);
				ret = -EFAULT;
				break;
			}

			/*
			 * Remember for the newly added memory region where we
			 * copied it from.
			 */
			ref->vas_reference = tsk_mm;
		} else {
			ref = update_vm_area(tsk_mm, vma, avas_mm, ref);
			if (!ref) {
				pr_vas_debug("Failed to update memory region (%#lx - %#lx) during task sync\n",
					     vma->vm_start, vma->vm_end);
				ret = -EFAULT;
				break;
			}
		}
	}

	return ret;
}

/**
 * sync_to_task() - Synchronize all task related part of the memory map from
 *		    the attached-VAS to the task.
 * @avas_mm: The memory map of the attached-VAS.
 * @tsk_mm: The original memory map of the task.
 *
 * This function requires that the semaphore of the attached-VAS memory map is
 * taken in read-mode and the semaphore of the task's memory map in write-mode.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int sync_to_task(struct mm_struct *avas_mm, struct mm_struct *tsk_mm)
{
	struct vm_area_struct *vma;
	int ret;

	ret = 0;
	for (vma = avas_mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vas_reference != tsk_mm) {
			pr_vas_debug("Skip unrelated memory region (%#lx - %#lx) during task resync\n",
				     vma->vm_start, vma->vm_end);
		} else {
			struct vm_area_struct *ref;

			ref = update_vm_area(avas_mm, vma, tsk_mm, NULL);
			if (!ref) {
				pr_vas_debug("Failed to update memory region (%#lx - %#lx) during task resync\n",
					     vma->vm_start, vma->vm_end);
				ret = -EFAULT;
				break;
			}
		}
	}

	return ret;
}

/**
 * sync_task() - Synchronize all task related parts of the memory maps to
 *		 reflect the latest state.
 * @avas_mm: The memory map of the attached-VAS.
 * @tsk_mm: The memory map of the task.
 * @dir: The direction in which the sync should happen:
 *		 1 => tsk -> avas
 *		-1 => avas -> tsk
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int sync_task(struct mm_struct *avas_mm, struct mm_struct *tsk_mm,
			    int dir)
{
	struct mm_struct *src_mm, *dst_mm;
	int ret;

	src_mm = dir == 1 ? tsk_mm : avas_mm;
	dst_mm = dir == 1 ? avas_mm : tsk_mm;

	/*
	 * We have nothing to do if nothing has changed the memory maps since
	 * the last sync.
	 */
	if (ktime_compare(src_mm->vas_last_update,
			  dst_mm->vas_last_update) == 0) {
		pr_vas_debug("Nothing to do during switch, memory map is up-to-date\n");
		return 0;
	}

	pr_vas_debug("Synchronize memory map from %s to %s\n",
		     dir == 1 ? "Task" : "Attached-VAS",
		     dir == 1 ? "Attached-VAS" : "Task");

	dump_memory_map("Before Task MM", tsk_mm);
	dump_memory_map("Before Attached-VAS MM", avas_mm);

	if (down_write_killable(&dst_mm->mmap_sem))
		return -EINTR;
	down_read_nested(&src_mm->mmap_sem, SINGLE_DEPTH_NESTING);

	if (dir == 1)
		ret = sync_from_task(avas_mm, tsk_mm);
	else
		ret = sync_to_task(avas_mm, tsk_mm);

	if (ret != 0)
		goto out_unlock;

	/*
	 * Also update all the information where the different memory regions
	 * such as code, data and stack start and end.
	 */
	dst_mm->start_code = src_mm->start_code;
	dst_mm->end_code = src_mm->end_code;
	dst_mm->start_data = src_mm->start_data;
	dst_mm->end_data = src_mm->end_data;
	dst_mm->start_brk = src_mm->start_brk;
	dst_mm->brk = src_mm->brk;
	dst_mm->start_stack = src_mm->start_stack;
	dst_mm->arg_start = src_mm->arg_start;
	dst_mm->arg_end = src_mm->arg_end;
	dst_mm->env_start = src_mm->env_end;
	dst_mm->env_end = src_mm->env_end;
	dst_mm->task_size = src_mm->task_size;

	dst_mm->vas_last_update = src_mm->vas_last_update;

	ret = 0;

out_unlock:
	up_read(&src_mm->mmap_sem);
	up_write(&dst_mm->mmap_sem);

	dump_memory_map("After Task MM", tsk_mm);
	dump_memory_map("After Attached-VAS MM", avas_mm);

	return ret;
}

/**
 * vas_prepare_switch() - Properly update and setup the memory maps before
 *			  performing the actual switch to a different address
 *			  space.
 * @from: The attached-VAS that we are switching away from, or NULL if we are
 *	  switching away from the task's original AS.
 * @to: The attached-VAS that we are switching to, or NULL if we are switching
 *	to the task's original AS.
 * @tsk: The pointer to the task for which the switch should happen.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int vas_prepare_switch(struct att_vas *from, struct att_vas *to,
			      struct task_struct *tsk)
{
	int ret;

	/* Before doing anything, synchronize the RSS-stat of the task. */
	sync_mm_rss(tsk->mm);

	/*
	 * When switching away from a VAS we have to first update the task's
	 * memory map so that it is always up-to-date
	 */
	if (from) {
		ret = sync_task(from->mm, tsk->original_mm, -1);
		if (ret != 0)
			return ret;
	}

	/*
	 * When switching to a VAS we have to update the VAS' memory map so that
	 * it contains all the up to date information of the task.
	 */
	if (to) {
		ret = sync_task(to->mm, tsk->original_mm, 1);
		if (ret != 0)
			return ret;
	}

	return 0;
}


/***
 * Externally visible functions
 ***/

/**
 * vas_create() - Create a new VAS.
 * @name: The name of the new VAS.
 * @mode: The access permissions of the new VAS.
 *
 * Return: The ID of the new VAS on success, -ERRNO otherwise.
 */
int vas_create(const char *name, umode_t mode)
{
	struct vas *vas;
	int ret;

	if (!name)
		return -EINVAL;

	if (vas_find(name) > 0)
		return -EEXIST;

	pr_vas_debug("Creating a new VAS - name: %s\n", name);

	/* Allocate and initialize the VAS. */
	vas = new_vas();
	if (!vas)
		return -ENOMEM;

	if (strscpy(vas->name, name, VAS_MAX_NAME_LENGTH) < 0) {
		ret = -EINVAL;
		goto out_free;
	}

	mutex_init(&vas->mtx);

	ret = init_vas_mm(vas);
	if (ret != 0)
		goto out_free;

	vas->att_count = 0;

	INIT_LIST_HEAD(&vas->attaches);
	spin_lock_init(&vas->share_lock);
	vas->sharing = 0;

	vas->mode = mode & 0666;
	vas->uid = current_uid();
	vas->gid = current_gid();

	ret = vas_insert(vas);
	if (ret != 0)
		/*
		 * We don't need to do anything here. @vas_insert will care
		 * for the deletion of the VAS before returning with an error.
		 */
		return ret;

	return vas->id;

out_free:
	delete_vas(vas);
	return ret;
}
EXPORT_SYMBOL(vas_create);

/**
 * vas_get() - Get a pointer to a VAS data structure.
 * @vid: The ID of the VAS whose data structure should be returned.
 *
 * Return: The pointer to the VAS data structure on success, NULL otherwise.
 */
struct vas *vas_get(int vid)
{
	return vas_lookup(vid);
}
EXPORT_SYMBOL(vas_get);

/**
 * vas_put() - Return a pointer to a VAS data structure that is not used any
 *	       more.
 * @vas: The pointer to the VAS data structure that is not used any more.
 */
void vas_put(struct vas *vas)
{
	if (!vas)
		return;

	__vas_put(vas);
}
EXPORT_SYMBOL(vas_put);

/**
 * vas_find() - Get the ID of the VAS with the given name.
 * @name: The name of the VAS for which the ID should be looked up.
 *
 * Return: The VAS ID if found, -ERRNO otherwise.
 */
int vas_find(const char *name)
{
	struct vas *vas;

	vas = vas_lookup_by_name(name);
	if (vas) {
		int vid = vas->id;

		vas_put(vas);
		return vid;
	}

	return -ESRCH;
}
EXPORT_SYMBOL(vas_find);

/**
 * vas_delete() - Delete the VAS with the given ID.
 * @vid: The ID of the VAS which should be deleted.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
int vas_delete(int vid)
{
	struct vas *vas;
	int ret;

	vas = vas_get(vid);
	if (!vas)
		return -EINVAL;

	pr_vas_debug("Deleting VAS - name: %s\n", vas->name);

	vas_lock(vas);

	if (vas->att_count != 0) {
		ret = -EBUSY;
		goto out_unlock;
	}

	/* The user needs write permission to the VAS to delete it. */
	ret = check_permission(vas->uid, vas->gid, vas->mode, MAY_WRITE);
	if (ret != 0) {
		pr_vas_debug("User doesn't have the appropriate permissions to delete the VAS\n");
		goto out_unlock;
	}

	vas_unlock(vas);

	vas_remove(vas);
	vas_put(vas);

	return 0;

out_unlock:
	vas_unlock(vas);
	vas_put(vas);

	return ret;
}
EXPORT_SYMBOL(vas_delete);

/**
 * vas_attach() - Attach a VAS to a process.
 * @tsk: The task_struct to which the VAS should be attached to.
 * @vid: The ID of the VAS which should be attached.
 * @type: The type how the VAS should be attached (rw/wo/ro).
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
int vas_attach(struct task_struct *tsk, int vid, int type)
{
	struct vas_context *ctx = tsk->vas_ctx;
	struct vas *vas;
	struct att_vas *avas;
	int ret;

	type &= (MAY_READ | MAY_WRITE);

	if (!tsk)
		return -EINVAL;

	vas = vas_get(vid);
	if (!vas)
		return -EINVAL;

	pr_vas_debug("Attaching VAS - name: %s - to task - pid: %d - %s\n",
		     vas->name, tsk->pid, access_type_str(type));

	vas_lock(vas);

	/*
	 * Before we can attach the VAS to the task we first have to make some
	 * sanity checks.
	 */

	/*
	 * 1: Check that the user has adequate permissions to attach the VAS in
	 * the given way.
	 */
	ret = check_permission(vas->uid, vas->gid, vas->mode, type);
	if (ret != 0) {
		pr_vas_debug("User doesn't have the appropriate permissions to attach the VAS\n");
		goto out_unlock;
	}

	/*
	 * 2: Check if this VAS is already attached to a task. If yes check if
	 * it is a different task or the one we want to attach currently.
	 */
	list_for_each_entry(avas, &vas->attaches, vas_link) {
		if (avas->tsk == tsk) {
			pr_vas_debug("VAS is already attached to the task\n");
			ret = 0;
			goto out_unlock;
		}
	}

	/* 3: Check if we reached the maximum number of shares for this VAS. */
	if (vas->att_count == VAS_MAX_SHARES) {
		ret = -EBUSY;
		goto out_unlock;
	}

	/*
	 * All sanity checks are done. We can now safely attach the VAS to the
	 * given task.
	 */

	/* Allocate and initialize the attached-VAS data structure. */
	avas = new_att_vas();
	if (!avas) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	ret = init_att_vas_mm(avas, tsk);
	if (ret != 0)
		goto out_free_avas;

	avas->vas = vas;
	avas->tsk = tsk;
	avas->type = type;

	ret = __vas_attach(avas, tsk, vas);
	if (ret != 0)
		goto out_free_avas;

	vas_context_lock(ctx);

	list_add(&avas->tsk_link, &ctx->vases);
	list_add(&avas->vas_link, &vas->attaches);

	vas_context_unlock(ctx);

	ret = 0;

out_unlock:
	vas_unlock(vas);
	vas_put(vas);

	return ret;

out_free_avas:
	delete_att_vas(avas);
	goto out_unlock;
}
EXPORT_SYMBOL(vas_attach);

/**
 * vas_detach() - Detach a VAS from a process.
 * @tsk: The task from which the VAS should be detached.
 * @vid: The ID of the VAS which should be detached.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
int vas_detach(struct task_struct *tsk, int vid)
{
	struct vas_context *ctx = tsk->vas_ctx;
	struct vas *vas;
	struct att_vas *avas;
	bool is_attached;
	int ret;

	if (!tsk)
		return -EINVAL;

	task_lock(tsk);
	vas_context_lock(ctx);

	is_attached = false;
	list_for_each_entry(avas, &ctx->vases, tsk_link) {
		if (avas->vas->id == vid) {
			is_attached = true;
			break;
		}
	}
	if (!is_attached) {
		pr_vas_debug("VAS is not attached to the given task\n");
		ret = -EINVAL;
		goto out_unlock_tsk;
	}

	vas = avas->vas;

	/*
	 * Make sure that our reference to the VAS can not be removed while we
	 * are currently working with it.
	 */
	__vas_get(vas);

	pr_vas_debug("Detaching VAS - name: %s - from task - pid: %d\n",
		     vas->name, tsk->pid);

	/*
	 * Before we can detach the VAS from the task we have to perform some
	 * sanity checks.
	 */

	/*
	 * 1: Check if the VAS we want to detach is currently the active VAS
	 * because we must not detach this VAS. The user first has to switch
	 * away.
	 */
	if (tsk->active_vas == vid) {
		pr_vas_debug("VAS is currently in use by the task\n");
		ret = -EBUSY;
		goto out_put_vas;
	}

	/*
	 * We are done with the sanity checks. It is now safe to detach the VAS
	 * from the given task.
	 */
	list_del(&avas->tsk_link);

	vas_context_unlock(ctx);
	task_unlock(tsk);

	vas_lock(vas);

	list_del(&avas->vas_link);

	ret = __vas_detach(avas, tsk, vas);
	if (ret != 0)
		goto out_reinsert;

	delete_att_vas(avas);

	vas_unlock(vas);
	__vas_put(vas);

	return 0;

out_reinsert:
	vas_context_lock(ctx);

	list_add(&avas->tsk_link, &ctx->vases);
	list_add(&avas->vas_link, &vas->attaches);

	vas_context_unlock(ctx);
	vas_unlock(vas);
	__vas_put(vas);

	return ret;

out_put_vas:
	__vas_put(vas);

out_unlock_tsk:
	vas_context_unlock(ctx);
	task_unlock(tsk);

	return ret;
}
EXPORT_SYMBOL(vas_detach);

/**
 * vas_switch() - Switch a task to a different AS.
 * @tsk: The task for which the VAS should be switched.
 * @vid: The ID of the VAS which should be activated. Use '0' to activate the
 *	 task's original address space again.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
int vas_switch(struct task_struct *tsk, int vid)
{
	struct vas_context *ctx;
	struct att_vas *next_avas, *old_avas;
	struct mm_struct *nextmm, *oldmm;
	bool is_attached;
	int ret;

	if (!tsk)
		return -EINVAL;

	ctx = tsk->vas_ctx;
	vas_context_lock(ctx);

	if (vid == 0) {
		pr_vas_debug("Switching to original mm\n");
		next_avas = NULL;
		nextmm = tsk->original_mm;
	} else {
		is_attached = false;
		list_for_each_entry(next_avas, &ctx->vases, tsk_link) {
			if (next_avas->vas->id == vid) {
				is_attached = true;
				break;
			}
		}
		if (!is_attached) {
			ret = -EINVAL;
			goto out_unlock;
		}

		pr_vas_debug("Switching to VAS - name: %s\n",
			     next_avas->vas->name);
		nextmm = next_avas->mm;
	}

	if (tsk->active_vas == 0) {
		pr_vas_debug("Switching from original mm\n");
		old_avas = NULL;
		oldmm = tsk->active_mm;
	} else {
		is_attached = false;
		list_for_each_entry(old_avas, &ctx->vases, tsk_link) {
			if (old_avas->vas->id == tsk->active_vas) {
				is_attached = true;
				break;
			}
		}
		if (!is_attached) {
			WARN(!is_attached, "Could not find the task's active VAS.\n");
			old_avas = NULL;
			oldmm = tsk->mm;
		} else {
			pr_vas_debug("Switching from VAS - name: %s\n",
				     old_avas->vas->name);
			oldmm = old_avas->mm;
		}
	}

	vas_context_unlock(ctx);

	/* Check if we are already running on the specified mm. */
	if (oldmm == nextmm)
		return 0;

	/*
	 * Prepare the mm_struct data structure we are switching to. Update the
	 * mappings for stack, code, data and other recent changes.
	 */
	ret = vas_prepare_switch(old_avas, next_avas, tsk);
	if (ret != 0) {
		pr_vas_debug("Failed to prepare memory maps for switch\n");
		return ret;
	}

	task_lock(tsk);

	/* Perform the actual switch in the new address space. */
	vmacache_flush(tsk);
	switch_mm(oldmm, nextmm, tsk);

	tsk->mm = nextmm;
	tsk->active_mm = nextmm;
	tsk->active_vas = vid;

	task_unlock(tsk);

	return 0;

out_unlock:
	vas_context_unlock(ctx);

	return ret;
}
EXPORT_SYMBOL(vas_switch);

/**
 * vas_getattr() - Get various attributes of a VAS.
 * @vid: The ID of the VAS for which the attributes should be returned.
 * @attr: The pointer to the &struct vas_attr where the attributes should be
 *	  saved.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
int vas_getattr(int vid, struct vas_attr *attr)
{
	struct vas *vas;
	struct user_namespace *ns = current_user_ns();

	if (!attr)
		return -EINVAL;

	vas = vas_get(vid);
	if (!vas)
		return -EINVAL;

	pr_vas_debug("Getting attributes for VAS - name: %s\n", vas->name);

	vas_lock(vas);

	memset(attr, 0, sizeof(struct vas_attr));
	attr->mode = vas->mode;
	attr->user = from_kuid(ns, vas->uid);
	attr->group = from_kgid(ns, vas->gid);

	vas_unlock(vas);
	vas_put(vas);

	return 0;
}
EXPORT_SYMBOL(vas_getattr);

/**
 * vas_setattr() - Set various attributes of a VAS.
 * @vid: The ID of the VAS for which the attributes should be updated.
 * @attr: The pointer to the &struct vas_attr containing the new attributes.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
int vas_setattr(int vid, struct vas_attr *attr)
{
	struct vas *vas;
	struct user_namespace *ns = current_user_ns();
	int ret;

	if (!attr)
		return -EINVAL;

	vas = vas_get(vid);
	if (!vas)
		return -EINVAL;

	pr_vas_debug("Setting attributes for VAS - name: %s\n", vas->name);

	vas_lock(vas);

	/* The user needs write permission to change attributes for the VAS. */
	ret = check_permission(vas->uid, vas->gid, vas->mode, MAY_WRITE);
	if (ret != 0) {
		pr_vas_debug("User doesn't have the appropriate permissions to set attributes for the VAS\n");
		goto out_unlock;
	}

	vas->mode = attr->mode & 0666;
	vas->uid = make_kuid(ns, attr->user);
	vas->gid = make_kgid(ns, attr->group);

	ret = 0;

out_unlock:
	vas_unlock(vas);
	vas_put(vas);

	return ret;
}
EXPORT_SYMBOL(vas_setattr);

/**
 * vas_init() - Initialize the VAS subsystem.
 */
void __init vas_init(void)
{
	/* Create the SLAB caches for our data structures. */
	vas_cachep = KMEM_CACHE(vas, SLAB_PANIC|SLAB_NOTRACK);
	att_vas_cachep = KMEM_CACHE(att_vas, SLAB_PANIC|SLAB_NOTRACK);
	vas_context_cachep = KMEM_CACHE(vas_context, SLAB_PANIC|SLAB_NOTRACK);

	/* Initialize the internal management data structures. */
	idr_init(&vases);
	spin_lock_init(&vases_lock);

	/* Initialize the place holder variables. */
	INVALID_VAS = new_vas();

	/* Initialize the VAS context of the init task. */
	vas_clone(0, &init_task);
}

/**
 * vas_sysfs_init() - Initialize VAS related sysfs directories.
 *
 * We need to use a postcore_initcall to initialize the sysfs directories,
 * because the 'sys/kernel' directory will be initialized in a core_initcall.
 * Hence, we have to queue the initialization of the VAS sysfs directories after
 * this.
 */
static int __init vas_sysfs_init(void)
{
	/* Setup the sysfs base directories. */
	vases_kset = kset_create_and_add("vas", NULL, kernel_kobj);
	if (!vases_kset) {
		pr_err("Failed to initialize the VAS sysfs directory\n");
		return -ENOMEM;
	}

	return 0;
}
postcore_initcall(vas_sysfs_init);

/**
 * vas_clone() - Copy/Initialize the task-specific VAS data structures during
 *		 the task cloning.
 * @clone_flags: The flags which were given to the system call by the user.
 * @tsk: The new task_struct which should be initialized.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
int vas_clone(int clone_flags, struct task_struct *tsk)
{
	int ret = 0;

	struct vas_context *ctx;

	if (clone_flags & CLONE_VM) {
		ctx = current->vas_ctx;

		pr_vas_debug("Copy VAS context (%p -- %d) for task - %p - from task - %p\n",
			     ctx, ctx->refcount, tsk, current);

		vas_context_lock(ctx);
		ctx->refcount++;
		vas_context_unlock(ctx);
	} else {
		pr_vas_debug("Create a new VAS context for task - %p\n",
			     tsk);

		ctx = new_vas_context();
		if (!ctx) {
			ret = -ENOMEM;
			goto out;
		}

		spin_lock_init(&ctx->lock);
		ctx->refcount = 1;
		INIT_LIST_HEAD(&ctx->vases);
	}

	tsk->vas_ctx = ctx;

out:
	return ret;
}

/**
 * vas_exit() - Destroy the task-specific VAS data structures during the task
 *		exiting.
 * @tsk: The task_struct that is going to exit.
 */
void vas_exit(struct task_struct *tsk)
{
	struct vas_context *ctx = tsk->vas_ctx;

	if (tsk->active_vas != 0) {
		int error;

		pr_vas_debug("Switch to original MM before exit for task - %p\n",
			     tsk);

		error = vas_switch(tsk, 0);
		if (error != 0)
			pr_alert("Switching back to original MM failed with %d\n",
				 error);
	}

	pr_vas_debug("Exiting VAS context (%p -- %d) for task - %p\n", ctx,
		     ctx->refcount, tsk);

	vas_context_lock(ctx);

	ctx->refcount--;
	tsk->vas_ctx = NULL;

	vas_context_unlock(ctx);

	if (ctx->refcount == 0) {
		/*
		 * We have to clear this VAS context from all the VAS it has
		 * attached before it is save to delete it. There is no need to
		 * hold the look while doing this since we are the last one
		 * having a reference to this particular VAS context.
		 */
		struct att_vas *avas, *s_avas;

		list_for_each_entry_safe(avas, s_avas, &ctx->vases, tsk_link) {
			struct vas *vas = avas->vas;
			int error;

			pr_vas_debug("Detaching VAS - name: %s - from exiting task - pid: %d\n",
				     vas->name, tsk->pid);

			/*
			 * Make sure our reference to the VAS is not deleted
			 * while we are currently working with it.
			 */
			__vas_get(vas);

			vas_lock(vas);

			error = __vas_detach(avas, tsk, vas);
			if (error != 0)
				pr_alert("Detaching VAS from task failed with %d\n",
					 error);

			list_del(&avas->tsk_link);
			list_del(&avas->vas_link);
			delete_att_vas(avas);

			vas_unlock(vas);
			__vas_put(vas);
		}

		/*
		 * All the attached VAS are detached. Now it is safe to remove
		 * this VAS context.
		 */
		delete_vas_context(ctx);

		pr_vas_debug("Deleted VAS context\n");
	}
}


/***
 * System Calls
 ***/

SYSCALL_DEFINE2(vas_create, const char __user *, name, umode_t, mode)
{
	char vas_name[VAS_MAX_NAME_LENGTH];
	int len;

	if (!name)
		return -EINVAL;

	len = strlen(name);
	if (len >= VAS_MAX_NAME_LENGTH)
		return -EINVAL;

	if (copy_from_user(vas_name, name, len) != 0)
		return -EFAULT;

	vas_name[len] = '\0';

	return vas_create(name, mode);
}

SYSCALL_DEFINE1(vas_delete, int, vid)
{
	if (vid < 0)
		return -EINVAL;

	return vas_delete(vid);
}

SYSCALL_DEFINE1(vas_find, const char __user *, name)
{
	char vas_name[VAS_MAX_NAME_LENGTH];
	int len;

	if (!name)
		return -EINVAL;

	len = strlen(name);
	if (len >= VAS_MAX_NAME_LENGTH)
		return -EINVAL;

	if (copy_from_user(vas_name, name, len) != 0)
		return -EFAULT;

	vas_name[len] = '\0';

	return vas_find(name);
}

SYSCALL_DEFINE3(vas_attach, pid_t, pid, int, vid, int, type)
{
	struct task_struct *tsk;
	int vas_acc_type;

	if (pid < 0 || vid < 0)
		return -EINVAL;

	tsk = pid == 0 ? current : find_task_by_vpid(pid);
	if (!tsk)
		return -ESRCH;

	vas_acc_type = build_vas_access_type(type);
	if (vas_acc_type == -1)
		return -EINVAL;

	return vas_attach(tsk, vid, vas_acc_type);
}

SYSCALL_DEFINE2(vas_detach, pid_t, pid, int, vid)
{
	struct task_struct *tsk;

	if (pid < 0 || vid < 0)
		return -EINVAL;

	tsk = pid == 0 ? current : find_task_by_vpid(pid);
	if (!tsk)
		return -ESRCH;

	return vas_detach(tsk, vid);
}

SYSCALL_DEFINE1(vas_switch, int, vid)
{
	struct task_struct *tsk = current;

	if (vid < 0)
		return -EINVAL;

	return vas_switch(tsk, vid);
}

SYSCALL_DEFINE0(active_vas)
{
	struct task_struct *tsk = current;

	return tsk->active_vas;
}

SYSCALL_DEFINE2(vas_getattr, int, vid, struct vas_attr __user *, uattr)
{
	struct vas_attr attr;
	int ret;

	if (vid < 0 || !uattr)
		return -EINVAL;

	ret = vas_getattr(vid, &attr);
	if (ret != 0)
		return ret;

	if (copy_to_user(uattr, &attr, sizeof(struct vas_attr)) != 0)
		return -EFAULT;

	return 0;
}

SYSCALL_DEFINE2(vas_setattr, int, vid, struct vas_attr __user *, uattr)
{
	struct vas_attr attr;

	if (vid < 0 || !uattr)
		return -EINVAL;

	if (copy_from_user(&attr, uattr, sizeof(struct vas_attr)) != 0)
		return -EFAULT;

	return vas_setattr(vid, &attr);
}
