#ifndef _LINUX_VAS_TYPES_H
#define _LINUX_VAS_TYPES_H

#include <uapi/linux/vas.h>

#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>


#define VAS_MAX_NAME_LENGTH 256

#define VAS_IS_ERROR(id) ((id) < 0)

/*
 * Forward declare various important data structures that we use.
 */
struct mm_struct;
struct task_struct;

/**
 * struct vas - A first class virtual address space (VAS).
 * @kobj: The internal kobject that we use for reference counting and sysfs
 *	  handling.
 * @id: The ID of the VAS.
 * @name: The user defined name of the VAS.
 * @mtx: The lock used to protect parallel access to the data structure.
 * @mm: The partial memory map containing all mappings of this VAS and its
 *	attached VAS segments.
 * @rcu: The RCU helper needed for asynchronous VAS deletion.
 * @att_count: The counter how many tasks have the VAS attached.
 * @attaches: The list of all tasks which have this VAS attached.
 * @share_lock: The lock used to protect changing of the sharing state.
 * @sharing: The current sharing state of the VAS.
 * @mode: The access permissions for the VAS.
 * @segments: The list of all VAS segments attached to this VAS.
 * @nr_segments: The total number of VAS segments attached to this VAS.
 * @uid: The UID of the owning user of the VAS.
 * @gid: The GID of the owning group of the VAS.
 *
 * This data structure contains all the necessary information of a VAS such as
 * its name, ID, its access rights and other management information such as the
 * list of all VAS segments that are attached to it.
 */
struct vas {
	struct kobject kobj;

	int id;
	char name[VAS_MAX_NAME_LENGTH];

	struct mutex mtx;

	struct mm_struct *mm;

	struct rcu_head rcu;

	u16 att_count;
	struct list_head attaches;

	spinlock_t share_lock;
	u32 sharing;

	struct list_head segments;
	u32 nr_segments;

	bool execable;

	umode_t mode;
	kuid_t uid;
	kgid_t gid;
};

/**
 * struct att_vas - A VAS being attached to a task.
 * @vas: The reference to the actual VAS that is attached.
 * @tsk: The reference to the actual task to which the VAS is attached.
 * @tsk_link: The link in the list of attached-VAS managed inside the task.
 * @vas_link: The link in the list of attached-VAS managed inside the VAS.
 * @type: The type of the attaching (rw/wo/ro).
 *
 * Once a VAS is attached to a process additional information are necessary.
 * This data structure contains all these information.
 */
struct att_vas {
	struct vas *vas;
	struct task_struct *tsk;

	struct mm_struct *mm;

	struct list_head tsk_link;
	struct list_head vas_link;

	int type;
};

/**
 * struct vas_seg - A VAS segment.
 * @kobj: The internal kobject that we use for reference counting and sysfs
 *	  handling.
 * @id: The ID of the VAS segment.
 * @name: The user defined name of the VAS segment.
 * @start: The virtual address where the VAS segment starts.
 * @end: The virtual address where the VAS segment ends.
 * @lenght: The size of the VAS segment in bytes.
 * @mm: The partial memory map containing all the mappings for this VAS segment.
 * @rcu: The RCU helper needed for asynchronous VAS segment deletion.
 * @att_count: The counter how often the VAS segment is attached to VAS.
 * @attaches: The list of VASes that have this VAS segment attached.
 * @share_lock: The lock used to protect the sharing state of the VAS segment.
 * @sharing: The current sharing state of the VAS segment.
 * @mode: The access permissions of the VAS segment.
 * @uid: The UID of the owning user of the VAS segment.
 * @gid: The GID of the owning group of the VAS segment.
 *
 * A VAS segment is a region in memory. Accordingly, it is very similar to a
 * vm_area. However, instead of a vm_area it can only represent a memory region
 * and not a file and also knows where it is mapped. In addition VAS segments
 * also have an ID, a name, access rights and a keep track how they are shared
 * between multiple VAS.
 */
struct vas_seg {
	struct kobject kobj;

	int id;
	char name[VAS_MAX_NAME_LENGTH];

	struct mutex mtx;

	unsigned long start;
	unsigned long end;
	unsigned long length;

	struct mm_struct *mm;

	struct rcu_head rcu;

	u16 att_count;
	struct list_head attaches;

	spinlock_t share_lock;
	u32 sharing;

	umode_t mode;
	kuid_t uid;
	kgid_t gid;
};

/**
 * struct att_vas_seg - A VAS segment being attached to a VAS.
 * @seg: The reference to the actual VAS segment that is attached.
 * @vas: The reference to the actual VAS to which the VAS segment is attached.
 * @vas_link: The link in the list of attached VAS segments managed inside the
 *	      VAS.
 * @seg_link: The link in the list of attached VAS segments managed inside the
 *	      VAS segment.
 * @type: The type of attaching (rw/wo/ro).
 *
 * Since a VAS segment can be attached to a multiple VAS this data structure is
 * necessary. It forms the connection between the VAS and the VAS segment
 * itself.
 */
struct att_vas_seg {
	struct vas_seg *seg;
	struct vas *vas;

	struct list_head vas_link;
	struct list_head seg_link;

	int type;
};

#endif
