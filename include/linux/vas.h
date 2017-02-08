#ifndef _LINUX_VAS_H
#define _LINUX_VAS_H


#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/vas_types.h>


/***
 * General management of the VAS subsystem
 ***/

#ifdef CONFIG_VAS

/***
 * Management of VASes
 ***/

/**
 * vas_lock() - Acquire the lock of a VAS.
 * @vas: The pointer to the VAS data structure that should be locked.
 */
#define vas_lock(vas) mutex_lock(&(vas)->mtx)

/**
 * vas_unlock() - Release the lock of a VAS.
 * @vas: The pointer to the VAS data structure that should be unlocked.
 */
#define vas_unlock(vas) mutex_unlock(&(vas)->mtx)

extern int vas_create(const char *name, umode_t mode);

extern struct vas *vas_get(int vid);
extern void vas_put(struct vas *vas);

extern int vas_find(const char *name);

extern int vas_delete(int vid);

extern int vas_attach(struct task_struct *tsk, int vid, int type);
extern int vas_detach(struct task_struct *tsk, int vid);
extern int vas_switch(struct task_struct *tsk, int vid);

extern int vas_getattr(int vid, struct vas_attr *attr);
extern int vas_setattr(int vid, struct vas_attr *attr);


/***
 * Management of VAS contexts
 ***/

/**
 * vas_context_lock() - Acquire the lock of a VAS context.
 * @ctx: The pointer to the VAS context data structure that should be locked.
 */
#define vas_context_lock(ctx) spin_lock(&(ctx)->lock)

/**
 * vas_context_unlock() - Release the lock of a VAS context.
 * @ctx: The pointer to the VAS context data structure that should be unlocked.
 */
#define vas_context_unlock(ctx) spin_unlock(&(ctx)->lock)


/***
 * Management of VAS segments
 ***/

/**
 * vas_seg_lock() - Acquire the lock of a VAS segment.
 * @seg: The pointer to the VAS segment data structure that should be locked.
 */
#define vas_seg_lock(seg) mutex_lock(&(seg)->mtx)

/**
 * vas_seg_unlock() - Release the lock of a VAS segment.
 * @seg: The pointer to the VAS segment data structure that should be unlocked.
 */
#define vas_seg_unlock(seg) mutex_unlock(&(seg)->mtx)

extern int vas_seg_create(const char *name, unsigned long start,
			  unsigned long end, umode_t mode);

extern struct vas_seg *vas_seg_get(int sid);
extern void vas_seg_put(struct vas_seg *seg);

extern int vas_seg_find(const char *name);

extern int vas_seg_delete(int id);

extern int vas_seg_attach(int vid, int sid, int type);
extern int vas_seg_detach(int vid, int sid);

extern int vas_seg_getattr(int sid, struct vas_seg_attr *attr);
extern int vas_seg_setattr(int sid, struct vas_seg_attr *attr);


/***
 * Management of the VAS subsystem
 ***/

extern void vas_init(void);


/***
 * Management of the VAS subsystem during fork and exit
 ***/

extern int vas_clone(int clone_flags, struct task_struct *tsk);
extern void vas_exit(struct task_struct *tsk);

#else /* CONFIG_VAS */

static inline void __init vas_init(void) {}
static inline int vas_clone(int cf, struct task_struct *tsk) { return 0; }
static inline int vas_exit(struct task_struct *tsk) { return 0; }

#endif /* CONFIG_VAS */


/***
 * Management of the VAS lazy attaching
 ***/

#ifdef CONFIG_VAS_LAZY_ATTACH

extern int vas_lazy_attach_vma(struct vm_area_struct *vma);

#else /* CONFIG_VAS_LAZY_ATTACH */

static inline int vas_lazy_attach_vma(struct vm_area_struct *vma) { return 0; }

#endif /* CONFIG_VAS_LAZY_ATTACH */

#endif
