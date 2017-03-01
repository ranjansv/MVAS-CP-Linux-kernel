#ifndef _UAPI_LINUX_VAS_H
#define _UAPI_LINUX_VAS_H

#include <linux/types.h>


/**
 * struct vas_attr - All VAS attributes that user can change.
 * @mode: The access permission for the VAS.
 * @user: The UID of the owning user of the VAS.
 * @group: The GID of the owning group of the VAS.
 */
struct vas_attr {
	__kernel_mode_t mode;
	__kernel_uid_t user;
	__kernel_gid_t group;
};

/**
 * struct vas_seg_attr - All VAS segment attributes that users can change.
 * @mode: The access permission for the VAS segment.
 * @user: The UID of the owning user of the VAS segment.
 * @group: The GID of the owning group of the VAS segment.
 */
struct vas_seg_attr {
	__kernel_mode_t mode;
	__kernel_uid_t user;
	__kernel_gid_t group;
};

#endif
