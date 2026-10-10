/*
 * Copyright (c) 2010, Gerard Lledó Vives, gerard.lledo@gmail.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */


#include <stdlib.h>

#include "inode.h"
#include "logging.h"
#include "ops.h"
#include "super.h"

void *op_init(struct fuse_conn_info *info)
{
    INFO("Using FUSE protocol %d.%d", info->proto_major, info->proto_minor);

#if defined(__linux__) && defined(FUSE_CAP_POSIX_ACL)
    /* Read-only: the kernel enforces our validated access ACL xattrs, including
     * supplementary groups and traversal. No ACL mutation/inheritance occurs. */
    if (info->capable & FUSE_CAP_POSIX_ACL) {
        info->want |= FUSE_CAP_POSIX_ACL;
        INFO("Kernel POSIX ACL enforcement enabled");
    } else {
        ERR("Kernel lacks POSIX ACL support; refusing a mode-only mount")
        abort();
    }
#endif

    if (inode_init() != 0) {
        ERR("inode initialization failed")
        abort();
    }

    return NULL;
}
