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

    if (inode_init() != 0) {
        ERR("inode initialization failed")
        abort();
    }

    return NULL;
}
