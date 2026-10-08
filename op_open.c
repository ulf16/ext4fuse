/*
 * Copyright (c) 2010, Gerard Lledó Vives, gerard.lledo@gmail.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */


#include <errno.h>
#include <sys/stat.h>

#include "common.h"
#include "inode.h"
#include "logging.h"
#include "ops.h"

int op_open(const char *path, struct fuse_file_info *fi)
{   
    DEBUG("open");
    if((fi->flags & 3) != O_RDONLY)
        return -EACCES;

    uint32_t number;
    int ret = inode_lookup(path, &number);
    if (ret < 0) return ret;
    struct ext4_inode inode;
    ret = inode_get_by_number(number, &inode);
    if (ret < 0) return ret;
    if (S_ISDIR(inode.i_mode)) return -EISDIR;
    fi->fh = number;
    DEBUG("%s is inode %d", path, fi->fh);

    return 0;
}
