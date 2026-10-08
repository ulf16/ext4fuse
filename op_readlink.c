/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2010, Gerard Lledó Vives, gerard.lledo@gmail.com
 * Derived from Gerard Lledó Vives's ext4fuse symlink reader (2010).
 */
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include "inode.h"
#include "ops.h"
int op_readlink(const char *path, char *buf, size_t size)
{
    if (!size) return -ERANGE;
    struct ext4_inode inode;
    int ret = inode_get_by_path(path, &inode);
    if (ret < 0) return ret;
    if (!S_ISLNK(inode.i_mode)) return -EINVAL;
    uint64_t length = inode_get_size(&inode);
    size_t take = size - 1;
    if (take > length) take = length;
    if (length < sizeof(inode.i_block) && !(inode.i_flags & EXT4_EXTENTS_FL)) {
        memcpy(buf, inode.i_block, take);
    } else {
        ret = inode_read_data(&inode, buf, take, 0);
        if (ret < 0) return ret;
        if ((size_t)ret != take) return -EIO;
    }
    buf[take] = 0;
    return 0;
}
