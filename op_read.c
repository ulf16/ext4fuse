/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2010, Gerard Lledó Vives, gerard.lledo@gmail.com
 * Derived from Gerard Lledó Vives's ext4fuse read callback (2010).
 */
#include <errno.h>
#include <limits.h>
#include <string.h>
#include "disk.h"
#include "inode.h"
#include "ops.h"

int inode_read_data(struct ext4_inode *inode, char *buf, size_t size, off_t offset)
{
    if (offset < 0 || size > INT_MAX) return -EINVAL;
    uint64_t file_size = inode_get_size(inode);
    if ((uint64_t)offset >= file_size) return 0;
    if (size > file_size - offset) size = file_size - offset;
    if (inode->i_flags & EXT4_INLINE_DATA_FL) {
        if (file_size > inode->reader_inline_size) return -EIO;
        memcpy(buf, inode->reader_inline + offset, size);
        return size;
    }
    size_t done = 0;
    while (done < size) {
        uint64_t position = (uint64_t)offset + done;
        if (position / BLOCK_SIZE > UINT32_MAX) return -EIO;
        uint32_t within = position % BLOCK_SIZE, run;
        uint64_t physical;
        int ret = inode_get_data_pblock(inode, position / BLOCK_SIZE, &physical, &run);
        if (ret < 0) return ret;
        if (!run) return -EIO;
        uint64_t available = (uint64_t)run * BLOCK_SIZE - within;
        size_t bytes = size - done;
        if (bytes > available) bytes = available;
        if (!physical) memset(buf + done, 0, bytes);
        else {
            ret = disk_read_exact(BLOCKS2BYTES(physical) + within, bytes, buf + done);
            if (ret < 0) return ret;
        }
        done += bytes;
    }
    return done;
}
int op_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    (void)path;
    if (!fi || fi->fh > UINT32_MAX) return -EINVAL;
    struct ext4_inode inode;
    int ret = inode_get_by_number(fi->fh, &inode);
    return ret < 0 ? ret : inode_read_data(&inode, buf, size, offset);
}
