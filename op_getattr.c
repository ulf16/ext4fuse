/*
 * Copyright (c) 2010, Gerard Lledó Vives, gerard.lledo@gmail.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "inode.h"
#include "logging.h"
#include "super.h"

int op_getattr(const char *path, struct stat *stbuf)
{
    struct ext4_inode inode;
    int ret = 0;

    DEBUG("getattr(%s)", path);

    memset(stbuf, 0, sizeof(struct stat));
    uint32_t number;
    ret = inode_lookup(path, &number);
    if (!ret) ret = inode_get_by_number(number, &inode);

    if (ret < 0) {
        return ret;
    }

    DEBUG("getattr done");

    stbuf->st_mode = inode.i_mode & ~0222;
    stbuf->st_nlink = inode.i_links_count;
    uint64_t size = inode_get_size(&inode);
    if (size > INT64_MAX) return -EOVERFLOW;
    stbuf->st_size = size;
    uint64_t blocks = inode.i_blocks_lo;
    if (super_huge_file() && super_linux_inode_format()) {
        blocks |= (uint64_t)inode.osd2.linux2.l_i_blocks_high << 32;
        if (inode.i_flags & EXT4_HUGE_FILE_FL) blocks *= BLOCK_SIZE / 512;
    }
    /* POSIX st_blocks always counts 512-byte units, even for huge-file inodes. */
    stbuf->st_blocks = blocks;
    stbuf->st_blksize = BLOCK_SIZE;
    stbuf->st_ino = number;
    stbuf->st_uid = inode.i_uid;
    stbuf->st_gid = inode.i_gid;
    if (super_linux_inode_format()) {
        stbuf->st_uid |= (uint32_t)inode.osd2.linux2.l_i_uid_high << 16;
        stbuf->st_gid |= (uint32_t)inode.osd2.linux2.l_i_gid_high << 16;
    }
    struct inode_times times;
    ret = inode_get_times(&inode, &times);
    if (ret < 0) return ret;
#ifdef __APPLE__
    stbuf->st_atimespec = times.access;
    stbuf->st_mtimespec = times.modify;
    stbuf->st_ctimespec = times.change;
    if (times.has_create) stbuf->st_birthtimespec = times.create;
#else
    stbuf->st_atim = times.access;
    stbuf->st_mtim = times.modify;
    stbuf->st_ctim = times.change;
#ifdef __FreeBSD__
    if (times.has_create) stbuf->st_birthtim = times.create;
#endif
#endif

    return 0;
}
