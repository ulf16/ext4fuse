/*
 * Copyright (c) 2010, Gerard Lledó Vives, gerard.lledo@gmail.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */


#include <string.h>
#include <errno.h>
#include <fuse.h>

#include "common.h"
#include "inode.h"
#include "logging.h"


static char *get_printable_name(char *s, struct ext4_dir_entry_2 *entry)
{
    memcpy(s, entry->name, entry->name_len);
    s[entry->name_len] = 0;
    return s;
}

int op_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    DEBUG("readdir");

    UNUSED(fi);
    char name_buf[EXT4_NAME_LEN + 1];
    struct ext4_dir_entry_2 *dentry = NULL;
    struct ext4_inode inode;

    /* We can use inode_get_by_number, but first we need to implement opendir */
    int ret = inode_get_by_path(path, &inode);

    if (ret < 0) {
        return ret;
    }

    struct inode_dir_ctx *dctx = inode_dir_ctx_get();
    ret = inode_dir_ctx_reset(dctx, &inode);
    if (ret < 0) { inode_dir_ctx_put(dctx); return ret; }
    while ((ret = inode_dentry_get(&inode, offset, dctx, &dentry)) > 0) {
        offset += dentry->rec_len;

        if (!dentry->inode) {
            /* It seems that is possible to have a dummy entry like this at the
             * begining of a block of dentries.  Looks like skipping is the
             * reasonable thing to do. */
            continue;
        }

        /* Providing offset to the filler function seems slower... */
        get_printable_name(name_buf, dentry);
        if (name_buf[0]) {
#if FUSE_MAJOR_VERSION >= 3
            if (filler(buf, name_buf, NULL, offset, 0) != 0) break;
#else
            if (filler(buf, name_buf, NULL, offset) != 0) break;
#endif
        }
    }
    inode_dir_ctx_put(dctx);

    return ret < 0 ? ret : 0;
}
