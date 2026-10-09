/* SPDX-License-Identifier: GPL-2.0-only */
/* Instrument directory block loads only in this harness, not the installed reader. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "disk.h"
#include "inode.h"
#include "logging.h"
static unsigned loads;
static int counted_dentry(struct ext4_inode *inode, off_t offset, struct inode_dir_ctx *ctx,
                          struct ext4_dir_entry_2 **entry)
{
    if (ctx->lblock!=(uint64_t)offset/BLOCK_SIZE) loads++;
    return inode_dentry_get(inode,offset,ctx,entry);
}
#define inode_dentry_get counted_dentry
#include "../dirindex.c"
#undef inode_dentry_get
int main(int argc,char **argv)
{
    if (argc!=4 || logging_open("/dev/null")<0 || disk_open(argv[1])<0 ||
        super_fill()<0 || super_group_fill()<0 || inode_init()<0) return 2;
    struct ext4_inode inode;if (inode_get_by_path(argv[2],&inode)<0) return 2;
    struct inode_dir_ctx *ctx=inode_dir_ctx_get();if (!ctx) return 2;
    uint32_t indexed=0,linear=0;loads=0;
    if (inode_dir_ctx_reset(ctx,&inode)<0) return 2;
    int a=inode_index_find(&inode,ctx,argv[3],strlen(argv[3]),&indexed);
    unsigned fast=loads;loads=0;inode_dir_ctx_reset(ctx,&inode);
    off_t offset=0;struct ext4_dir_entry_2 *d;int b;
    while ((b=counted_dentry(&inode,offset,ctx,&d))>0) {
        offset+=d->rec_len;
        if (d->inode && d->name_len==strlen(argv[3]) && !memcmp(d->name,argv[3],d->name_len)) {
            linear=d->inode;b=0;break;
        }
    }
    if (!linear && !b) b=-ENOENT;
    printf("%d %u %u %d %u %u\n",a,indexed,fast,b,linear,loads);
    inode_dir_ctx_put(ctx);
    return a==b && indexed==linear ? 0 : 1;
}
