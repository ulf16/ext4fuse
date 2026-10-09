/* SPDX-License-Identifier: GPL-2.0-only */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "inode.h"
#include "super.h"
#include "checksum.h"
struct index_frame { uint32_t logical; unsigned count, at, offset; unsigned char data[4096]; };
static uint32_t child(const struct index_frame *f)
{ return checksum_u32(f->data+f->offset+f->at*8+4)&0x0fffffffU; }
static int ancestor(const struct index_frame *frames, unsigned level, uint32_t logical)
{
    for (unsigned i=0;i<=level;i++) if (frames[i].logical==logical) return 1;
    return 0;
}
static int frame_read(struct ext4_inode *inode, struct inode_dir_ctx *ctx,
                      struct index_frame *f, uint32_t logical)
{
    struct ext4_dir_entry_2 *d;
    int ret=inode_dentry_get(inode,(uint64_t)logical*BLOCK_SIZE,ctx,&d);
    if (ret<=0) return ret<0 ? ret : -EIO;
    if (logical && (checksum_u32(ctx->buf) || checksum_u16(ctx->buf+4)!=BLOCK_SIZE ||
                    ctx->buf[6] || ctx->buf[7])) return -EIO;
    f->logical=logical;f->offset=logical ? 8 : 32;
    memcpy(f->data,ctx->buf,BLOCK_SIZE);
    f->count=checksum_u16(f->data+f->offset+2);f->at=0;
    return 0;
}
static void select_hash(struct index_frame *f, uint32_t hash)
{
    unsigned lo=1,hi=f->count;
    while (lo<hi) {
        unsigned mid=lo+(hi-lo)/2;
        if (checksum_u32(f->data+f->offset+mid*8)<=hash) lo=mid+1;
        else hi=mid;
    }
    f->at=lo-1;
}
int inode_index_find(struct ext4_inode *inode, struct inode_dir_ctx *ctx,
                     const char *name, size_t length, uint32_t *number)
{
    struct index_frame *frames=calloc(3,sizeof(*frames));
    if (!frames) return -ENOMEM;
    int ret=frame_read(inode,ctx,&frames[0],0);
    if (ret<0) goto out;
    unsigned depth=frames[0].data[30];
    uint32_t hash;
    ret=super_directory_hash(frames[0].data[28],name,length,&hash);
    if (ret<0) { ret=-EIO;goto out; }
    select_hash(&frames[0],hash);
    for (unsigned level=1;level<=depth;level++) {
        uint32_t logical=child(&frames[level-1]);
        if (ancestor(frames,level-1,logical)) { ret=-EIO;goto out; }
        ret=frame_read(inode,ctx,&frames[level],logical);
        if (ret<0) goto out;
        select_hash(&frames[level],hash);
    }
    uint64_t leaves=0,blocks=inode_get_size(inode)/BLOCK_SIZE;
    for (;;) {
        uint32_t logical=child(&frames[depth]);
        if (ancestor(frames,depth,logical) || ++leaves>blocks) { ret=-EIO;goto out; }
        off_t offset=(uint64_t)logical*BLOCK_SIZE,end=offset+BLOCK_SIZE;
        struct ext4_dir_entry_2 *d;
        while (offset<end && (ret=inode_dentry_get(inode,offset,ctx,&d))>0) {
            /* A selected leaf must not silently masquerade as an index node. */
            if (offset==(off_t)((uint64_t)logical*BLOCK_SIZE) && !d->inode &&
                d->rec_len==BLOCK_SIZE && !d->name_len) { ret=-EIO;goto out; }
            offset+=d->rec_len;
            if (d->inode && d->name_len==length && !memcmp(d->name,name,length)) {
                *number=d->inode;ret=0;goto out;
            }
        }
        if (ret<0) goto out;
        /* Advance to the next leaf in tree order only for hash collisions;
         * crossing an exhausted node may require advancing a parent frame. */
        int level=(int)depth;
        while (level>=0 && ++frames[level].at>=frames[level].count) level--;
        if (level<0 || (checksum_u32(frames[level].data+frames[level].offset+frames[level].at*8)&~1U)!=hash) {
            ret=-ENOENT;goto out;
        }
        for (unsigned next=level+1;next<=depth;next++) {
            uint32_t block=child(&frames[next-1]);
            if (ancestor(frames,next-1,block)) { ret=-EIO;goto out; }
            ret=frame_read(inode,ctx,&frames[next],block);
            if (ret<0) goto out;
        }
    }
out:
    free(frames);
    return ret;
}
