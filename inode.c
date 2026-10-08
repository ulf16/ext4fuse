/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2010, Gerard Lledó Vives, gerard.lledo@gmail.com
 * Derived from Gerard Lledó Vives's ext4fuse inode reader (2010).
 */
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <stddef.h>
#include "disk.h"
#include "extents.h"
#include "inode.h"
#include "super.h"

int inode_get_data_pblock(struct ext4_inode *inode, uint32_t logical,
                          uint64_t *physical, uint32_t *run)
{
    *physical = 0;
    if (run) *run = 1;
    if (inode->i_flags & EXT4_EXTENTS_FL)
        return extent_get_pblock(inode->i_block, sizeof(inode->i_block), logical, physical, run);
    uint64_t index = logical;
    uint64_t per_block = BLOCK_SIZE / sizeof(uint32_t);
    if (index < EXT4_NDIR_BLOCKS) {
        *physical = inode->i_block[index];
    } else {
        index -= EXT4_NDIR_BLOCKS;
        uint64_t capacity = per_block;
        unsigned level;
        for (level = 1; level <= 3; level++) {
            if (index < capacity) break;
            index -= capacity;
            capacity *= per_block;
        }
        if (level > 3) return -EIO;
        uint32_t pointer = inode->i_block[EXT4_IND_BLOCK + level - 1];
        while (level--) {
            if (!pointer) return 0;
            if (pointer >= super_block_count()) return -EIO;
            capacity /= per_block;
            uint64_t slot = index / capacity;
            index %= capacity;
            int ret = disk_read_exact(BLOCKS2BYTES(pointer) + slot * sizeof(pointer), sizeof(pointer), &pointer);
            if (ret < 0) return ret;
        }
        *physical = pointer;
    }
    return *physical >= super_block_count() ? -EIO : 0;
}

struct inode_dir_ctx *inode_dir_ctx_get(void)
{
    struct inode_dir_ctx *ctx = malloc(sizeof(*ctx) + BLOCK_SIZE);
    if (ctx) ctx->lblock = UINT32_MAX;
    return ctx;
}
void inode_dir_ctx_put(struct inode_dir_ctx *ctx) { free(ctx); }
int inode_dir_ctx_reset(struct inode_dir_ctx *ctx, struct ext4_inode *inode)
{
    if (!ctx) return -ENOMEM;
    if (!S_ISDIR(inode->i_mode)) return -ENOTDIR;
    uint64_t size = inode_get_size(inode);
    if (!size || size % BLOCK_SIZE || size / BLOCK_SIZE > UINT32_MAX) return -EIO;
    ctx->lblock = UINT32_MAX;
    return 0;
}

int inode_dentry_get(struct ext4_inode *inode, off_t offset, struct inode_dir_ctx *ctx,
                     struct ext4_dir_entry_2 **entry)
{
    *entry = NULL;
    if (offset < 0 || offset % 4) return -EINVAL;
    uint64_t size = inode_get_size(inode);
    if ((uint64_t)offset > size) return -EIO;
    if ((uint64_t)offset == size) return 0;
    uint32_t logical = (uint64_t)offset / BLOCK_SIZE;
    uint32_t position = offset % BLOCK_SIZE;
    if (ctx->lblock != logical) {
        uint64_t physical;
        int ret = inode_get_data_pblock(inode, logical, &physical, NULL);
        if (ret < 0) return ret;
        if (!physical) return -EIO; /* Directories cannot contain holes. */
        ret = disk_read_exact(BLOCKS2BYTES(physical), BLOCK_SIZE, ctx->buf);
        if (ret < 0) return ret;
        ctx->lblock = logical;
    }
    const size_t header = offsetof(struct ext4_dir_entry_2, name);
    if (BLOCK_SIZE - position < header) return -EIO;
    struct ext4_dir_entry_2 *d = (void *)(ctx->buf + position);
    if (d->rec_len < header || d->rec_len % 4 || d->rec_len > BLOCK_SIZE - position ||
        d->rec_len > size - offset || d->name_len > d->rec_len - header) return -EIO;
    if (d->inode && (d->inode > super_inode_count() || !d->name_len || d->file_type > 7 ||
        memchr(d->name, 0, d->name_len) || memchr(d->name, '/', d->name_len))) return -EIO;
    *entry = d;
    return 1;
}

int inode_get_by_number(uint32_t number, struct ext4_inode *inode)
{
    if (!number) return -ENOENT;
    if (number > super_inode_count()) return -EIO;
    number--;
    off_t off = super_group_inode_table_offset(number);
    off += (uint64_t)(number % super_inodes_per_group()) * super_inode_size();
    memset(inode, 0, sizeof(*inode));
    int ret = disk_read_exact(off, MIN(super_inode_size(), sizeof(*inode)), inode);
    if (ret < 0) return ret;
    if (inode->i_flags & (0x4U | 0x800U | 0x10000000U)) return -EIO;
    return 0;
}

int inode_lookup(const char *path, uint32_t *number)
{
    if (!path || *path != '/') return -EINVAL;
    int need_directory = path[strlen(path) - 1] == '/';
    uint32_t current = 2;
    struct inode_dir_ctx *ctx = inode_dir_ctx_get();
    if (!ctx) return -ENOMEM;
    int ret = 0;
    while (*path) {
        while (*path == '/') path++;
        size_t length = 0;
        while (length <= EXT4_NAME_LEN && path[length] && path[length] != '/') length++;
        if (!length) break;
        if (length > EXT4_NAME_LEN) { ret = -ENAMETOOLONG; break; }
        struct ext4_inode inode;
        ret = inode_get_by_number(current, &inode);
        if (ret < 0) break;
        ret = inode_dir_ctx_reset(ctx, &inode);
        if (ret < 0) break;
        off_t offset = 0;
        struct ext4_dir_entry_2 *d;
        while ((ret = inode_dentry_get(&inode, offset, ctx, &d)) > 0) {
            offset += d->rec_len;
            if (d->inode && length == d->name_len && !memcmp(path, d->name, length)) {
                current = d->inode;
                break;
            }
        }
        if (ret <= 0) { if (!ret) ret = -ENOENT; break; }
        path += length;
        ret = 0;
    }
    inode_dir_ctx_put(ctx);
    if (!ret && need_directory) {
        struct ext4_inode inode;
        ret = inode_get_by_number(current, &inode);
        if (!ret && !S_ISDIR(inode.i_mode)) ret = -ENOTDIR;
    }
    if (!ret) *number = current;
    return ret;
}

uint32_t inode_get_idx_by_path(const char *path)
{
    uint32_t number = 0;
    return inode_lookup(path, &number) < 0 ? 0 : number;
}
int inode_get_by_path(const char *path, struct ext4_inode *inode)
{
    uint32_t number;
    int ret = inode_lookup(path, &number);
    return ret < 0 ? ret : inode_get_by_number(number, inode);
}
int inode_init(void) { return 0; }
