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
#include "checksum.h"

/* Inline values live in the inode body, relative to the first xattr entry.
 * Validate the whole entry table before copying any system.data bytes. */
static int inline_directory_region(const unsigned char *data, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        if (size - offset < 8) return -EIO;
        uint32_t number = checksum_u32(data + offset);
        uint16_t length = checksum_u16(data + offset + 4);
        unsigned names = data[offset + 6], type = data[offset + 7];
        if (length < 8 || length % 4 || length > size - offset || names > length - 8)
            return -EIO;
        if (number && (number > super_inode_count() || !names || type > 7 ||
            memchr(data + offset + 8, 0, names) || memchr(data + offset + 8, '/', names)))
            return -EIO;
        offset += length;
    }
    return 0;
}

static int inode_inline_load(struct ext4_inode *inode, const unsigned char *raw,
                             size_t length, uint32_t number)
{
    if (!super_inline_data() || length <= 128 ||
        (inode->i_flags & (EXT4_EXTENTS_FL | EXT4_INDEX_FL)) ||
        !(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))) return -EIO;
    unsigned extra = checksum_u16(raw + 128);
    if (extra < 4 || extra % 4 || extra > length - 128) return -EIO;
    size_t header = 128 + extra;
    if (length - header < 8 || checksum_u32(raw + header) != 0xea020000U) return -EIO;
    size_t first = header + 4, cursor = first, value_floor = length;
    size_t data_offset = 0, data_size = 0;
    int found = 0;
    while (1) {
        if (length - cursor < 4) return -EIO;
        if (!checksum_u32(raw + cursor)) { cursor += 4; break; }
        if (length - cursor < 16) return -EIO;
        size_t entry_size = (16 + raw[cursor] + 3) & ~3U;
        if (entry_size > length - cursor) return -EIO;
        size_t value = first + checksum_u16(raw + cursor + 2);
        size_t bytes = checksum_u32(raw + cursor + 8);
        if (checksum_u32(raw + cursor + 4)) return -EIO;
        if (bytes) {
            if (value % 4 || value > length || bytes > length - value) return -EIO;
            if (value < value_floor) value_floor = value;
        }
        if (raw[cursor] == 4 && raw[cursor + 1] == 7 &&
            !memcmp(raw + cursor + 16, "data", 4)) {
            if (found++) return -EIO;
            data_offset = bytes ? value : 0; data_size = bytes;
        }
        cursor += entry_size;
    }
    if (!found || cursor > value_floor || 60 + data_size > sizeof(inode->reader_inline)) return -EIO;
    uint64_t size = inode_get_size(inode);
    if (S_ISREG(inode->i_mode)) {
        if (size > 60 + data_size) return -EIO;
        memcpy(inode->reader_inline, inode->i_block, 60);
        if (data_size) memcpy(inode->reader_inline + 60, raw + data_offset, data_size);
        inode->reader_inline_size = 60 + data_size;
    } else {
        uint32_t parent = checksum_u32((const void *)inode->i_block);
        if (!parent || parent > super_inode_count() || size != 60 + data_size ||
            80 + data_size > sizeof(inode->reader_inline)) return -EIO;
        if (inline_directory_region((const unsigned char *)inode->i_block + 4, 56) < 0 ||
            inline_directory_region(raw + data_offset, data_size) < 0) return -EIO;
        unsigned char *out = inode->reader_inline;
        struct ext4_dir_entry_2 *dot = (void *)out;
        dot->inode = number; dot->rec_len = 12; dot->name_len = 1; dot->file_type = 2; dot->name[0] = '.';
        dot = (void *)(out + 12);
        dot->inode = parent; dot->rec_len = 12; dot->name_len = 2; dot->file_type = 2;
        dot->name[0] = dot->name[1] = '.';
        memcpy(out + 24, (const unsigned char *)inode->i_block + 4, 56);
        if (data_size) memcpy(out + 80, raw + data_offset, data_size);
        inode->reader_inline_size = 80 + data_size;
    }
    return 0;
}

int inode_get_data_pblock(struct ext4_inode *inode, uint32_t logical,
                          uint64_t *physical, uint32_t *run)
{
    if (inode->i_flags & EXT4_INLINE_DATA_FL) return -EIO;
    *physical = 0;
    if (run) *run = 1;
    if (inode->i_flags & EXT4_EXTENTS_FL)
        return extent_get_pblock(inode->i_block, sizeof(inode->i_block), logical, physical, run, inode->reader_csum_seed);
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
    if (inode->i_flags & EXT4_INLINE_DATA_FL) {
        if (!inode->reader_inline_size) return -EIO;
        memcpy(ctx->buf, inode->reader_inline, inode->reader_inline_size);
        ctx->lblock = 0;
        return 0;
    }
    if (!size || size % BLOCK_SIZE || size / BLOCK_SIZE > UINT32_MAX) return -EIO;
    ctx->lblock = UINT32_MAX;
    return 0;
}

int inode_dentry_get(struct ext4_inode *inode, off_t offset, struct inode_dir_ctx *ctx,
                     struct ext4_dir_entry_2 **entry)
{
    *entry = NULL;
    if (offset < 0 || offset % 4) return -EINVAL;
    uint64_t size = (inode->i_flags & EXT4_INLINE_DATA_FL) ? inode->reader_inline_size : inode_get_size(inode);
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
        ret = checksum_directory(ctx->buf, inode->reader_csum_seed,
                                 inode->i_flags & EXT4_INDEX_FL, logical);
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
    /* Verify the full on-disk inode, including fields absent from our struct. */
    unsigned char raw[4096];
    size_t length=super_inode_size();
    int ret = disk_read_exact(off, length, raw);
    if (ret < 0) return ret;
    memcpy(inode, raw, MIN(length, offsetof(struct ext4_inode,reader_csum_seed)));
    uint32_t inum=number+1;
    uint32_t seed=checksum_crc32c(super_checksum_seed(),&inum,4);
    inode->reader_csum_seed=checksum_crc32c(seed,&inode->i_generation,4);
    if (super_metadata_csum()) {
        /* Linux i_checksum_lo is at 0x7c; i_checksum_hi at 0x82 requires
         * at least four bytes of i_extra_isize beyond the 128-byte inode. */
        uint32_t supplied=checksum_u16(raw+124);
        raw[124]=raw[125]=0;
        int high=length>128 && checksum_u16(raw+128)>=4;
        if (length>128 && (checksum_u16(raw+128)>length-128 || checksum_u16(raw+128)%4)) return -EIO;
        if (high) { supplied |= (uint32_t)checksum_u16(raw+130)<<16; raw[130]=raw[131]=0; }
        uint32_t crc=checksum_crc32c(inode->reader_csum_seed,raw,length);
        if (!high) crc &= 0xffff;
        if (crc!=supplied) return -EIO;
    }
    if (inode->i_flags & (0x4U | 0x800U)) return -EIO;
    if (inode->i_flags & EXT4_INLINE_DATA_FL)
        return inode_inline_load(inode, raw, length, inum);
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
