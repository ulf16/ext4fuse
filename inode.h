#ifndef INODE_H
#define INODE_H

#include <sys/types.h>
#include <time.h>

#include "types/ext4_inode.h"
#include "types/ext4_dentry.h"

struct inode_dir_ctx {
    uint32_t lblock;        /* Currently buffered lblock */
    uint8_t buf[];
};

static inline uint64_t inode_get_size(struct ext4_inode *inode)
{
    return ((uint64_t)inode->i_size_high << 32) | inode->i_size_lo;
}

struct inode_times {
    struct timespec access, modify, change, create;
    int has_create;
};
int inode_get_times(const struct ext4_inode *inode, struct inode_times *times);

int inode_get_data_pblock(struct ext4_inode *inode, uint32_t lblock,
                          uint64_t *pblock, uint32_t *extent_len);
int inode_read_data(struct ext4_inode *inode, char *buf, size_t size, off_t offset);
int inode_index_find(struct ext4_inode *inode, struct inode_dir_ctx *ctx,
                     const char *name, size_t length, uint32_t *number);
int inode_lookup(const char *path, uint32_t *number);

struct inode_dir_ctx *inode_dir_ctx_get(void);
void inode_dir_ctx_put(struct inode_dir_ctx *);
int inode_dir_ctx_reset(struct inode_dir_ctx *ctx, struct ext4_inode *inode);
int inode_dentry_get(struct ext4_inode *inode, off_t offset, struct inode_dir_ctx *ctx,
                     struct ext4_dir_entry_2 **entry);

/* Full verified inode bytes; checksum fields are zeroed during validation. */
int inode_get_raw(uint32_t number, struct ext4_inode *inode, unsigned char raw[4096]);
int inode_get_by_number(uint32_t n, struct ext4_inode *inode);
int inode_get_by_path(const char *path, struct ext4_inode *inode);
uint32_t inode_get_idx_by_path(const char *path);

int inode_init(void);

#endif
