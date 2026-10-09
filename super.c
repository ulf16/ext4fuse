/*
 * Copyright (c) 2010, Gerard Lledó Vives, gerard.lledo@gmail.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */


#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include "checksum.h"
#include "dirhash.h"
#include "types/ext4_super.h"

#include "disk.h"
#include "logging.h"
#include "super.h"

#define GROUP_DESC_MIN_SIZE         0x20
#define INCOMPAT_64BIT              0x0080
#define INCOMPAT_SUPPORTED         (0x0002 | 0x0010 | 0x0040 | 0x0080 | 0x0200 | 0x0400 | 0x2000 | 0x4000 | 0x8000)
#define RO_COMPAT_SUPPORTED        (0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0100 | 0x0400 | 0x1000 | 0x2000)

struct feature_name { uint32_t bit; const char *name; };
static const struct feature_name incompat_names[] = {
    {0x0001, "compression"}, {0x0004, "needs_recovery"},
    {0x0008, "journal_dev"}, {0x0010, "meta_bg"},
    {0x0100, "mmp"}, {0x0400, "ea_inode"}, {0x1000, "dirdata"},
    {0x4000, "largedir"}, {0x8000, "inline_data"},
    {0x10000, "encrypt"}, {0x20000, "casefold"}
};
static const struct feature_name ro_names[] = {
    {0x0004, "btree_dir"}, {0x0080, "snapshot"}, {0x0200, "bigalloc"},
    {0x0800, "replica"}, {0x4000, "shared_blocks"},
    {0x8000, "verity"}, {0x10000, "orphan_present"}
};

static int invalid(const char *reason)
{
    fprintf(stderr, "ext4fuse: %s\n", reason);
    return -EINVAL;
}

static int reject_features(const char *kind, uint32_t bits,
                           const struct feature_name *names, size_t count)
{
    if (!bits) return 0;
    fprintf(stderr, "ext4fuse: unsupported %s features (0x%08x):", kind, bits);
    uint32_t remaining = bits;
    for (size_t i = 0; i < count; i++) {
        if (bits & names[i].bit) {
            fprintf(stderr, " %s", names[i].name);
            remaining &= ~names[i].bit;
        }
    }
    if (remaining) fprintf(stderr, " unknown=0x%08x", remaining);
    fprintf(stderr, "\n");
    return -ENOTSUP;
}

static struct ext4_super_block super;
static struct ext4_group_desc *gdesc_table;
static uint32_t csum_seed;
int super_metadata_csum(void) { return !!(super.s_feature_ro_compat & 0x400); }
uint32_t super_checksum_seed(void) { return csum_seed; }
int super_linux_inode_format(void) { return super.s_creator_os == 0; }
uint32_t super_first_inode(void) { return super.s_rev_level ? super.s_first_ino : 11; }
int super_largedir(void) { return !!(super.s_feature_incompat & 0x4000); }
int super_ea_inode(void) { return !!(super.s_feature_incompat & 0x400); }
int super_inline_data(void) { return !!(super.s_feature_incompat & 0x8000); }
int super_huge_file(void) { return !!(super.s_feature_ro_compat & 0x8); }



static uint64_t super_block_group_size(void)
{   
    return BLOCKS2BYTES(super.s_blocks_per_group);
}

static uint32_t super_n_block_groups(void)
{
    return (super_block_count() - super.s_first_data_block - 1)
            / super.s_blocks_per_group + 1;
}

static uint32_t super_group_desc_size(void)
{
    return (super.s_feature_incompat & INCOMPAT_64BIT)
        ? super.s_desc_size : GROUP_DESC_MIN_SIZE;
}

uint64_t super_block_count(void) { return ((uint64_t)super.s_blocks_count_hi << 32) | super.s_blocks_count_lo; }
uint32_t super_inode_count(void) { return super.s_inodes_count; }

uint32_t super_block_size(void) {
    return ((uint64_t)1) << (super.s_log_block_size + 10);
}

uint32_t super_inodes_per_group(void)
{
    return super.s_inodes_per_group;
}

uint32_t super_inode_size(void)
{
    return super.s_rev_level ? super.s_inode_size : 128;
}


int super_fill(void)
{
    int ret = disk_read_exact(BOOT_SECTOR_SIZE, sizeof(super), &super);
    if (ret < 0) return invalid("cannot read complete superblock (truncated image or I/O error)");
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    return invalid("only little-endian hosts are supported");
#endif
    if (super.s_magic != 0xEF53) return invalid("not an ext filesystem (bad magic)");
    /* Modern checksum fields occupy offsets in the legacy reserved tail. */
    const unsigned char *raw = (const void *)&super;
    if (super_metadata_csum()) {
        if (raw[0x175] != 1) return invalid("unsupported metadata checksum algorithm");
        if (checksum_crc32c(~0U, raw, 0x3fc) != checksum_u32(raw+0x3fc))
            return invalid("superblock checksum mismatch");
        if (super.s_creator_os) return invalid("metadata checksums require Linux inode format");
    }
    if (super_ea_inode() && !super_linux_inode_format())
        return invalid("ea_inode requires Linux inode format");
    if (super_ea_inode() && (super_first_inode() < 11 || super_first_inode() > super_inode_count()))
        return invalid("invalid first non-reserved inode for ea_inode");
    csum_seed = (super.s_feature_incompat & 0x2000)
        ? checksum_u32(raw+0x270) : checksum_crc32c(~0U,super.s_uuid,16);
    if (super_inline_data() && !super_linux_inode_format())
        return invalid("inline data requires Linux inode format");
    if (super.s_rev_level > 1) return invalid("unsupported superblock revision");
    ret = reject_features("incompatible", super.s_feature_incompat & ~INCOMPAT_SUPPORTED,
                          incompat_names, sizeof(incompat_names) / sizeof(incompat_names[0]));
    if (ret < 0) return ret;
    ret = reject_features("read-only-compatible", super.s_feature_ro_compat & ~RO_COMPAT_SUPPORTED,
                          ro_names, sizeof(ro_names) / sizeof(ro_names[0]));
    if (ret < 0) return ret;
    if (!(super.s_state & 1) || (super.s_state & ~1) || super.s_last_orphan)
        return invalid("filesystem is not clean; unmount/check it on Linux before reading (no journal replay)");
    if (super.s_log_block_size > 2)
        return invalid("unsupported block size (only 1024, 2048, 4096 bytes are supported)");
    if (super.s_obso_log_frag_size != super.s_log_block_size)
        return invalid("inconsistent cluster/block size without bigalloc");
    if (super.s_first_data_block != (super.s_log_block_size == 0 ? 1U : 0U))
        return invalid("invalid first data block");
    if (!super.s_blocks_per_group || super.s_blocks_per_group > BLOCK_SIZE * 8 ||
        !super.s_inodes_per_group || super.s_inodes_per_group > BLOCK_SIZE * 8)
        return invalid("invalid blocks/inodes per group");
    if (super.s_blocks_count_hi && !(super.s_feature_incompat & INCOMPAT_64BIT))
        return invalid("high block count requires the 64bit feature");
    if (super_block_count() > INT64_MAX / (uint64_t)BLOCK_SIZE)
        return invalid("filesystem byte size exceeds signed 64-bit offsets");
    if (super_block_count() <= super.s_first_data_block || super.s_inodes_count < 2)
        return invalid("invalid filesystem block/inode counts");
    uint64_t groups = (super_block_count() - super.s_first_data_block - 1) / super.s_blocks_per_group + 1;
    if (groups > UINT32_MAX)
        return invalid("block group count exceeds 32-bit group numbering");
    uint32_t inode_size = super_inode_size();
    if (inode_size < 128 || inode_size > BLOCK_SIZE || (inode_size & (inode_size - 1)))
        return invalid("invalid inode size");
    if ((super.s_feature_incompat & INCOMPAT_64BIT) && super.s_desc_size != 64)
        return invalid("unsupported 64bit group descriptor size (expected 64 bytes)");
    if ((uint64_t)super.s_inodes_count > (uint64_t)super_n_block_groups() * super.s_inodes_per_group)
        return invalid("inode count exceeds block group capacity");
    ret = disk_check_size(super_block_count() * BLOCK_SIZE);
    if (ret < 0) return invalid("cannot verify input capacity against its declared filesystem size (undersized input or device query error)");

    INFO("BLOCK SIZE: %i", super_block_size());
    INFO("BLOCK GROUP SIZE: %i", super_block_group_size());
    INFO("N BLOCK GROUPS: %i", super_n_block_groups());
    INFO("INODE SIZE: %i", super_inode_size());
    INFO("INODES PER GROUP: %i", super_inodes_per_group());

    return 0;
}

/* Group descriptors have already been checked against filesystem bounds. */
off_t super_group_inode_table_offset(uint32_t inode_num)
{
    uint32_t n_group = inode_num / super_inodes_per_group();
    ASSERT(n_group < super_n_block_groups());
    DEBUG("Inode table offset: 0x%x", gdesc_table[n_group].bg_inode_table_lo);
    return BLOCKS2BYTES(((uint64_t)gdesc_table[n_group].bg_inode_table_hi << 32) | gdesc_table[n_group].bg_inode_table_lo);
}

/* Linux's primary descriptor placement; backup tables are not used. */
static int group_has_super(uint32_t group)
{
    if (!group) return 1;
    if (super.s_feature_compat & 0x200) {
        const unsigned char *raw = (const void *)&super;
        return group == checksum_u32(raw + 0x24c) || group == checksum_u32(raw + 0x250);
    }
    if (group == 1 || !(super.s_feature_ro_compat & 1)) return 1;
    const unsigned bases[] = {3, 5, 7};
    for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
        uint32_t value = group;
        while (value > 1 && value % bases[i] == 0) value /= bases[i];
        if (value == 1) return 1;
    }
    return 0;
}

static uint64_t descriptor_block(uint32_t index)
{
    if (!(super.s_feature_incompat & 0x10) || index < super.s_first_meta_bg)
        return (uint64_t)super.s_first_data_block + 1 + index;
    uint32_t group = index * (BLOCK_SIZE / super_group_desc_size());
    return (uint64_t)super.s_first_data_block + (uint64_t)group * super.s_blocks_per_group
         + group_has_super(group);
}

/* struct ext4_group_desc might be bigger than on disk structure, if we are not
 * using big ones.  That info is in the superblock.  Be careful when allocating
 * or manipulating this pointers. */
int super_group_fill(void)
{
    uint32_t groups = super_n_block_groups();
    uint32_t per_block = BLOCK_SIZE / super_group_desc_size();
    uint32_t blocks = ((uint64_t)groups + per_block - 1) / per_block;
    if ((super.s_feature_incompat & 0x10) && super.s_first_meta_bg > blocks)
        return invalid("first meta block group exceeds descriptor block count");
    if ((uint64_t)groups * sizeof(struct ext4_group_desc) > 256U * 1024 * 1024)
        return invalid("group descriptor allocation exceeds this reader's 256 MiB limit");
    struct ext4_group_desc *table = calloc(groups, sizeof(*table));
    if (!table) return invalid("cannot allocate group descriptor table");
    uint64_t inode_blocks = ((uint64_t)super.s_inodes_per_group * super_inode_size()
                            + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for (uint32_t i = 0; i < groups; i++) {
        uint64_t block = descriptor_block(i / per_block);
        if (block >= super_block_count()) {
            free(table);
            return invalid("group descriptor table exceeds filesystem bounds");
        }
        uint64_t offset = BLOCKS2BYTES(block) + (i % per_block) * super_group_desc_size();
        int ret = disk_read_exact(offset, super_group_desc_size(), &table[i]);
        if (ret < 0) {
            free(table);
            return invalid("cannot read complete group descriptor table (truncated image or I/O error)");
        }
        if (super_metadata_csum() || (super.s_feature_ro_compat & 0x10)) {
            unsigned char *desc=(void *)&table[i];
            uint16_t supplied=table[i].bg_checksum, calculated;
            size_t length=super_group_desc_size();
            if (super_metadata_csum()) {
                table[i].bg_checksum=0;
                uint32_t crc=checksum_crc32c(csum_seed,&i,4);
                calculated=checksum_crc32c(crc,desc,length);
                table[i].bg_checksum=supplied;
            } else {
                uint16_t crc=checksum_crc16(0xffff,super.s_uuid,16);
                crc=checksum_crc16(crc,&i,4);
                crc=checksum_crc16(crc,desc,30);
                calculated=checksum_crc16(crc,desc+32,length-32);
            }
            if (supplied!=calculated) { free(table); return invalid("group descriptor checksum mismatch"); }
        }
        uint64_t inode_table = ((uint64_t)table[i].bg_inode_table_hi << 32) | table[i].bg_inode_table_lo;
        if (inode_table <= super.s_first_data_block || inode_table >= super_block_count() ||
            inode_blocks > super_block_count() - inode_table) {
            free(table);
            return invalid("inode table exceeds filesystem bounds");
        }
    }
    free(gdesc_table);
    gdesc_table = table;
    return 0;
}

int super_directory_hash(unsigned version, const char *name, size_t length, uint32_t *hash)
{
    if (version<=2 && (super.s_flags & 2)) version+=3;
    return directory_hash(version,name,length,super.s_hash_seed,hash);
}
