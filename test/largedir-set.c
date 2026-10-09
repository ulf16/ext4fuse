/* SPDX-License-Identifier: GPL-2.0-only */
/* Test-only: add valid intermediate htree levels without millions of files. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ext2fs/ext2fs.h>
static unsigned get16(const char *p)
{ unsigned short v; memcpy(&v, p, 2); return ext2fs_le16_to_cpu(v); }
static void put16(char *p, unsigned v)
{ unsigned short value = ext2fs_cpu_to_le16(v); memcpy(p, &value, 2); }
static void put32(char *p, unsigned v)
{ unsigned value = ext2fs_cpu_to_le32(v); memcpy(p, &value, 4); }
int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    ext2_filsys fs = NULL;
    errcode_t err = ext2fs_open(argv[1], EXT2_FLAG_RW | EXT2_FLAG_64BITS, 0, 0,
                               unix_io_manager, &fs);
    if (!err) err = ext2fs_read_bitmaps(fs);
    ext2_ino_t ino = strtoul(argv[2], NULL, 10);
    struct ext2_inode inode;
    char root[4096], node[4096];
    blk64_t physical = 0;
    if (!err) err = ext2fs_read_inode(fs, ino, &inode);
    if (!err) err = ext2fs_bmap2(fs, ino, &inode, NULL, 0, 0, NULL, &physical);
    if (!err) err = ext2fs_read_dir_block4(fs, physical, root, 0, ino);
    if (!err && (!(inode.i_flags & EXT2_INDEX_FL) || (unsigned char)root[30] > 1)) return 2;
    while (!err && (unsigned char)root[30] < 2) {
        blk64_t logical = EXT2_I_SIZE(&inode) / fs->blocksize, added = 0;
        unsigned count = get16(root + 34);
        err = ext2fs_expand_dir(fs, ino);
        if (!err) err = ext2fs_read_inode(fs, ino, &inode);
        if (!err) err = ext2fs_bmap2(fs, ino, &inode, NULL, 0, logical, NULL, &added);
        if (err) break;
        memset(node, 0, sizeof(node));
        put16(node + 4, fs->blocksize);
        memcpy(node + 8, root + 32, count * 8);
        unsigned tail = ext2fs_has_feature_metadata_csum(fs->super) ? 8 : 0;
        put16(node + 8, (fs->blocksize - 8 - tail) / 8);
        root[30]++;
        put16(root + 34, 1);
        put32(root + 36, logical);
        err = ext2fs_write_dir_block4(fs, added, node, 0, ino);
        if (!err) err = ext2fs_write_dir_block4(fs, physical, root, 0, ino);
    }
    if (fs) { errcode_t closed = ext2fs_close(fs); if (!err) err = closed; }
    if (err) fprintf(stderr, "Largedir fixture error: %ld\n", (long)err);
    return err ? 1 : 0;
}
