/* SPDX-License-Identifier: GPL-2.0-only */
#include "mount-metadata.h"
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
/* Keep inode bounds compatible with libext2fs before 1.47.4. */
#define inode_includes(size, field)                                            \
  ((size) >= offsetof(struct ext2_inode_large, field) +                        \
                 sizeof(((struct ext2_inode_large *)0)->field))
static void put(unsigned char *p, uint64_t value) {
  for (unsigned i = 0; i < 8; i++)
    p[i] = value >> (i * 8);
}
errcode_t mount_inode_stat(ext2_filsys fs, ext2_ino_t ino, unsigned char **data,
                           size_t *bytes) {
  struct ext2_inode_large in = {0};
  size_t n = EXT2_INODE_SIZE(fs->super);
  if (n > sizeof(in))
    n = sizeof(in);
  errcode_t e = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&in, n);
  if (e)
    return e;
  if (inode_uid(in) == UINT32_MAX || inode_gid(in) == UINT32_MAX)
    return EIO;
  if (in.i_extra_isize && (in.i_extra_isize < 4 || in.i_extra_isize % 4 ||
                           in.i_extra_isize > EXT2_INODE_SIZE(fs->super) - 128))
    return EIO;
  size_t actual = 128 + in.i_extra_isize;
  if (actual > n)
    actual = n;
  uint32_t extra[4] = {0}, base[4] = {in.i_atime, in.i_mtime, in.i_ctime, 0};
  if (inode_includes(actual, i_atime_extra))
    extra[0] = in.i_atime_extra;
  if (inode_includes(actual, i_mtime_extra))
    extra[1] = in.i_mtime_extra;
  if (inode_includes(actual, i_ctime_extra))
    extra[2] = in.i_ctime_extra;
  if (inode_includes(actual, i_crtime))
    base[3] = in.i_crtime;
  if (inode_includes(actual, i_crtime_extra))
    extra[3] = in.i_crtime_extra;
  int removed_dir =
      (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFDIR && !in.i_links_count;
  uint64_t fields[16] = {
      ino,
      in.i_mode,
      in.i_links_count,
      inode_uid(in),
      inode_gid(in),
      removed_dir ? 0 : EXT2_I_SIZE((struct ext2_inode *)&in),
      removed_dir ? 0 : ext2fs_get_stat_i_blocks(fs, (struct ext2_inode *)&in),
      fs->blocksize};
  if (fields[5] > INT64_MAX || fields[6] > INT64_MAX)
    return EOVERFLOW;
  for (unsigned i = 0; i < 4; i++) {
    if ((extra[i] >> 2) >= 1000000000)
      return EIO;
    fields[8 + i * 2] =
        (int64_t)(int32_t)base[i] + ((uint64_t)(extra[i] & 3) << 32);
    fields[9 + i * 2] = extra[i] >> 2;
  }
  *data = calloc(128, 1);
  if (!*data)
    return ENOMEM;
  for (unsigned i = 0; i < 16; i++)
    put(*data + 8 * i, fields[i]);
  *bytes = 128;
  return 0;
}
errcode_t mount_geometry(ext2_filsys fs, unsigned char **data, size_t *bytes) {
  /* Mounted writer admission is narrower than the production read-only reader.
   */
  struct ext2_super_block *s = fs->super;
  if (s->s_creator_os != EXT2_OS_LINUX || s->s_state != EXT2_VALID_FS ||
      ext2fs_has_feature_journal_needs_recovery(s) ||
      ext2fs_has_feature_bigalloc(s) || ext2fs_has_feature_quota(s) ||
      ext2fs_has_feature_ea_inode(s) || ext2fs_has_feature_orphan_present(s) ||
      ext2fs_has_feature_inline_data(s) || ext2fs_has_feature_encrypt(s) ||
      ext2fs_has_feature_casefold(s) || ext2fs_has_feature_verity(s) ||
      ext2fs_has_feature_readonly(s) || ext2fs_has_feature_largedir(s))
    return EOPNOTSUPP;
  uint64_t free = ext2fs_free_blocks_count(s),
           reserved = ext2fs_r_blocks_count(s);
  uint64_t fields[10] = {fs->blocksize,
                         fs->blocksize,
                         ext2fs_blocks_count(s),
                         free,
                         free > reserved ? free - reserved : 0,
                         s->s_inodes_count,
                         s->s_free_inodes_count,
                         s->s_free_inodes_count,
                         255,
                         0};
  *data = calloc(80, 1);
  if (!*data)
    return ENOMEM;
  for (unsigned i = 0; i < 10; i++)
    put(*data + i * 8, fields[i]);
  *bytes = 80;
  return 0;
}
