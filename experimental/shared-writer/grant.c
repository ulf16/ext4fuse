/* SPDX-License-Identifier: GPL-2.0-only */
#include "grant.h"
#include "namespace.h"
#include <errno.h>
int grant_valid(const struct inode_grant *g) {
  return !g || !g->inode || !g->access || g->access > 3 ||
                 g->flags > GRANT_APPEND ||
                 (g->flags && !(g->access & GRANT_WRITE))
             ? EINVAL
             : 0;
}
errcode_t grant_inode(ext2_filsys fs, const struct inode_grant *g,
                      struct ext2_inode *in) {
  if (fs->super->s_creator_os != EXT2_OS_LINUX)
    return EOPNOTSUPP;
  if (grant_valid(g))
    return EINVAL;
  if (g->inode < EXT2_FIRST_INODE(fs->super) ||
      g->inode > fs->super->s_inodes_count)
    return ESTALE;
  errcode_t e = fs->inode_map ? 0 : ext2fs_read_inode_bitmap(fs);
  if (e)
    return e;
  if (!ext2fs_test_inode_bitmap2(fs->inode_map, g->inode))
    return ESTALE;
  e = ext2fs_read_inode(fs, g->inode, in);
  if (e)
    return e;
  if (in->i_generation != g->generation ||
      (in->i_mode & LINUX_S_IFMT) != LINUX_S_IFREG)
    return ESTALE;
  if (!in->i_links_count) {
    ext2_ino_t list[PIN_LIMIT];
    unsigned n;
    int found = 0;
    e = namespace_orphans(fs, list, &n);
    if (e)
      return e;
    for (unsigned i = 0; i < n; i++)
      if (list[i] == g->inode)
        found = 1;
    if (!found)
      return ESTALE;
  } else if (in->i_dtime)
    return ESTALE;
  return in->i_flags & GRANT_UNSUPPORTED ? EOPNOTSUPP : 0;
}
