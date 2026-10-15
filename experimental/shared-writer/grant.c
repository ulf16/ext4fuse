/* SPDX-License-Identifier: GPL-2.0-only */
#include "grant.h"
#include "namespace.h"
#include <errno.h>
int grant_valid(const struct inode_grant *g) {
  if (!g || !g->inode)
    return EINVAL;
  if (g->flags == GRANT_NODE)
    return g->access ? EINVAL : 0;
  if (g->flags == GRANT_DIRECTORY)
    return g->access == GRANT_DIR_READ || g->access == GRANT_DIR_SEARCH ||
                   g->access == (GRANT_DIR_READ | GRANT_DIR_SEARCH)
               ? 0
               : EINVAL;
  return !g->access || g->access > 3 || g->flags > GRANT_APPEND ||
                 (g->flags && !(g->access & GRANT_WRITE))
             ? EINVAL
             : 0;
}
static errcode_t identity(ext2_filsys fs, const struct inode_grant *g,
                          struct ext2_inode *in) {
  if (fs->super->s_creator_os != EXT2_OS_LINUX)
    return EOPNOTSUPP;
  if (grant_valid(g))
    return EINVAL;
  if ((g->inode < EXT2_FIRST_INODE(fs->super) &&
       !(g->inode == EXT2_ROOT_INO &&
         (g->flags == GRANT_DIRECTORY || g->flags == GRANT_NODE))) ||
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
  unsigned type = in->i_mode & LINUX_S_IFMT;
  if (in->i_generation != g->generation ||
      (g->flags == GRANT_NODE
           ? (type != LINUX_S_IFREG && type != LINUX_S_IFLNK &&
              !special_type(type))
           : type !=
                 (g->flags == GRANT_DIRECTORY ? LINUX_S_IFDIR : LINUX_S_IFREG)))
    return ESTALE;
  if (in->i_links_count && in->i_dtime)
    return ESTALE;
  if (g->flags == GRANT_DIRECTORY && in->i_links_count == 1)
    return EIO;
  if (g->flags == GRANT_DIRECTORY && (in->i_flags & (EXT4_CASEFOLD_FL)))
    return EOPNOTSUPP;
  if (g->flags == GRANT_DIRECTORY && (e = namespace_index_check(fs, g->inode)))
    return e;
  return in->i_flags & GRANT_UNSUPPORTED ? EOPNOTSUPP : 0;
}
static errcode_t member(const struct inode_grant *g,
                        const struct ext2_inode *in, const ext2_ino_t *list,
                        unsigned n) {
  if (in->i_links_count)
    return 0;
  for (unsigned i = 0; i < n; i++)
    if (list[i] == g->inode)
      return 0;
  return ESTALE;
}
errcode_t grant_inode_known(ext2_filsys fs, const struct inode_grant *g,
                            struct ext2_inode *in, const ext2_ino_t *list,
                            unsigned n) {
  if (n > PIN_LIMIT || (n && !list))
    return EINVAL;
  errcode_t e = identity(fs, g, in);
  return e ? e : member(g, in, list, n);
}
errcode_t grant_inode(ext2_filsys fs, const struct inode_grant *g,
                      struct ext2_inode *in) {
  errcode_t e = identity(fs, g, in);
  if (e || in->i_links_count)
    return e;
  ext2_ino_t list[PIN_LIMIT];
  unsigned n;
  e = namespace_orphans(fs, list, &n);
  return e ? e : member(g, in, list, n);
}
