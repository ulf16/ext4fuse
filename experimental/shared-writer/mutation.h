/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_MUTATION_H
#define EXPERIMENTAL_MUTATION_H
#include "grant.h"
#include "policy.h"
#include <ext2fs/ext2fs.h>
#include <stddef.h>
#include <stdint.h>
enum mutation_kind {
  MUT_WRITE = 1,
  MUT_TRUNCATE = 2,
  MUT_CREATE = 3,
  MUT_LINK = 4,
  MUT_RENAME = 5,
  MUT_UNLINK = 6,
  MUT_MKDIR = 7,
  MUT_RMDIR = 8,
  MUT_SYMLINK = 9,
  MUT_OPEN = 10,
  MUT_CHMOD = 11,
  MUT_CHOWN = 12,
  MUT_UTIMENS = 13,
  MUT_SETXATTR = 14,
  MUT_REMOVEXATTR = 15
};
struct mutation {
  enum mutation_kind kind;
  const char *path;
  uint64_t offset;
  const void *data;
  size_t length;
  uint32_t mode, uid, gid;
  int at;
  unsigned at_flags;
  struct inode_grant base, target_base;
};
/* Caller owns the staged transaction. Any error requires discarding the entire
 * writer handle and overlay; never publish partially applied operations. */
errcode_t mutation_parent(ext2_filsys fs, const char *path, ext2_ino_t *dir,
                          char **leaf, const struct credentials *credentials);
errcode_t mutation_parent_at(ext2_filsys fs, const struct mutation *op,
                             const char *path, int target, ext2_ino_t *dir,
                             char **leaf, const struct credentials *c);
#define OPEN_APPEND 4
#define OPEN_CREATE 8
#define OPEN_EXCL 16
#define OPEN_TRUNC 32
#define OPEN_NOFOLLOW 64
#define OPEN_DIRECTORY 128
errcode_t mutation_open_at(ext2_filsys fs, const struct mutation *op,
                           const struct credentials *c,
                           struct inode_grant *grant);
errcode_t mutation_apply(ext2_filsys fs, const struct mutation *operation);
errcode_t mutation_apply_as(ext2_filsys fs, const struct mutation *operation,
                            const struct credentials *credentials);
errcode_t mutation_apply_grant(ext2_filsys fs, const struct mutation *operation,
                               const struct credentials *credentials,
                               const struct inode_grant *grant);
#endif
