/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_MUTATION_H
#define EXPERIMENTAL_MUTATION_H
#include <ext2fs/ext2fs.h>
#include <stddef.h>
#include <stdint.h>
enum mutation_kind { MUT_WRITE = 1, MUT_TRUNCATE = 2, MUT_CREATE = 3 };
struct mutation {
  enum mutation_kind kind;
  const char *path;
  uint64_t offset;
  const void *data;
  size_t length;
  uint32_t mode, uid, gid;
};
/* Caller owns the staged transaction. Any error requires discarding the entire
 * writer handle and overlay; never publish partially applied operations. */
errcode_t mutation_apply(ext2_filsys fs, const struct mutation *operation);
#endif
