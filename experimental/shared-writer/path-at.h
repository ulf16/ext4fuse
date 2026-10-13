/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_PATH_AT_H
#define EXPERIMENTAL_PATH_AT_H
#include "namespace.h"
#define AT_FOLLOW 1
#define AT_MISSING 2
#define AT_PARENT 4
struct path_result {
  ext2_ino_t inode, parent;
  char leaf[256];
  int trailing;
};
errcode_t path_at(ext2_filsys fs, ext2_ino_t start, const char *path,
                  const struct credentials *c, unsigned flags,
                  struct path_result *result);
errcode_t path_base(ext2_filsys fs, const struct inode_grant *base,
                    const char *path, ext2_ino_t *ino);
errcode_t path_readlink(ext2_filsys fs, ext2_ino_t ino, char **target,
                        size_t *bytes);
#endif
