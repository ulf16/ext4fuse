/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_METADATA_H
#define EXPERIMENTAL_METADATA_H
#include "mutation.h"
#define METADATA_LIMIT 65536
errcode_t metadata_apply(ext2_filsys fs, const struct mutation *op,
                         const struct credentials *c,
                         const struct inode_grant *g);
errcode_t metadata_query(ext2_filsys fs, ext2_ino_t ino,
                         const struct credentials *c, const char *name,
                         unsigned char **data, size_t *bytes);
#endif
