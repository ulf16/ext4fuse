/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_MOUNT_METADATA_H
#define EXPERIMENTAL_MOUNT_METADATA_H
#include "path-at.h"
errcode_t mount_inode_stat(ext2_filsys fs, ext2_ino_t ino, unsigned char **data,
                           size_t *bytes);
errcode_t mount_geometry(ext2_filsys fs, unsigned char **data, size_t *bytes);
#endif
