/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_DIRECTORY_REF_H
#define EXPERIMENTAL_DIRECTORY_REF_H
#include "namespace.h"
errcode_t directory_walk(ext2_filsys fs, ext2_ino_t start, const char *path,
                         const struct credentials *credentials,
                         ext2_ino_t *result);
errcode_t directory_path(ext2_filsys fs, ext2_ino_t ino, unsigned char **path,
                         size_t *bytes);
errcode_t directory_names(ext2_filsys fs, ext2_ino_t ino, unsigned char **data,
                          size_t *bytes);
#endif
