/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXT4FUSE_ACL_H
#define EXT4FUSE_ACL_H
#include <stddef.h>
int ext4_acl_to_xattr(const unsigned char *disk, size_t bytes, char *out, size_t size);
#endif
