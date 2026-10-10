/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXT4FUSE_ACL_H
#define EXT4FUSE_ACL_H
#include <stddef.h>
int ext4_acl_to_xattr(const unsigned char *disk, size_t bytes, char *out, size_t size);
/* Resolver maps a numeric POSIX identity to a native UUID; errors fail closed. */
typedef int (*ext4_acl_uuid_fn)(int group, unsigned id, unsigned char uuid[16]);
int ext4_acl_to_macos(const unsigned char *disk, size_t bytes, unsigned mode,
                      char *out, size_t size, ext4_acl_uuid_fn resolve);
#endif
