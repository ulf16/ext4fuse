/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_POLICY_H
#define EXPERIMENTAL_POLICY_H
#include <ext2fs/ext2fs.h>
#include <stddef.h>
#include <stdint.h>
#define POLICY_GROUPS 64
#define POLICY_ACL_LIMIT 4096
struct credentials {
  uint32_t uid, gid, umask, ngroups, groups[POLICY_GROUPS];
};
/* Numeric identities are trusted input from a future frontend, not
 * authentication. Groups are strictly increasing; primary gid is included
 * implicitly. */
int policy_errno(errcode_t error);
int policy_credentials(const struct credentials *c);
int policy_decode(const unsigned char *data, size_t length,
                  struct credentials *c);
int policy_group(const struct credentials *c, uint32_t gid);
int policy_acl(const unsigned char *acl, size_t length, unsigned mode,
               uint32_t uid, uint32_t gid, const struct credentials *c,
               unsigned want);
int policy_inherit(unsigned char *acl, size_t length, unsigned requested,
                   unsigned *mode);
errcode_t policy_inode(ext2_filsys fs, ext2_ino_t ino,
                       const struct credentials *c, unsigned want);
errcode_t policy_path(ext2_filsys fs, const char *path,
                      const struct credentials *c, unsigned want,
                      ext2_ino_t *ino);
errcode_t policy_creation(ext2_filsys fs, ext2_ino_t parent,
                          const struct credentials *c, unsigned requested,
                          unsigned *mode, uint32_t *uid, uint32_t *gid,
                          unsigned char **acl, size_t *length);
errcode_t policy_writable(ext2_filsys fs, ext2_ino_t ino);
#endif
