/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_GRANT_H
#define EXPERIMENTAL_GRANT_H
#include "policy.h"
#define GRANT_READ 1
#define GRANT_WRITE 2
#define GRANT_APPEND 1
#define GRANT_DIRECTORY 2
#define GRANT_DIR_READ 4
#define GRANT_DIR_SEARCH 8
#define GRANT_UNSUPPORTED                                                      \
  (EXT2_COMPR_FL | EXT4_ENCRYPT_FL | EXT4_VERITY_FL | EXT4_INLINE_DATA_FL |    \
   EXT4_EA_INODE_FL)
struct inode_grant {
  uint32_t inode, generation, access, flags;
};
/* Trusted broker supplies open-time rights. Identity/flags are revalidated,
 * but mode/ACL grants are deliberately not reevaluated after open. */
int grant_valid(const struct inode_grant *grant);
/* Internal fast path: list must already have passed namespace_orphans in the
 * same immutable/staged filesystem context; never supply unvalidated lists. */
errcode_t grant_inode_known(ext2_filsys fs, const struct inode_grant *grant,
                            struct ext2_inode *inode, const ext2_ino_t *list,
                            unsigned count);
errcode_t grant_inode(ext2_filsys fs, const struct inode_grant *grant,
                      struct ext2_inode *inode);
#endif
