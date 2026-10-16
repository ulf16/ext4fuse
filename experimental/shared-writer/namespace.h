/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_NAMESPACE_H
#define EXPERIMENTAL_NAMESPACE_H
#include "mutation.h"
#ifndef PIN_LIMIT
#define PIN_LIMIT 65536
#endif
#define ANCESTOR_LIMIT 128
struct inode_pin {
  uint32_t inode, generation;
};
/* Legacy orphan chain only; all entries must be allocated, zero-link regular
 * files, symlinks, special inodes or empty directories. The trusted session supplies a snapshot
 * of its live inode pins, sorted strictly by inode at the producer boundary. */
void namespace_index_stats(uint64_t *full, uint64_t *reused);
errcode_t namespace_index_check(ext2_filsys fs, ext2_ino_t ino);
errcode_t namespace_directory_parent(ext2_filsys fs, ext2_ino_t ino,
                                     ext2_ino_t *parent);
errcode_t namespace_orphans(ext2_filsys fs, ext2_ino_t *list, unsigned *count);
errcode_t namespace_reap(ext2_filsys fs, const struct inode_pin *pins,
                         unsigned count);
errcode_t namespace_apply(ext2_filsys fs, const struct mutation *op,
                          const struct credentials *credentials,
                          const struct inode_pin *pins, unsigned count);
#endif
