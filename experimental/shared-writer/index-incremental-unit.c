/* SPDX-License-Identifier: GPL-2.0-only */
#include "namespace.h"
#include "overlay.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
extern struct struct_io_manager staged_manager;
static unsigned u16(const unsigned char *p) { return p[0] | p[1] << 8; }
static uint32_t u32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
         (uint32_t)p[3] << 24;
}
static ext2_filsys attach(const char *path) {
  ext2_filsys fs = NULL;
  assert(!ext2fs_open(path, EXT2_FLAG_RW | EXT2_FLAG_64BITS, 0, 0,
                      &staged_manager, &fs));
  assert(!ext2fs_read_bitmaps(fs));
  return fs;
}
int main(int argc, char **argv) {
  assert(argc == 2 || argc == 3);
  int bounded = argc == 3;
  active_overlay = overlay_open(argv[1], 2048);
  assert(active_overlay);
  ext2_filsys fs = attach(argv[1]);
  ext2_ino_t ino, target;
  assert(!ext2fs_lookup(fs, EXT2_ROOT_INO, "many", 4, NULL, &ino));
  assert(!ext2fs_lookup(fs, ino, "scale-00000001", 14, NULL, &target));
  assert(!namespace_index_check(fs, ino));
  uint64_t initial, reused, after, reused_after;
  namespace_index_leaf_stats(&initial, &reused);
  assert(initial > 100 && !reused);
  assert(!ext2fs_link(fs, ino, "incremental-A", target, EXT2_FT_REG_FILE));
  assert(!namespace_index_check(fs, ino));
  namespace_index_leaf_stats(&after, &reused_after);
  uint64_t mutation_reads = after - initial;
  if (!bounded) {
    assert(after - initial <= 16);
    assert(reused_after >= initial - 16);
  }
  /* An unchanged cached leaf cannot hide a newly freed referenced inode. */
  ext2fs_inode_alloc_stats2(fs, target, -1, 0);
  assert(namespace_index_check(fs, ino));
  ext2fs_inode_alloc_stats2(fs, target, 1, 0);
  assert(!namespace_index_check(fs, ino));
  struct ext2_inode in;
  assert(!ext2fs_read_inode(fs, ino, &in));
  blk64_t root, physical;
  assert(!ext2fs_bmap2(fs, ino, &in, NULL, 0, 0, NULL, &root));
  /* Independently probe a leaf reached through the last index branch. */
  unsigned char buf[4096], saved[4096];
  assert(!ext2fs_read_dir_block4(fs, root, buf, 0, ino));
  unsigned levels = buf[30], off = 32;
  for (;;) {
    unsigned n = u16(buf + off + 2);
    assert(n);
    unsigned logical = u32(buf + off + (n - 1) * 8 + 4);
    assert(!ext2fs_bmap2(fs, ino, &in, NULL, 0, logical, NULL, &physical));
    assert(!ext2fs_read_dir_block4(fs, physical, buf, 0, ino));
    if (!levels)
      break;
    levels--;
    off = 8;
  }
  memcpy(saved, buf, fs->blocksize);
  unsigned first = 0, second = 0, found = 0;
  unsigned end = fs->blocksize - 12;
  for (unsigned a = 0; a < end && !found; a += u16(buf + a + 4)) {
    if (!u32(buf + a))
      continue;
    for (unsigned b = a + u16(buf + a + 4); b < end; b += u16(buf + b + 4))
      if (u32(buf + b) && u16(buf + b + 4) >= 8U + buf[a + 6]) {
        first = a;
        second = b;
        found = 1;
        break;
      }
  }
  assert(found);
  /* Repaired checksum: rejection must come from duplicate-name validation. */
  buf[second + 6] = buf[first + 6];
  memcpy(buf + second + 8, buf + first + 8, buf[first + 6]);
  assert(!ext2fs_write_dir_block4(fs, physical, buf, 0, ino));
  assert(namespace_index_check(fs, ino));
  assert(namespace_index_check(fs, ino));
  assert(!ext2fs_write_dir_block4(fs, physical, saved, 0, ino));
  assert(!namespace_index_check(fs, ino));
  /* Allocation is rechecked even when the physical leaf bytes are unchanged. */
  ext2fs_block_alloc_stats2(fs, physical, -1);
  assert(namespace_index_check(fs, ino));
  ext2fs_block_alloc_stats2(fs, physical, 1);
  assert(!namespace_index_check(fs, ino));
  ext2fs_free(fs);
  overlay_rollback(active_overlay);
  fs = attach(argv[1]);
  uint64_t before_reset, ignored;
  namespace_index_leaf_stats(&before_reset, &ignored);
  assert(!namespace_index_check(fs, ino));
  namespace_index_leaf_stats(&after, &ignored);
  assert(after - before_reset ==
         initial); /* Rollback cannot reuse certificates. */
  overlay_suspend(active_overlay);
  assert(!overlay_publish(active_overlay));
  before_reset = after;
  assert(!namespace_index_check(fs, ino));
  namespace_index_leaf_stats(&after, &ignored);
  assert(after - before_reset == initial);
  printf("{\"result\":\"passed\",\"bounded\":%s,\"initial_leaves\":%llu,"
         "\"mutation_leaf_reads\":%llu,\"mutation_leaf_reuses\":%llu}\n",
         bounded ? "true" : "false", (unsigned long long)initial,
         (unsigned long long)mutation_reads, (unsigned long long)reused_after);
  ext2fs_free(fs);
  overlay_close(active_overlay);
  return 0;
}
