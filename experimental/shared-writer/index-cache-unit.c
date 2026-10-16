/* SPDX-License-Identifier: GPL-2.0-only */
#include "namespace.h"
#include "overlay.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
extern struct struct_io_manager staged_manager;
int main(int argc, char **argv) {
  assert(argc == 2);
  active_overlay = overlay_open(argv[1], 32);
  assert(active_overlay);
  ext2_filsys fs = NULL;
  assert(!ext2fs_open(argv[1], EXT2_FLAG_64BITS, 0, 0, &staged_manager, &fs));
  assert(!ext2fs_read_bitmaps(fs));
  ext2_ino_t ino;
  assert(!ext2fs_lookup(fs, EXT2_ROOT_INO, "many", 4, NULL, &ino));
  assert(!namespace_index_check(fs, ino));
  for (unsigned i = 0; i < 1000; i++)
    assert(!namespace_index_check(fs, ino));
  uint64_t full, reused;
  namespace_index_stats(&full, &reused);
  assert(full == 1 && reused == 1000);
  struct ext2_inode in;
  assert(!ext2fs_read_inode(fs, ino, &in));
  blk64_t block;
  int flags;
  assert(!ext2fs_bmap2(fs, ino, &in, NULL, 0, 0, &flags, &block));
  unsigned char bad = 0;
  assert(!overlay_write(active_overlay, block * fs->blocksize, 1, &bad));
  assert(namespace_index_check(fs, ino));
  assert(namespace_index_check(fs, ino)); /* Errors must never be cached. */
  overlay_rollback(active_overlay);
  assert(!namespace_index_check(fs, ino));
  overlay_suspend(active_overlay);
  assert(!overlay_publish(active_overlay));
  assert(!namespace_index_check(fs, ino));
  namespace_index_stats(&full, &reused);
  assert(full == 5 && reused == 1000);
  /* In-memory hash policy changes must also invalidate an otherwise same view. */
  fs->super->s_hash_seed[0] ^= 1;
  assert(namespace_index_check(fs, ino));
  fs->super->s_hash_seed[0] ^= 1;
  assert(!namespace_index_check(fs, ino));
  ext2fs_free(fs);
  overlay_close(active_overlay);
  /* Reopening the same path/address cannot reuse a previous view's cache. */
  active_overlay = overlay_open(argv[1], 32);
  assert(active_overlay);
  assert(!ext2fs_open(argv[1], EXT2_FLAG_64BITS, 0, 0, &staged_manager, &fs));
  assert(!namespace_index_check(fs, ino));
  namespace_index_stats(&full, &reused);
  assert(full == 7 && reused == 1001);
  printf("{\"result\":\"passed\",\"full_scans\":%llu,\"reused\":%llu}\n",
         (unsigned long long)full, (unsigned long long)reused);
  ext2fs_free(fs);
  overlay_close(active_overlay);
  return 0;
}
