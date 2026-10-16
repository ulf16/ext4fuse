/* SPDX-License-Identifier: GPL-2.0-only */
#include "namespace.h"
#include "overlay.h"
#include <assert.h>
#include <stdio.h>
extern struct struct_io_manager staged_manager;
int main(int argc, char **argv) {
  assert(argc == 3);
  unsigned failures = 0, succeeded = 0;
  uint64_t oldsize = 0, newsize = 0;
  const long boundaries[] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024};
  for (unsigned i = 0; i < sizeof(boundaries) / sizeof(*boundaries); i++) {
    active_overlay = overlay_open(argv[1], 2048);
    assert(active_overlay);
    ext2_filsys fs = NULL;
    ext2_ino_t ino;
    struct ext2_inode in;
    assert(!ext2fs_open(argv[1], EXT2_FLAG_RW | EXT2_FLAG_64BITS, 0, 0,
                        &staged_manager, &fs));
    assert(!ext2fs_read_bitmaps(fs));
    assert(!ext2fs_lookup(fs, EXT2_ROOT_INO, "sparse", 6, NULL, &ino));
    assert(!ext2fs_read_inode(fs, ino, &in));
    assert(!(in.i_flags & EXT2_INDEX_FL));
    oldsize = EXT2_I_SIZE(&in);
    overlay_fail_writes(active_overlay, boundaries[i]);
    errcode_t e = namespace_index_convert(fs, ino);
    if (!e) {
      e = ext2fs_close_free(&fs);
    }
    if (!e) {
      assert(!overlay_publish(active_overlay));
      assert(!overlay_export(active_overlay, argv[2], -1));
      succeeded = 1;
      overlay_close(active_overlay);
      break;
    }
    if (fs)
      ext2fs_free(fs);
    assert(overlay_publish(active_overlay));
    failures++;
    overlay_rollback(active_overlay);
    overlay_close(active_overlay);
  }
  assert(succeeded && failures >= 5);
  ext2_filsys out = NULL;
  ext2_ino_t ino;
  struct ext2_inode in;
  assert(!ext2fs_open(argv[2], EXT2_FLAG_64BITS, 0, 0, unix_io_manager, &out));
  assert(!ext2fs_lookup(out, EXT2_ROOT_INO, "sparse", 6, NULL, &ino));
  assert(!ext2fs_read_inode(out, ino, &in));
  assert(in.i_flags & EXT2_INDEX_FL);
  newsize = EXT2_I_SIZE(&in);
  assert(newsize < oldsize);
  ext2fs_free(out);
  printf("{\"result\":\"passed\",\"failed_write_boundaries\":%u,\"old_size\":%"
         "llu,\"new_size\":%llu}\n",
         failures, (unsigned long long)oldsize, (unsigned long long)newsize);
  return 0;
}
