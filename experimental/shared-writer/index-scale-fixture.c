/* SPDX-License-Identifier: GPL-2.0-only
 * Test-only offline fixture growth; never linked into the mounted writer. */
#include <ext2fs/ext2fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  unsigned count = strtoul(argv[2], NULL, 10);
  if (!count || count > 1048577)
    return 2;
  ext2_filsys fs = NULL;
  errcode_t e = ext2fs_open(argv[1], EXT2_FLAG_RW | EXT2_FLAG_64BITS, 0, 0,
                           unix_io_manager, &fs);
  ext2_ino_t dir;
  if (!e)
    e = ext2fs_read_bitmaps(fs);
  if (!e)
    e = ext2fs_lookup(fs, EXT2_ROOT_INO, "many", 4, NULL, &dir);
  struct ext2_inode parent;
  if (!e)
    e = ext2fs_read_inode(fs, dir, &parent);
  if (!e && !(parent.i_flags & EXT2_INDEX_FL))
    e = 1;
  for (unsigned i = 0; !e && i < count; i++) {
    char name[32];
    snprintf(name, sizeof(name), "scale-%08u", i);
    ext2_ino_t ino;
    e = ext2fs_new_inode(fs, dir, LINUX_S_IFREG | 0644, NULL, &ino);
    struct ext2_inode in = {0};
    in.i_mode = LINUX_S_IFREG | 0644;
    in.i_links_count = 1;
    in.i_generation = i + 1;
    if (!e) {
      ext2fs_inode_alloc_stats2(fs, ino, 1, 0);
      e = ext2fs_write_new_inode(fs, ino, &in);
    }
    if (!e)
      e = ext2fs_link(fs, dir, name, ino, EXT2_FT_REG_FILE);
  }
  if (!e)
    e = ext2fs_close(fs);
  else if (fs)
    ext2fs_free(fs);
  if (e)
    fprintf(stderr, "fixture growth failed: %ld\n", (long)e);
  return e ? 1 : 0;
}
