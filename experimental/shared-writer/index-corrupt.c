/* SPDX-License-Identifier: GPL-2.0-only */
/* Disposable fixture corruption only; never invoked by the production writer.
 */
#include <ext2fs/ext2fs.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  ext2_filsys fs;
  ext2_ino_t ino;
  struct ext2_inode in;
  blk64_t physical;
  unsigned char data[4096];
  errcode_t e;
  e = ext2fs_open(argv[1], EXT2_FLAG_RW | EXT2_FLAG_64BITS, 0, 0,
                  unix_io_manager, &fs);
  if (e)
    return 3;
  e = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, argv[2], &ino);
  if (!e)
    e = ext2fs_read_inode(fs, ino, &in);
  if (!e)
    e = ext2fs_bmap2(fs, ino, &in, NULL, 0, 0, NULL, &physical);
  if (!e)
    e = ext2fs_read_dir_block4(fs, physical, data, 0, ino);
  if (!e) {
    if (!strcmp(argv[3], "cycle"))
      memset(data + 36, 0, 4);
    else if (!strcmp(argv[3], "duplicate"))
      memcpy(data + 44, data + 36, 4);
    else if (!strcmp(argv[3], "range"))
      memset(data + 40, 0, 4);
    else {
      ext2fs_close(fs);
      return 4;
    }
    e = ext2fs_write_dir_block4(fs, physical, data, 0, ino);
  }
  errcode_t close = ext2fs_close(fs);
  if (e || close) {
    fprintf(stderr, "corrupt fixture: %ld/%ld\n", (long)e, (long)close);
    return 5;
  }
  return 0;
}
