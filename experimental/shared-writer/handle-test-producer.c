/* SPDX-License-Identifier: GPL-2.0-only
 * Test-only metadata producer: not installed or exposed by Session APIs.
 */
#include "overlay.h"
#include <errno.h>
#include <ext2fs/ext2fs.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern struct struct_io_manager staged_manager;
int main(int argc, char **argv) {
  if (argc != 3 || strcmp(argv[2], "--stream"))
    return 2;
  const char *mode = getenv("EXT4_TEST_HANDLE_MODE"),
             *gen = getenv("EXT4_TEST_HANDLE_GENERATION"),
             *flags = getenv("EXT4_TEST_HANDLE_FLAGS"),
             *acl = getenv("EXT4_TEST_HANDLE_DROP_ACL"),
             *cap = getenv("EXT4_TEST_HANDLE_CAP"),
             *path = getenv("EXT4_TEST_HANDLE_PATH"),
             *number = getenv("EXT4_TEST_HANDLE_INODE"),
             *next = getenv("EXT4_TEST_HANDLE_ORPHAN_NEXT");
  if (!mode && !gen && !flags && !acl && !cap && !next)
    return 2;
  if (!path)
    path = "/existing-file";
  active_overlay = overlay_open(argv[1], 2048);
  if (!active_overlay)
    return 2;
  ext2_filsys fs = NULL;
  errcode_t e = ext2fs_open(argv[1], EXT2_FLAG_RW | EXT2_FLAG_64BITS, 0, 0,
                            &staged_manager, &fs);
  if (!e)
    e = ext2fs_read_bitmaps(fs);
  ext2_ino_t ino;
  if (!e && number)
    ino = strtoul(number, NULL, 0);
  else if (!e)
    e = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
  struct ext2_inode_large in = {0};
  unsigned bytes = fs ? EXT2_INODE_SIZE(fs->super) : 0;
  if (bytes > sizeof(in))
    bytes = sizeof(in);
  if (!e)
    e = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&in, bytes);
  if (!e) {
    if (mode)
      in.i_mode = LINUX_S_IFREG | (strtoul(mode, NULL, 0) & 07777);
    if (next)
      in.i_dtime = strtoul(next, NULL, 0);
    if (gen)
      in.i_generation = strtoul(gen, NULL, 0);
    if (flags)
      in.i_flags =
          (in.i_flags & ~(EXT2_IMMUTABLE_FL | EXT2_APPEND_FL)) |
          (strtoul(flags, NULL, 0) & (EXT2_IMMUTABLE_FL | EXT2_APPEND_FL));
    e = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&in, bytes);
  }
  if (!e && (acl || cap)) {
    struct ext2_xattr_handle *h = NULL;
    e = ext2fs_xattrs_open(fs, ino, &h);
    if (!e)
      e = ext2fs_xattrs_read(h);
    if (!e && acl) {
      e = ext2fs_xattr_remove(h, "system.posix_acl_access");
      if (e == EXT2_ET_EA_KEY_NOT_FOUND)
        e = 0;
    }
    if (!e && cap) {
      if (!strcmp(cap, "1"))
        e = ext2fs_xattr_set(h, "security.capability", "blocked", 7);
      else {
        e = ext2fs_xattr_remove(h, "security.capability");
        if (e == EXT2_ET_EA_KEY_NOT_FOUND)
          e = 0;
      }
    }
    if (h) {
      errcode_t close = ext2fs_xattrs_close(&h);
      if (!e)
        e = close;
    }
  }
  if (!e) {
    e = ext2fs_close(fs);
    fs = NULL;
  }
  if (!e)
    e = overlay_publish(active_overlay);
  if (!e)
    e = overlay_stream(active_overlay, STDOUT_FILENO);
  if (fs)
    ext2fs_free(fs);
  overlay_close(active_overlay);
  return e ? 1 : 0;
}
