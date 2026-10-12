/* SPDX-License-Identifier: GPL-2.0-only
 * Compile the unchanged production reader with a test-only pread interception.
 */
#include "overlay.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static ssize_t staged_pread(int fd, void *b, size_t n, off_t off) {
  (void)fd;
  if (off < 0) {
    errno = EINVAL;
    return -1;
  }
  int e = overlay_read(active_overlay, (uint64_t)off, n, b, 1);
  if (e) {
    errno = e;
    return -1;
  }
  return n;
}
#define pread staged_pread
#include "disk.c"
#undef pread
#include "inode.h"
#include "ops.h"
int reader_refresh(void) {
  int ready = overlay_read(active_overlay, 0, 0, NULL, 1);
  if (ready)
    return ready;
  if (super_fill() || super_group_fill() || inode_init())
    return EIO;
  return 0;
}
int reader_attach(const char *path) {
  if (!active_overlay || strcmp(path, overlay_path(active_overlay)))
    return EINVAL;
  if (disk_fd >= 0)
    close(disk_fd);
  if (disk_open(path))
    return EIO;
  return reader_refresh();
}
int reader_absent(const char *path) {
  int ready = overlay_read(active_overlay, 0, 0, NULL, 1);
  if (ready)
    return ready;
  struct stat st;
  int e = op_getattr(path, &st);
  return e == -ENOENT ? 0 : EIO;
}
int reader_verify(const char *path, const void *data, size_t n) {
  int ready = overlay_read(active_overlay, 0, 0, NULL, 1);
  if (ready)
    return ready;
  struct stat st;
  int e = op_getattr(path, &st);
  if (e || st.st_size != (off_t)n)
    return EIO;
  struct fuse_file_info fi = {0};
  if (op_open(path, &fi))
    return EIO;
  void *b = malloc(n ? n : 1);
  if (!b)
    return ENOMEM;
  size_t off = 0;
  while (off < n) {
    size_t len = n - off > 65536 ? 65536 : n - off;
    int got = op_read(path, (char *)b + off, len, off, &fi);
    if (got != (int)len) {
      free(b);
      return EIO;
    }
    off += len;
  }
  int same = !memcmp(data, b, n);
  free(b);
  return same ? 0 : EIO;
}

int reader_metadata(const char *path, uint64_t *size, unsigned *mode) {
  int e = overlay_read(active_overlay, 0, 0, NULL, 1);
  if (e)
    return e;
  struct ext4_inode inode;
  int ret = inode_get_by_path(path, &inode);
  if (ret < 0)
    return -ret;
  *size = inode_get_size(&inode);
  *mode = inode.i_mode;
  return *size > INT64_MAX ? EOVERFLOW : 0;
}
