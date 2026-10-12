/* SPDX-License-Identifier: GPL-2.0-only
 * Private pipe transport for one resident reader. No FUSE mount or writes.
 */
#include "ops.h"
#include "overlay.h"
#include "policy.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
extern struct struct_io_manager staged_manager;
static int authorize(const char *image, const char *path,
                     const struct credentials *c, unsigned want) {
  ext2_filsys fs = NULL;
  errcode_t e =
      ext2fs_open(image, EXT2_FLAG_64BITS, 0, 0, &staged_manager, &fs);
  ext2_ino_t ino;
  if (!e)
    e = policy_path(fs, path, c, want, &ino);
  if (fs)
    ext2fs_free(fs);
  return policy_errno(e);
}
static int numeric_stat(const char *path, struct stat *st) {
  /* Numeric POSIX policy is independent of host UUID/Apple ACL translation. */
  uint64_t size;
  unsigned mode;
  int e = reader_metadata(path, &size, &mode);
  if (e)
    return -e;
  memset(st, 0, sizeof(*st));
  st->st_mode = mode;
  st->st_size = size;
  return 0;
}
#define READ_LIMIT (1024 * 1024)
static uint64_t get_le(const unsigned char *p, unsigned n) {
  uint64_t v = 0;
  for (unsigned i = 0; i < n; i++)
    v |= (uint64_t)p[i] << (i * 8);
  return v;
}
static void put_le(unsigned char *p, uint64_t v, unsigned n) {
  for (unsigned i = 0; i < n; i++)
    p[i] = v >> (i * 8);
}
static int reply(int error, uint64_t size, const void *data, size_t length) {
  unsigned char header[32] = "E4RP0001";
  put_le(header + 8, error, 4);
  put_le(header + 16, size, 8);
  put_le(header + 24, length, 8);
  return fwrite(header, 1, sizeof(header), stdout) != sizeof(header) ||
         (length && fwrite(data, 1, length, stdout) != length) ||
         fflush(stdout);
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  active_overlay = overlay_open(argv[1], 1);
  if (!active_overlay || reader_attach(argv[1]))
    return 2;
  unsigned char header[32];
  int result = 0, enforce = 0;
  struct credentials credentials = {0};
  for (;;) {
    size_t got = fread(header, 1, sizeof(header), stdin);
    if (!got && feof(stdin))
      break;
    if (got != sizeof(header) || memcmp(header, "E4RD0001", 8)) {
      result = 2;
      break;
    }
    uint32_t op = get_le(header + 8, 4), pathlen = get_le(header + 12, 4);
    uint64_t offset = get_le(header + 16, 8), length = get_le(header + 24, 8);
    if (op < 1 || op > 6 || pathlen > 4096 || length > READ_LIMIT ||
        offset > INT64_MAX ||
        (op == 6 ? (pathlen < 16 || pathlen > 16 + 4 * POLICY_GROUPS ||
                    offset || length)
                 : ((op == 1 || op == 2) ? !pathlen
                                         : (pathlen || offset || length))) ||
        (op == 1 && (offset || length))) {
      result = 2;
      break;
    }
    char path[4097];
    if (fread(path, 1, pathlen, stdin) != pathlen ||
        (op != 6 && memchr(path, 0, pathlen))) {
      result = 2;
      break;
    }
    path[pathlen] = 0;
    int e = 0;
    uint64_t size = 0;
    unsigned char *data = NULL, counts[16];
    size_t bytes = 0;
    if (op == 6) {
      e = enforce ? EPERM
                  : policy_decode((unsigned char *)path, pathlen, &credentials);
      if (!e)
        enforce = 1;
    } else if (op == 3) {
      overlay_suspend(active_overlay);
    } else if (op == 4) {
      e = overlay_publish(active_overlay);
      if (!e)
        e = reader_refresh();
      if (e)
        overlay_suspend(active_overlay);
    } else {
      /* Gate before even a cached inode lookup or statfs. */
      e = overlay_read(active_overlay, 0, 0, NULL, 1);
      if (!e && enforce)
        e = authorize(argv[1], op == 5 ? "/" : path, &credentials,
                      op == 2 ? 4 : 0);
      if (!e && op == 5) {
        struct statvfs st;
        int ret = op_statfs("/", &st);
        if (ret < 0)
          e = -ret;
        else {
          put_le(counts, st.f_bfree, 8);
          put_le(counts + 8, st.f_ffree, 8);
          bytes = sizeof(counts);
        }
      } else if (!e) {
        struct stat st;
        int ret = enforce ? numeric_stat(path, &st) : op_getattr(path, &st);
        if (ret < 0)
          e = -ret;
        else {
          size = st.st_size;
          if (op == 2) {
            if (!S_ISREG(st.st_mode))
              e = S_ISDIR(st.st_mode) ? EISDIR : EOPNOTSUPP;
            else {
              struct fuse_file_info fi = {0};
              ret = op_open(path, &fi);
              if (ret < 0)
                e = -ret;
              else {
                data = malloc(length ? length : 1);
                if (!data)
                  e = ENOMEM;
                else {
                  ret = op_read(path, (char *)data, length, offset, &fi);
                  if (ret < 0)
                    e = -ret;
                  else
                    bytes = ret;
                }
              }
            }
          }
        }
      }
    }
    if (reply(e, e ? 0 : size, e ? NULL : (op == 5 ? counts : data),
              e ? 0 : bytes)) {
      free(data);
      result = 2;
      break;
    }
    free(data);
  }
  overlay_close(active_overlay);
  return result;
}
