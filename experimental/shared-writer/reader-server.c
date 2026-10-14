/* SPDX-License-Identifier: GPL-2.0-only
 * Private pipe transport for one resident reader. No FUSE mount or writes.
 */
#include "handles.h"
#include "namespace.h"
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
static int valid_orphans(const char *image) {
  ext2_filsys fs = NULL;
  errcode_t e =
      ext2fs_open(image, EXT2_FLAG_64BITS, 0, 0, &staged_manager, &fs);
  if (!e && fs->super->s_last_orphan) {
    ext2_ino_t list[PIN_LIMIT];
    unsigned count;
    e = namespace_orphans(fs, list, &count);
  }
  if (fs)
    ext2fs_free(fs);
  return policy_errno(e);
}
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
  if (!active_overlay || valid_orphans(argv[1]) || reader_attach(argv[1]))
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
    int shape =
        op == 42   ? (pathlen || offset || length)
        : op == 37 ? (pathlen || offset || length)
        : op == 38 ? (pathlen < 9 || offset || length)
        : op == 39 ? (pathlen != 8 || !offset || offset > 255 || length)
        : op == 40 ? (pathlen != 8 || offset || length)
        : op == 41 ? (pathlen != 8 || offset > 7 || length)
        : op == 35 ? (pathlen < 9 || offset > 1 || length > 1)
        : op == 36 ? (pathlen != 8 || offset || length)
        : op == 30 ? (pathlen != 8 || offset || length)
        : op == 31 ? (pathlen < 9 || offset || length)
        : op == 32 ? (pathlen != 8 || offset || length)
        : op == 33 ? (pathlen < 16 || pathlen > 16 + 4 * POLICY_GROUPS ||
                      offset || length)
        : op == 34 ? (pathlen < 9 || offset > 7 || length)
        : op == 27 ? (pathlen != 12 || length < 8)
        : op == 28 ? (pathlen != 8 || length)
        : op == 29 ? (pathlen != 8 || offset || length)
        : op == 23 ? (pathlen || offset || length)
        : op == 24 ? (pathlen != 24 || offset || length)
        : op == 22 ? (pathlen < 9 || !offset || offset > 255 || length)
        : op == 25 ? (pathlen < 9 || offset > 1 || length)
        : op == 26 ? (pathlen < 9 || offset || length)
        : op == 21 ? (pathlen != 8 || offset || length)
        : op == 19 || op == 20 ? (pathlen < 9 || offset || length)
        : op == 18 ? (pathlen != 8 || (offset != 1 && offset != 4) || length)
        : op >= 15 && op <= 17 ? (pathlen != 8 || offset || length)
        : op == 14 ? (!pathlen || (offset != 1 && offset != 4) || length)
        : op == 13 ? (!pathlen || offset || length)
        : op == 12 ? (pathlen || offset || length)
        : op == 6  ? (pathlen < 16 || pathlen > 16 + 4 * POLICY_GROUPS ||
                      offset || length)
        : op == 7  ? (!pathlen || offset < 1 || offset > 3 || length > 1)
        : op >= 8  ? (pathlen != 8 || (op != 8 && (offset || length)))
        : op == 1 || op == 2 ? !pathlen
                             : (pathlen || offset || length);
    if (op < 1 || op > 42 ||
        pathlen > (op == 35 ? 4360
                   : (op == 19 || op == 20 || op == 22 || op == 25 ||
                      op == 26 || op == 31 || op == 34 || op == 38)
                       ? 4104
                       : 4096) ||
        length > READ_LIMIT || offset > INT64_MAX || shape ||
        (op == 1 && (offset || length))) {
      result = 2;
      break;
    }
    char path[4361];
    if (fread(path, 1, pathlen, stdin) != pathlen ||
        ((op <= 2 || op == 7 || op == 13 || op == 14) &&
         memchr(path, 0, pathlen))) {
      result = 2;
      break;
    }
    if ((op == 19 || op == 20 || op == 22 || op == 25 || op == 26 || op == 31 ||
         op == 34 || op == 38) &&
        memchr(path + 8, 0, pathlen - 8)) {
      result = 2;
      break;
    }
    path[pathlen] = 0;
    int e = 0;
    uint64_t size = 0;
    unsigned char *data = NULL, counts[16];
    size_t bytes = 0;
    if ((op >= 7 && op <= 12) || (op >= 14 && op != 33)) {
      e = handles_dispatch(argv[1], enforce ? &credentials : NULL, op,
                           (unsigned char *)path, pathlen, offset, length,
                           &size, &data, &bytes);
    } else if (op == 6 || op == 33) {
      e = enforce && op == 6
              ? EPERM
              : policy_decode((unsigned char *)path, pathlen, &credentials);
      if (!e)
        enforce = 1;
    } else if (op == 3) {
      overlay_suspend(active_overlay);
    } else if (op == 4) {
      e = overlay_publish(active_overlay);
      if (!e)
        e = valid_orphans(argv[1]);
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
          if (op == 13) {
            if (!S_ISLNK(st.st_mode))
              e = EINVAL;
            else if (!size || size > 4095)
              e = EIO;
            else {
              data = malloc(size + 1);
              if (!data)
                e = ENOMEM;
              else {
                ret = op_readlink(path, (char *)data, size + 1);
                if (ret < 0)
                  e = -ret;
                else
                  bytes = size;
              }
            }
          } else if (op == 2) {
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
  handles_destroy();
  overlay_close(active_overlay);
  return result;
}
