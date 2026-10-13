/* SPDX-License-Identifier: GPL-2.0-only */
#include "handles.h"
#include "namespace.h"
#include "ops.h"
#include "overlay.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
extern struct struct_io_manager staged_manager;
#define HANDLE_LIMIT 128
struct handle {
  uint64_t token;
  struct inode_grant grant;
  int stale;
};
static struct handle table[HANDLE_LIMIT];
static uint64_t last_token;
static uint64_t le(const unsigned char *p, unsigned n) {
  uint64_t v = 0;
  for (unsigned i = 0; i < n; i++)
    v |= (uint64_t)p[i] << (8 * i);
  return v;
}
static void put(unsigned char *p, uint64_t v, unsigned n) {
  for (unsigned i = 0; i < n; i++)
    p[i] = v >> (8 * i);
}
int handles_dispatch(const char *image, const struct credentials *c,
                     unsigned command, const unsigned char *path, size_t bytes,
                     uint64_t offset, uint64_t length, uint64_t *size,
                     unsigned char **data, size_t *count) {
  if (!c && command != 12)
    return EPERM;
  struct handle *h = NULL;
  if (command != 7 && command != 12) {
    if (bytes != 8)
      return EINVAL;
    uint64_t token = le(path, 8);
    for (unsigned i = 0; i < HANDLE_LIMIT; i++)
      if (table[i].token && table[i].token == token) {
        h = &table[i];
        break;
      }
    if (!h)
      return EBADF;
    if (command == 10) {
      memset(h, 0, sizeof(*h));
      return 0;
    }
    if (h->stale)
      return ESTALE;
  }
  int ready = overlay_read(active_overlay, 0, 0, NULL, 1);
  if (ready)
    return ready;
  ext2_filsys fs = NULL;
  errcode_t e =
      ext2fs_open(image, EXT2_FLAG_64BITS, 0, 0, &staged_manager, &fs);
  struct ext2_inode in = {0};
  if (!e && command == 7) {
    if (!offset || offset > 3 || length > 1 ||
        (length && !(offset & GRANT_WRITE)))
      e = EINVAL;
    for (unsigned i = 0; !h && i < HANDLE_LIMIT; i++)
      if (!table[i].token)
        h = &table[i];
    if (!e && (!h || last_token == UINT64_MAX))
      e = EMFILE;
    ext2_ino_t ino = 0;
    unsigned want =
        (offset & GRANT_READ ? 4 : 0) | (offset & GRANT_WRITE ? 2 : 0);
    if (!e)
      e = policy_path(fs, (const char *)path, c, want, &ino);
    if (!e)
      e = ext2fs_read_inode(fs, ino, &in);
    if (!e && (in.i_mode & LINUX_S_IFMT) != LINUX_S_IFREG)
      e = (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFDIR   ? EISDIR
          : (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFLNK ? ELOOP
                                                        : EOPNOTSUPP;
    struct inode_grant g = {ino, in.i_generation, offset, length};
    if (!e)
      e = grant_inode(fs, &g, &in);
    if (!e && (offset & GRANT_WRITE)) {
      if (in.i_flags & EXT2_IMMUTABLE_FL)
        e = EPERM;
      else if ((in.i_flags & EXT2_APPEND_FL) && !length)
        e = EPERM;
      else
        e = policy_writable(fs, ino);
    }
    if (!e) {
      *data = calloc(24, 1);
      if (!*data)
        e = ENOMEM;
      else {
        h->grant = g;
        h->token = ++last_token;
        h->stale = 0;
        put(*data, h->token, 8);
        put(*data + 8, g.inode, 4);
        put(*data + 12, g.generation, 4);
        put(*data + 16, g.access, 4);
        put(*data + 20, g.flags, 4);
        *count = 24;
        *size = EXT2_I_SIZE(&in);
      }
    }
  } else if (!e && command == 12) {
    *data = calloc(PIN_LIMIT * 8, 1);
    if (!*data)
      e = ENOMEM;
    ext2_ino_t seen[PIN_LIMIT];
    unsigned n = 0;
    for (unsigned i = 0; !e && i < HANDLE_LIMIT; i++) {
      if (!table[i].token || table[i].stale)
        continue;
      e = grant_inode(fs, &table[i].grant, &in);
      if (e == ESTALE) {
        table[i].stale = 1;
        e = 0;
        continue;
      }
      if (e)
        break;
      int duplicate = 0;
      for (unsigned j = 0; j < n; j++)
        if (seen[j] == table[i].grant.inode)
          duplicate = 1;
      if (duplicate)
        continue;
      seen[n] = table[i].grant.inode;
      put(*data + n * 8, table[i].grant.inode, 4);
      put(*data + n * 8 + 4, table[i].grant.generation, 4);
      n++;
    }
    if (!e) {
      *count = n * 8;
      *size = fs->super->s_last_orphan;
    }
  } else if (!e) {
    e = grant_inode(fs, &h->grant, &in);
    if (e == ESTALE)
      h->stale = 1;
    if (!e && ((command == 8 && !(h->grant.access & GRANT_READ)) ||
               (command == 11 && !(h->grant.access & GRANT_WRITE))))
      e = EBADF;
    if (!e)
      *size = EXT2_I_SIZE(&in);
    if (!e && command == 11) {
      *data = calloc(16, 1);
      if (!*data)
        e = ENOMEM;
      else {
        put(*data, h->grant.inode, 4);
        put(*data + 4, h->grant.generation, 4);
        put(*data + 8, h->grant.access, 4);
        put(*data + 12, h->grant.flags, 4);
        *count = 16;
      }
    }
    if (!e && command == 8) {
      *data = malloc(length ? length : 1);
      if (!*data)
        e = ENOMEM;
      else {
        struct fuse_file_info fi = {.fh = h->grant.inode};
        int got = op_read("", (char *)*data, length, offset, &fi);
        if (got < 0)
          e = -got;
        else
          *count = got;
      }
    }
  }
  if (fs)
    ext2fs_free(fs);
  return policy_errno(e);
}
