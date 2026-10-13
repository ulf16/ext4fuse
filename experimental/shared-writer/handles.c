/* SPDX-License-Identifier: GPL-2.0-only */
#include "handles.h"
#include "directory-ref.h"
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
static errcode_t add_pin(struct inode_pin *pins, unsigned *count,
                         ext2_ino_t ino, uint32_t generation) {
  if (ino == EXT2_ROOT_INO)
    return 0;
  for (unsigned i = 0; i < *count; i++)
    if (pins[i].inode == ino)
      return pins[i].generation == generation ? 0 : ESTALE;
  if (*count == PIN_LIMIT)
    return EMFILE;
  pins[*count] = (struct inode_pin){ino, generation};
  (*count)++;
  return 0;
}
static errcode_t pin_snapshot(ext2_filsys fs, struct inode_pin *pins,
                              unsigned *count) {
  *count = 0;
  ext2_ino_t orphans[PIN_LIMIT];
  unsigned orphan_count;
  errcode_t valid = namespace_orphans(fs, orphans, &orphan_count);
  if (valid)
    return valid;
  for (unsigned i = 0; i < HANDLE_LIMIT; i++) {
    struct handle *h = &table[i];
    if (!h->token || h->stale)
      continue;
    struct ext2_inode in;
    errcode_t e = grant_inode_known(fs, &h->grant, &in, orphans, orphan_count);
    if (e == ESTALE) {
      h->stale = 1;
      continue;
    }
    if (e)
      return e;
    int captured = 0;
    for (unsigned j = 0; j < *count; j++)
      if (pins[j].inode == h->grant.inode)
        captured = 1;
    e = add_pin(pins, count, h->grant.inode, in.i_generation);
    if (e)
      return e;
    if (h->grant.flags != GRANT_DIRECTORY || captured)
      continue;
    ext2_ino_t node = h->grant.inode, seen[PIN_LIMIT];
    unsigned depth = 0;
    while (node != EXT2_ROOT_INO) {
      if (depth == PIN_LIMIT)
        return EMFILE;
      for (unsigned j = 0; j < depth; j++)
        if (seen[j] == node)
          return EIO;
      seen[depth++] = node;
      e = namespace_directory_parent(fs, node, &node);
      if (e)
        return e;
      e = ext2fs_read_inode(fs, node, &in);
      if (e)
        return e;
      struct inode_grant parent = {node, in.i_generation, GRANT_DIR_SEARCH,
                                   GRANT_DIRECTORY};
      e = grant_inode_known(fs, &parent, &in, orphans, orphan_count);
      if (e)
        return e;
      e = add_pin(pins, count, node, in.i_generation);
      if (e)
        return e;
    }
  }
  return 0;
}
static errcode_t allocate(ext2_filsys fs, const struct inode_grant *g,
                          uint64_t *size, unsigned char **data, size_t *count) {
  struct handle *h = NULL;
  for (unsigned i = 0; !h && i < HANDLE_LIMIT; i++)
    if (!table[i].token)
      h = &table[i];
  if (!h || last_token == UINT64_MAX)
    return EMFILE;
  struct ext2_inode in;
  errcode_t e = grant_inode(fs, g, &in);
  if (e)
    return e;
  h->grant = *g;
  h->stale = 0;
  h->token = ++last_token;
  struct inode_pin pins[PIN_LIMIT];
  unsigned n;
  e = pin_snapshot(fs, pins, &n);
  if (e) {
    memset(h, 0, sizeof(*h));
    return e;
  }
  *data = calloc(24, 1);
  if (!*data) {
    memset(h, 0, sizeof(*h));
    return ENOMEM;
  }
  put(*data, h->token, 8);
  put(*data + 8, g->inode, 4);
  put(*data + 12, g->generation, 4);
  put(*data + 16, g->access, 4);
  put(*data + 20, g->flags, 4);
  *count = 24;
  *size = EXT2_I_SIZE(&in);
  return 0;
}
int handles_dispatch(const char *image, const struct credentials *c,
                     unsigned command, const unsigned char *path, size_t bytes,
                     uint64_t offset, uint64_t length, uint64_t *size,
                     unsigned char **data, size_t *count) {
  if (!c && command != 12)
    return EPERM;
  struct handle *h = NULL, root = {0};
  int root_request = 0;
  if (command != 7 && command != 12 && command != 14) {
    if ((command == 19 || command == 20) ? bytes < 9 : bytes != 8)
      return EINVAL;
    uint64_t token = le(path, 8);
    if (!token &&
        (command == 15 || command == 17 || command == 19 || command == 20))
      root_request = 1;
    else {
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
  }
  int ready = overlay_read(active_overlay, 0, 0, NULL, 1);
  if (ready)
    return ready;
  ext2_filsys fs = NULL;
  errcode_t e =
      ext2fs_open(image, EXT2_FLAG_64BITS, 0, 0, &staged_manager, &fs);
  if (!e)
    e = ext2fs_read_inode_bitmap(fs);
  struct ext2_inode in = {0};
  if (!e && root_request) {
    e = ext2fs_read_inode(fs, EXT2_ROOT_INO, &in);
    root.grant = (struct inode_grant){EXT2_ROOT_INO, in.i_generation,
                                      GRANT_DIR_SEARCH, GRANT_DIRECTORY};
    h = &root;
  }
  if (!e && (command == 7 || command == 14)) {
    int directory = command == 14;
    if (directory ? (offset != 1 && offset != 4) || length
                  : (!offset || offset > 3 || length > 1 ||
                     (length && !(offset & GRANT_WRITE))))
      e = EINVAL;
    ext2_ino_t ino = 0;
    unsigned want = directory ? offset
                              : (offset & GRANT_READ ? 4 : 0) |
                                    (offset & GRANT_WRITE ? 2 : 0);
    if (!e)
      e = policy_path(fs, (const char *)path, c, want, &ino);
    if (!e)
      e = ext2fs_read_inode(fs, ino, &in);
    if (!e && (!in.i_links_count || in.i_dtime))
      e = ESTALE;
    if (!e && (in.i_mode & LINUX_S_IFMT) !=
                  (directory ? LINUX_S_IFDIR : LINUX_S_IFREG))
      e = (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFLNK   ? ELOOP
          : directory                                   ? ENOTDIR
          : (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFDIR ? EISDIR
                                                        : EOPNOTSUPP;
    struct inode_grant g = {
        ino, in.i_generation,
        directory ? (offset == 4 ? GRANT_DIR_READ : GRANT_DIR_SEARCH) : offset,
        directory ? GRANT_DIRECTORY : length};
    if (!e)
      e = grant_inode(fs, &g, &in);
    if (!e && !directory && (offset & GRANT_WRITE)) {
      if (in.i_flags & EXT2_IMMUTABLE_FL)
        e = EPERM;
      else if ((in.i_flags & EXT2_APPEND_FL) && !length)
        e = EPERM;
      else
        e = policy_writable(fs, ino);
    }
    if (!e)
      e = allocate(fs, &g, size, data, count);
  } else if (!e && command == 12) {
    struct inode_pin pins[PIN_LIMIT];
    unsigned n;
    e = pin_snapshot(fs, pins, &n);
    if (!e) {
      *data = calloc(n ? n * 8 : 1, 1);
      if (!*data)
        e = ENOMEM;
      else {
        for (unsigned i = 0; i < n; i++) {
          put(*data + i * 8, pins[i].inode, 4);
          put(*data + i * 8 + 4, pins[i].generation, 4);
        }
        *count = n * 8;
        *size = fs->super->s_last_orphan;
      }
    }
  } else if (!e) {
    e = grant_inode(fs, &h->grant, &in);
    if (e == ESTALE)
      h->stale = 1;
    int directory = h->grant.flags == GRANT_DIRECTORY;
    if (!e && command >= 15 && !directory)
      e = ENOTDIR;
    if (!e && directory && (command == 8 || command == 11))
      e = EISDIR;
    if (!e && ((command == 8 && !(h->grant.access & GRANT_READ)) ||
               (command == 11 && !(h->grant.access & GRANT_WRITE)) ||
               (command == 16 && !(h->grant.access & GRANT_DIR_READ))))
      e = EBADF;
    if (!e)
      *size = directory && !in.i_links_count ? 0 : EXT2_I_SIZE(&in);
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
    if (!e && command == 15) {
      *data = calloc(16, 1);
      if (!*data)
        e = ENOMEM;
      else {
        put(*data, h->grant.inode, 4);
        put(*data + 4, h->grant.generation, 4);
        put(*data + 8, in.i_mode, 4);
        put(*data + 12, in.i_links_count, 4);
        *count = 16;
      }
    }
    if (!e && command == 16)
      e = directory_names(fs, h->grant.inode, data, count);
    if (!e && command == 17) {
      e = directory_path(fs, h->grant.inode, data, count);
      if (!e)
        *size = *count;
    }
    if (!e && command == 18) {
      if (offset != 1 && offset != 4)
        e = EINVAL;
      if (!e && offset == 1)
        e = policy_inode(fs, h->grant.inode, c, 1);
      if (!e && offset == 4 && !(h->grant.access & GRANT_DIR_READ))
        e = EBADF;
      struct inode_grant g = {h->grant.inode, h->grant.generation,
                              offset == 1 ? GRANT_DIR_SEARCH : GRANT_DIR_READ,
                              GRANT_DIRECTORY};
      if (!e)
        e = allocate(fs, &g, size, data, count);
    }
    if (!e && (command == 19 || command == 20)) {
      ext2_ino_t ino = 0;
      e = directory_walk(fs, h->grant.inode, (const char *)path + 8, c, &ino);
      if (!e)
        e = ext2fs_read_inode(fs, ino, &in);
      struct inode_grant g = {ino, in.i_generation, GRANT_DIR_SEARCH,
                              GRANT_DIRECTORY};
      if (!e)
        e = grant_inode(fs, &g, &in);
      if (!e && command == 19)
        e = allocate(fs, &g, size, data, count);
      if (!e && command == 20) {
        e = directory_path(fs, ino, data, count);
        if (!e)
          *size = *count;
      }
    }
  }
  if (fs)
    ext2fs_free(fs);
  return policy_errno(e);
}
