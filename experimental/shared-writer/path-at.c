/* SPDX-License-Identifier: GPL-2.0-only */
#include "path-at.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
errcode_t path_base(ext2_filsys fs, const struct inode_grant *base,
                    const char *path, ext2_ino_t *ino) {
  if (!path || !*path)
    return ENOENT;
  if (*path == '/') {
    *ino = EXT2_ROOT_INO;
    return 0;
  }
  if (!base || base->flags != GRANT_DIRECTORY)
    return ENOTDIR;
  struct ext2_inode in;
  errcode_t e = grant_inode(fs, base, &in);
  if (!e)
    *ino = base->inode;
  return e;
}
static errcode_t allocated(ext2_filsys fs, ext2_ino_t ino,
                           struct ext2_inode *in) {
  errcode_t e = fs->inode_map ? 0 : ext2fs_read_inode_bitmap(fs);
  if (e)
    return e;
  if (!ino || ino > fs->super->s_inodes_count ||
      (ino < EXT2_FIRST_INODE(fs->super) && ino != EXT2_ROOT_INO) ||
      !ext2fs_test_inode_bitmap2(fs->inode_map, ino))
    return EIO;
  e = ext2fs_read_inode(fs, ino, in);
  if (!e && (in->i_flags & (GRANT_UNSUPPORTED | EXT4_CASEFOLD_FL)))
    e = EOPNOTSUPP;
  if (!e && (in->i_mode & LINUX_S_IFMT) == LINUX_S_IFDIR)
    e = namespace_index_check(fs, ino);
  if (!e && in->i_links_count && in->i_dtime)
    e = EIO;
  if (!e && !in->i_links_count) {
    struct inode_grant g = {ino, in->i_generation, GRANT_DIR_SEARCH,
                            GRANT_DIRECTORY};
    if ((in->i_mode & LINUX_S_IFMT) == LINUX_S_IFLNK ||
        special_type(in->i_mode))
      g = (struct inode_grant){ino, in->i_generation, 0, GRANT_NODE};
    else if ((in->i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
      return EIO;
    e = grant_inode(fs, &g, in);
  }
  return e;
}
errcode_t path_readlink(ext2_filsys fs, ext2_ino_t ino, char **target,
                        size_t *bytes) {
  struct ext2_inode in;
  errcode_t e = allocated(fs, ino, &in);
  if (e)
    return e;
  if ((in.i_mode & LINUX_S_IFMT) != LINUX_S_IFLNK)
    return EINVAL;
  uint64_t n = EXT2_I_SIZE(&in);
  if (!n || n > 4095 || n >= fs->blocksize)
    return EIO;
  char *text = calloc(n + 1, 1);
  if (!text)
    return ENOMEM;
  if (ext2fs_is_fast_symlink(&in)) {
    if (n > sizeof(in.i_block))
      e = EIO;
    else
      memcpy(text, in.i_block, n);
  } else {
    ext2_file_t f = NULL;
    unsigned got = 0;
    e = ext2fs_file_open(fs, ino, 0, &f);
    if (!e)
      e = ext2fs_file_read(f, text, n, &got);
    if (!e && got != n)
      e = EIO;
    if (f) {
      errcode_t close = ext2fs_file_close(f);
      if (!e)
        e = close;
    }
  }
  if (!e && memchr(text, 0, n))
    e = EIO;
  if (e) {
    free(text);
    return e;
  }
  *target = text;
  *bytes = n;
  return 0;
}
errcode_t path_at(ext2_filsys fs, ext2_ino_t start, const char *path,
                  const struct credentials *c, unsigned flags,
                  struct path_result *r) {
  if (!path || !*path)
    return ENOENT;
  size_t n = strlen(path);
  if (n > 4096)
    return ENAMETOOLONG;
  memset(r, 0, sizeof(*r));
  char pending[4097];
  memcpy(pending, path, n + 1);
  ext2_ino_t ino = *path == '/' ? EXT2_ROOT_INO : start;
  unsigned links = 0;
  for (;;) {
    char *part = pending;
    while (*part == '/')
      part++;
    if (!*part) {
      struct ext2_inode in;
      errcode_t e = allocated(fs, ino, &in);
      if (!e && (in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
        e = ENOTDIR;
      if (e)
        return e;
      if (flags & AT_PARENT)
        return EBUSY;
      r->inode = ino;
      r->trailing = 1;
      return 0;
    }
    char *end = strchr(part, '/');
    size_t size = end ? (size_t)(end - part) : strlen(part);
    if (size > 255)
      return ENAMETOOLONG;
    char name[256];
    memcpy(name, part, size);
    name[size] = 0;
    char rest[4097];
    strcpy(rest, end ? end : "");
    char *next = rest;
    while (*next == '/')
      next++;
    int final = !*next, trailing = final && end;
    struct ext2_inode dir;
    errcode_t e = allocated(fs, ino, &dir);
    if (e)
      return e;
    if ((dir.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
      return ENOTDIR;
    if (c && (e = policy_inode(fs, ino, c, 1)))
      return e;
    int dot = !strcmp(name, "."), dotdot = !strcmp(name, "..");
    if (final && (flags & AT_PARENT)) {
      if (dot || dotdot)
        return EINVAL;
      if (!dir.i_links_count)
        return ENOENT;
      r->parent = ino;
      strcpy(r->leaf, name);
      r->trailing = trailing;
      e = ext2fs_lookup(fs, ino, name, size, NULL, &r->inode);
      if (e == EXT2_ET_FILE_NOT_FOUND) {
        r->inode = 0;
        return 0;
      }
      if (e)
        return e;
      struct ext2_inode in;
      e = allocated(fs, r->inode, &in);
      if (!e && trailing && (in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
        e = ENOTDIR;
      return e;
    }
    ext2_ino_t found = ino;
    if (dotdot)
      e = namespace_directory_parent(fs, ino, &found);
    else if (!dot) {
      if (!dir.i_links_count)
        return ENOENT;
      e = ext2fs_lookup(fs, ino, name, size, NULL, &found);
    }
    if (e == EXT2_ET_FILE_NOT_FOUND && final && (flags & AT_MISSING) &&
        !trailing) {
      r->parent = ino;
      strcpy(r->leaf, name);
      return 0;
    }
    if (e)
      return e;
    struct ext2_inode in;
    e = allocated(fs, found, &in);
    if (e)
      return e;
    if (!in.i_links_count && !dot && !dotdot)
      return EIO;
    unsigned type = in.i_mode & LINUX_S_IFMT;
    if (type == LINUX_S_IFLNK && (!final || trailing || (flags & AT_FOLLOW))) {
      if (++links > 40)
        return ELOOP;
      char *target = NULL;
      size_t bytes = 0;
      e = path_readlink(fs, found, &target, &bytes);
      if (e)
        return e;
      if (bytes + strlen(rest) > 4096) {
        free(target);
        return ENAMETOOLONG;
      }
      if (*target == '/')
        ino = EXT2_ROOT_INO;
      memcpy(pending, target, bytes);
      strcpy(pending + bytes, rest);
      free(target);
      continue;
    }
    if ((!final || trailing) && type != LINUX_S_IFDIR)
      return ENOTDIR;
    if (final) {
      r->inode = found;
      r->parent = ino;
      strcpy(r->leaf, name);
      r->trailing = trailing;
      return 0;
    }
    ino = found;
    strcpy(pending, rest);
  }
}
