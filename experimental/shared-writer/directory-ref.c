/* SPDX-License-Identifier: GPL-2.0-only */
#include "directory-ref.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
struct names {
  unsigned char *data;
  size_t bytes;
  ext2_ino_t find;
  unsigned matches;
  int error;
};
static int entry(struct ext2_dir_entry *de, int offset, int blocksize,
                 char *buf, void *private) {
  (void)offset;
  (void)blocksize;
  (void)buf;
  struct names *n = private;
  unsigned size = ext2fs_dirent_name_len(de);
  if (!de->inode || (size == 1 && de->name[0] == '.') ||
      (size == 2 && !memcmp(de->name, "..", 2)))
    return 0;
  if (!size || size > 255 || memchr(de->name, 0, size) ||
      memchr(de->name, '/', size)) {
    n->error = EIO;
    return DIRENT_ABORT;
  }
  if (n->find && de->inode != n->find)
    return 0;
  if (n->find && ++n->matches > 1) {
    n->error = EIO;
    return DIRENT_ABORT;
  }
  if (n->bytes + 2 + size > 1024 * 1024) {
    n->error = EOVERFLOW;
    return DIRENT_ABORT;
  }
  unsigned char *more = realloc(n->data, n->bytes + 2 + size);
  if (!more) {
    n->error = ENOMEM;
    return DIRENT_ABORT;
  }
  n->data = more;
  n->data[n->bytes] = size;
  n->data[n->bytes + 1] = size >> 8;
  memcpy(n->data + n->bytes + 2, de->name, size);
  n->bytes += 2 + size;
  return 0;
}
errcode_t directory_names(ext2_filsys fs, ext2_ino_t ino, unsigned char **data,
                          size_t *bytes) {
  struct ext2_inode in;
  errcode_t e = ext2fs_read_inode(fs, ino, &in);
  if (e)
    return e;
  if (!in.i_links_count) {
    *data = NULL;
    *bytes = 0;
    return 0;
  }
  struct names n = {0};
  e = ext2fs_dir_iterate(fs, ino, 0, NULL, entry, &n);
  if (!e)
    e = n.error;
  if (e) {
    free(n.data);
    return e;
  }
  *data = n.data;
  *bytes = n.bytes;
  return 0;
}
errcode_t directory_path(ext2_filsys fs, ext2_ino_t ino, unsigned char **path,
                         size_t *bytes) {
  char buffer[4097];
  size_t length = 0;
  ext2_ino_t seen[PIN_LIMIT];
  unsigned count = 0;
  while (ino != EXT2_ROOT_INO) {
    if (count == PIN_LIMIT)
      return EOVERFLOW;
    for (unsigned i = 0; i < count; i++)
      if (seen[i] == ino)
        return EIO;
    seen[count++] = ino;
    struct ext2_inode in;
    errcode_t e = ext2fs_read_inode(fs, ino, &in);
    if (e)
      return e;
    if (!in.i_links_count)
      return ENOENT;
    ext2_ino_t parent;
    e = namespace_directory_parent(fs, ino, &parent);
    if (e)
      return e;
    struct names n = {.find = ino};
    e = ext2fs_dir_iterate(fs, parent, 0, NULL, entry, &n);
    if (!e)
      e = n.error;
    if (!e && n.matches != 1)
      e = n.matches ? EIO : ENOENT;
    if (e) {
      free(n.data);
      return e;
    }
    size_t size = n.data[0] | (unsigned)n.data[1] << 8;
    if (length + size + 1 > 4096) {
      free(n.data);
      return ENAMETOOLONG;
    }
    memmove(buffer + size + 1, buffer, length);
    buffer[0] = '/';
    memcpy(buffer + 1, n.data + 2, size);
    length += size + 1;
    free(n.data);
    ino = parent;
  }
  if (!length) {
    buffer[0] = '/';
    length = 1;
  }
  *path = malloc(length);
  if (!*path)
    return ENOMEM;
  memcpy(*path, buffer, length);
  *bytes = length;
  return 0;
}
errcode_t directory_walk(ext2_filsys fs, ext2_ino_t start, const char *path,
                         const struct credentials *c, ext2_ino_t *result) {
  if (!path || !*path || strlen(path) > 4096)
    return EINVAL;
  ext2_ino_t ino = *path == '/' ? EXT2_ROOT_INO : start;
  if (!strcmp(path, "/")) {
    errcode_t e = policy_inode(fs, ino, c, 1);
    if (!e)
      *result = ino;
    return e;
  }
  char *copy = strdup(path + (*path == '/'));
  if (!copy)
    return ENOMEM;
  char *part = copy;
  errcode_t e = 0;
  for (;;) {
    char *slash = strchr(part, '/');
    if (slash)
      *slash = 0;
    size_t size = strlen(part);
    if (!size || size > 255) {
      e = EINVAL;
      break;
    }
    struct ext2_inode in;
    e = ext2fs_read_inode(fs, ino, &in);
    if (e)
      break;
    if ((in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR) {
      e = ENOTDIR;
      break;
    }
    e = policy_inode(fs, ino, c, 1);
    if (e)
      break;
    if (!strcmp(part, ".."))
      e = namespace_directory_parent(fs, ino, &ino);
    else if (strcmp(part, ".")) {
      if (!in.i_links_count) {
        e = ENOENT;
        break;
      }
      e = ext2fs_lookup(fs, ino, part, size, NULL, &ino);
    }
    if (e)
      break;
    e = ext2fs_read_inode(fs, ino, &in);
    if (e)
      break;
    if ((in.i_mode & LINUX_S_IFMT) == LINUX_S_IFLNK) {
      e = ELOOP;
      break;
    }
    if ((in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR) {
      e = ENOTDIR;
      break;
    }
    if (!slash) {
      e = policy_inode(fs, ino, c, 1);
      break;
    }
    part = slash + 1;
  }
  free(copy);
  if (!e)
    *result = ino;
  return e;
}
