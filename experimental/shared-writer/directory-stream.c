/* SPDX-License-Identifier: GPL-2.0-only */
#include "directory-stream.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifndef DIRECTORY_STREAM_BYTES
#define DIRECTORY_STREAM_BYTES (64U * 1024 * 1024)
#endif
#ifndef DIRECTORY_STREAM_TOTAL
#define DIRECTORY_STREAM_TOTAL (256U * 1024 * 1024)
#endif
/* Reader is serialized. Cookies are locators, not inode capabilities. A range
 * is never reused by another snapshot in this reader process. */
static size_t live_bytes;
static uint64_t last_cookie;
static void put(unsigned char *p, uint64_t n, unsigned bytes) {
  for (unsigned i = 0; i < bytes; i++)
    p[i] = n >> (8 * i);
}
void directory_stream_clear(struct directory_stream *s) {
  live_bytes -= s->capacity * sizeof(*s->entries);
  free(s->entries);
  memset(s, 0, sizeof(*s));
}
struct capture {
  struct directory_stream stream;
  ext2_filsys fs;
  ext2_ino_t ino, parent;
  unsigned dot, dotdot;
  errcode_t error;
};
static int entry(struct ext2_dir_entry *de, int offset, int blocksize,
                 char *buf, void *private) {
  (void)offset;
  (void)blocksize;
  (void)buf;
  struct capture *c = private;
  struct directory_stream *s = &c->stream;
  if (!de->inode)
    return 0;
  unsigned n = ext2fs_dirent_name_len(de), type = ext2fs_dirent_file_type(de);
  if (!n || n > 255 || memchr(de->name, 0, n) || memchr(de->name, '/', n) ||
      type > EXT2_FT_SYMLINK || de->inode > c->fs->super->s_inodes_count ||
      (de->inode < EXT2_FIRST_INODE(c->fs->super) &&
       de->inode != EXT2_ROOT_INO) ||
      !ext2fs_test_inode_bitmap2(c->fs->inode_map, de->inode)) {
    c->error = EIO;
    return DIRENT_ABORT;
  }
  if (n == 1 && de->name[0] == '.') {
    if (++c->dot != 1 || de->inode != c->ino) {
      c->error = EIO;
      return DIRENT_ABORT;
    }
  } else if (n == 2 && !memcmp(de->name, "..", 2)) {
    if (++c->dotdot != 1 || de->inode != c->parent) {
      c->error = EIO;
      return DIRENT_ABORT;
    }
  }
  if (s->count == s->capacity) {
    size_t max = DIRECTORY_STREAM_BYTES / sizeof(*s->entries);
    if (s->count == max) {
      c->error = EOVERFLOW;
      return DIRENT_ABORT;
    }
    size_t capacity = s->capacity ? s->capacity * 2 : 8;
    if (capacity > max)
      capacity = max;
    size_t bytes = capacity * sizeof(*s->entries);
    if (bytes > DIRECTORY_STREAM_TOTAL - live_bytes) {
      c->error = ENOMEM;
      return DIRENT_ABORT;
    }
    struct stream_entry *more = realloc(s->entries, bytes);
    if (!more) {
      c->error = ENOMEM;
      return DIRENT_ABORT;
    }
    s->entries = more;
    s->capacity = capacity;
  }
  static const unsigned types[] = {0, 8, 4, 2, 6, 1, 12, 10};
  struct stream_entry *out = &s->entries[s->count++];
  out->inode = de->inode;
  out->type = types[type];
  out->bytes = n;
  memcpy(out->name, de->name, n);
  out->name[n] = 0;
  return 0;
}
static errcode_t capture(ext2_filsys fs, ext2_ino_t ino,
                         struct directory_stream *s) {
  struct ext2_inode in;
  errcode_t e = ext2fs_read_inode(fs, ino, &in);
  if (e)
    return e;
  if (!in.i_links_count) {
    s->loaded = 1;
    return 0;
  }
  struct capture c = {.fs = fs, .ino = ino};
  e = namespace_directory_parent(fs, ino, &c.parent);
  if (!e)
    e = ext2fs_dir_iterate(fs, ino, 0, NULL, entry, &c);
  if (!e)
    e = c.error;
  if (!e && (c.dot != 1 || c.dotdot != 1))
    e = EIO;
  if (!e && c.stream.count > (uint64_t)(INT64_MAX - 1) - last_cookie)
    e = EOVERFLOW;
  if (e) {
    free(c.stream.entries);
    return e;
  }
  c.stream.base = last_cookie;
  last_cookie += c.stream.count;
  c.stream.loaded = 1;
  live_bytes += c.stream.capacity * sizeof(*s->entries);
  *s = c.stream;
  return 0;
}
static errcode_t index_at(const struct directory_stream *s, uint64_t offset,
                          size_t *index) {
  if (offset == DIRECTORY_CURRENT) {
    *index = s->position;
    return 0;
  }
  if (!offset) {
    *index = 0;
    return 0;
  }
  if (!s->loaded || offset <= s->base || offset - s->base > s->count)
    return EINVAL;
  *index = offset - s->base;
  return 0;
}
static uint64_t cookie(const struct directory_stream *s, size_t index) {
  return index ? s->base + index : 0;
}
errcode_t directory_stream_seek(struct directory_stream *s, uint64_t offset,
                                uint64_t *position) {
  size_t index;
  errcode_t e = index_at(s, offset, &index);
  if (!e) {
    s->position = index;
    *position = cookie(s, index);
  }
  return e;
}
errcode_t directory_stream_page(ext2_filsys fs, ext2_ino_t ino,
                                struct directory_stream *s, uint64_t offset,
                                unsigned limit, size_t budget, uint64_t *next,
                                unsigned char **data, size_t *bytes) {
  if (!limit || limit > 4096 || budget < 8 || budget > 1024 * 1024)
    return EINVAL;
  size_t begin;
  errcode_t e = index_at(s, offset, &begin);
  if (e)
    return e;
  if (!s->loaded && (e = capture(fs, ino, s)))
    return e;
  size_t end = begin, used = 8;
  while (end < s->count && end - begin < limit) {
    size_t record = 16 + s->entries[end].bytes;
    if (record > budget - used)
      break;
    used += record;
    end++;
  }
  if (end == begin && begin < s->count)
    return ERANGE;
  unsigned char *out = calloc(used, 1);
  if (!out)
    return ENOMEM;
  put(out, end == s->count, 4);
  put(out + 4, end - begin, 4);
  size_t at = 8;
  for (size_t i = begin; i < end; i++) {
    const struct stream_entry *entry = &s->entries[i];
    put(out + at, cookie(s, i + 1), 8);
    put(out + at + 8, entry->inode, 4);
    put(out + at + 12, entry->type, 2);
    put(out + at + 14, entry->bytes, 2);
    memcpy(out + at + 16, entry->name, entry->bytes);
    at += 16 + entry->bytes;
  }
  s->position = end;
  *next = cookie(s, end);
  *data = out;
  *bytes = used;
  return 0;
}
