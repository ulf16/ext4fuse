/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_DIRECTORY_STREAM_H
#define EXPERIMENTAL_DIRECTORY_STREAM_H
#include "namespace.h"
#define DIRECTORY_CURRENT INT64_MAX
struct stream_entry {
  uint32_t inode;
  uint16_t type, bytes;
  unsigned char name[256];
};
struct directory_stream {
  struct stream_entry *entries;
  size_t count, capacity, position;
  uint64_t base;
  int loaded;
};
void directory_stream_clear(struct directory_stream *stream);
errcode_t directory_stream_page(ext2_filsys fs, ext2_ino_t ino,
                                struct directory_stream *stream,
                                uint64_t offset, unsigned limit, size_t budget,
                                uint64_t *next, unsigned char **data,
                                size_t *bytes);
errcode_t directory_stream_seek(struct directory_stream *stream,
                                uint64_t offset, uint64_t *position);
#endif
