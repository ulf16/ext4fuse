/* SPDX-License-Identifier: GPL-2.0-only */
#include "overlay.h"
#include <errno.h>
#include <ext2fs/ext2fs.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
extern struct struct_io_manager staged_manager;
static errcode_t ioopen(const char *n, int flags, io_channel *out) {
  (void)flags;
  if (!active_overlay || strcmp(n, overlay_path(active_overlay)))
    return EINVAL;
  io_channel c = calloc(1, sizeof(*c));
  if (!c)
    return ENOMEM;
  c->magic = EXT2_ET_MAGIC_IO_CHANNEL;
  c->manager = &staged_manager;
  c->block_size = 1024;
  c->refcount = 1;
  c->name = strdup(n);
  if (!c->name) {
    free(c);
    return ENOMEM;
  }
  c->private_data = active_overlay;
  *out = c;
  return 0;
}
static errcode_t ioclose(io_channel c) {
  if (--c->refcount)
    return 0;
  free(c->name);
  free(c);
  return 0;
}
static errcode_t blocksize(io_channel c, int b) {
  if (b < 512 || b > 65536 || (b & (b - 1)))
    return EINVAL;
  c->block_size = b;
  return 0;
}
static errcode_t range(io_channel c, unsigned long long block, int count,
                       uint64_t *off, size_t *n) {
  if (block > UINT64_MAX / (unsigned)c->block_size)
    return EOVERFLOW;
  *off = block * (unsigned)c->block_size;
  if (count < 0) {
    *n = (size_t)(-(int64_t)count);
  } else {
    if ((uint64_t)count > SIZE_MAX / (unsigned)c->block_size)
      return EOVERFLOW;
    *n = (size_t)count * c->block_size;
  }
  return 0;
}
static errcode_t read64(io_channel c, unsigned long long b, int n, void *d) {
  uint64_t off;
  size_t len;
  errcode_t e = range(c, b, n, &off, &len);
  return e ? e : overlay_read(c->private_data, off, len, d, 0);
}
static errcode_t write64(io_channel c, unsigned long long b, int n,
                         const void *d) {
  uint64_t off;
  size_t len;
  errcode_t e = range(c, b, n, &off, &len);
  return e ? e : overlay_write(c->private_data, off, len, d);
}
static errcode_t read32(io_channel c, unsigned long b, int n, void *d) {
  return read64(c, b, n, d);
}
static errcode_t write32(io_channel c, unsigned long b, int n, const void *d) {
  return write64(c, b, n, d);
}
static errcode_t flush(io_channel c) {
  (void)c;
  return 0;
}
static errcode_t writebyte(io_channel c, unsigned long off, int n,
                           const void *d) {
  if (n < 0)
    return EINVAL;
  return overlay_write(c->private_data, off, n, d);
}
struct struct_io_manager staged_manager = {.magic = EXT2_ET_MAGIC_IO_MANAGER,
                                           .name = "serialized-memory-overlay",
                                           .open = ioopen,
                                           .close = ioclose,
                                           .set_blksize = blocksize,
                                           .read_blk = read32,
                                           .write_blk = write32,
                                           .flush = flush,
                                           .write_byte = writebyte,
                                           .read_blk64 = read64,
                                           .write_blk64 = write64};
