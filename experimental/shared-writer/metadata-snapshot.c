/* SPDX-License-Identifier: GPL-2.0-only
 * Private consistency-check image: metadata only, never regular-file payloads.
 * Selection follows e2fsprogs misc/e2image.c (Theodore Ts'o, GPL).
 * This is scratch space for e2fsck, not a backup or recoverable data image.
 */
#ifdef __linux__
#define _GNU_SOURCE
#include <linux/falloc.h>
#endif
#include "overlay.h"
#include <errno.h>
#include <ext2fs/ext2fs.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern struct struct_io_manager staged_manager;
struct snapshot {
  int fd, error;
  uint64_t used, budget;
  int all;
  blk64_t *blocks;
  size_t count, capacity;
};
static int copy_block(ext2_filsys fs, blk64_t block, struct snapshot *s) {
  if (block >= ext2fs_blocks_count(fs->super))
    return EIO;
  if (s->used > s->budget || fs->blocksize > s->budget - s->used)
    return ENOSPC;
  if (s->count == s->capacity) {
    size_t capacity = s->capacity ? s->capacity * 2 : 512;
    if (capacity < s->capacity || capacity > SIZE_MAX / sizeof(*s->blocks))
      return EOVERFLOW;
    void *blocks = realloc(s->blocks, capacity * sizeof(*s->blocks));
    if (!blocks)
      return ENOMEM;
    s->blocks = blocks;
    s->capacity = capacity;
  }
  s->blocks[s->count++] = block;
  s->used += fs->blocksize;
  return 0;
}
static int order(const void *a, const void *b) {
  blk64_t x = *(const blk64_t *)a, y = *(const blk64_t *)b;
  return x < y ? -1 : x > y;
}
static int punch(int fd, uint64_t offset, uint64_t end) {
  if (end <= offset)
    return 0;
#ifdef __APPLE__
  struct fpunchhole range = {.fp_offset = offset, .fp_length = end - offset};
  if (fcntl(fd, F_PUNCHHOLE, &range) < 0)
    return errno;
#elif defined(__linux__)
  if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset,
                end - offset) < 0)
    return errno;
#else
  (void)fd;
  return EOPNOTSUPP;
#endif
  return 0;
}
static int emit(ext2_filsys fs, struct snapshot *s) {
  qsort(s->blocks, s->count, sizeof(*s->blocks), order);
  uint64_t size = ext2fs_blocks_count(fs->super) * (uint64_t)fs->blocksize;
  size_t i = 0;
  uint64_t previous_end = 0;
  while (i < s->count) {
    uint64_t run_start = s->blocks[i] * (uint64_t)fs->blocksize / 4096 * 4096,
             run_end = run_start;
    while (i < s->count &&
           s->blocks[i] * (uint64_t)fs->blocksize / 4096 * 4096 <= run_end) {
      uint64_t offset = s->blocks[i] * (uint64_t)fs->blocksize / 4096 * 4096;
      unsigned char page[4096] = {0};
      while (i < s->count &&
             s->blocks[i] * (uint64_t)fs->blocksize / 4096 * 4096 == offset) {
        blk64_t block = s->blocks[i++];
        int e = overlay_read(
            active_overlay, block * (uint64_t)fs->blocksize, fs->blocksize,
            page + block * (uint64_t)fs->blocksize - offset, 1);
        if (e)
          return e;
        while (i < s->count && s->blocks[i] == block)
          i++;
      }
      size_t left = size - offset < 4096 ? size - offset : 4096;
      unsigned char *data = page;
      uint64_t at = offset;
      while (left) {
        ssize_t n = pwrite(s->fd, data, left, at);
        if (n < 0 && errno == EINTR)
          continue;
        if (n <= 0)
          return n < 0 ? errno : EIO;
        data += n;
        left -= n;
        at += n;
      }
      run_end = offset + 4096;
    }
    /* macOS can densely allocate small gaps and speculative space past a write.
     * Deallocate both gaps after each sorted run, not after the whole export.
     */
    if (fsync(s->fd) < 0)
      return errno;
    int e = punch(s->fd, previous_end, run_start);
    if (e)
      return e;
    e = punch(s->fd, run_end, size / 4096 * 4096);
    if (e)
      return e;
    previous_end = run_end;
  }
  return 0;
}
static int visit(ext2_filsys fs, blk64_t *block, e2_blkcnt_t count, blk64_t ref,
                 int offset, void *data) {
  (void)ref;
  (void)offset;
  struct snapshot *s = data;
  if ((s->all || count < 0) && *block) {
    s->error = copy_block(fs, *block, s);
    if (s->error)
      return BLOCK_ABORT;
  }
  return 0;
}
int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  char *end;
  errno = 0;
  uint64_t budget = strtoull(argv[3], &end, 10);
  if (errno || !argv[3][0] || argv[3][0] == '-' || *end || !budget ||
      budget > (1ULL << 40))
    return 2;
  active_overlay = overlay_open(argv[1], 1);
  if (!active_overlay) {
    perror("snapshot view");
    return 1;
  }
  ext2_filsys fs = NULL;
  errcode_t e =
      ext2fs_open(argv[1], EXT2_FLAG_64BITS, 0, 0, &staged_manager, &fs);
  if (e) {
    fprintf(stderr, "snapshot open: %ld\n", (long)e);
    overlay_close(active_overlay);
    return 1;
  }
  if (fs->blocksize > 4096 || !(fs->super->s_state & EXT2_VALID_FS) ||
      (fs->super->s_state & ~EXT2_VALID_FS) ||
      (fs->super->s_feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER))
    e = EINVAL;
  int fd = -1;
  if (!e) {
    fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0)
      e = errno;
  }
  struct snapshot s = {.fd = fd, .budget = budget};
  if (!e &&
      ftruncate(fd, ext2fs_blocks_count(fs->super) * (uint64_t)fs->blocksize))
    e = errno;
  if (!e)
    e = copy_block(fs, 0, &s);
  if (!e && fs->super->s_first_data_block)
    e = copy_block(fs, fs->super->s_first_data_block, &s);
  for (unsigned n = 0; !e && n < fs->desc_blocks; n++)
    e = copy_block(
        fs, ext2fs_descriptor_block_loc2(fs, fs->super->s_first_data_block, n),
        &s);
  for (dgrp_t g = 0; !e && g < fs->group_desc_count; g++) {
    unsigned count = fs->inode_blocks_per_group;
    if (ext2fs_has_group_desc_csum(fs))
      count -=
          ext2fs_bg_itable_unused(fs, g) / EXT2_INODES_PER_BLOCK(fs->super);
    if (!ext2fs_bg_flags_test(fs, g, EXT2_BG_INODE_UNINIT))
      for (unsigned n = 0; !e && n < count; n++)
        e = copy_block(fs, ext2fs_inode_table_loc(fs, g) + n, &s);
    if (!e && !ext2fs_bg_flags_test(fs, g, EXT2_BG_BLOCK_UNINIT))
      e = copy_block(fs, ext2fs_block_bitmap_loc(fs, g), &s);
    if (!e && !ext2fs_bg_flags_test(fs, g, EXT2_BG_INODE_UNINIT))
      e = copy_block(fs, ext2fs_inode_bitmap_loc(fs, g), &s);
  }
  ext2_inode_scan scan = NULL;
  if (!e)
    e = ext2fs_open_inode_scan(fs, 0, &scan);
  while (!e) {
    ext2_ino_t ino;
    struct ext2_inode inode;
    e = ext2fs_get_next_inode(scan, &ino, &inode);
    if (e || !ino)
      break;
    if (!inode.i_links_count)
      continue;
    blk64_t acl = ext2fs_file_acl_block(fs, &inode);
    if (acl)
      e = copy_block(fs, acl, &s);
    if (e || !ext2fs_inode_has_valid_blocks2(fs, &inode))
      continue;
    s.all = LINUX_S_ISDIR(inode.i_mode) || LINUX_S_ISLNK(inode.i_mode) ||
            ino == fs->super->s_journal_inum ||
            ino == fs->super->s_orphan_file_inum;
    s.error = 0;
    e = ext2fs_block_iterate3(fs, ino, BLOCK_FLAG_READ_ONLY, NULL, visit, &s);
    if (!e)
      e = s.error;
  }
  if (scan)
    ext2fs_close_inode_scan(scan);
  if (!e)
    e = emit(fs, &s);
  free(s.blocks);
  if (!e && fsync(fd))
    e = errno;
  if (fd >= 0)
    close(fd);
  ext2fs_close(fs);
  overlay_close(active_overlay);
  if (e) {
    fprintf(stderr, "metadata snapshot failed: %ld\n", (long)e);
    return 1;
  }
  printf("%" PRIu64 "\n", s.used);
  return 0;
}
