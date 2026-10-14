/* SPDX-License-Identifier: GPL-2.0-only */
#include "namespace.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
/* Bound validation work independently of untrusted inode/index counts. */
#define INDEX_BLOCKS 16384
#define INDEX_NAMES 65536
struct index_check {
  ext2_filsys fs;
  ext2_ino_t ino;
  struct ext2_inode in;
  unsigned blocks, names, algorithm;
  unsigned char *seen;
  blk64_t *physical;
  char **name;
};
static unsigned get16(const unsigned char *p) { return p[0] | p[1] << 8; }
static uint32_t get32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
         (uint32_t)p[3] << 24;
}
static errcode_t read_block(struct index_check *c, unsigned logical,
                            void *buf) {
  if (logical >= c->blocks || c->seen[logical])
    return EIO;
  c->seen[logical] = 1;
  int flags;
  blk64_t physical;
  errcode_t e =
      ext2fs_bmap2(c->fs, c->ino, &c->in, NULL, 0, logical, &flags, &physical);
  if (e)
    return e;
  if (!physical || flags & BMAP_RET_UNINIT ||
      physical < c->fs->super->s_first_data_block ||
      physical >= ext2fs_blocks_count(c->fs->super) ||
      !ext2fs_test_block_bitmap2(c->fs->block_map, physical))
    return EIO;
  c->physical[logical] = physical;
  return ext2fs_read_dir_block4(c->fs, physical, buf, 0, c->ino);
}
static errcode_t leaf(struct index_check *c, unsigned logical, uint32_t low,
                      uint64_t high, int collision) {
  unsigned char buf[4096];
  errcode_t e = read_block(c, logical, buf);
  if (e)
    return e;
  unsigned end = c->fs->blocksize;
  if (ext2fs_has_feature_metadata_csum(c->fs->super)) {
    end -= 12;
    if (get32(buf + end) || get16(buf + end + 4) != 12 || buf[end + 6] ||
        buf[end + 7] != 0xde)
      return EIO;
  }
  for (unsigned at = 0; at < end;) {
    if (end - at < 8)
      return EIO;
    unsigned rec = get16(buf + at + 4), n = buf[at + 6], type = buf[at + 7];
    uint32_t ino = get32(buf + at);
    if (rec < 8 || rec % 4 || rec > end - at || n > rec - 8 ||
        type > EXT2_FT_SYMLINK)
      return EIO;
    if (ino) {
      if (!n || ino > c->fs->super->s_inodes_count ||
          !ext2fs_test_inode_bitmap2(c->fs->inode_map, ino) ||
          memchr(buf + at + 8, 0, n) || memchr(buf + at + 8, '/', n) ||
          (n == 1 && buf[at + 8] == '.') ||
          (n == 2 && !memcmp(buf + at + 8, "..", 2)))
        return EIO;
      ext2_dirhash_t hash, minor;
      e = ext2fs_dirhash(c->algorithm, (char *)buf + at + 8, n,
                         c->fs->super->s_hash_seed, &hash, &minor);
      if (e)
        return e;
      if (hash < low || hash > high || (hash == high && !collision))
        return EIO;
      if (c->names == INDEX_NAMES)
        return EFBIG;
      char *name = malloc(n + 1);
      if (!name)
        return ENOMEM;
      memcpy(name, buf + at + 8, n);
      name[n] = 0;
      c->name[c->names++] = name;
    }
    at += rec;
  }
  return 0;
}
static errcode_t node(struct index_check *c, unsigned logical, unsigned depth,
                      uint32_t low, uint64_t high, int collision) {
  unsigned char buf[4096];
  errcode_t e = read_block(c, logical, buf);
  if (e)
    return e;
  unsigned off = logical ? 8 : 32;
  if (!logical) {
    if (get32(buf) != c->ino || get16(buf + 4) != 12 || buf[6] != 1 ||
        buf[8] != '.' || !get32(buf + 12) ||
        get16(buf + 16) != c->fs->blocksize - 12 || buf[18] != 2 ||
        memcmp(buf + 20, "..", 2) || get32(buf + 24) || buf[28] > 2 ||
        buf[29] != 8 || buf[30] != depth || buf[31])
      return EIO;
    c->algorithm =
        buf[28] + ((c->fs->super->s_flags & EXT2_FLAGS_UNSIGNED_HASH) ? 3 : 0);
  } else if (get32(buf) || get16(buf + 4) != c->fs->blocksize || buf[6] ||
             buf[7])
    return EIO;
  unsigned tail = ext2fs_has_feature_metadata_csum(c->fs->super) ? 8 : 0;
  unsigned limit = (c->fs->blocksize - off - tail) / 8,
           count = get16(buf + off + 2);
  if (get16(buf + off) != limit || !count || count > limit)
    return EIO;
  uint32_t previous = low;
  for (unsigned i = 0; i < count; i++) {
    uint32_t lower = i ? get32(buf + off + i * 8) : low;
    uint64_t upper =
        i + 1 < count ? get32(buf + off + (i + 1) * 8) & ~1U : high;
    int continuation =
        i + 1 < count ? (get32(buf + off + (i + 1) * 8) & 1) : collision;
    if (i && (lower < previous || (lower & ~1U) < low ||
              (uint64_t)(lower & ~1U) > high))
      return EIO;
    uint32_t child = get32(buf + off + i * 8 + 4);
    if (child & 0xf0000000U || !child || upper < (lower & ~1U))
      return EIO;
    e = depth ? node(c, child, depth - 1, lower & ~1U, upper, continuation)
              : leaf(c, child, lower & ~1U, upper, continuation);
    if (e)
      return e;
    previous = lower;
  }
  return 0;
}
static int compare_name(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}
static int compare_block(const void *a, const void *b) {
  blk64_t x = *(const blk64_t *)a, y = *(const blk64_t *)b;
  return x < y ? -1 : x > y;
}
errcode_t namespace_index_check(ext2_filsys fs, ext2_ino_t ino) {
  struct index_check c = {.fs = fs, .ino = ino};
  errcode_t e = ext2fs_read_inode(fs, ino, &c.in);
  if (e || !(c.in.i_flags & EXT2_INDEX_FL))
    return e;
  if (fs->blocksize != 1024 && fs->blocksize != 2048 && fs->blocksize != 4096)
    return EOPNOTSUPP;
  uint64_t size = EXT2_I_SIZE(&c.in);
  if ((c.in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR ||
      !ext2fs_has_feature_dir_index(fs->super) || size % fs->blocksize ||
      size < 2 * fs->blocksize)
    return EIO;
  if (size / fs->blocksize > INDEX_BLOCKS)
    return EFBIG;
  if (!fs->block_map && (e = ext2fs_read_block_bitmap(fs)))
    return e;
  if (!fs->inode_map && (e = ext2fs_read_inode_bitmap(fs)))
    return e;
  c.blocks = size / fs->blocksize;
  c.seen = calloc(c.blocks, 1);
  c.physical = calloc(c.blocks, sizeof(*c.physical));
  c.name = calloc(INDEX_NAMES, sizeof(*c.name));
  if (!c.seen || !c.physical || !c.name) {
    e = ENOMEM;
    goto out;
  }
  /* Read depth safely before the recursive, bounded full-tree walk. */
  unsigned char root[4096];
  e = read_block(&c, 0, root);
  if (e)
    goto out;
  c.seen[0] = 0;
  if (root[30] > 1) {
    e = EOPNOTSUPP;
    goto out;
  }
  e = node(&c, 0, root[30], 0, 1ULL << 32, 0);
  if (e)
    goto out;
  for (unsigned i = 0; i < c.blocks; i++)
    if (!c.seen[i]) {
      e = EIO;
      goto out;
    }
  qsort(c.physical, c.blocks, sizeof(*c.physical), compare_block);
  for (unsigned i = 1; i < c.blocks; i++)
    if (c.physical[i] == c.physical[i - 1]) {
      e = EIO;
      goto out;
    }
  qsort(c.name, c.names, sizeof(*c.name), compare_name);
  for (unsigned i = 1; i < c.names; i++)
    if (!strcmp(c.name[i], c.name[i - 1])) {
      e = EIO;
      goto out;
    }
out:
  for (unsigned i = 0; i < c.names; i++)
    free(c.name[i]);
  free(c.name);
  free(c.physical);
  free(c.seen);
  return e;
}
