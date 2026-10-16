/* SPDX-License-Identifier: GPL-2.0-only
 * Transaction-local linear -> HTree rebuild. The directory inode, links,
 * permissions, ACLs and generation stay unchanged; staged failure rolls back.
 */
#include "namespace.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#define CONVERT_BLOCKS 131072
#define CONVERT_NAMES 1048576
struct convert_entry {
  uint32_t inode, hash, minor;
  unsigned char length, type;
  char name[256];
};
static unsigned u16(const unsigned char *p) { return p[0] | p[1] << 8; }
static uint32_t u32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
         (uint32_t)p[3] << 24;
}
static void put(unsigned char *p, uint32_t v, unsigned n) {
  for (unsigned i = 0; i < n; i++)
    p[i] = v >> (8 * i);
}
static int by_name(const void *a, const void *b) {
  return strcmp(((const struct convert_entry *)a)->name,
                ((const struct convert_entry *)b)->name);
}
static int by_hash(const void *a, const void *b) {
  const struct convert_entry *x = a, *y = b;
  if (x->hash != y->hash)
    return x->hash < y->hash ? -1 : 1;
  if (x->minor != y->minor)
    return x->minor < y->minor ? -1 : 1;
  return by_name(a, b);
}
static int by_block(const void *a, const void *b) {
  blk64_t x = *(const blk64_t *)a, y = *(const blk64_t *)b;
  return x < y ? -1 : x > y;
}
static errcode_t mapping(ext2_filsys fs, ext2_ino_t ino, struct ext2_inode *in,
                         unsigned logical, blk64_t *physical) {
  int flags;
  errcode_t e = ext2fs_bmap2(fs, ino, in, NULL, 0, logical, &flags, physical);
  if (!e && (!*physical || flags & BMAP_RET_UNINIT ||
             *physical < fs->super->s_first_data_block ||
             *physical >= ext2fs_blocks_count(fs->super) ||
             !ext2fs_test_block_bitmap2(fs->block_map, *physical)))
    e = EIO;
  return e;
}
static void entry(unsigned char *p, uint32_t ino, unsigned rec,
                  const char *name, unsigned n, unsigned type) {
  put(p, ino, 4);
  put(p + 4, rec, 2);
  p[6] = n;
  p[7] = type;
  memcpy(p + 8, name, n);
}
static errcode_t write_block(ext2_filsys fs, ext2_ino_t ino,
                             struct ext2_inode *in, unsigned logical,
                             unsigned char *buf) {
  blk64_t physical;
  errcode_t e = mapping(fs, ino, in, logical, &physical);
  return e ? e : ext2fs_write_dir_block4(fs, physical, buf, 0, ino);
}
errcode_t namespace_index_convert(ext2_filsys fs, ext2_ino_t ino) {
  struct ext2_inode in;
  errcode_t e = ext2fs_read_inode(fs, ino, &in);
  if (e || in.i_flags & EXT2_INDEX_FL)
    return e;
  if (!ext2fs_has_feature_dir_index(fs->super))
    return EOPNOTSUPP;
  if ((in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR || !in.i_links_count ||
      in.i_flags & (GRANT_UNSUPPORTED | EXT4_CASEFOLD_FL) ||
      (fs->blocksize != 1024 && fs->blocksize != 2048 &&
       fs->blocksize != 4096) ||
      fs->super->s_def_hash_version > 2)
    return EOPNOTSUPP;
  uint64_t size = EXT2_I_SIZE(&in);
  if (!size || size % fs->blocksize)
    return EIO;
  if (size / fs->blocksize > CONVERT_BLOCKS)
    return EFBIG;
  if ((!fs->inode_map || !fs->block_map) && (e = ext2fs_read_bitmaps(fs)))
    return e;
  unsigned old_blocks = size / fs->blocksize, count = 0, capacity = 0;
  unsigned parent = 0, dots = 0, dotdots = 0;
  unsigned tail = ext2fs_has_feature_metadata_csum(fs->super) ? 12 : 0;
  unsigned end = fs->blocksize - tail;
  unsigned algorithm =
      fs->super->s_def_hash_version +
      ((fs->super->s_flags & EXT2_FLAGS_UNSIGNED_HASH) ? 3 : 0);
  struct convert_entry *names = NULL;
  unsigned *starts = NULL;
  blk64_t *physical = calloc(old_blocks, sizeof(*physical));
  if (!physical)
    return ENOMEM;
  unsigned char buf[4096];
  for (unsigned block = 0; !e && block < old_blocks; block++) {
    e = mapping(fs, ino, &in, block, &physical[block]);
    if (!e)
      e = ext2fs_read_dir_block4(fs, physical[block], buf, 0, ino);
    if (e)
      break;
    if (tail && (u32(buf + end) || u16(buf + end + 4) != 12 || buf[end + 6] ||
                 buf[end + 7] != 0xde)) {
      e = EIO;
      break;
    }
    for (unsigned at = 0; at < end;) {
      if (end - at < 8) {
        e = EIO;
        break;
      }
      unsigned rec = u16(buf + at + 4), n = buf[at + 6], type = buf[at + 7];
      uint32_t target = u32(buf + at);
      if (rec < 8 || rec % 4 || rec > end - at || n > rec - 8 ||
          type > EXT2_FT_SYMLINK) {
        e = EIO;
        break;
      }
      if (target) {
        const char *name = (const char *)buf + at + 8;
        if (!n || target > fs->super->s_inodes_count ||
            !ext2fs_test_inode_bitmap2(fs->inode_map, target) ||
            memchr(name, 0, n) || memchr(name, '/', n)) {
          e = EIO;
          break;
        }
        if (n == 1 && name[0] == '.') {
          if (block || at || rec != 12 || target != ino || dots++) {
            e = EIO;
            break;
          }
        } else if (n == 2 && !memcmp(name, "..", 2)) {
          if (block || at != 12 || dotdots++) {
            e = EIO;
            break;
          }
          parent = target;
        } else {
          if (target < EXT2_FIRST_INODE(fs->super) || count == CONVERT_NAMES) {
            e = EIO;
            break;
          }
          if (count == capacity) {
            unsigned next = capacity ? capacity * 2 : 64;
            struct convert_entry *grown = realloc(names, next * sizeof(*names));
            if (!grown) {
              e = ENOMEM;
              break;
            }
            names = grown;
            capacity = next;
          }
          struct convert_entry *r = &names[count++];
          memset(r, 0, sizeof(*r));
          r->inode = target;
          r->length = n;
          r->type = type;
          memcpy(r->name, name, n);
          e = ext2fs_dirhash(algorithm, name, n, fs->super->s_hash_seed,
                             &r->hash, &r->minor);
          if (e)
            break;
        }
      }
      at += rec;
    }
  }
  if (!e && (dots != 1 || dotdots != 1))
    e = EIO;
  struct ext2_inode parent_inode;
  if (!e)
    e = ext2fs_read_inode(fs, parent, &parent_inode);
  if (!e && (parent_inode.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
    e = EIO;
  if (!e) {
    qsort(physical, old_blocks, sizeof(*physical), by_block);
    for (unsigned i = 1; i < old_blocks; i++)
      if (physical[i] == physical[i - 1]) {
        e = EIO;
        break;
      }
  }
  if (!e && count) {
    qsort(names, count, sizeof(*names), by_name);
    for (unsigned i = 1; i < count; i++)
      if (!strcmp(names[i].name, names[i - 1].name)) {
        e = EIO;
        break;
      }
    qsort(names, count, sizeof(*names), by_hash);
  }
  if (e)
    goto out;
  starts = calloc(count + 2, sizeof(*starts));
  if (!starts) {
    e = ENOMEM;
    goto out;
  }
  unsigned leaves = 1, used = 0;
  for (unsigned i = 0; i < count; i++) {
    unsigned rec = (8U + names[i].length + 3) & ~3U;
    if (used + rec > end) {
      starts[leaves++] = i;
      used = 0;
    }
    used += rec;
  }
  starts[leaves] = count;
  unsigned dx_tail = tail ? 8 : 0;
  unsigned root_limit = (fs->blocksize - 32 - dx_tail) / 8;
  unsigned node_limit = (fs->blocksize - 8 - dx_tail) / 8;
  unsigned nodes =
      leaves > root_limit ? (leaves + node_limit - 1) / node_limit : 0;
  unsigned blocks = 1 + leaves + nodes;
  if (nodes > root_limit || blocks > CONVERT_BLOCKS) {
    e = EFBIG;
    goto out;
  }
  /* Validate the complete source and plan before staging conversion writes. */
  for (unsigned i = old_blocks; !e && i < blocks; i++)
    e = ext2fs_expand_dir(fs, ino);
  if (!e)
    e = ext2fs_read_inode(fs, ino, &in);
  if (!e && blocks < old_blocks)
    e = ext2fs_punch(fs, ino, &in, NULL, blocks, ~0ULL);
  if (e)
    goto out;
  in.i_flags |= EXT2_INDEX_FL;
  e = ext2fs_inode_size_set(fs, &in, (uint64_t)blocks * fs->blocksize);
  if (!e)
    e = ext2fs_write_inode(fs, ino, &in);
  for (unsigned i = 0; !e && i < leaves; i++) {
    memset(buf, 0, fs->blocksize);
    unsigned at = 0;
    for (unsigned j = starts[i]; j < starts[i + 1]; j++) {
      struct convert_entry *r = &names[j];
      unsigned rec =
          j + 1 == starts[i + 1] ? end - at : (8U + r->length + 3) & ~3U;
      entry(buf + at, r->inode, rec, r->name, r->length, r->type);
      at += rec;
    }
    if (!at)
      put(buf + 4, end, 2);
    if (tail) {
      put(buf + end + 4, 12, 2);
      buf[end + 7] = 0xde;
    }
    e = write_block(fs, ino, &in, i + 1, buf);
  }
  for (unsigned group = 0; !e && group < (nodes ? nodes : 1); group++) {
    memset(buf, 0, fs->blocksize);
    unsigned off = nodes ? 8 : 32;
    if (nodes)
      put(buf + 4, fs->blocksize, 2);
    else {
      unsigned type = ext2fs_has_feature_filetype(fs->super) ? EXT2_FT_DIR : 0;
      entry(buf, ino, 12, ".", 1, type);
      entry(buf + 12, parent, fs->blocksize - 12, "..", 2, type);
      buf[28] = fs->super->s_def_hash_version;
      buf[29] = 8;
    }
    unsigned first = nodes ? group * node_limit : 0;
    unsigned n = leaves - first;
    if (n > (nodes ? node_limit : root_limit))
      n = nodes ? node_limit : root_limit;
    put(buf + off, nodes ? node_limit : root_limit, 2);
    put(buf + off + 2, n, 2);
    for (unsigned j = 0; j < n; j++) {
      unsigned leaf = first + j;
      if (j) {
        uint32_t hash = names[starts[leaf]].hash;
        if (hash == names[starts[leaf] - 1].hash)
          hash |= 1;
        put(buf + off + j * 8, hash, 4);
      }
      put(buf + off + j * 8 + 4, leaf + 1, 4);
    }
    e = write_block(fs, ino, &in, nodes ? leaves + group + 1 : 0, buf);
  }
  if (!e && nodes) {
    memset(buf, 0, fs->blocksize);
    unsigned type = ext2fs_has_feature_filetype(fs->super) ? EXT2_FT_DIR : 0;
    entry(buf, ino, 12, ".", 1, type);
    entry(buf + 12, parent, fs->blocksize - 12, "..", 2, type);
    buf[28] = fs->super->s_def_hash_version;
    buf[29] = 8;
    buf[30] = 1;
    put(buf + 32, root_limit, 2);
    put(buf + 34, nodes, 2);
    for (unsigned j = 0; j < nodes; j++) {
      if (j) {
        unsigned start = starts[j * node_limit];
        uint32_t hash = names[start].hash;
        if (hash == names[start - 1].hash)
          hash |= 1;
        put(buf + 32 + j * 8, hash, 4);
      }
      put(buf + 36 + j * 8, leaves + j + 1, 4);
    }
    e = write_block(fs, ino, &in, 0, buf);
  }
  if (!e)
    e = namespace_index_check(fs, ino);
out:
  free(starts);
  free(names);
  free(physical);
  return e;
}
