/* SPDX-License-Identifier: GPL-2.0-only */
#include "namespace.h"
#include "overlay.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
/* Bound validation work independently of untrusted inode/index counts. */
#define INDEX_BLOCKS 131072
#define INDEX_NAMES 1048576
#define INDEX_CACHE 64
struct leaf_record {
  uint32_t inode, hash, fingerprint;
  unsigned length;
  const unsigned char *name;
};
struct leaf_certificate {
  uint64_t baseline, epoch;
  blk64_t physical;
  ext2_ino_t ino;
  uint32_t generation, seed[4], features[3], checksum_seed, runtime_seed;
  unsigned char uuid[16];
  unsigned blocksize, algorithm, count, refs, cached;
  size_t bytes;
  struct leaf_record *records;
  struct leaf_certificate *next, *previous, *hash_next;
};
struct leaf_hold {
  struct leaf_certificate *certificate;
  struct leaf_hold *next;
};
#ifndef INDEX_LEAF_BYTES
#define INDEX_LEAF_BYTES (32U * 1024 * 1024)
#endif
#define LEAF_BUCKETS 4096
static struct leaf_certificate *leaf_buckets[LEAF_BUCKETS], *leaf_head,
    *leaf_tail;
static size_t leaf_bytes;
static uint64_t leaf_reads, leaf_reuses;
void namespace_index_leaf_stats(uint64_t *reads, uint64_t *reuses) {
  *reads = leaf_reads;
  *reuses = leaf_reuses;
}
struct index_check {
  ext2_filsys fs;
  ext2_ino_t ino;
  struct ext2_inode in;
  unsigned blocks, names, capacity, algorithm;
  struct leaf_hold *holds;
  unsigned char *seen;
  blk64_t *physical;
  struct leaf_record **name;
};
/* Cache only successful complete validations of one immutable overlay view.
 * No filesystem pointer is retained: libext2fs handles are reopened frequently.
 * Every overlay write, base refresh/suspend and rollback changes the revision.
 * Compare the inode and superblock too, including in-memory bitmap counters and
 * hash policy. Changed views walk the graph and recheck global invariants;
 * immutable leaf certificates avoid repeating unchanged byte/hash work. */
static struct index_cached {
  uint64_t epoch;
  ext2_ino_t ino;
  struct ext2_inode in;
  struct ext2_super_block super;
} cache[INDEX_CACHE];
static unsigned next_cache;
static uint64_t scans, hits;
void namespace_index_stats(uint64_t *full, uint64_t *reused) {
  *full = scans;
  *reused = hits;
}
static unsigned get16(const unsigned char *p) { return p[0] | p[1] << 8; }
static uint32_t get32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
         (uint32_t)p[3] << 24;
}
static errcode_t map_block(struct index_check *c, unsigned logical,
                           blk64_t *physical) {
  if (logical >= c->blocks || c->seen[logical])
    return EIO;
  c->seen[logical] = 1;
  int flags;
  errcode_t e =
      ext2fs_bmap2(c->fs, c->ino, &c->in, NULL, 0, logical, &flags, physical);
  if (e)
    return e;
  if (!*physical || flags & BMAP_RET_UNINIT ||
      *physical < c->fs->super->s_first_data_block ||
      *physical >= ext2fs_blocks_count(c->fs->super) ||
      !ext2fs_test_block_bitmap2(c->fs->block_map, *physical))
    return EIO;
  c->physical[logical] = *physical;
  return 0;
}
static errcode_t read_block(struct index_check *c, unsigned logical,
                            void *buf) {
  blk64_t physical;
  errcode_t e = map_block(c, logical, &physical);
  return e ? e : ext2fs_read_dir_block4(c->fs, physical, buf, 0, c->ino);
}
static unsigned leaf_bucket(blk64_t physical, ext2_ino_t ino) {
  return (unsigned)(physical ^ (physical >> 32) ^ ino * 2654435761U) %
         LEAF_BUCKETS;
}
static void discard_certificate(struct leaf_certificate *p) {
  if (p->previous)
    p->previous->next = p->next;
  else
    leaf_head = p->next;
  if (p->next)
    p->next->previous = p->previous;
  else
    leaf_tail = p->previous;
  struct leaf_certificate **at =
      &leaf_buckets[leaf_bucket(p->physical, p->ino)];
  while (*at && *at != p)
    at = &(*at)->hash_next;
  if (*at)
    *at = p->hash_next;
  leaf_bytes -= p->bytes;
  free(p);
}
static void cache_certificate(struct leaf_certificate *p) {
  if (!p->baseline || p->bytes > INDEX_LEAF_BYTES)
    return;
  while (leaf_bytes > INDEX_LEAF_BYTES - p->bytes) {
    struct leaf_certificate *old = leaf_tail;
    while (old && old->refs)
      old = old->previous;
    if (!old)
      return;
    discard_certificate(old);
  }
  unsigned bucket = leaf_bucket(p->physical, p->ino);
  p->hash_next = leaf_buckets[bucket];
  leaf_buckets[bucket] = p;
  p->next = leaf_head;
  if (leaf_head)
    leaf_head->previous = p;
  else
    leaf_tail = p;
  leaf_head = p;
  p->cached = 1;
  leaf_bytes += p->bytes;
}
static errcode_t checked_name(struct index_check *c, struct leaf_record *r) {
  if (c->names == INDEX_NAMES)
    return EFBIG;
  if (!c->capacity || (c->names + 1) * 2 > c->capacity) {
    unsigned capacity = c->capacity ? c->capacity * 2 : 128;
    struct leaf_record **table = calloc(capacity, sizeof(*table));
    if (!table)
      return ENOMEM;
    for (unsigned i = 0; i < c->capacity; i++)
      if (c->name[i]) {
        unsigned at = c->name[i]->fingerprint % capacity;
        while (table[at])
          at = (at + 1) % capacity;
        table[at] = c->name[i];
      }
    free(c->name);
    c->name = table;
    c->capacity = capacity;
  }
  unsigned at = r->fingerprint % c->capacity;
  while (c->name[at]) {
    struct leaf_record *old = c->name[at];
    if (old->length == r->length && !memcmp(old->name, r->name, r->length))
      return EIO;
    at = (at + 1) % c->capacity;
  }
  c->name[at] = r;
  c->names++;
  return 0;
}
static errcode_t leaf(struct index_check *c, unsigned logical, uint32_t low,
                      uint64_t high, int collision) {
  blk64_t physical;
  errcode_t e = map_block(c, logical, &physical);
  if (e)
    return e;
  uint64_t baseline = overlay_baseline(active_overlay);
  uint64_t epoch =
      overlay_page_epoch(active_overlay, physical * c->fs->blocksize);
  struct leaf_certificate *p = leaf_buckets[leaf_bucket(physical, c->ino)];
  for (; p; p = p->hash_next)
    if (baseline && p->baseline == baseline && p->epoch == epoch &&
        p->physical == physical && p->ino == c->ino &&
        p->generation == c->in.i_generation &&
        p->blocksize == c->fs->blocksize && p->algorithm == c->algorithm &&
        p->features[0] == c->fs->super->s_feature_compat &&
        p->features[1] == c->fs->super->s_feature_incompat &&
        p->features[2] == c->fs->super->s_feature_ro_compat &&
        p->checksum_seed == c->fs->super->s_checksum_seed &&
        p->runtime_seed == c->fs->csum_seed &&
        !memcmp(p->uuid, c->fs->super->s_uuid, sizeof(p->uuid)) &&
        !memcmp(p->seed, c->fs->super->s_hash_seed, sizeof(p->seed)))
      break;
  if (p)
    leaf_reuses++;
  else {
    unsigned char buf[4096];
    leaf_reads++;
    e = ext2fs_read_dir_block4(c->fs, physical, buf, 0, c->ino);
    if (e)
      return e;
    unsigned end = c->fs->blocksize, count = 0;
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
      if (rec < 8 || rec % 4 || rec > end - at || n > rec - 8 ||
          type > EXT2_FT_SYMLINK)
        return EIO;
      if (get32(buf + at)) {
        if (!n || memchr(buf + at + 8, 0, n) || memchr(buf + at + 8, '/', n) ||
            (n == 1 && buf[at + 8] == '.') ||
            (n == 2 && !memcmp(buf + at + 8, "..", 2)))
          return EIO;
        count++;
      }
      at += rec;
    }
    size_t bytes =
        sizeof(*p) + count * sizeof(struct leaf_record) + c->fs->blocksize;
    p = calloc(1, bytes);
    if (!p)
      return ENOMEM;
    p->bytes = bytes;
    p->baseline = baseline;
    p->epoch = epoch;
    p->physical = physical;
    p->ino = c->ino;
    p->generation = c->in.i_generation;
    p->blocksize = c->fs->blocksize;
    p->features[0] = c->fs->super->s_feature_compat;
    p->features[1] = c->fs->super->s_feature_incompat;
    p->features[2] = c->fs->super->s_feature_ro_compat;
    p->checksum_seed = c->fs->super->s_checksum_seed;
    p->runtime_seed = c->fs->csum_seed;
    memcpy(p->uuid, c->fs->super->s_uuid, sizeof(p->uuid));
    p->algorithm = c->algorithm;
    memcpy(p->seed, c->fs->super->s_hash_seed, sizeof(p->seed));
    p->records = (struct leaf_record *)(p + 1);
    unsigned char *data = (unsigned char *)(p->records + count);
    memcpy(data, buf, c->fs->blocksize);
    for (unsigned at = 0; at < end; at += get16(data + at + 4))
      if (get32(data + at)) {
        struct leaf_record *r = &p->records[p->count++];
        r->inode = get32(data + at);
        r->length = data[at + 6];
        r->name = data + at + 8;
        ext2_dirhash_t minor;
        e = ext2fs_dirhash(c->algorithm, (const char *)r->name, r->length,
                           c->fs->super->s_hash_seed, &r->hash, &minor);
        if (e) {
          free(p);
          return e;
        }
        r->fingerprint = 2166136261U;
        for (unsigned i = 0; i < r->length; i++)
          r->fingerprint = (r->fingerprint ^ r->name[i]) * 16777619U;
      }
    cache_certificate(p);
  }
  struct leaf_hold *hold = malloc(sizeof(*hold));
  if (!hold) {
    if (!p->cached)
      free(p);
    return ENOMEM;
  }
  *hold = (struct leaf_hold){p, c->holds};
  c->holds = hold;
  p->refs++;
  for (unsigned i = 0; i < p->count; i++) {
    struct leaf_record *r = &p->records[i];
    /* Allocation and routing can change even when the leaf bytes do not. */
    if (r->inode > c->fs->super->s_inodes_count ||
        !ext2fs_test_inode_bitmap2(c->fs->inode_map, r->inode) ||
        r->hash < low || r->hash > high || (r->hash == high && !collision))
      return EIO;
    e = checked_name(c, r);
    if (e)
      return e;
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
static int compare_block(const void *a, const void *b) {
  blk64_t x = *(const blk64_t *)a, y = *(const blk64_t *)b;
  return x < y ? -1 : x > y;
}
errcode_t namespace_index_check(ext2_filsys fs, ext2_ino_t ino) {
  struct index_check c = {.fs = fs, .ino = ino};
  errcode_t e = ext2fs_read_inode(fs, ino, &c.in);
  if (e || !(c.in.i_flags & EXT2_INDEX_FL))
    return e;
  uint64_t epoch = overlay_epoch(active_overlay);
  for (unsigned i = 0; epoch && i < INDEX_CACHE; i++)
    if (cache[i].epoch == epoch && cache[i].ino == ino &&
        !memcmp(&cache[i].in, &c.in, sizeof(c.in)) &&
        !memcmp(&cache[i].super, fs->super, sizeof(*fs->super))) {
      hits++;
      return 0;
    }
  scans++;
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
  if (!c.seen || !c.physical) {
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
  if (!e && epoch) {
    struct index_cached *entry = &cache[next_cache++ % INDEX_CACHE];
    entry->epoch = epoch;
    entry->ino = ino;
    entry->in = c.in;
    entry->super = *fs->super;
  }
out:
  while (c.holds) {
    struct leaf_hold *hold = c.holds;
    c.holds = hold->next;
    struct leaf_certificate *p = hold->certificate;
    if (!--p->refs && !p->cached)
      free(p);
    free(hold);
  }
  free(c.name);
  free(c.physical);
  free(c.seen);
  return e;
}
