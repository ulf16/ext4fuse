/* SPDX-License-Identifier: GPL-2.0-only */
#include "handles.h"
#include "directory-ref.h"
#include "directory-stream.h"
#include "metadata.h"
#include "mount-metadata.h"
#include "ops.h"
#include "overlay.h"
#include "path-at.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
extern struct struct_io_manager staged_manager;
#ifndef HANDLE_LIMIT
#define HANDLE_LIMIT 8192
#endif
#ifndef NODE_LIMIT
#define NODE_LIMIT 32768
#endif
#define TOKEN_BITS 17
#define TOKEN_MASK ((1ULL << TOKEN_BITS) - 1)
#if HANDLE_LIMIT + NODE_LIMIT >= (1 << TOKEN_BITS)
#error handle slot encoding overflow
#endif
#define TABLE_LIMIT (HANDLE_LIMIT + NODE_LIMIT)
static int mounted_nodes;
struct handle {
  uint64_t token, verified;
  struct handle *node_next;
  struct inode_grant grant;
  int stale, pending;
  unsigned slot;
  struct handle *next, *previous;
  struct directory_stream stream;
};
/* Stable, individually allocated slots: growing the pool cannot invalidate a
 * handle borrowed by a nested open. Tokens encode a slot plus a never-reused
 * serial; a released slot can never resurrect an old capability. */
static struct handle *table[TABLE_LIMIT], *live;
static unsigned cursor[2];
static struct handle *node_buckets[65536];
static unsigned node_bucket(ext2_ino_t ino) { return (ino * 2654435761U) % 65536; }
static uint64_t last_token;
static struct handle *free_slot(int node) {
  unsigned begin = node ? HANDLE_LIMIT : 0;
  unsigned length = node ? NODE_LIMIT : HANDLE_LIMIT;
  for (unsigned j = 0; j < length; j++) {
    unsigned i = begin + (cursor[node] + j) % length;
    if (!table[i]) {
      struct handle *h = calloc(1, sizeof(*h));
      if (!h)
        return NULL;
      h->slot = i;
      h->next = live;
      if (live)
        live->previous = h;
      live = table[i] = h;
      cursor[node] = (i - begin + 1) % length;
      return h;
    }
  }
  return NULL;
}
static void clear_handle(struct handle *h) {
  directory_stream_clear(&h->stream);
  if (h->previous)
    h->previous->next = h->next;
  else
    live = h->next;
  if (h->next)
    h->next->previous = h->previous;
  if (h->slot >= HANDLE_LIMIT && h->token) {
    struct handle **at = &node_buckets[node_bucket(h->grant.inode)];
    while (*at && *at != h)
      at = &(*at)->node_next;
    if (*at)
      *at = h->node_next;
  }
  table[h->slot] = NULL;
  free(h);
}
static int token_available(void) { return last_token < (UINT64_MAX >> TOKEN_BITS); }
static void assign_token(struct handle *h) {
  h->token = (++last_token << TOKEN_BITS) | h->slot;
}
void handles_destroy(void) {
  while (live)
    clear_handle(live);
}
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
static unsigned pin_slots[2 * PIN_LIMIT], pin_generations[2 * PIN_LIMIT];
static unsigned pin_position(ext2_ino_t ino) {
  unsigned at = (ino * 2654435761U) % (2 * PIN_LIMIT);
  while (pin_slots[at] && pin_slots[at] != ino)
    at = (at + 1) % (2 * PIN_LIMIT);
  return at;
}
static errcode_t add_pin(struct inode_pin *pins, unsigned *count,
                         ext2_ino_t ino, uint32_t generation) {
  if (ino == EXT2_ROOT_INO)
    return 0;
  unsigned at = pin_position(ino);
  if (pin_slots[at])
    return 0;
  if (*count == PIN_LIMIT)
    return EMFILE;
  pin_slots[at] = ino;
  pin_generations[at] = generation;
  pins[*count] = (struct inode_pin){ino, generation};
  (*count)++;
  return 0;
}
static int compare_inode(const void *a, const void *b) {
  ext2_ino_t x = *(const ext2_ino_t *)a, y = *(const ext2_ino_t *)b;
  return x < y ? -1 : x > y;
}
static errcode_t pin_snapshot_ready(ext2_filsys fs, struct inode_pin *pins,
                                    unsigned *count, unsigned *reapable) {
  *count = 0;
  memset(pin_slots, 0, sizeof(pin_slots));
  ext2_ino_t orphans[PIN_LIMIT];
  unsigned orphan_count;
  errcode_t valid = namespace_orphans(fs, orphans, &orphan_count);
  if (valid)
    return valid;
  qsort(orphans, orphan_count, sizeof(*orphans), compare_inode);
  for (struct handle *h = live; h; h = h->next) {
    if (!h->token || h->stale || h->pending)
      continue;
    unsigned position = pin_position(h->grant.inode);
    if (pin_slots[position] && pin_generations[position] == h->grant.generation)
      continue;
    uint64_t epoch = overlay_epoch(active_overlay);
    if (epoch && h->verified == epoch && h->grant.flags != GRANT_DIRECTORY) {
      errcode_t e = add_pin(pins, count, h->grant.inode, h->grant.generation);
      if (e)
        return e;
      continue;
    }
    struct ext2_inode in;
    errcode_t e = grant_inode_known(fs, &h->grant, &in, orphans, orphan_count);
    if (e == ESTALE) {
      h->stale = 1;
      continue;
    }
    if (e)
      return e;
    h->verified = epoch;
    int captured = !!pin_slots[pin_position(h->grant.inode)];
    e = add_pin(pins, count, h->grant.inode, in.i_generation);
    if (e)
      return e;
    if (h->grant.flags != GRANT_DIRECTORY || captured)
      continue;
    ext2_ino_t node = h->grant.inode, seen[ANCESTOR_LIMIT];
    unsigned depth = 0;
    while (node != EXT2_ROOT_INO) {
      if (depth == ANCESTOR_LIMIT)
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
  if (reapable) {
    *reapable = 0;
    /* Every inserted pin was validated against this same published view,
     * including zero-link directory ancestors. No producer is needed when
     * all validated orphans still have a live pin. */
    for (unsigned i = 0; i < orphan_count; i++)
      if (!pin_slots[pin_position(orphans[i])])
        (*reapable)++;
  }
  return 0;
}
static errcode_t pin_snapshot(ext2_filsys fs, struct inode_pin *pins,
                              unsigned *count) {
  return pin_snapshot_ready(fs, pins, count, NULL);
}
static errcode_t allocate(ext2_filsys fs, const struct inode_grant *g,
                          uint64_t *size, unsigned char **data, size_t *count) {
  if (!token_available())
    return EMFILE;
  struct handle *h = free_slot(0);
  if (!h)
    return EMFILE;
  struct ext2_inode in;
  errcode_t e = grant_inode(fs, g, &in);
  if (e) {
    clear_handle(h);
    return e;
  }
  h->grant = *g;
  h->stale = 0;
  assign_token(h);
  struct inode_pin pins[PIN_LIMIT];
  unsigned n;
  e = pin_snapshot(fs, pins, &n);
  if (e) {
    clear_handle(h);
    return e;
  }
  *data = calloc(24, 1);
  if (!*data) {
    clear_handle(h);
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
static errcode_t node_allocate(ext2_filsys fs, ext2_ino_t ino, uint64_t *size,
                               unsigned char **data, size_t *count) {
  struct ext2_inode in;
  errcode_t e = ext2fs_read_inode(fs, ino, &in);
  if (e)
    return e;
  struct inode_grant g = {
      ino, in.i_generation,
      (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFDIR ? GRANT_DIR_SEARCH : 0,
      (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFDIR ? GRANT_DIRECTORY
                                                  : GRANT_NODE};
  if ((e = grant_inode(fs, &g, &in)))
    return e;
  struct handle *slot = NULL;
  int created = 0;
  unsigned bucket = node_bucket(ino);
  for (struct handle *candidate = node_buckets[bucket]; candidate; candidate = candidate->node_next) {
    if (candidate->slot >= HANDLE_LIMIT && candidate->token && candidate->grant.inode == ino &&
        candidate->grant.generation == in.i_generation && !candidate->stale) {
      slot = candidate;
      break;
    }
  }
  if (!slot) {
    if (!token_available())
      return EMFILE;
    slot = free_slot(1);
    if (!slot)
      return EMFILE;
    created = 1;
    assign_token(slot);
    slot->grant = g;
    slot->node_next = node_buckets[bucket];
    node_buckets[bucket] = slot;
    struct inode_pin pins[PIN_LIMIT];
    unsigned n;
    e = pin_snapshot(fs, pins, &n);
    if (e) {
      clear_handle(slot);
      return e;
    }
  }
  *data = calloc(24, 1);
  if (!*data) {
    if (created)
      clear_handle(slot);
    return ENOMEM;
  }
  put(*data, slot->token, 8);
  put(*data + 8, g.inode, 4);
  put(*data + 12, g.generation, 4);
  put(*data + 16, g.access, 4);
  put(*data + 20, g.flags, 4);
  *count = 24;
  *size = EXT2_I_SIZE(&in);
  return 0;
}
int handles_dispatch(const char *image, const struct credentials *c,
                     unsigned command, const unsigned char *path, size_t bytes,
                     uint64_t offset, uint64_t length, uint64_t *size,
                     unsigned char **data, size_t *count) {
  if (command == 37) {
    if (!c || bytes || offset || length || mounted_nodes)
      return EINVAL;
    mounted_nodes = 1;
    return 0;
  }
  if (command >= 38 && command <= 43 && !mounted_nodes)
    return EPERM;
  if (command == 42) {
    if (!c || !mounted_nodes || bytes || offset || length)
      return EINVAL;
    int ready = overlay_read(active_overlay, 0, 0, NULL, 1);
    if (ready)
      return ready;
    ext2_filsys fs = NULL;
    errcode_t e =
        ext2fs_open(image, EXT2_FLAG_64BITS, 0, 0, &staged_manager, &fs);
    struct inode_pin pins[PIN_LIMIT];
    unsigned count = 0;
    if (!e)
      e = pin_snapshot(fs, pins, &count);
    if (fs)
      ext2fs_free(fs);
    if (e)
      return policy_errno(e);
    if (count == PIN_LIMIT || !token_available())
      return EMFILE;
    for (unsigned i = HANDLE_LIMIT; i < TABLE_LIMIT; i++)
      if (!table[i])
        return 0;
    return EMFILE;
  }
  if (command == 23) {
    if (!c)
      return EPERM;
    int ready = overlay_read(active_overlay, 0, 0, NULL, 1);
    if (ready)
      return ready;
    ext2_filsys fs = NULL;
    errcode_t e =
        ext2fs_open(image, EXT2_FLAG_64BITS, 0, 0, &staged_manager, &fs);
    struct inode_pin pins[PIN_LIMIT];
    unsigned n = 0;
    if (!e)
      e = pin_snapshot(fs, pins, &n);
    if (fs)
      ext2fs_free(fs);
    if (e)
      return policy_errno(e);
    if (n == PIN_LIMIT || !token_available())
      return EMFILE;
    struct handle *slot = free_slot(0);
    if (!slot)
      return EMFILE;
    *data = calloc(8, 1);
    if (!*data) {
      clear_handle(slot);
      return ENOMEM;
    }
    assign_token(slot);
    slot->pending = 1;
    put(*data, slot->token, 8);
    *count = 8;
    return 0;
  }
  if (!c && command != 12 && command != 44)
    return EPERM;
  struct handle *h = NULL, root = {0};
  int root_request = 0;
  if (command != 7 && command != 12 && command != 44 && command != 14) {
    if ((command == 19 || command == 20 || command == 22 || command == 25 ||
         command == 26 || command == 31 || command == 34 || command == 35 ||
         command == 38)
            ? bytes < 9
        : command == 27 ? bytes != 12
        : command == 24 ? bytes != 24
                        : bytes != 8)
      return EINVAL;
    uint64_t token = le(path, 8);
    if (!token &&
        (command == 15 || command == 17 || command == 19 || command == 20 ||
         command == 21 || command == 22 || command == 25 || command == 26 ||
         command == 30 || command == 31 || command == 32 || command == 34 ||
         command == 35 || command == 36 || command == 38))
      root_request = 1;
    else {
      if ((token & TOKEN_MASK) >= TABLE_LIMIT)
        return EBADF;
      h = table[token & TOKEN_MASK];
      if (h && h->token != token)
        h = NULL;
      if (!h)
        return EBADF;
      if (command == 10) {
        clear_handle(h);
        return 0;
      }
      if (h->stale)
        return ESTALE;
      if (h->pending && command != 24)
        return EBADF;
      if (!h->pending && command == 24)
        return EBADF;
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
  if (!e && command == 24) {
    struct inode_grant g = {le(path + 8, 4), le(path + 12, 4), le(path + 16, 4),
                            le(path + 20, 4)};
    e = grant_inode(fs, &g, &in);
    if (!e) {
      h->grant = g;
      h->pending = 0;
      struct inode_pin pins[PIN_LIMIT];
      unsigned n;
      e = pin_snapshot(fs, pins, &n);
      if (e) {
        h->pending = 1;
        memset(&h->grant, 0, sizeof(h->grant));
      }
    }
    if (!e) {
      *data = calloc(24, 1);
      if (!*data)
        e = ENOMEM;
      else {
        put(*data, h->token, 8);
        memcpy(*data + 8, path + 8, 16);
        *count = 24;
        *size = EXT2_I_SIZE(&in);
      }
    }
  } else if (!e && (command == 7 || command == 14)) {
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
  } else if (!e && (command == 12 || command == 44)) {
    struct inode_pin pins[PIN_LIMIT];
    unsigned n, reapable = 0;
    e = pin_snapshot_ready(fs, pins, &n, command == 44 ? &reapable : NULL);
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
        *size = command == 44 ? reapable : fs->super->s_last_orphan;
      }
    }
  } else if (!e) {
    e = grant_inode(fs, &h->grant, &in);
    if (e == ESTALE)
      h->stale = 1;
    int directory = h->grant.flags == GRANT_DIRECTORY;
    if (!e && command >= 15 && command != 30 && command != 35 &&
        command != 36 && command != 39 && command != 40 && command != 41 &&
        command != 43 && !directory)
      e = ENOTDIR;
    if (!e && h->grant.flags == GRANT_NODE && (command == 8 || command == 11))
      e = EBADF;
    if (!e && directory && (command == 8 || command == 11))
      e = EISDIR;
    if (!e && ((command == 8 && !(h->grant.access & GRANT_READ)) ||
               (command == 11 && !(h->grant.access & GRANT_WRITE)) ||
               ((command == 16 || (command >= 27 && command <= 29)) &&
                !(h->grant.access & GRANT_DIR_READ))))
      e = EBADF;
    if (!e)
      *size = directory && !in.i_links_count ? 0 : EXT2_I_SIZE(&in);
    if (!e && (command == 11 || command == 21 || command == 36)) {
      *data = calloc(16, 1);
      if (!*data)
        e = ENOMEM;
      else {
        put(*data, h->grant.inode, 4);
        put(*data + 4, h->grant.generation, 4);
        put(*data + 8, h->grant.access, 4);
        put(*data + 12, h->grant.flags, 4);
        *count = 16;
        if (command == 36)
          *size = 0;
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
    if (!e && command == 27)
      e = directory_stream_page(fs, h->grant.inode, &h->stream, offset,
                                le(path + 8, 4), length, size, data, count);
    if (!e && command == 28)
      e = directory_stream_seek(&h->stream, offset, size);
    if (!e && command == 29) {
      directory_stream_clear(&h->stream);
      *size = 0;
    }
    if (!e && command == 38) {
      const char *name = (const char *)path + 8;
      if (!*name || strlen(name) > 255 || strchr(name, '/'))
        e = EINVAL;
      struct path_result r = {0};
      if (!e && offset) {
        /* The kernel's implicit root reference requires identity, not search
         * permission. It must still permit owner getattr/chmod on a mode-000
         * root. Ordinary lookup always rechecks directory search permission. */
        if (offset != 1 || !root_request || strcmp(name, "."))
          e = EINVAL;
        else
          r.inode = EXT2_ROOT_INO;
      } else if (!e)
        e = path_at(fs, h->grant.inode, name, c, 0, &r);
      if (!e)
        e = node_allocate(fs, r.inode, size, data, count);
    }
    if (!e && command == 43) {
      /* Mounted kernel cache read-modify-write only. Derive its read handle
       * from a live regular-file WRITE capability, never a lookup/RO pin.
       * macOS default_permissions still gates application opens and fd I/O. */
      if (h->grant.flags > GRANT_APPEND || !(h->grant.access & GRANT_WRITE))
        e = EBADF;
      if (!e) {
        struct inode_grant g = {h->grant.inode, h->grant.generation,
                                GRANT_READ, 0};
        e = allocate(fs, &g, size, data, count);
      }
    }
    if (!e && command == 39) {
      /* Open an already-looked-up identity with fresh authorization. No
       * pathname is reconstructed; lookup pins themselves confer no data
       * rights. */
      unsigned access = offset & 3;
      int append = !!(offset & OPEN_APPEND);
      if (!access || offset & ~(3U | OPEN_APPEND | OPEN_DIRECTORY))
        e = EINVAL;
      if (!e && (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFLNK)
        e = ELOOP;
      /* IPC belongs to the host kernel. Device inodes never become regular
       * data grants, irrespective of the mount's nodev enforcement. */
      if (!e && special_type(in.i_mode))
        e = ENXIO;
      if (!e && (offset & OPEN_DIRECTORY) && !directory)
        e = ENOTDIR;
      if (!e && directory && (access & GRANT_WRITE))
        e = EISDIR;
      if (!e)
        e = policy_inode(fs, h->grant.inode, c,
                         (access & GRANT_READ ? 4 : 0) |
                             (access & GRANT_WRITE ? 2 : 0));
      if (!e && (access & GRANT_WRITE)) {
        if ((in.i_flags & EXT2_IMMUTABLE_FL) ||
            ((in.i_flags & EXT2_APPEND_FL) && !append))
          e = EPERM;
        else
          e = policy_writable(fs, h->grant.inode);
      }
      struct inode_grant g = {h->grant.inode, h->grant.generation,
                              directory ? GRANT_DIR_READ : access,
                              directory ? GRANT_DIRECTORY : append};
      if (!e)
        e = allocate(fs, &g, size, data, count);
    }
    if (!e && command == 40) {
      char *target = NULL;
      e = path_readlink(fs, h->grant.inode, &target, count);
      if (!e) {
        *data = (unsigned char *)target;
        *size = *count;
      }
    }
    if (!e && command == 41) {
      e = offset > 7 ? EINVAL : policy_inode(fs, h->grant.inode, c, offset);
      *size = 0;
    }
    if (!e && command == 35) {
      const unsigned char *body = path + 8;
      size_t n = bytes - 8;
      const unsigned char *sep = memchr(body, 0, n);
      if (!sep || offset > 1 || length > 1 ||
          n - (size_t)(sep - body) - 1 > 255 ||
          memchr(sep + 1, 0, n - (size_t)(sep - body) - 1))
        e = EINVAL;
      else {
        ext2_ino_t ino = h->grant.inode;
        if (sep != body) {
          if (!directory)
            e = ENOTDIR;
          struct path_result r;
          if (!e)
            e = path_at(fs, ino, (const char *)body, c, length ? AT_FOLLOW : 0,
                        &r);
          if (!e)
            ino = r.inode;
        } else if (root_request)
          e = EINVAL;
        size_t namelen = n - (size_t)(sep - body) - 1;
        if (!e && ((!offset && !namelen) || (offset && namelen)))
          e = EINVAL;
        if (!e)
          e = metadata_query(fs, ino, c, offset ? NULL : (const char *)sep + 1,
                             data, count);
        if (!e)
          *size = *count;
      }
    }
    if (!e && command == 30)
      e = mount_inode_stat(fs, h->grant.inode, data, count);
    if (!e && command == 32)
      e = mount_geometry(fs, data, count);
    if (!e && (command == 31 || command == 34)) {
      struct path_result r;
      e = path_at(fs, h->grant.inode, (const char *)path + 8, c,
                  command == 34 ? AT_FOLLOW : 0, &r);
      if (!e && command == 31)
        e = mount_inode_stat(fs, r.inode, data, count);
      if (!e && command == 34)
        e = policy_inode(fs, r.inode, c, offset);
      if (!e && command == 34)
        *size = 0;
    }
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
    if (!e && command == 22) {
      struct mutation op = {.kind = MUT_OPEN,
                            .at = 1,
                            .base = h->grant,
                            .path = (const char *)path + 8,
                            .offset = offset};
      struct inode_grant g;
      if (offset & (OPEN_CREATE | OPEN_EXCL | OPEN_TRUNC))
        e = EINVAL;
      else
        e = mutation_open_at(fs, &op, c, &g);
      if (!e)
        e = allocate(fs, &g, size, data, count);
    }
    if (!e && (command == 25 || command == 26)) {
      struct path_result r;
      e = path_at(fs, h->grant.inode, (const char *)path + 8, c,
                  command == 25 && offset ? AT_FOLLOW : 0, &r);
      if (!e && command == 26) {
        char *target = NULL;
        e = path_readlink(fs, r.inode, &target, count);
        if (!e) {
          *data = (unsigned char *)target;
          *size = *count;
        }
      } else if (!e) {
        e = ext2fs_read_inode(fs, r.inode, &in);
        if (!e) {
          *data = calloc(16, 1);
          if (!*data)
            e = ENOMEM;
          else {
            put(*data, r.inode, 4);
            put(*data + 4, in.i_generation, 4);
            put(*data + 8, in.i_mode, 4);
            put(*data + 12, in.i_links_count, 4);
            *count = 16;
            *size =
                (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFDIR && !in.i_links_count
                    ? 0
                    : EXT2_I_SIZE(&in);
          }
        }
      }
    }
    if (!e && (command == 19 || command == 20)) {
      ext2_ino_t ino = 0;
      if (command == 19) {
        struct path_result r;
        e = path_at(fs, h->grant.inode, (const char *)path + 8, c, AT_FOLLOW,
                    &r);
        if (!e) {
          ino = r.inode;
          e = ext2fs_read_inode(fs, ino, &in);
        }
        if (!e && (in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
          e = ENOTDIR;
        if (!e)
          e = policy_inode(fs, ino, c, 1);
      } else
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
