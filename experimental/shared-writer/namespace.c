/* SPDX-License-Identifier: GPL-2.0-only */
#include "namespace.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static errcode_t supported(ext2_filsys fs) {
  return fs->super->s_creator_os != EXT2_OS_LINUX ||
                 ext2fs_has_feature_bigalloc(fs->super) ||
                 ext2fs_has_feature_quota(fs->super) ||
                 ext2fs_has_feature_ea_inode(fs->super) ||
                 ext2fs_has_feature_orphan_present(fs->super)
             ? EOPNOTSUPP
             : 0;
}
errcode_t namespace_orphans(ext2_filsys fs, ext2_ino_t *list, unsigned *count) {
  *count = 0;
  errcode_t e = supported(fs);
  if (e)
    return e;
  if (!fs->inode_map && (e = ext2fs_read_inode_bitmap(fs)))
    return e;
  ext2_ino_t ino = fs->super->s_last_orphan;
  while (ino) {
    if (*count == PIN_LIMIT || ino < EXT2_FIRST_INODE(fs->super) ||
        ino > fs->super->s_inodes_count ||
        !ext2fs_test_inode_bitmap2(fs->inode_map, ino))
      return EIO;
    for (unsigned i = 0; i < *count; i++)
      if (list[i] == ino)
        return EIO;
    struct ext2_inode in;
    if ((e = ext2fs_read_inode(fs, ino, &in)))
      return e;
    if (in.i_links_count ||
        ((in.i_mode & LINUX_S_IFMT) != LINUX_S_IFREG &&
         (in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR) ||
        (in.i_flags & GRANT_UNSUPPORTED))
      return EIO;
    list[(*count)++] = ino;
    ino = in.i_dtime;
  }
  /* Directory '..' references must form a bounded allocated ancestry tree;
   * every unlinked ancestor belongs to this same validated orphan list. */
  for (unsigned i = 0; i < *count; i++) {
    struct ext2_inode in;
    if ((e = ext2fs_read_inode(fs, list[i], &in)))
      return e;
    if ((in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
      continue;
    ext2_ino_t seen[PIN_LIMIT], node = list[i];
    unsigned depth = 0;
    for (;;) {
      if (node == EXT2_ROOT_INO) {
        ext2_ino_t parent;
        e = namespace_directory_parent(fs, node, &parent);
        if (e || parent != node)
          return e ? e : EIO;
        break;
      }
      if (depth == PIN_LIMIT)
        return EIO;
      for (unsigned j = 0; j < depth; j++)
        if (seen[j] == node)
          return EIO;
      seen[depth++] = node;
      if ((e = ext2fs_read_inode(fs, node, &in)))
        return e;
      if (!in.i_links_count) {
        int found = 0;
        for (unsigned j = 0; j < *count; j++)
          if (list[j] == node)
            found = 1;
        if (!found)
          return EIO;
      }
      ext2_ino_t parent;
      if ((e = namespace_directory_parent(fs, node, &parent)))
        return e;
      if (node == EXT2_ROOT_INO) {
        if (parent != node)
          return EIO;
        break;
      }
      node = parent;
    }
  }
  return 0;
}
static int pinned(const struct inode_pin *pins, unsigned count, ext2_ino_t ino,
                  uint32_t generation) {
  for (unsigned i = 0; i < count; i++)
    if (pins[i].inode == ino && pins[i].generation == generation)
      return 1;
  return 0;
}
static errcode_t stamp(ext2_filsys fs, ext2_ino_t ino, int directory) {
  struct ext2_inode_large in = {0};
  unsigned bytes = EXT2_INODE_SIZE(fs->super);
  if (bytes > sizeof(in))
    bytes = sizeof(in);
  errcode_t e =
      ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&in, bytes);
  if (e)
    return e;
  in.i_ctime = (uint32_t)time(NULL);
  if (in.i_extra_isize >= 8)
    in.i_ctime_extra = 0;
  if (directory) {
    in.i_mtime = in.i_ctime;
    if (in.i_extra_isize >= 12)
      in.i_mtime_extra = 0;
  }
  return ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&in, bytes);
}
static errcode_t reclaim(ext2_filsys fs, ext2_ino_t ino) {
  struct ext2_inode_large in = {0};
  unsigned bytes = EXT2_INODE_SIZE(fs->super);
  if (bytes > sizeof(in))
    bytes = sizeof(in);
  errcode_t e =
      ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&in, bytes);
  if (e)
    return e;
  unsigned type = in.i_mode & LINUX_S_IFMT;
  if (in.i_links_count ||
      (type != LINUX_S_IFREG && type != LINUX_S_IFDIR &&
       type != LINUX_S_IFLNK) ||
      (in.i_flags & GRANT_UNSUPPORTED))
    return EIO;
  if (!ext2fs_is_fast_symlink((struct ext2_inode *)&in) ||
      (in.i_flags & EXT4_EXTENTS_FL))
    e = ext2fs_punch(fs, ino, (struct ext2_inode *)&in, NULL, 0, ~0ULL);
  else
    memset(in.i_block, 0, sizeof(in.i_block));
  if (!e)
    e = ext2fs_free_ext_attr(fs, ino, &in);
  if (!e)
    e = ext2fs_inode_size_set(fs, (struct ext2_inode *)&in, 0);
  in.i_dtime = (uint32_t)time(NULL);
  if (!e)
    e = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&in, bytes);
  if (!e)
    ext2fs_inode_alloc_stats2(fs, ino, -1, type == LINUX_S_IFDIR);
  return e;
}
errcode_t namespace_reap(ext2_filsys fs, const struct inode_pin *pins,
                         unsigned count) {
  if (count > PIN_LIMIT || (count && !pins))
    return EINVAL;
  ext2_ino_t list[PIN_LIMIT];
  unsigned n;
  errcode_t e = namespace_orphans(fs, list, &n);
  if (e)
    return e;
  /* Reject malformed/stale broker pins before changing any metadata. */
  for (unsigned i = 0; i < count; i++) {
    struct ext2_inode in;
    if ((e = ext2fs_read_inode(fs, pins[i].inode, &in)))
      return e;
    int directory = (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFDIR;
    struct inode_grant g = {pins[i].inode, pins[i].generation,
                            directory ? GRANT_DIR_SEARCH : GRANT_READ,
                            directory ? GRANT_DIRECTORY : 0};
    if ((e = grant_inode_known(fs, &g, &in, list, n)))
      return e;
    for (unsigned j = 0; j < i; j++)
      if (pins[i].inode == pins[j].inode)
        return EINVAL;
  }
  ext2_ino_t head = 0;
  for (unsigned i = n; i; i--) {
    struct ext2_inode in;
    if ((e = ext2fs_read_inode(fs, list[i - 1], &in)))
      return e;
    if (pinned(pins, count, list[i - 1], in.i_generation)) {
      if (in.i_dtime != head) {
        in.i_dtime = head;
        if ((e = ext2fs_write_inode(fs, list[i - 1], &in)))
          return e;
      }
      head = list[i - 1];
    } else if ((e = reclaim(fs, list[i - 1])))
      return e;
  }
  if (fs->super->s_last_orphan != head) {
    fs->super->s_last_orphan = head;
    ext2fs_mark_super_dirty(fs);
  }
  return 0;
}
static errcode_t resolve(ext2_filsys fs, const char *path,
                         const struct credentials *c, ext2_ino_t *dir,
                         char **leaf, unsigned want) {
  errcode_t e = mutation_parent(fs, path, dir, leaf, c);
  if (!e && c)
    e = policy_inode(fs, *dir, c, want);
  struct ext2_inode in;
  if (!e)
    e = ext2fs_read_inode(fs, *dir, &in);
  if (!e && (in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
    e = ENOTDIR;
  if (!e &&
      (in.i_flags & (GRANT_UNSUPPORTED | EXT4_CASEFOLD_FL | EXT2_INDEX_FL)))
    e = EOPNOTSUPP;
  if (!e && (in.i_flags & EXT2_IMMUTABLE_FL))
    e = EPERM;
  return e;
}
static errcode_t entry_inode(ext2_filsys fs, ext2_ino_t ino,
                             struct ext2_inode *in) {
  if (ino < EXT2_FIRST_INODE(fs->super) || ino > fs->super->s_inodes_count ||
      !ext2fs_test_inode_bitmap2(fs->inode_map, ino))
    return EIO;
  errcode_t e = ext2fs_read_inode(fs, ino, in);
  if (e)
    return e;
  unsigned type = in->i_mode & LINUX_S_IFMT;
  if (type != LINUX_S_IFREG && type != LINUX_S_IFDIR && type != LINUX_S_IFLNK)
    return EOPNOTSUPP;
  if (type == LINUX_S_IFDIR &&
      (in->i_flags & (EXT2_INDEX_FL | EXT4_CASEFOLD_FL)))
    return EOPNOTSUPP;
  if (type == LINUX_S_IFLNK &&
      (!EXT2_I_SIZE(in) || EXT2_I_SIZE(in) >= fs->blocksize))
    return EIO;
  if (!in->i_links_count || in->i_dtime)
    return EIO;
  if (in->i_flags & GRANT_UNSUPPORTED)
    return EOPNOTSUPP;
  return in->i_flags & (EXT2_IMMUTABLE_FL | EXT2_APPEND_FL) ? EPERM : 0;
}
static errcode_t removable(ext2_filsys fs, ext2_ino_t dir,
                           const struct ext2_inode *file,
                           const struct credentials *c) {
  struct ext2_inode in;
  errcode_t e = ext2fs_read_inode(fs, dir, &in);
  if (e)
    return e;
  if (in.i_flags & EXT2_APPEND_FL)
    return EPERM;
  if (c && c->uid && (in.i_mode & LINUX_S_ISVTX) && c->uid != inode_uid(in) &&
      c->uid != inode_uid(*file))
    return EPERM;
  return 0;
}
static errcode_t link_name(ext2_filsys fs, ext2_ino_t dir, const char *leaf,
                           ext2_ino_t ino, unsigned type) {
  errcode_t e = ext2fs_link(fs, dir, leaf, ino, type);
  if (e == EXT2_ET_DIR_NO_SPACE || e == EXT2_ET_DIR_NO_SPACE_FOR_CSUM) {
    e = ext2fs_expand_dir(fs, dir);
    if (!e)
      e = ext2fs_link(fs, dir, leaf, ino, type);
  }
  return e;
}
static errcode_t drop(ext2_filsys fs, ext2_ino_t dir, const char *leaf,
                      ext2_ino_t ino, const struct inode_pin *pins,
                      unsigned count) {
  struct ext2_inode in;
  errcode_t e = ext2fs_read_inode(fs, ino, &in);
  if (!e)
    e = ext2fs_unlink(fs, dir, leaf, ino, 0);
  if (e)
    return e;
  in.i_links_count--;
  if (!in.i_links_count && pinned(pins, count, ino, in.i_generation)) {
    ext2_ino_t list[PIN_LIMIT];
    unsigned n;
    if ((e = namespace_orphans(fs, list, &n)))
      return e;
    if (n == PIN_LIMIT)
      return ENOSPC;
    in.i_dtime = fs->super->s_last_orphan;
    fs->super->s_last_orphan = ino;
    ext2fs_mark_super_dirty(fs);
  }
  if ((e = ext2fs_write_inode(fs, ino, &in)))
    return e;
  if (!in.i_links_count && !pinned(pins, count, ino, in.i_generation))
    e = reclaim(fs, ino);
  else
    e = stamp(fs, ino, 0);
  if (!e)
    e = stamp(fs, dir, 1);
  return e;
}
static errcode_t parent_links(ext2_filsys fs, ext2_ino_t dir, int delta) {
  struct ext2_inode in;
  errcode_t e = ext2fs_read_inode(fs, dir, &in);
  if (e)
    return e;
  if (in.i_links_count < 2 || (delta < 0 && in.i_links_count == 2))
    return EIO;
  if (delta > 0 && in.i_links_count >= 65000)
    return EMLINK;
  in.i_links_count += delta;
  return ext2fs_write_inode(fs, dir, &in);
}
struct dots {
  ext2_ino_t self, parent, new_parent;
  unsigned dot, dotdot, other;
  int error;
};
static int directory_entries(struct ext2_dir_entry *entry, int offset,
                             int blocksize, char *buf, void *private) {
  (void)offset;
  (void)blocksize;
  (void)buf;
  struct dots *d = private;
  if (!entry->inode)
    return 0;
  unsigned n = ext2fs_dirent_name_len(entry);
  if ((n == 1 && entry->name[0] == '.') ||
      (n == 2 && !memcmp(entry->name, "..", 2))) {
    unsigned type = ext2fs_dirent_file_type(entry);
    if (type && type != EXT2_FT_DIR) {
      d->error = EIO;
      return DIRENT_ABORT;
    }
  }
  if (n == 1 && entry->name[0] == '.') {
    if (++d->dot != 1 || entry->inode != d->self)
      d->error = EIO;
  } else if (n == 2 && !memcmp(entry->name, "..", 2)) {
    if (++d->dotdot != 1 || entry->inode != d->parent)
      d->error = EIO;
    else if (d->new_parent) {
      entry->inode = d->new_parent;
      return DIRENT_CHANGED;
    }
  } else
    d->other++;
  return d->error ? DIRENT_ABORT : 0;
}
static errcode_t directory_check(ext2_filsys fs, ext2_ino_t ino,
                                 ext2_ino_t parent, int empty,
                                 ext2_ino_t new_parent) {
  struct ext2_inode in;
  errcode_t e = ext2fs_read_inode(fs, ino, &in);
  if (e)
    return e;
  if (in.i_links_count && in.i_links_count < 2)
    return EIO;
  struct dots dots = {.self = ino, .parent = parent, .new_parent = new_parent};
  e = ext2fs_dir_iterate(fs, ino, 0, NULL, directory_entries, &dots);
  if (e)
    return e;
  if (dots.error || dots.dot != 1 || dots.dotdot != 1)
    return EIO;
  if (empty && dots.other)
    return ENOTEMPTY;
  if (empty && in.i_links_count && in.i_links_count != 2)
    return EIO;
  return 0;
}
errcode_t namespace_directory_parent(ext2_filsys fs, ext2_ino_t ino,
                                     ext2_ino_t *parent) {
  if (!fs->inode_map) {
    errcode_t e = ext2fs_read_inode_bitmap(fs);
    if (e)
      return e;
  }
  if (!ino || ino > fs->super->s_inodes_count ||
      !ext2fs_test_inode_bitmap2(fs->inode_map, ino))
    return EIO;
  struct ext2_inode in;
  errcode_t e = ext2fs_read_inode(fs, ino, &in);
  if (e)
    return e;
  if ((in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR ||
      (in.i_flags & (GRANT_UNSUPPORTED | EXT2_INDEX_FL | EXT4_CASEFOLD_FL)))
    return EOPNOTSUPP;
  e = ext2fs_lookup(fs, ino, "..", 2, NULL, parent);
  if (!e && (!*parent || *parent > fs->super->s_inodes_count ||
             !ext2fs_test_inode_bitmap2(fs->inode_map, *parent)))
    e = EIO;
  if (!e)
    e = directory_check(fs, ino, *parent, !in.i_links_count, 0);
  if (!e) {
    struct ext2_inode ancestor;
    e = ext2fs_read_inode(fs, *parent, &ancestor);
    if (!e && (ancestor.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
      e = EIO;
    if (!e && ((ino == EXT2_ROOT_INO && *parent != ino) ||
               (ino != EXT2_ROOT_INO && *parent == ino)))
      e = EIO;
  }
  return e;
}
static errcode_t no_cycle(ext2_filsys fs, ext2_ino_t moving,
                          ext2_ino_t parent) {
  ext2_ino_t seen[4096];
  unsigned count = 0;
  for (;;) {
    if (parent == moving)
      return EINVAL;
    if (count == 4096)
      return ELOOP;
    for (unsigned i = 0; i < count; i++)
      if (seen[i] == parent)
        return EIO;
    if (!parent || parent > fs->super->s_inodes_count ||
        !ext2fs_test_inode_bitmap2(fs->inode_map, parent))
      return EIO;
    seen[count++] = parent;
    struct ext2_inode in;
    errcode_t e = ext2fs_read_inode(fs, parent, &in);
    if (e)
      return e;
    if ((in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR || in.i_links_count < 2 ||
        in.i_dtime)
      return EIO;
    ext2_ino_t next;
    e = ext2fs_lookup(fs, parent, "..", 2, NULL, &next);
    if (e)
      return e;
    if (parent == EXT2_ROOT_INO)
      return next == parent ? 0 : EIO;
    parent = next;
  }
}
static errcode_t drop_directory(ext2_filsys fs, ext2_ino_t dir,
                                const char *name, ext2_ino_t ino,
                                const struct inode_pin *pins, unsigned count) {
  errcode_t e = directory_check(fs, ino, dir, 1, 0);
  if (e)
    return e;
  e = ext2fs_unlink(fs, dir, name, ino, 0);
  struct ext2_inode in;
  if (!e)
    e = ext2fs_read_inode(fs, ino, &in);
  if (!e) {
    in.i_links_count = 0;
    if (pinned(pins, count, ino, in.i_generation)) {
      ext2_ino_t list[PIN_LIMIT];
      unsigned n;
      e = namespace_orphans(fs, list, &n);
      if (!e && n == PIN_LIMIT)
        e = ENOSPC;
      if (!e) {
        in.i_dtime = fs->super->s_last_orphan;
        fs->super->s_last_orphan = ino;
        ext2fs_mark_super_dirty(fs);
      }
    }
    if (!e)
      e = ext2fs_write_inode(fs, ino, &in);
  }
  if (!e)
    e = pinned(pins, count, ino, in.i_generation) ? stamp(fs, ino, 0)
                                                  : reclaim(fs, ino);
  if (!e)
    e = parent_links(fs, dir, -1);
  if (!e)
    e = stamp(fs, dir, 1);
  return e;
}
static errcode_t set_acl(ext2_filsys fs, ext2_ino_t ino, const char *key,
                         const unsigned char *value, size_t length) {
  struct ext2_xattr_handle *h = NULL;
  unsigned flags = XATTR_HANDLE_FLAG_RAW;
  errcode_t e = ext2fs_xattrs_open(fs, ino, &h);
  if (!e)
    e = ext2fs_xattrs_flags(h, &flags, NULL);
  if (!e)
    e = ext2fs_xattrs_read(h);
  if (!e)
    e = ext2fs_xattr_set(h, key, value, length);
  if (h) {
    errcode_t close = ext2fs_xattrs_close(&h);
    if (!e)
      e = close;
  }
  return e;
}
static errcode_t copy_default_acl(ext2_filsys fs, ext2_ino_t parent,
                                  ext2_ino_t ino) {
  struct ext2_xattr_handle *h = NULL;
  unsigned flags = XATTR_HANDLE_FLAG_RAW;
  unsigned char *value = NULL;
  size_t length = 0;
  errcode_t e = ext2fs_xattrs_open(fs, parent, &h);
  if (!e)
    e = ext2fs_xattrs_flags(h, &flags, NULL);
  if (!e)
    e = ext2fs_xattrs_read(h);
  if (!e)
    e = ext2fs_xattr_get(h, "system.posix_acl_default", (void **)&value,
                         &length);
  if (h) {
    errcode_t close = ext2fs_xattrs_close(&h);
    if (!e)
      e = close;
  }
  if (e == EXT2_ET_EA_KEY_NOT_FOUND)
    e = 0;
  else if (!e)
    e = set_acl(fs, ino, "system.posix_acl_default", value, length);
  free(value);
  return e;
}
static errcode_t create_entry(ext2_filsys fs, ext2_ino_t dir, const char *name,
                              const struct mutation *op,
                              const struct credentials *c) {
  int directory = op->kind == MUT_MKDIR;
  if (ext2fs_has_feature_inline_data(fs->super) &&
      (directory || op->length >= 60))
    return EOPNOTSUPP;
  if (!directory && op->length >= fs->blocksize)
    return ENAMETOOLONG;
  struct ext2_inode parent, previous;
  errcode_t e = ext2fs_read_inode(fs, dir, &parent);
  if (e)
    return e;
  if (directory && (parent.i_links_count < 2 || parent.i_links_count >= 65000))
    return parent.i_links_count < 2 ? EIO : EMLINK;
  unsigned mode = op->mode & 0777;
  uint32_t uid = op->uid, gid = op->gid;
  unsigned char *acl = NULL;
  size_t acl_length = 0;
  if (c && directory)
    e = policy_creation(fs, dir, c, mode, &mode, &uid, &gid, &acl, &acl_length);
  else if (c) {
    uid = c->uid;
    gid = (parent.i_mode & LINUX_S_ISGID) ? inode_gid(parent) : c->gid;
  }
  ext2_ino_t ino = 0;
  if (!e)
    e = ext2fs_new_inode(fs, dir,
                         (directory ? LINUX_S_IFDIR : LINUX_S_IFLNK) | mode,
                         NULL, &ino);
  if (!e)
    e = ext2fs_read_inode(fs, ino, &previous);
  if (!e && previous.i_generation == UINT32_MAX)
    e = EOVERFLOW;
  char *target = NULL;
  if (!e && !directory) {
    target = calloc(op->length + 1, 1);
    if (!target)
      e = ENOMEM;
    else
      memcpy(target, op->data, op->length);
  }
  if (!e)
    e = directory ? ext2fs_mkdir(fs, dir, ino, NULL)
                  : ext2fs_symlink(fs, dir, ino, NULL, target);
  free(target);
  struct ext2_inode in;
  char *block = NULL;
  blk64_t physical = 0;
  if (!e)
    e = ext2fs_read_inode(fs, ino, &in);
  /* Directory data checksums contain generation: capture the raw new block,
   * advance identity, then rewrite its checksum through libext2fs. */
  if (!e && directory) {
    e = ext2fs_bmap2(fs, ino, &in, NULL, 0, 0, NULL, &physical);
    if (!e && !physical)
      e = EIO;
    if (!e) {
      block = malloc(fs->blocksize);
      if (!block)
        e = ENOMEM;
    }
    if (!e)
      e = io_channel_read_blk64(fs->io, physical, 1, block);
  }
  if (!e) {
    in.i_generation = previous.i_generation + 1;
    in.i_mode =
        (directory ? LINUX_S_IFDIR : LINUX_S_IFLNK) | (directory ? mode : 0777);
    if (directory)
      in.i_mode |= (op->mode & LINUX_S_ISVTX) | (parent.i_mode & LINUX_S_ISGID);
    in.i_uid = uid;
    in.i_gid = gid;
    ext2fs_set_i_uid_high(in, uid >> 16);
    ext2fs_set_i_gid_high(in, gid >> 16);
    e = ext2fs_write_inode(fs, ino, &in);
  }
  if (!e && directory)
    e = ext2fs_write_dir_block4(fs, physical, block, 0, ino);
  free(block);
  if (!e && acl)
    e = set_acl(fs, ino, "system.posix_acl_access", acl, acl_length);
  if (!e && directory && c && acl)
    e = copy_default_acl(fs, dir, ino);
  free(acl);
  if (!e)
    e = link_name(fs, dir, name, ino,
                  directory ? EXT2_FT_DIR : EXT2_FT_SYMLINK);
  if (!e)
    e = stamp(fs, dir, 1);
  return e;
}
errcode_t namespace_apply(ext2_filsys fs, const struct mutation *op,
                          const struct credentials *c,
                          const struct inode_pin *pins, unsigned count) {
  errcode_t e = supported(fs);
  if (e)
    return e;
  if (!op || op->kind < MUT_LINK || op->kind > MUT_SYMLINK || op->offset)
    return EINVAL;
  int creating = op->kind == MUT_MKDIR || op->kind == MUT_SYMLINK;
  int payload =
      op->kind == MUT_LINK || op->kind == MUT_RENAME || op->kind == MUT_SYMLINK;
  if ((!creating && (op->mode || op->uid || op->gid)) ||
      (creating && op->mode > (op->kind == MUT_MKDIR ? 01777 : 0777)) ||
      (payload ? (!op->length || op->length > 4096 || !op->data ||
                  memchr(op->data, 0, op->length))
               : op->length))
    return EINVAL;
  if (c && policy_credentials(c))
    return EINVAL;
  if (c && creating && (op->uid != c->uid || op->gid != c->gid))
    return EINVAL;
  ext2_ino_t from = 0, to = 0, ino = 0, victim = 0;
  char *name = NULL, *newname = NULL, *target = NULL;
  struct ext2_inode in, old;
  e = resolve(fs, op->path, c, &from, &name, op->kind == MUT_LINK ? 1 : 3);
  if (e) {
    free(name);
    return e;
  }
  e = ext2fs_lookup(fs, from, name, strlen(name), NULL, &ino);
  if (creating) {
    if (!e)
      e = EEXIST;
    else if (e == EXT2_ET_FILE_NOT_FOUND)
      e = create_entry(fs, from, name, op, c);
    free(name);
    return e;
  }
  if (!e)
    e = entry_inode(fs, ino, &in);
  unsigned type = e ? 0 : in.i_mode & LINUX_S_IFMT;
  if (!e && op->kind == MUT_LINK && type == LINUX_S_IFDIR)
    e = EPERM;
  if (!e && op->kind == MUT_UNLINK && type == LINUX_S_IFDIR)
    e = EISDIR;
  if (!e && op->kind == MUT_RMDIR && type != LINUX_S_IFDIR)
    e = ENOTDIR;
  if (!e && type == LINUX_S_IFDIR)
    e = directory_check(fs, ino, from, op->kind == MUT_RMDIR, 0);
  if (!e && op->kind != MUT_LINK)
    e = removable(fs, from, &in, c);
  if (!e && op->kind == MUT_LINK && c && c->uid && c->uid != inode_uid(in)) {
    if (type != LINUX_S_IFREG || (in.i_mode & LINUX_S_ISUID) ||
        ((in.i_mode & LINUX_S_ISGID) && (in.i_mode & LINUX_S_IXGRP)))
      e = EPERM;
    else
      e = policy_inode(fs, ino, c, 6);
  }
  if (!e && (op->kind == MUT_LINK || op->kind == MUT_RENAME)) {
    target = calloc(op->length + 1, 1);
    if (!target)
      e = ENOMEM;
    else {
      memcpy(target, op->data, op->length);
      e = resolve(fs, target, c, &to, &newname, 3);
    }
    if (!e) {
      e = ext2fs_lookup(fs, to, newname, strlen(newname), NULL, &victim);
      if (e == EXT2_ET_FILE_NOT_FOUND) {
        victim = 0;
        e = 0;
      }
    }
    if (!e && victim && op->kind == MUT_LINK)
      e = EEXIST;
    if (!e && victim && op->kind == MUT_RENAME) {
      e = entry_inode(fs, victim, &old);
      unsigned other = e ? 0 : old.i_mode & LINUX_S_IFMT;
      if (!e && type == LINUX_S_IFDIR && other != LINUX_S_IFDIR)
        e = ENOTDIR;
      if (!e && type != LINUX_S_IFDIR && other == LINUX_S_IFDIR)
        e = EISDIR;
      if (!e)
        e = removable(fs, to, &old, c);
      if (!e && victim != ino && other == LINUX_S_IFDIR)
        e = directory_check(fs, victim, to, 1, 0);
    }
    if (!e && type == LINUX_S_IFDIR && victim != ino) {
      e = no_cycle(fs, ino, to);
      if (!e && from != to && c)
        e = policy_inode(fs, ino, c, 2);
    }
  }
  if (!e && op->kind == MUT_RMDIR)
    e = drop_directory(fs, from, name, ino, pins, count);
  else if (!e && op->kind == MUT_UNLINK)
    e = drop(fs, from, name, ino, pins, count);
  else if (!e && op->kind == MUT_RENAME &&
           victim == ino) { /* same-inode no-op */
  } else if (!e) {
    if (op->kind == MUT_LINK && in.i_links_count == 65535)
      e = EMLINK;
    if (!e && victim)
      e = type == LINUX_S_IFDIR
              ? drop_directory(fs, to, newname, victim, pins, count)
              : drop(fs, to, newname, victim, pins, count);
    unsigned filetype = type == LINUX_S_IFDIR   ? EXT2_FT_DIR
                        : type == LINUX_S_IFLNK ? EXT2_FT_SYMLINK
                                                : EXT2_FT_REG_FILE;
    if (!e)
      e = link_name(fs, to, newname, ino, filetype);
    if (!e && op->kind == MUT_RENAME)
      e = ext2fs_unlink(fs, from, name, ino, 0);
    if (!e && op->kind == MUT_RENAME && type == LINUX_S_IFDIR && from != to) {
      e = directory_check(fs, ino, from, 0, to);
      if (!e)
        e = parent_links(fs, from, -1);
      if (!e)
        e = parent_links(fs, to, 1);
    }
    if (!e && op->kind == MUT_LINK) {
      in.i_links_count++;
      e = ext2fs_write_inode(fs, ino, &in);
    }
    if (!e)
      e = stamp(fs, ino, 0);
    if (!e)
      e = stamp(fs, to, 1);
    if (!e && from != to && op->kind == MUT_RENAME)
      e = stamp(fs, from, 1);
  }
  free(name);
  free(newname);
  free(target);
  return e;
}
