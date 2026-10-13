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
    if (in.i_links_count || (in.i_mode & LINUX_S_IFMT) != LINUX_S_IFREG ||
        (in.i_flags & GRANT_UNSUPPORTED))
      return EIO;
    list[(*count)++] = ino;
    ino = in.i_dtime;
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
  if (in.i_links_count || (in.i_mode & LINUX_S_IFMT) != LINUX_S_IFREG ||
      (in.i_flags & GRANT_UNSUPPORTED))
    return EIO;
  e = ext2fs_punch(fs, ino, (struct ext2_inode *)&in, NULL, 0, ~0ULL);
  if (!e)
    e = ext2fs_free_ext_attr(fs, ino, &in);
  if (!e)
    e = ext2fs_inode_size_set(fs, (struct ext2_inode *)&in, 0);
  in.i_dtime = (uint32_t)time(NULL);
  if (!e)
    e = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&in, bytes);
  if (!e)
    ext2fs_inode_alloc_stats2(fs, ino, -1, 0);
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
    struct inode_grant g = {pins[i].inode, pins[i].generation, GRANT_READ, 0};
    struct ext2_inode in;
    if ((e = grant_inode(fs, &g, &in)))
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
static errcode_t regular(ext2_filsys fs, ext2_ino_t ino,
                         struct ext2_inode *in) {
  if (ino < EXT2_FIRST_INODE(fs->super) || ino > fs->super->s_inodes_count ||
      !ext2fs_test_inode_bitmap2(fs->inode_map, ino))
    return EIO;
  errcode_t e = ext2fs_read_inode(fs, ino, in);
  if (e)
    return e;
  if ((in->i_mode & LINUX_S_IFMT) != LINUX_S_IFREG)
    return (in->i_mode & LINUX_S_IFMT) == LINUX_S_IFDIR ? EISDIR : EOPNOTSUPP;
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
                           ext2_ino_t ino) {
  errcode_t e = ext2fs_link(fs, dir, leaf, ino, EXT2_FT_REG_FILE);
  if (e == EXT2_ET_DIR_NO_SPACE || e == EXT2_ET_DIR_NO_SPACE_FOR_CSUM) {
    e = ext2fs_expand_dir(fs, dir);
    if (!e)
      e = ext2fs_link(fs, dir, leaf, ino, EXT2_FT_REG_FILE);
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
errcode_t namespace_apply(ext2_filsys fs, const struct mutation *op,
                          const struct credentials *c,
                          const struct inode_pin *pins, unsigned count) {
  errcode_t e = supported(fs);
  if (e)
    return e;
  if (!op || op->kind < MUT_LINK || op->kind > MUT_UNLINK || op->offset ||
      op->mode || op->uid || op->gid ||
      (op->kind == MUT_UNLINK ? op->length != 0
                              : (!op->length || op->length > 4096 ||
                                 !op->data || memchr(op->data, 0, op->length))))
    return EINVAL;
  if (c && policy_credentials(c))
    return EINVAL;
  ext2_ino_t from = 0, to = 0, ino = 0, victim = 0;
  char *name = NULL, *newname = NULL, *target = NULL;
  struct ext2_inode in, old;
  e = resolve(fs, op->path, c, &from, &name, op->kind == MUT_LINK ? 1 : 3);
  if (!e)
    e = ext2fs_lookup(fs, from, name, strlen(name), NULL, &ino);
  if (!e)
    e = regular(fs, ino, &in);
  if (!e && op->kind != MUT_LINK)
    e = removable(fs, from, &in, c);
  if (!e && op->kind == MUT_LINK && c && c->uid && c->uid != inode_uid(in)) {
    if ((in.i_mode & LINUX_S_ISUID) ||
        ((in.i_mode & LINUX_S_ISGID) && (in.i_mode & LINUX_S_IXGRP)))
      e = EPERM;
    else
      e = policy_inode(fs, ino, c, 6);
  }
  if (!e && op->kind != MUT_UNLINK) {
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
      e = regular(fs, victim, &old);
      if (!e)
        e = removable(fs, to, &old, c);
    }
  }
  if (!e && op->kind == MUT_UNLINK)
    e = drop(fs, from, name, ino, pins, count);
  else if (!e && op->kind == MUT_RENAME &&
           victim == ino) { /* POSIX same-inode no-op. */
  } else if (!e) {
    if (op->kind == MUT_LINK && in.i_links_count == 65535)
      e = EMLINK;
    if (!e && victim)
      e = drop(fs, to, newname, victim, pins, count);
    if (!e)
      e = link_name(fs, to, newname, ino);
    if (!e && op->kind == MUT_RENAME)
      e = ext2fs_unlink(fs, from, name, ino, 0);
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
