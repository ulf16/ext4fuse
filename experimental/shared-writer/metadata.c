/* SPDX-License-Identifier: GPL-2.0-only */
#include "metadata.h"
#include "acl.h"
#include "path-at.h"
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define INCLUDES(n, field)                                                     \
  ((n) >= offsetof(struct ext2_inode_large, field) +                           \
              sizeof(((struct ext2_inode_large *)0)->field))
static uint64_t le(const unsigned char *p, unsigned n) {
  uint64_t v = 0;
  for (unsigned i = 0; i < n; i++)
    v |= (uint64_t)p[i] << (i * 8);
  return v;
}
static void put(unsigned char *p, uint64_t v, unsigned n) {
  for (unsigned i = 0; i < n; i++)
    p[i] = v >> (i * 8);
}
static errcode_t inode(ext2_filsys fs, ext2_ino_t ino,
                       struct ext2_inode_large *in, size_t *n) {
  memset(in, 0, sizeof(*in));
  *n = EXT2_INODE_SIZE(fs->super);
  if (*n > sizeof(*in))
    *n = sizeof(*in);
  errcode_t e = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)in, *n);
  if (e)
    return e;
  if (in->i_extra_isize &&
      (in->i_extra_isize < 4 || in->i_extra_isize % 4 ||
       in->i_extra_isize > EXT2_INODE_SIZE(fs->super) - 128))
    return EIO;
  if (inode_uid(*in) == UINT32_MAX || inode_gid(*in) == UINT32_MAX)
    return EIO;
  return 0;
}
static errcode_t opened(ext2_filsys fs, ext2_ino_t ino,
                        struct ext2_xattr_handle **h) {
  unsigned flags = XATTR_HANDLE_FLAG_RAW;
  errcode_t e = ext2fs_xattrs_open(fs, ino, h);
  if (!e)
    e = ext2fs_xattrs_flags(*h, &flags, NULL);
  if (!e)
    e = ext2fs_xattrs_read(*h);
  return e;
}
static errcode_t closed(struct ext2_xattr_handle **h, errcode_t e) {
  if (*h) {
    errcode_t close = ext2fs_xattrs_close(h);
    if (!e)
      e = close;
  }
  return e;
}
static int acl_name(const char *name) {
  return !strcmp(name, "system.posix_acl_access") ||
         !strcmp(name, "system.posix_acl_default");
}
static int user_name(const char *name) {
  return !strncmp(name, "user.", 5) && name[5];
}
static errcode_t name_valid(const char *name) {
  size_t n = strlen(name);
  if (!n || n > 255)
    return EINVAL;
  return user_name(name) || acl_name(name) ? 0 : EOPNOTSUPP;
}
static errcode_t stamp(struct ext2_inode_large *in, size_t n, unsigned which,
                       int64_t sec, uint64_t ns) {
  if (ns >= 1000000000)
    return EINVAL;
  if (sec < INT32_MIN || sec > INT64_C(15032385535))
    return EOVERFLOW;
  size_t actual = 128 + in->i_extra_isize;
  if (actual > n)
    actual = n;
  uint32_t *base = which == 0   ? &in->i_atime
                   : which == 1 ? &in->i_mtime
                                : &in->i_ctime;
  uint32_t *extra = which == 0   ? &in->i_atime_extra
                    : which == 1 ? &in->i_mtime_extra
                                 : &in->i_ctime_extra;
  int extended = which == 0   ? INCLUDES(actual, i_atime_extra)
                 : which == 1 ? INCLUDES(actual, i_mtime_extra)
                              : INCLUDES(actual, i_ctime_extra);
  if (!extended && (sec > INT32_MAX || ns))
    return EOVERFLOW;
  *base = (uint32_t)sec;
  if (extended)
    *extra =
        ((uint32_t)ns << 2) | ((uint64_t)(sec - (int64_t)(int32_t)sec) >> 32);
  return 0;
}
static errcode_t now_stamp(struct ext2_inode_large *in, size_t n,
                           unsigned which, struct timespec now) {
  size_t actual = 128 + in->i_extra_isize;
  if (actual > n)
    actual = n;
  int extended = which == 0   ? INCLUDES(actual, i_atime_extra)
                 : which == 1 ? INCLUDES(actual, i_mtime_extra)
                              : INCLUDES(actual, i_ctime_extra);
  return stamp(in, n, which, now.tv_sec, extended ? now.tv_nsec : 0);
}
/* Linux xattr ACL v2 uses fixed 8-byte records; ext4 stores packed v1. */
static errcode_t acl_decode(const unsigned char *src, size_t bytes,
                            unsigned char **out, size_t *size, unsigned *mode) {
  if (bytes < 4 || bytes > METADATA_LIMIT || le(src, 4) != 2 || (bytes - 4) % 8)
    return EINVAL;
  *out = calloc(bytes, 1);
  if (!*out)
    return ENOMEM;
  put(*out, 1, 4);
  *size = 4;
  *mode = 0;
  unsigned group = 0, mask = 0, have_mask = 0;
  for (size_t at = 4; at < bytes; at += 8) {
    unsigned tag = le(src + at, 2), perm = le(src + at + 2, 2);
    uint32_t id = le(src + at + 4, 4);
    int named = tag == 2 || tag == 8;
    if ((named && id == UINT32_MAX) || (!named && id != UINT32_MAX)) {
      free(*out);
      *out = NULL;
      return EINVAL;
    }
    memcpy(*out + *size, src + at, named ? 8 : 4);
    *size += named ? 8 : 4;
    if (tag == 1)
      *mode |= perm << 6;
    if (tag == 4)
      group = perm;
    if (tag == 16) {
      mask = perm;
      have_mask = 1;
    }
    if (tag == 32)
      *mode |= perm;
  }
  if (ext4_acl_to_xattr(*out, *size, NULL, 0) < 0) {
    free(*out);
    *out = NULL;
    return EINVAL;
  }
  if (*size > POLICY_ACL_LIMIT) {
    free(*out);
    *out = NULL;
    return E2BIG;
  }
  *mode |= (have_mask ? mask : group) << 3;
  return 0;
}
static errcode_t chmod_acl(ext2_filsys fs, ext2_ino_t ino, unsigned mode) {
  struct ext2_xattr_handle *h = NULL;
  void *data = NULL;
  size_t n = 0;
  errcode_t e = opened(fs, ino, &h);
  if (!e)
    e = ext2fs_xattr_get(h, "system.posix_acl_access", &data, &n);
  if (e == EXT2_ET_EA_KEY_NOT_FOUND)
    return closed(&h, 0);
  if (!e && ext4_acl_to_xattr(data, n, NULL, 0) < 0)
    e = EIO;
  int mask = 0;
  for (size_t at = 4; !e && at < n;) {
    unsigned tag = le((unsigned char *)data + at, 2);
    if (tag == 16)
      mask = 1;
    at += tag == 2 || tag == 8 ? 8 : 4;
  }
  for (size_t at = 4; !e && at < n;) {
    unsigned char *p = (unsigned char *)data + at;
    unsigned tag = le(p, 2);
    if (tag == 1)
      put(p + 2, (mode >> 6) & 7, 2);
    if (tag == 16 || (tag == 4 && !mask))
      put(p + 2, (mode >> 3) & 7, 2);
    if (tag == 32)
      put(p + 2, mode & 7, 2);
    at += tag == 2 || tag == 8 ? 8 : 4;
  }
  if (!e)
    e = ext2fs_xattr_set(h, "system.posix_acl_access", data, n);
  free(data);
  return closed(&h, e);
}
errcode_t metadata_apply(ext2_filsys fs, const struct mutation *op,
                         const struct credentials *c,
                         const struct inode_grant *g) {
  if (policy_credentials(c) || !op || op->kind < MUT_CHMOD ||
      op->kind > MUT_REMOVEXATTR)
    return EINVAL;
  struct ext2_super_block *super = fs->super;
  if (super->s_creator_os != EXT2_OS_LINUX || super->s_state != EXT2_VALID_FS ||
      ext2fs_has_feature_journal_needs_recovery(super) ||
      ext2fs_has_feature_quota(super) || ext2fs_has_feature_bigalloc(super) ||
      ext2fs_has_feature_ea_inode(super) ||
      ext2fs_has_feature_inline_data(super) ||
      ext2fs_has_feature_encrypt(super) || ext2fs_has_feature_casefold(super) ||
      ext2fs_has_feature_verity(super) || ext2fs_has_feature_readonly(super) ||
      ext2fs_has_feature_largedir(super) ||
      ext2fs_has_feature_orphan_present(super))
    return EOPNOTSUPP;
  ext2_ino_t ino;
  errcode_t e = 0;
  struct ext2_inode identity;
  if (g) {
    e = grant_inode(fs, g, &identity);
    ino = g->inode;
  } else {
    if (!op->at)
      return EINVAL;
    struct path_result r;
    ext2_ino_t start;
    e = path_base(fs, &op->base, op->path, &start);
    if (!e)
      e = path_at(fs, start, op->path, c, op->at_flags ? AT_FOLLOW : 0, &r);
    if (!e)
      ino = r.inode;
  }
  if (e)
    return e;
  struct ext2_inode_large in;
  size_t n;
  e = inode(fs, ino, &in, &n);
  if (e)
    return e;
  unsigned type = in.i_mode & LINUX_S_IFMT;
  if (type != LINUX_S_IFREG && type != LINUX_S_IFDIR && type != LINUX_S_IFLNK)
    return EOPNOTSUPP;
  if (in.i_flags & GRANT_UNSUPPORTED)
    return EOPNOTSUPP;
  if (op->kind == MUT_UTIMENS && op->length == 32 &&
      le((unsigned char *)op->data + 8, 8) == UINT64_MAX - 1 &&
      le((unsigned char *)op->data + 24, 8) == UINT64_MAX - 1)
    return 0;
  if (in.i_flags & (EXT2_IMMUTABLE_FL | EXT2_APPEND_FL))
    return EPERM;
  e = policy_inode(fs, ino, c, 0);
  if (e)
    return e;
  int owner = !c->uid || c->uid == inode_uid(in);
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now))
    return errno;
  if (op->kind == MUT_CHMOD) {
    if (op->mode > 07777 || op->uid || op->gid || op->offset || op->length)
      return EINVAL;
    if (type == LINUX_S_IFLNK)
      return EOPNOTSUPP;
    if (!owner)
      return EPERM;
    e = policy_writable(fs, ino);
    if (e)
      return e;
    unsigned mode = op->mode;
    if (c->uid && !policy_group(c, inode_gid(in)))
      mode &= ~LINUX_S_ISGID;
    e = chmod_acl(fs, ino, mode);
    if (e)
      return e;
    in.i_mode = type | mode;
  } else if (op->kind == MUT_CHOWN) {
    if (op->mode || op->offset || op->length)
      return EINVAL;
    if (!owner ||
        (c->uid && ((op->uid != UINT32_MAX && op->uid != inode_uid(in)) ||
                    (op->gid != UINT32_MAX && !policy_group(c, op->gid)))))
      return EPERM;
    e = policy_writable(fs, ino);
    if (e)
      return e;
    if (op->uid != UINT32_MAX) {
      in.i_uid = op->uid & 65535;
      ext2fs_set_i_uid_high(in, op->uid >> 16);
    }
    if (op->gid != UINT32_MAX) {
      in.i_gid = op->gid & 65535;
      ext2fs_set_i_gid_high(in, op->gid >> 16);
    }
    if (type == LINUX_S_IFREG &&
        (op->uid != UINT32_MAX || op->gid != UINT32_MAX))
      in.i_mode &= ~(LINUX_S_ISUID | LINUX_S_ISGID);
  } else if (op->kind == MUT_UTIMENS) {
    if (op->mode || op->uid || op->gid || op->offset || op->length != 32)
      return EINVAL;
    const unsigned char *p = op->data;
    uint64_t a = le(p + 8, 8), m = le(p + 24, 8);
    if (!owner) {
      if (a != UINT64_MAX || m != UINT64_MAX)
        return EPERM;
      e = policy_inode(fs, ino, c, 2);
      if (e)
        return e;
    }
    for (unsigned i = 0; i < 2; i++) {
      uint64_t ns = le(p + i * 16 + 8, 8);
      int64_t sec = (int64_t)le(p + i * 16, 8);
      if (ns == UINT64_MAX - 1)
        continue;
      e = ns == UINT64_MAX ? now_stamp(&in, n, i, now)
                           : stamp(&in, n, i, sec, ns);
      if (e)
        return e;
    }
  } else {
    if (op->uid || op->gid || op->offset || op->length < 5 ||
        op->length > METADATA_LIMIT + 259 || op->mode > 2)
      return EINVAL;
    const unsigned char *p = op->data;
    size_t namebytes = le(p, 4);
    if (!namebytes || namebytes > 255 || namebytes > op->length - 4 ||
        memchr(p + 4, 0, namebytes))
      return EINVAL;
    char name[256];
    memcpy(name, p + 4, namebytes);
    name[namebytes] = 0;
    e = name_valid(name);
    if (e)
      return e;
    const void *value = p + 4 + namebytes;
    size_t bytes = op->length - 4 - namebytes;
    if (op->kind == MUT_REMOVEXATTR && (bytes || op->mode))
      return EINVAL;
    if (op->kind == MUT_SETXATTR && bytes &&
        (!strcmp(name, NATIVE_INHERIT_KEY) ||
         !strcmp(name, "system.posix_acl_default"))) {
      struct ext2_xattr_handle *check = NULL;
      void *conflict = NULL;
      size_t length = 0;
      e = opened(fs, ino, &check);
      if (!e)
        e = ext2fs_xattr_get(check,
                             !strcmp(name, NATIVE_INHERIT_KEY)
                                 ? "system.posix_acl_default"
                                 : NATIVE_INHERIT_KEY,
                             &conflict, &length);
      free(conflict);
      if (!e)
        e = EOPNOTSUPP;
      else if (e == EXT2_ET_EA_KEY_NOT_FOUND)
        e = 0;
      e = closed(&check, e);
      if (e)
        return e;
    }
    int native = !strcmp(name, NATIVE_INHERIT_KEY);
    if (native) {
      if (!owner)
        return EPERM;
      if (type != LINUX_S_IFDIR)
        return EACCES;
      if (op->kind == MUT_SETXATTR) {
        e = policy_native_valid(value, bytes);
        if (e)
          return e;
      }
    } else if (user_name(name)) {
      if (type == LINUX_S_IFLNK)
        return EOPNOTSUPP;
      if (type == LINUX_S_IFDIR && (in.i_mode & LINUX_S_ISVTX) && !owner)
        return EPERM;
      e = policy_inode(fs, ino, c, 2);
      if (e)
        return e;
    } else if (!owner)
      return EPERM;
    if (acl_name(name) && type == LINUX_S_IFLNK)
      return EOPNOTSUPP;
    if (!strcmp(name, "system.posix_acl_default") && type != LINUX_S_IFDIR)
      return EACCES;
    struct ext2_xattr_handle *h = NULL;
    void *old = NULL;
    size_t oldbytes = 0;
    e = opened(fs, ino, &h);
    if (!e)
      e = ext2fs_xattr_get(h, name, &old, &oldbytes);
    free(old);
    int exists = !e;
    if (e == EXT2_ET_EA_KEY_NOT_FOUND)
      e = 0;
    if (!e && ((op->kind == MUT_REMOVEXATTR || op->mode == 2) && !exists))
      e = ENODATA;
    if (!e && op->mode == 1 && exists)
      e = EEXIST;
    unsigned char *acl = NULL;
    size_t aclbytes = 0;
    unsigned mode = 0;
    int access = !strcmp(name, "system.posix_acl_access");
    if (!e && op->kind == MUT_SETXATTR && acl_name(name) && bytes) {
      e = acl_decode(value, bytes, &acl, &aclbytes, &mode);
      if (!e && access) {
        in.i_mode = (in.i_mode & ~0777) | mode;
        if (c->uid && !policy_group(c, inode_gid(in)))
          in.i_mode &= ~LINUX_S_ISGID;
      }
    }
    if (!e) {
      int remove = op->kind == MUT_REMOVEXATTR || (acl_name(name) && !bytes) ||
                   (access && aclbytes == 16);
      if (remove) {
        if (exists)
          e = ext2fs_xattr_remove(h, name);
      } else
        e = ext2fs_xattr_set(h, name, acl ? acl : value,
                             acl ? aclbytes : bytes);
    }
    free(acl);
    e = closed(&h, e);
    if (e)
      return e;
  }
  /* xattr APIs can change EA block/checksum fields; refresh before writing
   * ordinary inode metadata so those changes are not overwritten. */
  struct ext2_inode_large fresh;
  size_t freshbytes;
  e = inode(fs, ino, &fresh, &freshbytes);
  if (e)
    return e;
  fresh.i_mode = in.i_mode;
  fresh.i_uid = in.i_uid;
  fresh.i_gid = in.i_gid;
  ext2fs_set_i_uid_high(fresh, inode_uid(in) >> 16);
  ext2fs_set_i_gid_high(fresh, inode_gid(in) >> 16);
  if (op->kind == MUT_UTIMENS) {
    fresh.i_atime = in.i_atime;
    fresh.i_atime_extra = in.i_atime_extra;
    fresh.i_mtime = in.i_mtime;
    fresh.i_mtime_extra = in.i_mtime_extra;
  }
  e = now_stamp(&fresh, freshbytes, 2, now);
  return e ? e
           : ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&fresh,
                                     freshbytes);
}
struct list {
  unsigned char *data;
  size_t bytes;
  errcode_t error;
};
static int list_attr(char *name, char *value, size_t bytes, void *raw) {
  (void)value;
  (void)bytes;
  struct list *list = raw;
  if (!user_name(name) && !acl_name(name))
    return 0;
  size_t n = strlen(name) + 1;
  if (n > 256 || n > METADATA_LIMIT - list->bytes) {
    list->error = E2BIG;
    return 1;
  }
  unsigned char *p = realloc(list->data, list->bytes + n);
  if (!p) {
    list->error = ENOMEM;
    return 1;
  }
  list->data = p;
  memcpy(p + list->bytes, name, n);
  list->bytes += n;
  return 0;
}
errcode_t metadata_query(ext2_filsys fs, ext2_ino_t ino,
                         const struct credentials *c, const char *name,
                         unsigned char **data, size_t *bytes) {
  *data = NULL;
  *bytes = 0;
  errcode_t e = policy_inode(fs, ino, c, 0);
  if (e)
    return e;
  struct ext2_xattr_handle *h = NULL;
  e = opened(fs, ino, &h);
  if (!e && !name) {
    struct list list = {0};
    e = ext2fs_xattrs_iterate(h, list_attr, &list);
    if (list.error)
      e = list.error;
    *data = list.data;
    *bytes = list.bytes;
  } else if (!e) {
    e = name_valid(name);
    if (!e && user_name(name) && strcmp(name, NATIVE_INHERIT_KEY))
      e = policy_inode(fs, ino, c, 4);
    if (!e)
      e = ext2fs_xattr_get(h, name, (void **)data, bytes);
    if (e == EXT2_ET_EA_KEY_NOT_FOUND)
      e = ENODATA;
    if (!e && acl_name(name)) {
      int n = ext4_acl_to_xattr(*data, *bytes, NULL, 0);
      if (n < 0)
        e = EIO;
      else {
        unsigned char *converted = malloc(n);
        if (!converted)
          e = ENOMEM;
        else {
          ext4_acl_to_xattr(*data, *bytes, (char *)converted, n);
          free(*data);
          *data = converted;
          *bytes = n;
        }
      }
    }
    if (!e && *bytes > METADATA_LIMIT)
      e = E2BIG;
  }
  e = closed(&h, e);
  if (e) {
    free(*data);
    *data = NULL;
    *bytes = 0;
  }
  return e;
}
