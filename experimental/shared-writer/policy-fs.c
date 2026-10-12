/* SPDX-License-Identifier: GPL-2.0-only */
#include "acl.h"
#include "policy.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
static errcode_t xattr(ext2_filsys fs, ext2_ino_t ino, const char *name,
                       unsigned char **value, size_t *length) {
  *value = NULL;
  *length = 0;
  struct ext2_xattr_handle *h = NULL;
  errcode_t e = ext2fs_xattrs_open(fs, ino, &h);
  unsigned flags = XATTR_HANDLE_FLAG_RAW;
  if (!e)
    e = ext2fs_xattrs_flags(h, &flags, NULL);
  if (!e)
    e = ext2fs_xattrs_read(h);
  if (!e)
    e = ext2fs_xattr_get(h, name, (void **)value, length);
  if (h) {
    errcode_t close = ext2fs_xattrs_close(&h);
    if (!e)
      e = close;
  }
  return e;
}
static errcode_t reject_xattr(ext2_filsys fs, ext2_ino_t ino,
                              const char *name) {
  unsigned char *value = NULL;
  size_t n = 0;
  errcode_t e = xattr(fs, ino, name, &value, &n);
  free(value);
  return e == EXT2_ET_EA_KEY_NOT_FOUND ? 0 : e ? e : EOPNOTSUPP;
}
errcode_t policy_writable(ext2_filsys fs, ext2_ino_t ino) {
  /* Clearing file capabilities requires an explicit killpriv policy; preserving
   * them after unprivileged data changes could grant stale privileges. */
  return reject_xattr(fs, ino, "security.capability");
}
errcode_t policy_inode(ext2_filsys fs, ext2_ino_t ino,
                       const struct credentials *c, unsigned want) {
  if (policy_credentials(c))
    return EINVAL;
  if (fs->super->s_creator_os != EXT2_OS_LINUX)
    return EOPNOTSUPP;
  struct ext2_inode in;
  errcode_t e = ext2fs_read_inode(fs, ino, &in);
  if (e)
    return e;
  if (inode_uid(in) == UINT32_MAX || inode_gid(in) == UINT32_MAX)
    return EIO;
  e = reject_xattr(fs, ino, "system.richacl");
  if (e)
    return e;
  unsigned char *acl = NULL;
  size_t n = 0;
  e = xattr(fs, ino, "system.posix_acl_access", &acl, &n);
  if (e == EXT2_ET_EA_KEY_NOT_FOUND)
    e = policy_acl(NULL, 0, in.i_mode, inode_uid(in), inode_gid(in), c, want);
  else if (!e) {
    if (!acl || n < 4)
      e = EIO;
    else
      e = policy_acl(acl, n, in.i_mode, inode_uid(in), inode_gid(in), c, want);
  }
  free(acl);
  if (!e && !c->uid && (want & 1) &&
      (in.i_mode & LINUX_S_IFMT) == LINUX_S_IFREG && !(in.i_mode & 0111))
    e = EACCES;
  return e;
}
errcode_t policy_path(ext2_filsys fs, const char *path,
                      const struct credentials *c, unsigned want,
                      ext2_ino_t *ino) {
  if (!path || path[0] != '/' || strlen(path) > 4096)
    return EINVAL;
  *ino = EXT2_ROOT_INO;
  if (!path[1])
    return policy_inode(fs, *ino, c, want);
  char *copy = strdup(path + 1);
  if (!copy)
    return ENOMEM;
  char *part = copy;
  errcode_t e = 0;
  for (;;) {
    char *slash = strchr(part, '/');
    if (slash)
      *slash = 0;
    if (!*part || strlen(part) > 255 || !strcmp(part, ".") ||
        !strcmp(part, "..")) {
      e = EINVAL;
      break;
    }
    struct ext2_inode dir;
    e = ext2fs_read_inode(fs, *ino, &dir);
    if (e)
      break;
    if ((dir.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR) {
      e = ENOTDIR;
      break;
    }
    e = policy_inode(fs, *ino, c, 1);
    if (e)
      break;
    ext2_ino_t next;
    e = ext2fs_lookup(fs, *ino, part, strlen(part), NULL, &next);
    if (e)
      break;
    *ino = next;
    if (!slash) {
      e = policy_inode(fs, *ino, c, want);
      break;
    }
    part = slash + 1;
  }
  free(copy);
  return e;
}
errcode_t policy_creation(ext2_filsys fs, ext2_ino_t parent,
                          const struct credentials *c, unsigned requested,
                          unsigned *mode, uint32_t *uid, uint32_t *gid,
                          unsigned char **acl, size_t *length) {
  *acl = NULL;
  *length = 0;
  errcode_t e = policy_inode(fs, parent, c, 3);
  if (e)
    return e;
  struct ext2_inode in;
  e = ext2fs_read_inode(fs, parent, &in);
  if (e)
    return e;
  if ((in.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
    return ENOTDIR;
  *uid = c->uid;
  *gid = in.i_mode & LINUX_S_ISGID ? inode_gid(in) : c->gid;
  e = xattr(fs, parent, "system.posix_acl_default", acl, length);
  if (e == EXT2_ET_EA_KEY_NOT_FOUND) {
    *mode = requested & ~c->umask;
    return 0;
  }
  if (!e)
    e = policy_inherit(*acl, *length, requested, mode);
  return e;
}
