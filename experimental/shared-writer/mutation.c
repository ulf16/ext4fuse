/* SPDX-License-Identifier: GPL-2.0-only */
#include "mutation.h"
#include "path-at.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define MAX_FILE (64ULL * 1024 * 1024)
#define MAX_DATA (4U * 1024 * 1024)
#define UNSUPPORTED                                                            \
  (EXT2_COMPR_FL | EXT4_ENCRYPT_FL | EXT4_VERITY_FL | EXT4_INLINE_DATA_FL |    \
   EXT4_EA_INODE_FL)

errcode_t mutation_parent(ext2_filsys fs, const char *path, ext2_ino_t *dir,
                          char **leaf, const struct credentials *credentials) {
  if (!path || path[0] != '/' || strlen(path) > 4096 || !path[1] ||
      path[strlen(path) - 1] == '/')
    return EINVAL;
  char *copy = strdup(path + 1);
  if (!copy)
    return ENOMEM;
  *dir = EXT2_ROOT_INO;
  char *component = copy;
  errcode_t e = 0;
  for (;;) {
    char *slash = strchr(component, '/');
    if (slash)
      *slash = 0;
    size_t n = strlen(component);
    if (!n || n > 255 || !strcmp(component, ".") || !strcmp(component, "..")) {
      e = EINVAL;
      break;
    }
    struct ext2_inode inode;
    e = ext2fs_read_inode(fs, *dir, &inode);
    if (e)
      break;
    if ((inode.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR) {
      e = ENOTDIR;
      break;
    }
    if (inode.i_flags & (UNSUPPORTED | EXT4_CASEFOLD_FL)) {
      e = EOPNOTSUPP;
      break;
    }
    if (credentials) {
      e = policy_inode(fs, *dir, credentials, 1);
      if (e)
        break;
    }
    if (!slash) {
      *leaf = strdup(component);
      if (!*leaf)
        e = ENOMEM;
      break;
    }
    ext2_ino_t next;
    e = ext2fs_lookup(fs, *dir, component, n, NULL, &next);
    if (e)
      break;
    e = ext2fs_read_inode(fs, next, &inode);
    if (e)
      break;
    if ((inode.i_mode & LINUX_S_IFMT) == LINUX_S_IFLNK) {
      e = ELOOP;
      break;
    }
    if ((inode.i_mode & LINUX_S_IFMT) != LINUX_S_IFDIR) {
      e = ENOTDIR;
      break;
    }
    *dir = next;
    component = slash + 1;
  }
  free(copy);
  return e;
}
errcode_t mutation_parent_at(ext2_filsys fs, const struct mutation *op,
                             const char *path, int target, ext2_ino_t *dir,
                             char **leaf, const struct credentials *c) {
  if (!op->at)
    return mutation_parent(fs, path, dir, leaf, c);
  ext2_ino_t start = 0;
  struct path_result r;
  errcode_t e =
      path_base(fs, target ? &op->target_base : &op->base, path, &start);
  if (!e)
    e = path_at(fs, start, path, c, AT_PARENT, &r);
  if (e == EINVAL || e == EBUSY) {
    struct path_result special;
    errcode_t resolved = path_at(fs, start, path, c, AT_FOLLOW, &special);
    if (resolved)
      return resolved;
    if (target)
      return op->kind == MUT_LINK ? EEXIST : EBUSY;
    if (op->kind == MUT_MKDIR || op->kind == MUT_SYMLINK ||
        op->kind == MUT_CREATE)
      return EEXIST;
    if (op->kind == MUT_LINK)
      return EPERM;
    if (op->kind == MUT_UNLINK || op->kind == MUT_WRITE ||
        op->kind == MUT_TRUNCATE)
      return EISDIR;
    if (op->kind == MUT_RENAME || e == EBUSY)
      return EBUSY;
    size_t n = strlen(path);
    while (n && path[n - 1] == '/')
      n--;
    return n >= 2 && path[n - 1] == '.' && path[n - 2] == '.' ? ENOTEMPTY
                                                              : EINVAL;
  }
  if (!e && r.trailing && !r.inode && op->kind != MUT_MKDIR)
    e = ENOENT;
  if (!e) {
    *dir = r.parent;
    *leaf = strdup(r.leaf);
    if (!*leaf)
      e = ENOMEM;
  }
  return e;
}
static errcode_t touch(ext2_filsys fs, ext2_ino_t ino, int clear_privileges) {
  struct ext2_inode_large in = {0};
  unsigned bytes = EXT2_INODE_SIZE(fs->super);
  if (bytes > sizeof(in))
    bytes = sizeof(in);
  errcode_t e =
      ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&in, bytes);
  if (e)
    return e;
  if (clear_privileges)
    in.i_mode &= ~(LINUX_S_ISUID | LINUX_S_ISGID);
  in.i_mtime = in.i_ctime = (uint32_t)time(NULL);
  if (in.i_extra_isize >= 8)
    in.i_ctime_extra = 0;
  if (in.i_extra_isize >= 12)
    in.i_mtime_extra = 0;
  return ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&in, bytes);
}
static errcode_t create_file(ext2_filsys fs, ext2_ino_t dir, const char *name,
                             const struct mutation *op, ext2_ino_t *ino,
                             const unsigned char *acl, size_t acl_length) {
  struct ext2_inode parent_inode;
  errcode_t e = ext2fs_read_inode(fs, dir, &parent_inode);
  if (e)
    return e;
  if (parent_inode.i_flags & EXT2_IMMUTABLE_FL)
    return EPERM;
  if (parent_inode.i_flags & (EXT2_INDEX_FL | EXT4_CASEFOLD_FL))
    return EOPNOTSUPP;
  e = ext2fs_new_inode(fs, dir, LINUX_S_IFREG | op->mode, NULL, ino);
  if (e)
    return e;
  struct ext2_inode previous;
  e = ext2fs_read_inode(fs, *ino, &previous);
  if (e)
    return e;
  if (previous.i_generation == UINT32_MAX)
    return EOVERFLOW;
  struct ext2_inode in = {0};
  in.i_generation = previous.i_generation + 1;
  in.i_mode = LINUX_S_IFREG | op->mode;
  in.i_uid = op->uid & 0xffff;
  in.i_gid = op->gid & 0xffff;
  ext2fs_set_i_uid_high(in, op->uid >> 16);
  ext2fs_set_i_gid_high(in, op->gid >> 16);
  in.i_links_count = 1;
  in.i_atime = in.i_ctime = in.i_mtime = (uint32_t)time(NULL);
  if (ext2fs_has_feature_extents(fs->super)) {
    ext2_extent_handle_t handle;
    e = ext2fs_extent_open2(fs, *ino, &in, &handle);
    if (e)
      return e;
    ext2fs_extent_free(handle);
  }
  e = ext2fs_write_new_inode(fs, *ino, &in);
  if (e)
    return e;
  ext2fs_inode_alloc_stats2(fs, *ino, 1, 0);
  if (acl) {
    struct ext2_xattr_handle *handle = NULL;
    unsigned flags = XATTR_HANDLE_FLAG_RAW;
    e = ext2fs_xattrs_open(fs, *ino, &handle);
    if (!e)
      e = ext2fs_xattrs_flags(handle, &flags, NULL);
    if (!e)
      e = ext2fs_xattrs_read(handle);
    if (!e)
      e = ext2fs_xattr_set(handle, "system.posix_acl_access", acl, acl_length);
    if (handle) {
      errcode_t close = ext2fs_xattrs_close(&handle);
      if (!e)
        e = close;
    }
    if (e)
      return e;
  }
  e = ext2fs_link(fs, dir, name, *ino, EXT2_FT_REG_FILE);
  if (e == EXT2_ET_DIR_NO_SPACE || e == EXT2_ET_DIR_NO_SPACE_FOR_CSUM) {
    e = ext2fs_expand_dir(fs, dir);
    if (!e)
      e = ext2fs_link(fs, dir, name, *ino, EXT2_FT_REG_FILE);
  }
  if (!e)
    e = touch(fs, dir, 0);
  return e;
}
static errcode_t apply_inode(ext2_filsys fs, const struct mutation *op,
                             ext2_ino_t ino,
                             const struct credentials *credentials,
                             const struct inode_grant *grant);
errcode_t mutation_apply(ext2_filsys fs, const struct mutation *op) {
  return mutation_apply_as(fs, op, NULL);
}
errcode_t mutation_apply_as(ext2_filsys fs, const struct mutation *op,
                            const struct credentials *credentials) {
  if (!op || op->kind < MUT_WRITE || op->kind > MUT_CREATE ||
      op->length > MAX_DATA || op->offset > MAX_FILE ||
      op->length > MAX_FILE - op->offset || (op->length && !op->data) ||
      op->mode > 0777 || (op->kind == MUT_TRUNCATE && op->length) ||
      (op->kind == MUT_CREATE && op->offset))
    return EINVAL;
  if (credentials && policy_credentials(credentials))
    return EINVAL;
  ext2_ino_t dir, ino;
  char *leaf = NULL;
  errcode_t e =
      mutation_parent_at(fs, op, op->path, 0, &dir, &leaf, credentials);
  if (e)
    return e;
  e = ext2fs_lookup(fs, dir, leaf, strlen(leaf), NULL, &ino);
  if (op->at && op->kind != MUT_CREATE) {
    ext2_ino_t start = 0;
    struct path_result r;
    e = path_base(fs, &op->base, op->path, &start);
    if (!e)
      e = path_at(fs, start, op->path, credentials, AT_FOLLOW, &r);
    if (!e)
      ino = r.inode;
  }
  if (op->kind == MUT_CREATE) {
    if (!e)
      e = EEXIST;
    else if (e == EXT2_ET_FILE_NOT_FOUND) {
      struct mutation resolved = *op;
      unsigned char *acl = NULL;
      size_t acl_length = 0;
      e = 0;
      if (credentials)
        e = policy_creation(fs, dir, credentials, op->mode, &resolved.mode,
                            &resolved.uid, &resolved.gid, &acl, &acl_length);
      if (!e)
        e = create_file(fs, dir, leaf, &resolved, &ino, acl, acl_length);
      free(acl);
    }
  }
  free(leaf);
  if (e)
    return e;
  return apply_inode(fs, op, ino, credentials, NULL);
}
errcode_t mutation_apply_grant(ext2_filsys fs, const struct mutation *op,
                               const struct credentials *credentials,
                               const struct inode_grant *grant) {
  if (policy_credentials(credentials) || grant_valid(grant) || !op ||
      (op->kind != MUT_WRITE && op->kind != MUT_TRUNCATE) || op->mode ||
      op->uid || op->gid)
    return EINVAL;
  if (!(grant->access & GRANT_WRITE))
    return EBADF;
  return apply_inode(fs, op, grant->inode, credentials, grant);
}
static errcode_t apply_inode(ext2_filsys fs, const struct mutation *op,
                             ext2_ino_t ino,
                             const struct credentials *credentials,
                             const struct inode_grant *grant) {
  struct ext2_inode in;
  errcode_t e =
      grant ? grant_inode(fs, grant, &in) : ext2fs_read_inode(fs, ino, &in);
  if (e)
    return e;
  unsigned type = in.i_mode & LINUX_S_IFMT;
  if (type != LINUX_S_IFREG)
    return type == LINUX_S_IFLNK   ? ELOOP
           : type == LINUX_S_IFDIR ? EISDIR
                                   : EOPNOTSUPP;
  if (in.i_flags & EXT2_IMMUTABLE_FL)
    return EPERM;
  if (in.i_flags & UNSUPPORTED)
    return EOPNOTSUPP;
  uint64_t size = EXT2_I_SIZE(&in);
  struct mutation resolved = *op;
  if (grant && (grant->flags & GRANT_APPEND) && op->kind == MUT_WRITE)
    resolved.offset = size;
  op = &resolved;
  if (op->length > MAX_DATA || op->offset > MAX_FILE ||
      op->length > MAX_FILE - op->offset || (op->length && !op->data) ||
      (op->kind == MUT_TRUNCATE && op->length))
    return EINVAL;
  if ((in.i_flags & EXT2_APPEND_FL) &&
      (op->kind == MUT_TRUNCATE || (grant && !(grant->flags & GRANT_APPEND)) ||
       op->offset != size))
    return EPERM;
  if (credentials && op->kind != MUT_CREATE) {
    e = grant ? 0 : policy_inode(fs, ino, credentials, 2);
    if (!e)
      e = policy_writable(fs, ino);
    if (e)
      return e;
  }
  if (op->kind == MUT_WRITE && !op->length)
    return 0;
  ext2_file_t file;
  e = ext2fs_file_open(fs, ino, EXT2_FILE_WRITE, &file);
  if (e)
    return e;
  if (op->kind == MUT_TRUNCATE)
    e = ext2fs_file_set_size2(file, op->offset);
  else {
    e = ext2fs_file_llseek(file, op->offset, SEEK_SET, NULL);
    unsigned done = 0;
    if (!e && op->length)
      e = ext2fs_file_write(file, op->data, op->length, &done);
    if (!e && done != op->length)
      e = EIO;
  }
  errcode_t close = ext2fs_file_close(file);
  if (!e)
    e = close;
  return e ? e : touch(fs, ino, credentials && credentials->uid != 0);
}

errcode_t mutation_open_at(ext2_filsys fs, const struct mutation *op,
                           const struct credentials *c, struct inode_grant *g) {
  unsigned flags = op->offset, access = flags & 3;
  if (!op->at || op->offset > 255 || policy_credentials(c) || !access ||
      flags > 255 || op->length || op->mode > 0777 || op->uid || op->gid ||
      ((flags & (OPEN_APPEND | OPEN_TRUNC)) && !(access & GRANT_WRITE)) ||
      ((flags & OPEN_EXCL) && !(flags & OPEN_CREATE)) ||
      ((flags & OPEN_DIRECTORY) && (flags & OPEN_CREATE)))
    return EINVAL;
  ext2_ino_t start = 0;
  struct path_result r;
  errcode_t e = path_base(fs, &op->base, op->path, &start);
  unsigned follow =
      (flags & OPEN_NOFOLLOW) ||
              ((flags & (OPEN_CREATE | OPEN_EXCL)) == (OPEN_CREATE | OPEN_EXCL))
          ? 0
          : AT_FOLLOW;
  if (!e)
    e = path_at(fs, start, op->path, c,
                follow | ((flags & OPEN_CREATE) ? AT_MISSING : 0), &r);
  if (e)
    return e;
  int created = !r.inode;
  if (!created && (flags & OPEN_EXCL))
    return EEXIST;
  if (created) {
    if (!(flags & OPEN_CREATE) || !r.parent)
      return ENOENT;
    struct ext2_inode parent;
    e = ext2fs_read_inode(fs, r.parent, &parent);
    if (e)
      return e;
    if (!parent.i_links_count)
      return ENOENT;
    if (parent.i_flags & (GRANT_UNSUPPORTED | EXT2_INDEX_FL | EXT4_CASEFOLD_FL))
      return EOPNOTSUPP;
    struct mutation create = {.kind = MUT_CREATE, .mode = op->mode};
    unsigned char *acl = NULL;
    size_t bytes = 0;
    e = policy_creation(fs, r.parent, c, create.mode, &create.mode, &create.uid,
                        &create.gid, &acl, &bytes);
    if (!e)
      e = create_file(fs, r.parent, r.leaf, &create, &r.inode, acl, bytes);
    free(acl);
    if (e)
      return e;
  }
  struct ext2_inode in;
  e = ext2fs_read_inode(fs, r.inode, &in);
  if (e)
    return e;
  unsigned type = in.i_mode & LINUX_S_IFMT;
  if (type == LINUX_S_IFLNK)
    return flags & OPEN_DIRECTORY ? ENOTDIR : ELOOP;
  if ((flags & OPEN_DIRECTORY) && type != LINUX_S_IFDIR)
    return ENOTDIR;
  if (type == LINUX_S_IFDIR && (access & GRANT_WRITE))
    return EISDIR;
  if (type != LINUX_S_IFDIR && type != LINUX_S_IFREG)
    return EOPNOTSUPP;
  *g = (struct inode_grant){
      r.inode, in.i_generation, type == LINUX_S_IFDIR ? GRANT_DIR_READ : access,
      type == LINUX_S_IFDIR ? GRANT_DIRECTORY : !!(flags & OPEN_APPEND)};
  e = grant_inode(fs, g, &in);
  if (!e && !created)
    e = policy_inode(fs, r.inode, c,
                     (access & GRANT_READ ? 4 : 0) |
                         (access & GRANT_WRITE ? 2 : 0));
  if (!e && (access & GRANT_WRITE)) {
    if ((in.i_flags & EXT2_IMMUTABLE_FL) ||
        ((in.i_flags & EXT2_APPEND_FL) &&
         (!(flags & OPEN_APPEND) || (flags & OPEN_TRUNC))))
      e = EPERM;
    else
      e = policy_writable(fs, r.inode);
  }
  if (!e && (flags & OPEN_TRUNC)) {
    struct mutation truncate = {.kind = MUT_TRUNCATE};
    e = mutation_apply_grant(fs, &truncate, c, g);
  }
  return e;
}
