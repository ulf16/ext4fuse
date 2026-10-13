/* SPDX-License-Identifier: GPL-2.0-only
 * Experimental FUSE 3 bridge. All writes belong to the parent Python broker;
 * this process never opens an image/device. Foreground, single-threaded only.
 */
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#define LIMIT (1024U * 1024)
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int failed;
static uid_t owner;
static mode_t initial_umask;
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
static int transfer(int fd, void *data, size_t n, int writing) {
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  unsigned char *p = data;
  while (n) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t elapsed = (now.tv_sec - start.tv_sec) * 1000 +
                      (now.tv_nsec - start.tv_nsec) / 1000000;
    if (elapsed >= 120000)
      return -EIO;
    struct pollfd f = {fd, writing ? POLLOUT : POLLIN, 0};
    int ready = poll(&f, 1, 120000 - elapsed);
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready <= 0 || !(f.revents & f.events))
      return -EIO;
    ssize_t got = writing ? write(fd, p, n) : read(fd, p, n);
    if (got < 0 && (errno == EINTR || errno == EAGAIN))
      continue;
    if (got <= 0)
      return -EIO;
    p += got;
    n -= got;
  }
  return 0;
}
static int rpc(unsigned op, const char *path, const void *payload,
               size_t length, uint64_t handle, uint64_t offset, uint64_t arg,
               uint64_t *value, unsigned char **data, size_t *bytes) {
  size_t n = path ? strlen(path) : 0;
  if (n > 4096 || length > LIMIT)
    return -E2BIG;
  struct fuse_context *ctx = op == 22 ? NULL : fuse_get_context();
  int internal = op == 22 || op == 23 || op == 7 || op == 10 || op == 19 ||
                 op == 20 ||
                 (ctx && !ctx->pid && !ctx->uid && (op == 1 || op == 18));
  if (internal)
    ctx = NULL;
  uid_t uid = ctx ? ctx->uid : owner;
  gid_t gid = ctx ? ctx->gid : getgid();
  mode_t mask = ctx ? ctx->umask : initial_umask;
  if (uid != owner)
    return -EACCES;
  gid_t groups[64];
  int count = internal ? getgroups(64, groups) : fuse_getgroups(64, groups);
  /* Unknown supplementary membership must never become a grant from the
   * daemon's broader group list. Primary gid remains authenticated by FUSE. */
  if (count == -ENOSYS && !internal)
    count = 0;
  if (count < 0 || count > 64)
    return count < 0 ? (internal ? -errno : count) : -EOVERFLOW;
  unsigned char header[60] = "E4FM0001", packed[256], reply[32];
  put(header + 8, op, 4);
  put(header + 12, n, 4);
  put(header + 16, length, 4);
  put(header + 20, uid, 4);
  put(header + 24, gid, 4);
  put(header + 28, mask, 4);
  put(header + 32, count, 4);
  put(header + 36, handle, 8);
  put(header + 44, offset, 8);
  put(header + 52, arg, 8);
  for (int i = 0; i < count; i++)
    put(packed + 4 * i, groups[i], 4);
  *data = NULL;
  *bytes = 0;
  *value = 0;
  pthread_mutex_lock(&mutex);
  int e = failed ? -EIO : transfer(STDOUT_FILENO, header, sizeof(header), 1);
  if (!e)
    e = transfer(STDOUT_FILENO, packed, count * 4, 1);
  if (!e && n)
    e = transfer(STDOUT_FILENO, (void *)path, n, 1);
  if (!e && length)
    e = transfer(STDOUT_FILENO, (void *)payload, length, 1);
  if (!e)
    e = transfer(STDIN_FILENO, reply, sizeof(reply), 0);
  unsigned error = 0;
  if (!e) {
    error = le(reply + 8, 4);
    *value = le(reply + 16, 8);
    *bytes = le(reply + 24, 8);
    if (memcmp(reply, "E4FP0001", 8) || le(reply + 12, 4) || error > 4095 ||
        *bytes > LIMIT || (error && (*value || *bytes)))
      e = -EIO;
  }
  if (!e && *bytes) {
    *data = malloc(*bytes);
    if (!*data)
      e = -ENOMEM;
    else
      e = transfer(STDIN_FILENO, *data, *bytes, 0);
  }
  if (e) {
    failed = 1;
    free(*data);
    *data = NULL;
    *bytes = 0;
  }
  pthread_mutex_unlock(&mutex);
  if (e && ctx && ctx->fuse)
    fuse_exit(ctx->fuse);
  return e ? e : -(int)error;
}
static int empty(unsigned op, const char *path, const void *data, size_t length,
                 uint64_t h, uint64_t off, uint64_t arg) {
  unsigned char *out = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(op, path, data, length, h, off, arg, &value, &out, &bytes);
  free(out);
  return e ? e : bytes || value ? -EIO : 0;
}
static int getattr_cb(const char *path, struct stat *st,
                      struct fuse_file_info *fi) {
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(1, path, NULL, 0, fi ? fi->fh : 0, 0, 0, &value, &raw, &bytes);
  if (e)
    return e;
  if (bytes != 128 || value) {
    free(raw);
    return -EIO;
  }
  uint64_t f[16];
  for (unsigned i = 0; i < 16; i++)
    f[i] = le(raw + 8 * i, 8);
  free(raw);
  if (f[1] > UINT16_MAX || f[2] > 65535 || f[3] >= UINT32_MAX ||
      f[4] >= UINT32_MAX || f[5] > INT64_MAX || f[6] > INT64_MAX)
    return -EIO;
  for (unsigned i = 9; i < 16; i += 2)
    if (f[i] >= 1000000000)
      return -EIO;
  memset(st, 0, sizeof(*st));
  st->st_ino = f[0];
  st->st_mode = f[1];
  st->st_nlink = f[2];
  st->st_uid = f[3];
  st->st_gid = f[4];
  st->st_size = f[5];
  st->st_blocks = f[6];
#ifdef __APPLE__
  st->st_blksize = 0;
  st->st_atimespec = (struct timespec){(int64_t)f[8], f[9]};
  st->st_mtimespec = (struct timespec){(int64_t)f[10], f[11]};
  st->st_ctimespec = (struct timespec){(int64_t)f[12], f[13]};
  st->st_birthtimespec = (struct timespec){(int64_t)f[14], f[15]};
#else
  st->st_blksize = f[7];
  st->st_atim = (struct timespec){(int64_t)f[8], f[9]};
  st->st_mtim = (struct timespec){(int64_t)f[10], f[11]};
  st->st_ctim = (struct timespec){(int64_t)f[12], f[13]};
#endif
  return 0;
}
static int open_common(const char *path, mode_t mode, struct fuse_file_info *fi,
                       unsigned op) {
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(op, path, NULL, 0, 0, 0,
              (uint32_t)fi->flags | ((uint64_t)(mode & 07777) << 32), &value,
              &raw, &bytes);
  free(raw);
  if (e)
    return e;
  if (bytes || !value)
    return -EIO;
  fi->fh = value;
  fi->direct_io = op == 8 ? 0 : 1;
  fi->keep_cache = 0;
  fi->cache_readdir = 0;
  return 0;
}
static int open_cb(const char *p, struct fuse_file_info *fi) {
  return open_common(p, 0, fi, 2);
}
static int create_cb(const char *p, mode_t m, struct fuse_file_info *fi) {
  return open_common(p, m, fi, 3);
}
static int opendir_cb(const char *p, struct fuse_file_info *fi) {
  return open_common(p, 0, fi, 8);
}
static int read_cb(const char *p, char *buf, size_t n, off_t off,
                   struct fuse_file_info *fi) {
  if (off < 0 || n > LIMIT)
    return -EINVAL;
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(4, p, NULL, 0, fi->fh, off, n, &value, &raw, &bytes);
  if (e)
    return e;
  if (bytes > n || value) {
    free(raw);
    return -EIO;
  }
  if (bytes)
    memcpy(buf, raw, bytes);
  free(raw);
  return bytes;
}
static int write_cb(const char *p, const char *buf, size_t n, off_t off,
                    struct fuse_file_info *fi) {
  if (off < 0 || n > LIMIT)
    return -EINVAL;
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(5, p, buf, n, fi->fh, off, 0, &value, &raw, &bytes);
  free(raw);
  if (e)
    return e;
  return bytes || value != n ? -EIO : (int)value;
}
static int truncate_cb(const char *p, off_t n, struct fuse_file_info *fi) {
  return n < 0 ? -EINVAL : empty(6, p, NULL, 0, fi ? fi->fh : 0, n, 0);
}
static int release_cb(const char *p, struct fuse_file_info *fi) {
  return empty(7, p, NULL, 0, fi->fh, 0, 0);
}
static int releasedir_cb(const char *p, struct fuse_file_info *fi) {
  return empty(10, p, NULL, 0, fi->fh, 0, 0);
}
static int flush_cb(const char *p, struct fuse_file_info *fi) {
  return empty(19, p, NULL, 0, fi->fh, 0, 0);
}
static int fsync_cb(const char *p, int data, struct fuse_file_info *fi) {
  (void)data;
  return empty(20, p, NULL, 0, fi ? fi->fh : 0, 0, 0);
}
static int mkdir_cb(const char *p, mode_t m) {
  return empty(11, p, NULL, 0, 0, 0, m & 07777);
}
static int rmdir_cb(const char *p) { return empty(12, p, NULL, 0, 0, 0, 0); }
static int unlink_cb(const char *p) {
  struct fuse_context *ctx = fuse_get_context();
  unsigned op = ctx && !ctx->pid && !ctx->uid ? 23 : 13;
  return empty(op, p, NULL, 0, 0, 0, 0);
}
static int rename_cb(const char *a, const char *b, unsigned flags) {
  return empty(14, a, b, strlen(b), 0, 0, flags);
}
static int link_cb(const char *a, const char *b) {
  return empty(15, a, b, strlen(b), 0, 0, 0);
}
static int symlink_cb(const char *target, const char *path) {
  return empty(16, path, target, strlen(target), 0, 0, 0);
}
static int access_cb(const char *p, int mask) {
  return empty(21, p, NULL, 0, 0, 0, mask);
}
static int readlink_cb(const char *p, char *buf, size_t n) {
  if (!n)
    return -EINVAL;
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(17, p, NULL, 0, 0, 0, 0, &value, &raw, &bytes);
  if (e)
    return e;
  if (value || !bytes || bytes > 4095 || memchr(raw, 0, bytes)) {
    free(raw);
    return -EIO;
  }
  size_t copy = bytes < n - 1 ? bytes : n - 1;
  memcpy(buf, raw, copy);
  buf[copy] = 0;
  free(raw);
  return 0;
}
static int statfs_cb(const char *p, struct statvfs *st) {
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(18, p, NULL, 0, 0, 0, 0, &value, &raw, &bytes);
  if (e)
    return e;
  if (value || bytes != 80) {
    free(raw);
    return -EIO;
  }
  uint64_t f[10];
  for (unsigned i = 0; i < 10; i++)
    f[i] = le(raw + 8 * i, 8);
  free(raw);
  memset(st, 0, sizeof(*st));
  st->f_bsize = f[0];
  st->f_frsize = f[1];
  st->f_blocks = f[2];
  st->f_bfree = f[3];
  st->f_bavail = f[4];
  st->f_files = f[5];
  st->f_ffree = f[6];
  st->f_favail = f[7];
  st->f_namemax = f[8];
  st->f_flag = f[9];
  return 0;
}
static int readdir_cb(const char *p, void *buf, fuse_fill_dir_t filler,
                      off_t off, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags) {
  (void)flags;
  if (off < 0)
    return -EINVAL;
  uint64_t position = off;
  for (;;) {
    unsigned char *raw = NULL;
    size_t bytes;
    uint64_t next;
    int e = rpc(9, p, NULL, 0, fi->fh, position, 0, &next, &raw, &bytes);
    if (e)
      return e;
    if (bytes < 8 || le(raw, 4) > 1 || le(raw + 4, 4) > 128) {
      free(raw);
      return -EIO;
    }
    unsigned count = le(raw + 4, 4);
    int eof = le(raw, 4);
    size_t at = 8;
    uint64_t last = position;
    if (!count && !eof) {
      free(raw);
      return -EIO;
    }
    for (unsigned i = 0; i < count; i++) {
      if (bytes - at < 16) {
        free(raw);
        return -EIO;
      }
      uint64_t cookie = le(raw + at, 8);
      unsigned kind = le(raw + at + 12, 2), n = le(raw + at + 14, 2);
      if (!le(raw + at + 8, 4) || !cookie || cookie >= INT64_MAX ||
          cookie <= last ||
          !(kind == 0 || kind == 1 || kind == 2 || kind == 4 || kind == 6 ||
            kind == 8 || kind == 10 || kind == 12) ||
          !n || n > 255 || n > bytes - at - 16 || memchr(raw + at + 16, 0, n) ||
          memchr(raw + at + 16, '/', n)) {
        free(raw);
        return -EIO;
      }
      last = cookie;
      at += 16 + n;
    }
    if (at != bytes || (count && last != next) ||
        (!count && next != position)) {
      free(raw);
      return -EIO;
    }
    at = 8;
    for (unsigned i = 0; i < count; i++) {
      struct stat st = {0};
      st.st_ino = le(raw + at + 8, 4);
      st.st_mode = le(raw + at + 12, 2) << 12;
      unsigned n = le(raw + at + 14, 2);
      char name[256];
      memcpy(name, raw + at + 16, n);
      name[n] = 0;
      if (filler(buf, name, &st, le(raw + at, 8), 0)) {
        free(raw);
        return 0;
      }
      at += 16 + n;
    }
    free(raw);
    if (eof)
      return 0;
    position = next;
  }
}
static void *init_cb(struct fuse_conn_info *info, struct fuse_config *cfg) {
  info->want &= ~FUSE_CAP_WRITEBACK_CACHE;
#ifdef FUSE_CAP_POSIX_ACL
  info->want &= ~FUSE_CAP_POSIX_ACL;
#endif
#ifdef FUSE_CAP_DONT_MASK
  if (info->capable & FUSE_CAP_DONT_MASK)
    info->want |= FUSE_CAP_DONT_MASK;
#endif
  if (info->max_write > LIMIT)
    info->max_write = LIMIT;
  cfg->attr_timeout = 0;
  cfg->entry_timeout = 0;
  cfg->negative_timeout = 0;
  cfg->kernel_cache = 0;
  cfg->auto_cache = 0;
  cfg->direct_io = 1;
  cfg->use_ino = 1;
  cfg->hard_remove = 0;
  cfg->nullpath_ok = 1;
  return NULL;
}
static int chmod_cb(const char *p, mode_t m, struct fuse_file_info *fi) {
  return empty(24, p, NULL, 0, fi ? fi->fh : 0, 0, m & 07777);
}
static int chown_cb(const char *p, uid_t u, gid_t g,
                    struct fuse_file_info *fi) {
  return empty(25, p, NULL, 0, fi ? fi->fh : 0, 0,
               (uint32_t)u | ((uint64_t)(uint32_t)g << 32));
}
static int utimens_cb(const char *p, const struct timespec t[2],
                      struct fuse_file_info *fi) {
  unsigned char payload[32];
  for (unsigned i = 0; i < 2; i++) {
    uint64_t ns = UINT64_MAX;
    int64_t sec = 0;
    if (t) {
      sec = t[i].tv_sec;
      ns = t[i].tv_nsec == UTIME_NOW    ? UINT64_MAX
           : t[i].tv_nsec == UTIME_OMIT ? UINT64_MAX - 1
                                        : t[i].tv_nsec;
      if (ns < UINT64_MAX - 1 && ns >= 1000000000)
        return -EINVAL;
    }
    put(payload + i * 16, sec, 8);
    put(payload + i * 16 + 8, ns, 8);
  }
  return empty(26, p, payload, sizeof(payload), fi ? fi->fh : 0, 0, 0);
}
static int setxattr_cb(const char *p, const char *name, const char *value,
                       size_t n, int flags) {
  int accepted = XATTR_CREATE | XATTR_REPLACE;
#ifdef __APPLE__
  accepted |= XATTR_NOFOLLOW;
#endif
  if (flags & ~accepted || ((flags & XATTR_CREATE) && (flags & XATTR_REPLACE)))
    return -EINVAL;
  size_t length = strlen(name);
  if (!length || length > 255 || n > 65536)
    return -E2BIG;
  unsigned char *payload = malloc(length + 1 + n);
  if (!payload)
    return -ENOMEM;
  memcpy(payload, name, length + 1);
  if (n)
    memcpy(payload + length + 1, value, n);
  unsigned mode = flags & XATTR_CREATE ? 1 : flags & XATTR_REPLACE ? 2 : 0;
  int e = empty(27, p, payload, length + 1 + n, 0, 0, mode);
  free(payload);
  return e;
}
static int attr_read(unsigned op, const char *p, const char *name, char *out,
                     size_t n) {
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e =
      rpc(op, p, name, name ? strlen(name) : 0, 0, 0, 0, &value, &raw, &bytes);
  if (e)
    return e;
  if (value || bytes > 65536) {
    free(raw);
    return -EIO;
  }
  if (n && bytes > n) {
    free(raw);
    return -ERANGE;
  }
  if (n && bytes)
    memcpy(out, raw, bytes);
  free(raw);
  return bytes;
}
static int getxattr_cb(const char *p, const char *name, char *value, size_t n) {
  return attr_read(29, p, name, value, n);
}
static int listxattr_cb(const char *p, char *names, size_t n) {
  return attr_read(30, p, NULL, names, n);
}
static int removexattr_cb(const char *p, const char *name) {
  return empty(28, p, name, strlen(name), 0, 0, 0);
}
static const struct fuse_operations operations = {.init = init_cb,
                                                  .getattr = getattr_cb,
                                                  .open = open_cb,
                                                  .create = create_cb,
                                                  .read = read_cb,
                                                  .write = write_cb,
                                                  .truncate = truncate_cb,
                                                  .release = release_cb,
                                                  .flush = flush_cb,
                                                  .fsync = fsync_cb,
                                                  .opendir = opendir_cb,
                                                  .readdir = readdir_cb,
                                                  .releasedir = releasedir_cb,
                                                  .fsyncdir = fsync_cb,
                                                  .mkdir = mkdir_cb,
                                                  .rmdir = rmdir_cb,
                                                  .unlink = unlink_cb,
                                                  .rename = rename_cb,
                                                  .link = link_cb,
                                                  .symlink = symlink_cb,
                                                  .readlink = readlink_cb,
                                                  .statfs = statfs_cb,
                                                  .access = access_cb,
                                                  .chmod = chmod_cb,
                                                  .chown = chown_cb,
                                                  .utimens = utimens_cb,
                                                  .setxattr = setxattr_cb,
                                                  .getxattr = getxattr_cb,
                                                  .listxattr = listxattr_cb,
                                                  .removexattr =
                                                      removexattr_cb};
int main(int argc, char **argv) {
  if (argc != 2 || getuid() != geteuid()) {
    fprintf(
        stderr,
        "Usage: mount-frontend MOUNTPOINT (private broker pipe required)\n");
    return 2;
  }
  owner = getuid();
  initial_umask = umask(0);
  umask(initial_umask);
  signal(SIGPIPE, SIG_IGN);
  int e = empty(22, NULL, NULL, 0, 0, 0, 0);
  if (e) {
    fprintf(stderr, "mount broker handshake: %s\n", strerror(-e));
    return 2;
  }
  char *args[] = {argv[0],
                  argv[1],
                  "-f",
                  "-s",
                  "-onodev,nosuid,fsname=ext4fuse-experimental"
#ifdef __APPLE__
                  ,
                  "-odefer_permissions"
#endif
  };
  return fuse_main(sizeof(args) / sizeof(args[0]), args, &operations, NULL);
}
