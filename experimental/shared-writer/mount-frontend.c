/* SPDX-License-Identifier: GPL-2.0-only
 * Experimental FUSE 3 bridge. All writes belong to the parent Python broker;
 * this process never opens an image/device. Foreground, single-threaded only.
 */
#include <errno.h>
#include <fcntl.h>
#include <fuse_lowlevel.h>
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
static struct fuse_session *session;
static void stop_session(void) {
  failed = 1;
  if (session)
    fuse_session_exit(session);
}
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
static int rpc(fuse_req_t req, unsigned op, const char *path,
               const void *payload, size_t length, uint64_t handle,
               uint64_t offset, uint64_t arg, uint64_t *value,
               unsigned char **data, size_t *bytes) {
  size_t n = path ? strlen(path) : 0;
  if (n > 4096 || length > LIMIT)
    return -E2BIG;
  const struct fuse_ctx *ctx = req ? fuse_req_ctx(req) : NULL;
  int internal = !req || op == 102 || op == 109 || op == 112 || op == 121 ||
                 op == 122 ||
                 (ctx && !ctx->pid && !ctx->uid && (op == 103 || op == 120));
  if (internal)
    ctx = NULL;
  uid_t uid = ctx ? ctx->uid : owner;
  gid_t gid = ctx ? ctx->gid : getgid();
  mode_t mask = ctx ? ctx->umask : initial_umask;
  if (uid != owner)
    return -EACCES;
  gid_t groups[64];
  int count =
      internal ? getgroups(64, groups) : fuse_req_getgroups(req, 64, groups);
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
  if (e && session)
    stop_session();
  return e ? e : -(int)error;
}
static int empty(fuse_req_t req, unsigned op, const char *path,
                 const void *data, size_t length, uint64_t ino, uint64_t offset,
                 uint64_t arg) {
  unsigned char *out = NULL;
  size_t bytes;
  uint64_t value;
  int e =
      rpc(req, op, path, data, length, ino, offset, arg, &value, &out, &bytes);
  free(out);
  return e ? e : bytes || value ? -EIO : 0;
}
static void error(fuse_req_t req, int e) {
  fuse_reply_err(req, e < 0 ? -e : e);
}
static int decode_stat(const unsigned char *raw, struct stat *st) {
  uint64_t f[16];
  for (unsigned i = 0; i < 16; i++)
    f[i] = le(raw + 8 * i, 8);
  if (f[1] > UINT16_MAX || f[2] > 65535 || f[3] >= UINT32_MAX ||
      f[4] >= UINT32_MAX || f[5] > INT64_MAX || f[6] > INT64_MAX)
    return -EIO;
  for (unsigned i = 9; i < 16; i += 2)
    if (f[i] >= 1000000000)
      return -EIO;
  memset(st, 0, sizeof(*st));
  if (!f[0])
    return -EIO;
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

static int entry_data(uint64_t number, const unsigned char *raw, size_t bytes,
                      struct fuse_entry_param *entry) {
  if (!number || number >= INT64_MAX || bytes != 136)
    return -EIO;
  memset(entry, 0, sizeof(*entry));
  entry->ino = number;
  entry->generation = le(raw, 8);
  return decode_stat(raw + 8, &entry->attr);
}
static void entry_reply(fuse_req_t req, unsigned op, fuse_ino_t ino,
                        const char *name, const void *payload, size_t length,
                        uint64_t offset, uint64_t arg,
                        struct fuse_file_info *fi) {
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t number;
  int e = rpc(req, op, name, payload, length, ino, offset, arg, &number, &raw,
              &bytes);
  int broker_error = e;
  struct fuse_entry_param entry;
  uint64_t fh = 0;
  if (!e && fi) {
    if (bytes != 144 || !(fh = le(raw, 8)))
      e = -EIO;
    else
      e = entry_data(number, raw + 8, bytes - 8, &entry);
    fi->fh = fh;
    fi->direct_io = 1;
    fi->keep_cache = 0;
  } else if (!e)
    e = entry_data(number, raw, bytes, &entry);
  free(raw);
  if (e) {
    /* A valid broker EIO may follow successful durable recovery. Only
     * malformed success replies require disconnecting this transport. */
    if (!broker_error)
      stop_session();
    error(req, e);
    return;
  }
  int sent =
      fi ? fuse_reply_create(req, &entry, fi) : fuse_reply_entry(req, &entry);
  /* An interrupted lookup/create reply carries no kernel lookup reference.
   * Balance both kinds of reference before processing the next request. */
  if (sent) {
    if (fi)
      empty(NULL, 109, NULL, NULL, 0, number, fh, 0);
    if (empty(NULL, 102, NULL, NULL, 0, number, 0, 1))
      stop_session();
  }
}
static void lookup_cb(fuse_req_t req, fuse_ino_t parent, const char *name) {
  entry_reply(req, 101, parent, name, NULL, 0, 0, 0, NULL);
}
static void forget_cb(fuse_req_t req, fuse_ino_t ino, uint64_t count) {
  if (empty(NULL, 102, NULL, NULL, 0, ino, 0, count))
    stop_session();
  fuse_reply_none(req);
}
static void forget_multi_cb(fuse_req_t req, size_t count,
                            struct fuse_forget_data *items) {
  for (size_t i = 0; i < count; i++)
    if (empty(NULL, 102, NULL, NULL, 0, items[i].ino, 0, items[i].nlookup)) {
      stop_session();
      break;
    }
  fuse_reply_none(req);
}
static void getattr_cb(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi) {
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(req, 103, NULL, NULL, 0, ino, fi ? fi->fh : 0, 0, &value, &raw,
              &bytes);
  struct stat st;
  if (!e)
    e = value || bytes != 128 ? -EIO : decode_stat(raw, &st);
  free(raw);
  if (e)
    error(req, e);
  else
    fuse_reply_attr(req, &st, 0);
}
static void open_common(fuse_req_t req, fuse_ino_t ino,
                        struct fuse_file_info *fi, unsigned op) {
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t fh;
  int e = rpc(req, op, NULL, NULL, 0, ino, 0, (uint32_t)fi->flags, &fh, &raw,
              &bytes);
  free(raw);
  if (!e && (bytes || !fh))
    e = -EIO;
  if (e) {
    error(req, e);
    return;
  }
  fi->fh = fh;
  fi->direct_io = op == 110 ? 0 : 1;
  fi->keep_cache = 0;
  fi->cache_readdir = 0;
  if (fuse_reply_open(req, fi))
    empty(NULL, op == 110 ? 112 : 109, NULL, NULL, 0, ino, fh, 0);
}
static void open_cb(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  open_common(req, ino, fi, 104);
}
static void opendir_cb(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi) {
  open_common(req, ino, fi, 110);
}
static void create_cb(fuse_req_t req, fuse_ino_t parent, const char *name,
                      mode_t mode, struct fuse_file_info *fi) {
  entry_reply(req, 105, parent, name, NULL, 0, 0,
              (uint32_t)fi->flags | ((uint64_t)(mode & 07777) << 32), fi);
}
static void read_cb(fuse_req_t req, fuse_ino_t ino, size_t n, off_t off,
                    struct fuse_file_info *fi) {
  if (off < 0 || n > LIMIT) {
    error(req, -EINVAL);
    return;
  }
  unsigned char payload[8];
  put(payload, n, 8);
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e =
      rpc(req, 106, NULL, payload, 8, ino, fi->fh, off, &value, &raw, &bytes);
  if (!e && (value || bytes > n))
    e = -EIO;
  if (e)
    error(req, e);
  else
    fuse_reply_buf(req, (const char *)raw, bytes);
  free(raw);
}
static void write_cb(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t n,
                     off_t off, struct fuse_file_info *fi) {
  if (off < 0 || n > LIMIT) {
    error(req, -EINVAL);
    return;
  }
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(req, 107, NULL, buf, n, ino, fi->fh, off, &value, &raw, &bytes);
  free(raw);
  if (!e && (bytes || value != n))
    e = -EIO;
  if (e)
    error(req, e);
  else
    fuse_reply_write(req, value);
}
static void release_cb(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi) {
  error(req, empty(req, 109, NULL, NULL, 0, ino, fi->fh, 0));
}
static void releasedir_cb(fuse_req_t req, fuse_ino_t ino,
                          struct fuse_file_info *fi) {
  error(req, empty(req, 112, NULL, NULL, 0, ino, fi->fh, 0));
}
static void flush_cb(fuse_req_t req, fuse_ino_t ino,
                     struct fuse_file_info *fi) {
  error(req, empty(req, 121, NULL, NULL, 0, ino, fi->fh, 0));
}
static void fsync_cb(fuse_req_t req, fuse_ino_t ino, int datasync,
                     struct fuse_file_info *fi) {
  (void)datasync;
  error(req, empty(req, 122, NULL, NULL, 0, ino, fi->fh, 0));
}
static void mkdir_cb(fuse_req_t req, fuse_ino_t parent, const char *name,
                     mode_t mode) {
  entry_reply(req, 113, parent, name, NULL, 0, 0, mode & 07777, NULL);
}
static void unlink_cb(fuse_req_t req, fuse_ino_t parent, const char *name) {
  error(req, empty(req, 115, name, NULL, 0, parent, 0, 0));
}
static void rmdir_cb(fuse_req_t req, fuse_ino_t parent, const char *name) {
  error(req, empty(req, 114, name, NULL, 0, parent, 0, 0));
}
static void rename_cb(fuse_req_t req, fuse_ino_t parent, const char *name,
                      fuse_ino_t newparent, const char *newname,
                      unsigned flags) {
  error(req, empty(req, 116, name, newname, strlen(newname), parent, flags,
                   newparent));
}
static void link_cb(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent,
                    const char *name) {
  entry_reply(req, 117, ino, name, NULL, 0, 0, parent, NULL);
}
static void symlink_cb(fuse_req_t req, const char *link, fuse_ino_t parent,
                       const char *name) {
  entry_reply(req, 118, parent, name, link, strlen(link), 0, 0, NULL);
}
static void access_cb(fuse_req_t req, fuse_ino_t ino, int mask) {
  error(req, empty(req, 123, NULL, NULL, 0, ino, 0, mask));
}
static void readlink_cb(fuse_req_t req, fuse_ino_t ino) {
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(req, 119, NULL, NULL, 0, ino, 0, 0, &value, &raw, &bytes);
  if (!e && (value || !bytes || bytes > 4095 || memchr(raw, 0, bytes)))
    e = -EIO;
  if (e)
    error(req, e);
  else {
    char link[4096];
    memcpy(link, raw, bytes);
    link[bytes] = 0;
    fuse_reply_readlink(req, link);
  }
  free(raw);
}
static void statfs_cb(fuse_req_t req, fuse_ino_t ino) {
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e =
      rpc(req, 120, NULL, NULL, 0, ino ? ino : 1, 0, 0, &value, &raw, &bytes);
  struct statvfs st = {0};
  if (!e && (value || bytes != 80))
    e = -EIO;
  if (!e) {
    st.f_bsize = le(raw, 8);
    st.f_frsize = le(raw + 8, 8);
    st.f_blocks = le(raw + 16, 8);
    st.f_bfree = le(raw + 24, 8);
    st.f_bavail = le(raw + 32, 8);
    st.f_files = le(raw + 40, 8);
    st.f_ffree = le(raw + 48, 8);
    st.f_favail = le(raw + 56, 8);
    st.f_namemax = le(raw + 64, 8);
    st.f_flag = le(raw + 72, 8);
  }
  free(raw);
  if (e)
    error(req, e);
  else
    fuse_reply_statfs(req, &st);
}
static void readdir_cb(fuse_req_t req, fuse_ino_t ino, size_t n, off_t off,
                       struct fuse_file_info *fi) {
  if (off < 0 || n > LIMIT) {
    error(req, -EINVAL);
    return;
  }
  char *out = malloc(n ? n : 1);
  if (!out) {
    error(req, -ENOMEM);
    return;
  }
  size_t used = 0;
  uint64_t position = off;
  int e = 0, done = 0;
  while (!done && used < n) {
    unsigned char *raw = NULL;
    size_t bytes;
    uint64_t next;
    e = rpc(req, 111, NULL, NULL, 0, ino, fi->fh, position, &next, &raw,
            &bytes);
    if (e)
      break;
    if (bytes < 8 || le(raw, 4) > 1 || le(raw + 4, 4) > 128) {
      free(raw);
      e = -EIO;
      break;
    }
    unsigned count = le(raw + 4, 4);
    int eof = le(raw, 4);
    size_t at = 8;
    uint64_t last = position;
    if (!count && !eof) {
      free(raw);
      e = -EIO;
      break;
    }
    for (unsigned i = 0; i < count; i++) {
      if (bytes - at < 16) {
        e = -EIO;
        break;
      }
      uint64_t cookie = le(raw + at, 8);
      unsigned kind = le(raw + at + 12, 2), length = le(raw + at + 14, 2);
      if (!le(raw + at + 8, 4) || !cookie || cookie >= INT64_MAX ||
          cookie <= last ||
          !(kind == 0 || kind == 1 || kind == 2 || kind == 4 || kind == 6 ||
            kind == 8 || kind == 10 || kind == 12) ||
          !length || length > 255 || length > bytes - at - 16 ||
          memchr(raw + at + 16, 0, length) ||
          memchr(raw + at + 16, '/', length)) {
        e = -EIO;
        break;
      }
      last = cookie;
      at += 16 + length;
    }
    if (!e && (at != bytes || (count && last != next) ||
               (!count && next != position)))
      e = -EIO;
    if (e) {
      free(raw);
      break;
    }
    at = 8;
    for (unsigned i = 0; i < count; i++) {
      struct stat st = {0};
      st.st_ino = le(raw + at + 8, 4);
      st.st_mode = le(raw + at + 12, 2) << 12;
      unsigned length = le(raw + at + 14, 2);
      char name[256];
      memcpy(name, raw + at + 16, length);
      name[length] = 0;
      size_t needed = fuse_add_direntry(req, out + used, n - used, name, &st,
                                        le(raw + at, 8));
      if (needed > n - used) {
        done = 1;
        break;
      }
      used += needed;
      at += 16 + length;
    }
    free(raw);
    if (eof)
      done = 1;
    position = next;
  }
  if (e)
    error(req, e);
  else
    fuse_reply_buf(req, out, used);
  free(out);
}
static void setattr_cb(fuse_req_t req, fuse_ino_t ino, struct stat *st,
                       int fields, struct fuse_file_info *fi) {
  int known = FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID |
              FUSE_SET_ATTR_SIZE | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME |
              FUSE_SET_ATTR_ATIME_NOW | FUSE_SET_ATTR_MTIME_NOW |
              FUSE_SET_ATTR_CTIME | FUSE_SET_ATTR_FORCE;
#ifdef FUSE_SET_ATTR_FILE
  known |= FUSE_SET_ATTR_FILE;
#endif
#ifdef FUSE_SET_ATTR_OPEN
  known |= FUSE_SET_ATTR_OPEN;
#endif
#ifdef FUSE_SET_ATTR_TIMES_SET
  known |= FUSE_SET_ATTR_TIMES_SET;
#endif
#ifdef FUSE_SET_ATTR_TOUCH
  known |= FUSE_SET_ATTR_TOUCH;
#endif
  if (fields & ~known) {
    error(req, -EOPNOTSUPP);
    return;
  }
  unsigned flags = fields & 0x1bf;
#ifdef FUSE_SET_ATTR_TOUCH
  if (fields & FUSE_SET_ATTR_TOUCH)
    flags |= FUSE_SET_ATTR_ATIME_NOW | FUSE_SET_ATTR_MTIME_NOW;
#endif
  unsigned char payload[64] = {0};
  put(payload, flags, 4);
  if (fields & FUSE_SET_ATTR_MODE)
    put(payload + 4, st->st_mode & 07777, 4);
  if (fields & FUSE_SET_ATTR_UID)
    put(payload + 8, st->st_uid, 8);
  if (fields & FUSE_SET_ATTR_GID)
    put(payload + 16, st->st_gid, 8);
  if (fields & FUSE_SET_ATTR_SIZE) {
    if (st->st_size < 0) {
      error(req, -EINVAL);
      return;
    }
    put(payload + 24, st->st_size, 8);
  }
#ifdef __APPLE__
  struct timespec at = {0}, mt = {0};
  if (fields & FUSE_SET_ATTR_ATIME)
    at = st->st_atimespec;
  if (fields & FUSE_SET_ATTR_MTIME)
    mt = st->st_mtimespec;
#else
  struct timespec at = {0}, mt = {0};
  if (fields & FUSE_SET_ATTR_ATIME)
    at = st->st_atim;
  if (fields & FUSE_SET_ATTR_MTIME)
    mt = st->st_mtim;
#endif
  if (fields & FUSE_SET_ATTR_ATIME) {
    put(payload + 32, at.tv_sec, 8);
    put(payload + 40, at.tv_nsec, 8);
  }
  if (fields & FUSE_SET_ATTR_MTIME) {
    put(payload + 48, mt.tv_sec, 8);
    put(payload + 56, mt.tv_nsec, 8);
  }
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(req, 108, NULL, payload, sizeof(payload), ino, fi ? fi->fh : 0, 0,
              &value, &raw, &bytes);
  struct stat result;
  if (!e)
    e = value || bytes != 128 ? -EIO : decode_stat(raw, &result);
  free(raw);
  if (e)
    error(req, e);
  else
    fuse_reply_attr(req, &result, 0);
}
static void setxattr_cb(fuse_req_t req, fuse_ino_t ino, const char *name,
                        const char *value, size_t n, int flags) {
  int accepted = XATTR_CREATE | XATTR_REPLACE;
#ifdef __APPLE__
  accepted |= XATTR_NOFOLLOW;
  if (!strcmp(name, "com.apple.system.Security"))
    accepted |= XATTR_NOSECURITY;
#endif
  if (flags & ~accepted ||
      ((flags & XATTR_CREATE) && (flags & XATTR_REPLACE))) {
    error(req, -EINVAL);
    return;
  }
  size_t length = strlen(name);
  if (!length || length > 255 || n > 65536) {
    error(req, -E2BIG);
    return;
  }
  char *payload = malloc(length + 1 + n);
  if (!payload) {
    error(req, -ENOMEM);
    return;
  }
  memcpy(payload, name, length + 1);
  if (n)
    memcpy(payload + length + 1, value, n);
  error(req, empty(req, 124, NULL, payload, length + 1 + n, ino, 0,
                   flags & XATTR_CREATE    ? 1
                   : flags & XATTR_REPLACE ? 2
                                           : 0));
  free(payload);
}
static void attr_read(fuse_req_t req, unsigned op, fuse_ino_t ino,
                      const char *name, size_t n) {
  unsigned char *raw = NULL;
  size_t bytes;
  uint64_t value;
  int e = rpc(req, op, NULL, name, name ? strlen(name) : 0, ino, 0, 0, &value,
              &raw, &bytes);
  if (!e && (value || bytes > 65536))
    e = -EIO;
  if (!e && n && bytes > n)
    e = -ERANGE;
  if (e)
    error(req, e);
  else if (!n)
    fuse_reply_xattr(req, bytes);
  else
    fuse_reply_buf(req, (const char *)raw, bytes);
  free(raw);
}
static void getxattr_cb(fuse_req_t req, fuse_ino_t ino, const char *name,
                        size_t n) {
  attr_read(req, 126, ino, name, n);
}
static void listxattr_cb(fuse_req_t req, fuse_ino_t ino, size_t n) {
  attr_read(req, 127, ino, NULL, n);
}
static void removexattr_cb(fuse_req_t req, fuse_ino_t ino, const char *name) {
  error(req, empty(req, 125, NULL, name, strlen(name), ino, 0, 0));
}
static void init_cb(void *unused, struct fuse_conn_info *info) {
  (void)unused;
  info->want &= ~FUSE_CAP_WRITEBACK_CACHE;
#ifdef FUSE_CAP_POSIX_ACL
  info->want &= ~FUSE_CAP_POSIX_ACL;
#endif
#ifdef FUSE_CAP_HANDLE_KILLPRIV
  info->want &= ~FUSE_CAP_HANDLE_KILLPRIV;
#endif
#ifdef FUSE_CAP_HANDLE_KILLPRIV_V2
  info->want &= ~FUSE_CAP_HANDLE_KILLPRIV_V2;
#endif
#ifdef FUSE_CAP_EXPORT_SUPPORT
  info->want &= ~FUSE_CAP_EXPORT_SUPPORT;
#endif
#ifdef FUSE_CAP_DONT_MASK
  if (info->capable & FUSE_CAP_DONT_MASK)
    info->want |= FUSE_CAP_DONT_MASK;
#endif
  if (info->max_write > LIMIT)
    info->max_write = LIMIT;
}
static const struct fuse_lowlevel_ops operations = {
    .init = init_cb,
    .lookup = lookup_cb,
    .forget = forget_cb,
    .forget_multi = forget_multi_cb,
    .getattr = getattr_cb,
    .setattr = setattr_cb,
    .readlink = readlink_cb,
    .mkdir = mkdir_cb,
    .unlink = unlink_cb,
    .rmdir = rmdir_cb,
    .symlink = symlink_cb,
    .rename = rename_cb,
    .link = link_cb,
    .open = open_cb,
    .create = create_cb,
    .read = read_cb,
    .write = write_cb,
    .flush = flush_cb,
    .release = release_cb,
    .fsync = fsync_cb,
    .opendir = opendir_cb,
    .readdir = readdir_cb,
    .releasedir = releasedir_cb,
    .fsyncdir = fsync_cb,
    .statfs = statfs_cb,
    .access = access_cb,
    .setxattr = setxattr_cb,
    .getxattr = getxattr_cb,
    .listxattr = listxattr_cb,
    .removexattr = removexattr_cb};
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
  if (empty(NULL, 100, NULL, NULL, 0, 0, 0, 0)) {
    fprintf(stderr, "low-level broker handshake failed\n");
    return 2;
  }
  char *fixed[] = {argv[0],
                   argv[1],
                   "-f",
                   "-s",
                   "-onodev,nosuid,fsname=ext4fuse-experimental"
#ifdef __APPLE__
                   ,
                   "-odefault_permissions,extended_security"
#endif
  };
  struct fuse_args args =
      FUSE_ARGS_INIT(sizeof(fixed) / sizeof(fixed[0]), fixed);
  struct fuse_cmdline_opts opts = {0};
  int result = 2, signals = 0, mounted = 0;
  if (fuse_parse_cmdline(&args, &opts))
    goto done;
  session = fuse_session_new(&args, &operations, sizeof(operations), NULL);
  if (!session)
    goto done;
  if (fuse_set_signal_handlers(session))
    goto done;
  signals = 1;
  if (fuse_session_mount(session, opts.mountpoint))
    goto done;
  mounted = 1;
  result = fuse_session_loop(session);
done:
  if (mounted)
    fuse_session_unmount(session);
  if (signals)
    fuse_remove_signal_handlers(session);
  if (session)
    fuse_session_destroy(session);
  free(opts.mountpoint);
  fuse_opt_free_args(&args);
  return failed || result < 0 ? 2 : result;
}
