/* SPDX-License-Identifier: GPL-2.0-only
 * Experimental serialized transaction overlay. Base descriptor is always
 * read-only.
 */
#include "overlay.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define PAGE 4096
#define BUCKETS 1024
struct page {
  uint64_t idx;
  unsigned char data[PAGE];
  struct page *next;
};
struct overlay {
  int fd, base_fd;
  unsigned sector;
  uint64_t size;
  char *path;
  size_t used, limit;
  long fail_writes;
  int published, poisoned;
  struct page *pages[BUCKETS];
};
struct overlay *active_overlay;
static struct page *find(struct overlay *t, uint64_t i) {
  for (struct page *p = t->pages[i % BUCKETS]; p; p = p->next)
    if (p->idx == i)
      return p;
  return NULL;
}
static int exact_read(int fd, void *b, size_t n, uint64_t off) {
  while (n) {
    ssize_t r = pread(fd, b, n, (off_t)off);
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0)
      return r < 0 ? errno : EIO;
    b = (char *)b + r;
    n -= r;
    off += r;
  }
  return 0;
}
/* Guard normalization is confined to explicitly inherited, read-only device
 * descriptors. Paths alone never opt an ordinary image into device access. */
static int base_read(struct overlay *t, void *b, size_t n, uint64_t off) {
  if (t->base_fd < 0)
    return exact_read(t->fd, b, n, off);
  uint64_t original = off;
  size_t length = n;
  unsigned char *out = b;
  unsigned char sector[4096];
  while (n) {
    unsigned inside = off % t->sector;
    if (inside || n < t->sector) {
      int e = exact_read(t->base_fd, sector, t->sector, off - inside);
      if (e)
        return e;
      size_t take = t->sector - inside;
      if (take > n)
        take = n;
      memcpy(out, sector + inside, take);
      out += take;
      off += take;
      n -= take;
    } else {
      size_t take = n - n % t->sector;
      int e = exact_read(t->base_fd, out, take, off);
      if (e)
        return e;
      out += take;
      off += take;
      n -= take;
    }
  }
  if (original <= 1080 && 1080 - original < length)
    ((unsigned char *)b)[1080 - original] = 0x53;
  if (original <= 1081 && 1081 - original < length)
    ((unsigned char *)b)[1081 - original] = 0xef;
  return 0;
}
static int device_view(struct overlay *t, const struct stat *token) {
  const char *config = getenv("EXT4_DEVICE_VIEW");
  if (!config)
    return 0;
  unsigned fd, sector;
  uint64_t size, dev, ino, rawdev, rawino, rdev;
  int end = 0;
  if (sscanf(config,
             "%u,%u,%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%" SCNu64
             ",%" SCNu64 "%n",
             &fd, &sector, &size, &dev, &ino, &rawdev, &rawino, &rdev,
             &end) != 8 ||
      config[end] || fd > INT_MAX ||
      (sector < 512 || sector > 4096 || (sector & (sector - 1))) ||
      size != (uint64_t)token->st_size || dev != (uint64_t)token->st_dev ||
      ino != (uint64_t)token->st_ino)
    return EINVAL;
  struct stat raw;
  int flags = fcntl((int)fd, F_GETFL);
  if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || fstat((int)fd, &raw) ||
      (!S_ISBLK(raw.st_mode) && !S_ISCHR(raw.st_mode)) ||
      (uint64_t)raw.st_dev != rawdev || (uint64_t)raw.st_ino != rawino ||
      (uint64_t)raw.st_rdev != rdev)
    return EINVAL;
  t->base_fd = dup((int)fd);
  if (t->base_fd < 0)
    return errno;
  if (fcntl(t->base_fd, F_SETFD, FD_CLOEXEC) < 0) {
    int e = errno;
    close(t->base_fd);
    t->base_fd = -1;
    return e;
  }
  t->sector = sector;
  return 0;
}
static int exact_write(int fd, const void *b, size_t n, uint64_t off) {
  while (n) {
    ssize_t r = pwrite(fd, b, n, (off_t)off);
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0)
      return r < 0 ? errno : EIO;
    b = (const char *)b + r;
    n -= r;
    off += r;
  }
  return 0;
}
struct overlay *overlay_open(const char *path, size_t max) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return NULL;
  struct stat s;
  if (fstat(fd, &s) || !S_ISREG(s.st_mode) || s.st_size <= 0 ||
      s.st_size % PAGE) {
    close(fd);
    errno = EINVAL;
    return NULL;
  }
  struct overlay *t = calloc(1, sizeof(*t));
  if (!t) {
    close(fd);
    return NULL;
  }
  t->path = strdup(path);
  if (!t->path) {
    close(fd);
    free(t);
    return NULL;
  }
  t->fd = fd;
  t->base_fd = -1;
  int view_error = device_view(t, &s);
  if (view_error) {
    free(t->path);
    free(t);
    close(fd);
    errno = view_error;
    return NULL;
  }
  t->size = s.st_size;
  t->limit = max;
  t->fail_writes = -1;
  t->published = 1;
  return t;
}
void overlay_rollback(struct overlay *t) {
  for (size_t i = 0; i < BUCKETS; i++)
    while (t->pages[i]) {
      struct page *p = t->pages[i];
      t->pages[i] = p->next;
      free(p);
    }
  t->used = 0;
  t->poisoned = 0;
  t->published = 1;
  t->fail_writes = -1;
}
void overlay_close(struct overlay *t) {
  if (!t)
    return;
  overlay_rollback(t);
  if (t->base_fd >= 0)
    close(t->base_fd);
  close(t->fd);
  free(t->path);
  free(t);
  if (active_overlay == t)
    active_overlay = NULL;
}
int overlay_read(struct overlay *t, uint64_t off, size_t n, void *b,
                 int reader) {
  if (off > t->size || n > t->size - off)
    return EIO;
  if (reader && (!t->published || t->poisoned))
    return EBUSY;
  unsigned char *out = b;
  while (n) {
    uint64_t idx = off / PAGE;
    size_t inside = off % PAGE, len = PAGE - inside;
    if (len > n)
      len = n;
    struct page *p = find(t, idx);
    int e = 0;
    if (p)
      memcpy(out, p->data + inside, len);
    else {
      while (len < n && !find(t, (off + len) / PAGE)) {
        size_t more = n - len > PAGE ? PAGE : n - len;
        len += more;
      }
      e = base_read(t, out, len, off);
    }
    if (e)
      return e;
    off += len;
    n -= len;
    out += len;
  }
  return 0;
}
int overlay_write(struct overlay *t, uint64_t off, size_t n, const void *b) {
  if (t->poisoned)
    return EIO;
  if (off > t->size || n > t->size - off) {
    t->poisoned = 1;
    return EIO;
  }
  if (t->fail_writes == 0) {
    t->poisoned = 1;
    return ENOSPC;
  }
  if (t->fail_writes > 0)
    t->fail_writes--;
  t->published = 0;
  const unsigned char *in = b;
  while (n) {
    uint64_t idx = off / PAGE;
    size_t inside = off % PAGE, len = PAGE - inside;
    if (len > n)
      len = n;
    struct page *p = find(t, idx);
    if (!p) {
      if (t->used >= t->limit) {
        t->poisoned = 1;
        return ENOSPC;
      }
      p = calloc(1, sizeof(*p));
      if (!p) {
        t->poisoned = 1;
        return ENOMEM;
      }
      int e = base_read(t, p->data, PAGE, idx * PAGE);
      if (e) {
        free(p);
        t->poisoned = 1;
        return e;
      }
      p->idx = idx;
      p->next = t->pages[idx % BUCKETS];
      t->pages[idx % BUCKETS] = p;
      t->used++;
    }
    memcpy(p->data + inside, in, len);
    off += len;
    n -= len;
    in += len;
  }
  return 0;
}
void overlay_suspend(struct overlay *t) { t->published = 0; }
int overlay_publish(struct overlay *t) {
  if (t->poisoned)
    return EIO;
  t->published = 1;
  return 0;
}
void overlay_fail_writes(struct overlay *t, long n) { t->fail_writes = n; }
size_t overlay_pages(struct overlay *t) { return t->used; }
const char *overlay_path(struct overlay *t) { return t->path; }
int overlay_export(struct overlay *t, const char *path, long fail_page) {
  if (!t->published || t->poisoned)
    return EBUSY;
  size_t length = strlen(path) + 32;
  char *temporary = malloc(length);
  if (!temporary)
    return ENOMEM;
  snprintf(temporary, length, "%s.stage.XXXXXX", path);
  int fd = mkstemp(temporary);
  if (fd < 0) {
    int e = errno;
    free(temporary);
    return e;
  }
  unsigned char *buf = malloc(1048576);
  int e = buf ? 0 : ENOMEM;
  for (uint64_t off = 0; !e && off < t->size;) {
    size_t len = t->size - off < 1048576 ? t->size - off : 1048576;
    e = base_read(t, buf, len, off);
    if (!e)
      e = exact_write(fd, buf, len, off);
    off += len;
  }
  free(buf);
  long done = 0;
  for (size_t i = 0; !e && i < BUCKETS; i++)
    for (struct page *p = t->pages[i]; p; p = p->next) {
      if (fail_page >= 0 && done++ == fail_page) {
        e = EIO;
        break;
      }
      e = exact_write(fd, p->data, PAGE, p->idx * PAGE);
      if (e)
        break;
    }
  if (!e && fsync(fd))
    e = errno;
  if (close(fd) && !e)
    e = errno;
  /* Publish only a complete image; link is atomic and never replaces an
   * existing destination. */
  if (!e && link(temporary, path))
    e = errno;
  unlink(temporary);
  free(temporary);
  return e;
}

/* The private transport carries original and replacement pages. The durable
 * consumer computes cryptographic digests and seals the transaction. */
static int stream_write(int fd, const void *data, size_t length) {
  while (length) {
    ssize_t n = write(fd, data, length);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return n < 0 ? errno : EIO;
    data = (const unsigned char *)data + n;
    length -= (size_t)n;
  }
  return 0;
}
static void little64(unsigned char *out, uint64_t value) {
  for (unsigned i = 0; i < 8; i++)
    out[i] = (unsigned char)(value >> (i * 8));
}
static int page_order(const void *a, const void *b) {
  const struct page *left = *(const struct page *const *)a;
  const struct page *right = *(const struct page *const *)b;
  return left->idx < right->idx ? -1 : left->idx > right->idx;
}
int overlay_stream(struct overlay *t, int fd) {
  if (!t->published || t->poisoned)
    return EBUSY;
  if (t->used > 1048576 || t->used > SIZE_MAX / sizeof(struct page *))
    return EOVERFLOW;
  struct page **ordered = calloc(t->used ? t->used : 1, sizeof(*ordered));
  if (!ordered)
    return ENOMEM;
  size_t count = 0;
  for (size_t i = 0; i < BUCKETS; i++)
    for (struct page *p = t->pages[i]; p; p = p->next)
      ordered[count++] = p;
  qsort(ordered, count, sizeof(*ordered), page_order);
  unsigned char header[24] = "E4OVL001";
  little64(header + 8, t->size);
  little64(header + 16, count);
  int e = stream_write(fd, header, sizeof(header));
  unsigned char record[8 + PAGE * 2];
  for (size_t i = 0; !e && i < count; i++) {
    little64(record, ordered[i]->idx);
    e = base_read(t, record + 8, PAGE, ordered[i]->idx * PAGE);
    if (!e) {
      memcpy(record + 8 + PAGE, ordered[i]->data, PAGE);
      e = stream_write(fd, record, sizeof(record));
    }
  }
  free(ordered);
  return e;
}
