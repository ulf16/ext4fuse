/* SPDX-License-Identifier: GPL-2.0-only
 * Experimental serialized transaction overlay. Base descriptor is always
 * read-only.
 */
#include "overlay.h"
#include <errno.h>
#include <fcntl.h>
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
  int fd;
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
      e = exact_read(t->fd, out, len, off);
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
      int e = exact_read(t->fd, p->data, PAGE, idx * PAGE);
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
    e = exact_read(t->fd, buf, len, off);
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
