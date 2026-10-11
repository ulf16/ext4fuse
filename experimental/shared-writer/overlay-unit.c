/* SPDX-License-Identifier: GPL-2.0-only */
#include "overlay.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define SIZE (2U * 1024 * 1024)
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x);                     \
      return 1;                                                                \
    }                                                                          \
    count++;                                                                   \
  } while (0)
static unsigned state = 0x31415926;
static unsigned rng(void) {
  state = state * 1664525U + 1013904223U;
  return state;
}
int main(void) {
  unsigned count = 0;
  char path[4096];
  const char *tmp = getenv("TMPDIR");
  if (!tmp)
    tmp = "/tmp";
  CHECK(snprintf(path, sizeof(path), "%s/ext4-overlay-unit.XXXXXX", tmp) <
        (int)sizeof(path));
  int fd = mkstemp(path);
  CHECK(fd >= 0);
  unsigned char *base = malloc(SIZE), *model = malloc(SIZE),
                *buf = malloc(65536), *read = malloc(65536);
  CHECK(base && model && buf && read);
  for (unsigned i = 0; i < SIZE; i++)
    base[i] = (i * 37U + (i >> 9)) & 255;
  CHECK(write(fd, base, SIZE) == SIZE);
  CHECK(close(fd) == 0);
  memcpy(model, base, SIZE);
  struct overlay *t = overlay_open(path, SIZE / 4096);
  CHECK(t != NULL);
  for (unsigned i = 0; i < 1500; i++) {
    if (i % 17 == 0) {
      overlay_rollback(t);
      memcpy(model, base, SIZE);
    }
    unsigned n = 1 + rng() % 65536, off = rng() % (SIZE - n + 1);
    for (unsigned j = 0; j < n; j++)
      buf[j] = rng() & 255;
    CHECK(overlay_write(t, off, n, buf) == 0);
    memcpy(model + off, buf, n);
    CHECK(overlay_read(t, off, n, read, 1) == EBUSY);
    CHECK(overlay_read(t, off, n, read, 0) == 0);
    CHECK(!memcmp(buf, read, n));
    CHECK(overlay_publish(t) == 0);
    for (unsigned j = 0; j < 3; j++) {
      n = 1 + rng() % 65536;
      off = rng() % (SIZE - n + 1);
      CHECK(overlay_read(t, off, n, read, 1) == 0);
      CHECK(!memcmp(read, model + off, n));
    }
  }
  CHECK(overlay_write(t, SIZE - 2, 4, buf) == EIO);
  CHECK(overlay_publish(t) == EIO);
  CHECK(overlay_read(t, 0, 1, read, 1) == EBUSY);
  overlay_rollback(t);
  CHECK(overlay_read(t, 0, 65536, read, 1) == 0);
  CHECK(!memcmp(base, read, 65536));
  overlay_close(t);
  t = overlay_open(path, 2);
  CHECK(t);
  CHECK(overlay_write(t, 0, 3 * 4096, buf) == ENOSPC);
  CHECK(overlay_pages(t) == 2);
  CHECK(overlay_publish(t) == EIO);
  CHECK(overlay_read(t, 0, 1, read, 1) == EBUSY);
  overlay_rollback(t);
  CHECK(overlay_read(t, 0, 65536, read, 1) == 0);
  CHECK(!memcmp(base, read, 65536));
  CHECK(overlay_write(t, UINT64_MAX, 4, buf) == EIO);
  overlay_close(t);
  CHECK(unlink(path) == 0);
  free(base);
  free(model);
  free(buf);
  free(read);
  printf("PASS: %u randomized overlay, publication, boundary and "
         "resource-limit checks\n",
         count);
  return 0;
}
