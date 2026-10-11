/* SPDX-License-Identifier: GPL-2.0-only */
#include "overlay.h"
#include <errno.h>
#include <unistd.h>
static ssize_t overlay_test_pread(int fd, void *buf, size_t n, off_t off) {
  (void)fd;
  int e = overlay_read(active_overlay, off, n, buf, 1);
  if (e) {
    errno = e;
    return -1;
  }
  return n;
}
#define pread overlay_test_pread
#define main existing_benchmark_main
#include "test/bulk-reader.c"
#undef main
int main(int argc, char **argv) {
  if (argc < 5)
    return 2;
  active_overlay = overlay_open(argv[2], 2048);
  if (!active_overlay)
    return 2;
  unsigned char page[4096];
  if (overlay_read(active_overlay, 0, sizeof(page), page, 0) ||
      overlay_write(active_overlay, 0, sizeof(page), page) ||
      overlay_publish(active_overlay))
    return 2;
  int rc = existing_benchmark_main(argc, argv);
  overlay_close(active_overlay);
  return rc;
}
