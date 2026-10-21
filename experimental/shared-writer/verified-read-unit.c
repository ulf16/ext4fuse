/* SPDX-License-Identifier: GPL-2.0-only */
#include "overlay.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  unsigned long long offset = strtoull(argv[2], NULL, 10);
  unsigned long length = strtoul(argv[3], NULL, 10);
  if (length > 1048576)
    return 2;
  struct overlay *view = overlay_open(argv[1], 1);
  if (!view)
    return 2;
  unsigned char *data = malloc(length ? length : 1);
  int error = !data || overlay_read(view, offset, length, data, 1);
  if (!error && fwrite(data, 1, length, stdout) != length)
    error = 1;
  free(data);
  overlay_close(view);
  return error ? 1 : 0;
}
