/* SPDX-License-Identifier: GPL-2.0-only */
#include "ops.h"
#include "overlay.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  active_overlay = overlay_open(argv[1], 1);
  if (!active_overlay || reader_attach(argv[1]))
    return 2;
  FILE *file = fopen(argv[3], "rb");
  if (!file)
    return 2;
  struct stat info;
  if (fstat(fileno(file), &info) || info.st_size < 0 ||
      info.st_size > 64 * 1024 * 1024)
    return 2;
  unsigned char *data = malloc(info.st_size ? info.st_size : 1);
  if (!data || fread(data, 1, info.st_size, file) != (size_t)info.st_size)
    return 2;
  fclose(file);
  int error = reader_verify(argv[2], data, info.st_size);
  free(data);
  overlay_close(active_overlay);
  return error ? 1 : 0;
}
