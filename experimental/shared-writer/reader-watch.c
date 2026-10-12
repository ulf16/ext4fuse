/* SPDX-License-Identifier: GPL-2.0-only
 * Keep the same production-reader instance and base descriptor across commits.
 */
#include "overlay.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  active_overlay = overlay_open(argv[1], 1);
  if (!active_overlay || reader_attach(argv[1]))
    return 2;
  char command[64];
  while (fgets(command, sizeof(command), stdin)) {
    int e = 0;
    if (!strcmp(command, "pause\n")) {
      overlay_suspend(active_overlay);
      e = reader_absent("/not-present") == EBUSY ? 0 : EIO;
    } else if (!strcmp(command, "resume\n")) {
      e = overlay_publish(active_overlay);
      if (!e)
        e = reader_refresh();
    } else {
      char *end;
      long step = strtol(command, &end, 10);
      if (step < 0 || step > 100 || strcmp(end, "\n"))
        return 2;
      size_t size = 160 * 1024 + step * 4096;
      unsigned char *data = malloc(size);
      if (!data)
        return 2;
      for (size_t i = 0; i < size; i++)
        data[i] = (i * 131 + (i >> 8)) ^ (0x5a + step);
      e = reader_verify("/renamed-file", data, size);
      free(data);
    }
    printf("%d\n", e);
    fflush(stdout);
  }
  overlay_close(active_overlay);
  return 0;
}
