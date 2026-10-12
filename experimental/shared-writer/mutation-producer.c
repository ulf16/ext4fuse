/* SPDX-License-Identifier: GPL-2.0-only */
#include "mutation.h"
#include "overlay.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
extern struct struct_io_manager staged_manager;
static uint64_t little(const unsigned char *p, size_t n) {
  uint64_t value = 0;
  for (size_t i = 0; i < n; i++)
    value |= (uint64_t)p[i] << (i * 8);
  return value;
}
static int read_all(FILE *f, void *data, size_t n) {
  return fread(data, 1, n, f) == n ? 0 : EINVAL;
}
int main(int argc, char **argv) {
  if (argc != 3 || strcmp(argv[2], "--stream"))
    return 2;
  const char *request = getenv("EXT4_MUTATION_REQUEST");
  if (!request)
    return 2;
  int fd = open(request, O_RDONLY | O_NOFOLLOW);
  if (fd < 0)
    return 2;
  struct stat info;
  if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < 12 ||
      info.st_size > 5 * 1024 * 1024) {
    close(fd);
    return 2;
  }
  FILE *input = fdopen(fd, "rb");
  if (!input) {
    close(fd);
    return 2;
  }
  unsigned char header[40];
  struct mutation ops[64] = {0};
  unsigned count = 0;
  size_t total = 0;
  struct credentials credentials = {0};
  int enforce = 0;
  errcode_t e = read_all(input, header, 12);
  if (!e) {
    if (!memcmp(header, "E4REQ002", 8))
      enforce = 1;
    else if (memcmp(header, "E4REQ001", 8))
      e = EINVAL;
  }
  if (!e) {
    count = little(header + 8, 4);
    if (!count || count > 64) {
      count = 0;
      e = EINVAL;
    }
  }
  if (!e && enforce) {
    unsigned char context[16 + 4 * POLICY_GROUPS];
    e = read_all(input, header, 4);
    size_t bytes = little(header, 4);
    if (!e && (bytes < 16 || bytes > sizeof(context)))
      e = EINVAL;
    if (!e)
      e = read_all(input, context, bytes);
    if (!e)
      e = policy_decode(context, bytes, &credentials);
  }
  for (unsigned i = 0; !e && i < count; i++) {
    e = read_all(input, header, 40);
    if (e)
      break;
    uint32_t pathlen = little(header + 4, 4);
    uint64_t length = little(header + 32, 8);
    if (!pathlen || pathlen > 4096 || length > 4 * 1024 * 1024 ||
        length > 4 * 1024 * 1024 - total || little(header + 20, 4)) {
      e = EINVAL;
      break;
    }
    ops[i].kind = little(header, 4);
    ops[i].mode = little(header + 8, 4);
    ops[i].uid = little(header + 12, 4);
    ops[i].gid = little(header + 16, 4);
    ops[i].offset = little(header + 24, 8);
    ops[i].length = length;
    char *path = calloc(pathlen + 1, 1);
    void *data = malloc(length ? length : 1);
    ops[i].path = path;
    ops[i].data = data;
    if (!path || !data) {
      e = ENOMEM;
      break;
    }
    e = read_all(input, path, pathlen);
    if (!e && memchr(path, 0, pathlen))
      e = EINVAL;
    if (!e)
      e = read_all(input, data, length);
    total += length;
  }
  if (!e && (fgetc(input) != EOF || ferror(input)))
    e = EINVAL;
  fclose(input);
  struct overlay *overlay = NULL;
  ext2_filsys fs = NULL;
  if (!e) {
    overlay = overlay_open(argv[1], 2048);
    if (!overlay)
      e = errno;
  }
  active_overlay = overlay;
  if (!e)
    e = ext2fs_open(argv[1], EXT2_FLAG_RW | EXT2_FLAG_64BITS, 0, 0,
                    &staged_manager, &fs);
  if (!e && (ext2fs_has_feature_journal_needs_recovery(fs->super) ||
             !(fs->super->s_state & EXT2_VALID_FS)))
    e = EINVAL;
  if (!e)
    e = ext2fs_read_bitmaps(fs);
  const char *failure = getenv("EXT4_TEST_MUTATION_FAIL_WRITES");
  if (!e && failure)
    overlay_fail_writes(overlay, strtol(failure, NULL, 10));
  for (unsigned i = 0; !e && i < count; i++)
    e = mutation_apply_as(fs, &ops[i], enforce ? &credentials : NULL);
  if (!e) {
    e = ext2fs_close(fs);
    fs = NULL;
  }
  if (!e)
    e = overlay_publish(overlay);
  if (!e)
    e = overlay_stream(overlay, STDOUT_FILENO);
  if (fs)
    ext2fs_free(fs);
  overlay_close(overlay);
  for (unsigned i = 0; i < count; i++) {
    free((void *)ops[i].path);
    free((void *)ops[i].data);
  }
  if (e && enforce) {
    /* Complete bounded error frame, distinct from a successful overlay. */
    unsigned char failure[24] = "E4ER0001";
    unsigned code = policy_errno(e);
    for (unsigned i = 0; i < 8; i++)
      failure[8 + i] = (uint64_t)code >> (8 * i);
    if (write(STDOUT_FILENO, failure, sizeof(failure)) != sizeof(failure))
      return 1;
  }
  if (e)
    fprintf(stderr, "mutation transaction rejected: %ld (%s)\n", (long)e,
            e > 0 && e < 4096 ? strerror(e) : error_message(e));
  return e ? 1 : 0;
}
