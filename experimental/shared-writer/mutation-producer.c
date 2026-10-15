/* SPDX-License-Identifier: GPL-2.0-only */
#include "metadata.h"
#include "mutation.h"
#include "namespace.h"
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
  int enforce = 0, by_inode = 0, broker = 0, at = 0;
  struct inode_pin pins[PIN_LIMIT] = {0};
  unsigned pin_count = 0;
  struct inode_grant grants[64] = {0};
  errcode_t e = read_all(input, header, 12);
  if (!e) {
    if (!memcmp(header, "E4REQ006", 8))
      enforce = broker = by_inode = 1;
    else if (!memcmp(header, "E4REQ005", 8))
      enforce = broker = at = 1;
    else if (!memcmp(header, "E4REQ004", 8))
      enforce = broker = 1;
    else if (!memcmp(header, "E4REQ003", 8))
      enforce = by_inode = 1;
    else if (!memcmp(header, "E4REQ002", 8))
      enforce = 1;
    else if (memcmp(header, "E4REQ001", 8))
      e = EINVAL;
  }
  if (!e) {
    count = little(header + 8, 4);
    if ((!count && !broker) || count > 64) {
      count = 0;
      e = EINVAL;
    }
  }
  if (!e && enforce) {
    unsigned char context[16 + 4 * POLICY_GROUPS];
    e = read_all(input, header, 4);
    size_t bytes = little(header, 4);
    if (!e &&
        ((!broker || at || bytes) && (bytes < 16 || bytes > sizeof(context))))
      e = EINVAL;
    if (!e)
      e = read_all(input, context, bytes);
    if (!e && bytes)
      e = policy_decode(context, bytes, &credentials);
    if (!e && !bytes)
      enforce = 0;
  }
  if (!e && broker) {
    e = read_all(input, header, 4);
    pin_count = little(header, 4);
    if (!e && pin_count > PIN_LIMIT)
      e = EINVAL;
    for (unsigned i = 0; !e && i < pin_count; i++) {
      e = read_all(input, header, 8);
      pins[i].inode = little(header, 4);
      pins[i].generation = little(header + 4, 4);
    }
  }
  for (unsigned i = 0; !e && i < count; i++) {
    if (at) {
      unsigned char bases[32];
      e = read_all(input, bases, sizeof(bases));
      for (unsigned j = 0; !e && j < 2; j++) {
        struct inode_grant *g = j ? &ops[i].target_base : &ops[i].base;
        g->inode = little(bases + j * 16, 4);
        g->generation = little(bases + j * 16 + 4, 4);
        g->access = little(bases + j * 16 + 8, 4);
        g->flags = little(bases + j * 16 + 12, 4);
        if (grant_valid(g) ||
            (g->flags != GRANT_DIRECTORY && (j || g->flags != GRANT_NODE)))
          e = EINVAL;
      }
      ops[i].at = 1;
      if (e)
        break;
    }
    e = read_all(input, header, 40);
    if (e)
      break;
    uint32_t pathlen = little(header + 4, 4);
    uint64_t length = little(header + 32, 8);
    if ((by_inode && pathlen != 16) || !pathlen || pathlen > 4096 ||
        length > 4 * 1024 * 1024 || length > 4 * 1024 * 1024 - total ||
        (!at && little(header + 20, 4))) {
      e = EINVAL;
      break;
    }
    ops[i].kind = little(header, 4);
    if (at && ops[i].base.flags == GRANT_NODE && ops[i].kind != MUT_LINK) {
      e = EINVAL;
      break;
    }
    if (ops[i].kind == MUT_OPEN && (!at || count != 1)) {
      e = EINVAL;
      break;
    }
    ops[i].at_flags = little(header + 20, 4);
    if (ops[i].at_flags > 1 ||
        (ops[i].at_flags && ops[i].kind != MUT_LINK &&
         (ops[i].kind < MUT_CHMOD || ops[i].kind > MUT_REMOVEXATTR))) {
      e = EINVAL;
      break;
    }
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
    if (!e && !by_inode && memchr(path, 0, pathlen))
      e = EINVAL;
    if (!e && by_inode) {
      grants[i].inode = little((unsigned char *)path, 4);
      grants[i].generation = little((unsigned char *)path + 4, 4);
      grants[i].access = little((unsigned char *)path + 8, 4);
      grants[i].flags = little((unsigned char *)path + 12, 4);
      if (grant_valid(&grants[i]))
        e = EINVAL;
    }
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
  if (!e && broker)
    e = namespace_reap(fs, pins, pin_count);
  struct inode_grant opened[64] = {0};
  for (unsigned i = 0; !e && i < count; i++)
    e = ops[i].kind == MUT_MKNOD
            ? (by_inode
                   ? EINVAL
                   : namespace_apply(fs, &ops[i], enforce ? &credentials : NULL,
                                     pins, pin_count))
        : ops[i].kind == MUT_ALLOCATE
            ? (by_inode
                   ? mutation_apply_grant(fs, &ops[i], &credentials, &grants[i])
                   : EINVAL)
        : ops[i].kind >= MUT_CHMOD
            ? metadata_apply(fs, &ops[i], enforce ? &credentials : NULL,
                             by_inode ? &grants[i] : NULL)
        : ops[i].kind == MUT_OPEN && at
            ? mutation_open_at(fs, &ops[i], &credentials, &opened[i])
        : ops[i].kind >= MUT_LINK && !by_inode
            ? namespace_apply(fs, &ops[i], enforce ? &credentials : NULL, pins,
                              pin_count)
        : by_inode
            ? mutation_apply_grant(fs, &ops[i], &credentials, &grants[i])
            : mutation_apply_as(fs, &ops[i], enforce ? &credentials : NULL);
  if (!e && broker)
    e = namespace_reap(fs, pins, pin_count);
  if (!e) {
    e = ext2fs_close(fs);
    fs = NULL;
  }
  if (!e)
    e = overlay_publish(overlay);
  if (!e && at && count == 1 && ops[0].kind == MUT_OPEN) {
    size_t n = strlen(request);
    char *report = malloc(n + 8);
    if (!report)
      e = ENOMEM;
    else {
      memcpy(report, request, n);
      strcpy(report + n, ".result");
      int out = open(report, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
      free(report);
      unsigned char record[16];
      uint32_t values[4] = {opened[0].inode, opened[0].generation,
                            opened[0].access, opened[0].flags};
      for (unsigned j = 0; j < 4; j++)
        for (unsigned k = 0; k < 4; k++)
          record[j * 4 + k] = values[j] >> (k * 8);
      if (out < 0)
        e = errno;
      else {
        if (write(out, record, 16) != 16 || fsync(out))
          e = EIO;
        if (close(out) && !e)
          e = errno;
      }
    }
  }
  if (!e)
    e = overlay_stream(overlay, STDOUT_FILENO);
  if (fs)
    ext2fs_free(fs);
  overlay_close(overlay);
  for (unsigned i = 0; i < count; i++) {
    free((void *)ops[i].path);
    free((void *)ops[i].data);
  }
  if (e && (enforce || broker)) {
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
