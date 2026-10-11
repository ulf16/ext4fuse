/* SPDX-License-Identifier: GPL-2.0-only */
#include "overlay.h"
#include <errno.h>
#include <ext2fs/ext2fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
extern struct struct_io_manager staged_manager;
static unsigned checks;
#define CHECK(x)                                                               \
  do {                                                                         \
    errcode_t e = (x);                                                         \
    if (e) {                                                                   \
      fprintf(stderr, "FAIL line %d: %s: %ld (%s)\n", __LINE__, #x, (long)e,   \
              error_message(e));                                               \
      exit(1);                                                                 \
    }                                                                          \
    checks++;                                                                  \
  } while (0)
static ext2_filsys writer(const char *image) {
  ext2_filsys fs;
  CHECK(ext2fs_open(image, EXT2_FLAG_RW | EXT2_FLAG_64BITS, 0, 0,
                    &staged_manager, &fs));
  CHECK(ext2fs_read_bitmaps(fs));
  CHECK((ext2fs_has_feature_journal_needs_recovery(fs->super) ||
         !(fs->super->s_state & EXT2_VALID_FS))
            ? EINVAL
            : 0);
  return fs;
}
static errcode_t create(ext2_filsys fs, const char *name, ext2_ino_t *ino) {
  errcode_t e =
      ext2fs_new_inode(fs, EXT2_ROOT_INO, LINUX_S_IFREG | 0644, 0, ino);
  if (e)
    return e;
  struct ext2_inode in = {0};
  in.i_mode = LINUX_S_IFREG | 0644;
  in.i_links_count = 1;
  in.i_atime = in.i_ctime = in.i_mtime = (uint32_t)time(NULL);
  if (ext2fs_has_feature_extents(fs->super)) {
    ext2_extent_handle_t h;
    e = ext2fs_extent_open2(fs, *ino, &in, &h);
    if (e)
      return e;
    ext2fs_extent_free(h);
  }
  e = ext2fs_write_new_inode(fs, *ino, &in);
  if (e)
    return e;
  ext2fs_inode_alloc_stats2(fs, *ino, 1, 0);
  return ext2fs_link(fs, EXT2_ROOT_INO, name, *ino, EXT2_FT_REG_FILE);
}
static errcode_t write_data(ext2_filsys fs, ext2_ino_t ino, uint64_t off,
                            const void *p, unsigned n) {
  ext2_file_t file;
  errcode_t e = ext2fs_file_open(fs, ino, EXT2_FILE_WRITE, &file);
  if (e)
    return e;
  e = ext2fs_file_llseek(file, off, SEEK_SET, NULL);
  unsigned done = 0;
  if (!e)
    e = ext2fs_file_write(file, p, n, &done);
  errcode_t close = ext2fs_file_close(file);
  return e ? e : close ? close : done == n ? 0 : EIO;
}
static void publish(ext2_filsys fs) {
  CHECK(ext2fs_flush(fs));
  CHECK(overlay_publish(active_overlay));
  CHECK(reader_refresh());
}
int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  struct overlay *t = overlay_open(argv[1], 2048);
  if (!t) {
    perror("overlay_open");
    return 2;
  }
  active_overlay = t;
  CHECK(reader_attach(argv[1]));
  CHECK(reader_absent("/new-file"));
  ext2_filsys fs = writer(argv[1]);
  size_t full = 224 * 1024;
  unsigned char *data = malloc(full);
  if (!data)
    return 2;
  for (size_t i = 0; i < full; i++)
    data[i] = (unsigned char)((i * 131 + (i >> 8)) ^ 0x5a);
  ext2_ino_t ino;
  CHECK(create(fs, "new-file", &ino));
  CHECK(write_data(fs, ino, 0, data, 128 * 1024));
  unsigned char probe;
  CHECK(overlay_read(t, 0, 1, &probe, 1) == EBUSY ? 0 : EIO);
  CHECK(reader_absent("/new-file") == EBUSY ? 0 : EIO);
  publish(fs);
  CHECK(reader_verify("/new-file", data, 128 * 1024));
  CHECK(write_data(fs, ino, 128 * 1024, data + 128 * 1024, 96 * 1024));
  publish(fs);
  CHECK(reader_verify("/new-file", data, full));
  CHECK(ext2fs_link(fs, EXT2_ROOT_INO, "renamed-file", ino, EXT2_FT_REG_FILE));
  CHECK(ext2fs_unlink(fs, EXT2_ROOT_INO, "new-file", ino, 0));
  publish(fs);
  CHECK(reader_absent("/new-file"));
  CHECK(reader_verify("/renamed-file", data, full));
  ext2_file_t file;
  CHECK(ext2fs_file_open(fs, ino, EXT2_FILE_WRITE, &file));
  CHECK(ext2fs_file_set_size2(file, 96 * 1024));
  CHECK(ext2fs_file_close(file));
  publish(fs);
  CHECK(reader_verify("/renamed-file", data, 96 * 1024));
  CHECK(write_data(fs, ino, 96 * 1024, data + 96 * 1024, 64 * 1024));
  publish(fs);
  CHECK(reader_verify("/renamed-file", data, 160 * 1024));
  CHECK(ext2fs_close(fs));
  CHECK(overlay_publish(t));
  CHECK(reader_refresh());
  CHECK(reader_verify("/renamed-file", data, 160 * 1024));
  size_t pages = overlay_pages(t);
  char *failed = malloc(strlen(argv[2]) + 16);
  sprintf(failed, "%s.failed", argv[2]);
  CHECK(overlay_export(t, failed, 2) == EIO ? 0 : EIO);
  CHECK(overlay_export(t, argv[2], -1));
  CHECK(overlay_export(t, argv[2], -1) == EEXIST ? 0 : EIO);
  CHECK(reader_verify("/renamed-file", data, 160 * 1024));
  overlay_rollback(t);
  CHECK(reader_refresh());
  CHECK(reader_absent("/new-file"));
  CHECK(reader_absent("/renamed-file"));
  for (long failure = 0; failure <= 20; failure = failure == 0   ? 1
                                                  : failure == 1 ? 3
                                                  : failure == 3 ? 8
                                                  : failure == 8 ? 20
                                                                 : 21) {
    fs = writer(argv[1]);
    overlay_fail_writes(t, failure);
    errcode_t injected = create(fs, "failure-file", &ino);
    for (unsigned off = 0; !injected && off < 128 * 1024; off += 1024)
      injected = write_data(fs, ino, off, data + off, 1024);
    if (!injected)
      injected = ext2fs_flush(fs);
    CHECK((injected == ENOSPC || injected == EIO) ? 0 : EIO);
    CHECK(overlay_publish(t) == EIO ? 0 : EIO);
    CHECK(reader_absent("/failure-file") == EBUSY ? 0 : EIO);
    ext2fs_free(fs);
    overlay_rollback(t);
    CHECK(reader_refresh());
    CHECK(reader_absent("/failure-file"));
  }
  fs = writer(argv[1]);
  CHECK(create(fs, "post-rollback", &ino));
  CHECK(write_data(fs, ino, 0, data, 4096));
  publish(fs);
  CHECK(reader_verify("/post-rollback", data, 4096));
  ext2fs_free(fs);
  overlay_rollback(t);
  CHECK(reader_refresh());
  CHECK(reader_absent("/post-rollback"));
  overlay_close(t);
  free(data);
  free(failed);
  printf("PASS: %u shared-reader, libext2fs mutation, publication, rollback "
         "and injected-failure checks; %zu staged pages\n",
         checks, pages);
  return 0;
}
