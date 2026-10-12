/* SPDX-License-Identifier: GPL-2.0-only */
#define main original_prototype_main
#include "prototype.c"
#undef main
int main(int argc, char **argv) {
  if (argc != 3 || strcmp(argv[2], "--stream"))
    return 2;
  const char *value = getenv("EXT4_STEP");
  char *end;
  long step = value ? strtol(value, &end, 10) : 0;
  if (!value || *end || step < 1 || step > 100)
    return 2;
  struct overlay *t = overlay_open(argv[1], 2048);
  if (!t)
    return 2;
  active_overlay = t;
  CHECK(reader_attach(argv[1]));
  ext2_filsys fs = writer(argv[1]);
  ext2_ino_t ino;
  CHECK(ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, "renamed-file", &ino));
  size_t size = 160 * 1024 + step * 4096;
  unsigned char *data = malloc(size);
  if (!data)
    return 2;
  for (size_t i = 0; i < size; i++)
    data[i] = (i * 131 + (i >> 8)) ^ (0x5a + step);
  ext2_file_t file;
  CHECK(ext2fs_file_open(fs, ino, EXT2_FILE_WRITE, &file));
  CHECK(ext2fs_file_set_size2(file, size));
  CHECK(ext2fs_file_close(file));
  CHECK(write_data(fs, ino, 0, data, size));
  CHECK(ext2fs_close(fs));
  CHECK(overlay_publish(t));
  CHECK(reader_refresh());
  CHECK(reader_verify("/renamed-file", data, size));
  CHECK(overlay_stream(t, STDOUT_FILENO));
  overlay_close(t);
  free(data);
  return 0;
}
