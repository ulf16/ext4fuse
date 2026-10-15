/* SPDX-License-Identifier: GPL-2.0-only
 * Ephemeral private regular-file view for trusted e2fsprogs journal recovery.
 * Reads fall through to the inherited read-only source. Writes only touch the
 * bounded overlay. A control request seals/streams it; EOF discards it.
 */
#include "overlay.h"
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static struct fuse *mount_fs;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t capacity;
static int ready_fd, sealed, result = ECANCELED;
static struct timespec modified;
static int file(const char *path) { return !strcmp(path, "/image"); }
static int attributes(const char *path, struct stat *st,
                      struct fuse_file_info *fi) {
  (void)fi;
  memset(st, 0, sizeof(*st));
  st->st_uid = getuid();
  st->st_gid = getgid();
  st->st_blksize = 4096;
  if (!strcmp(path, "/")) {
    st->st_mode = S_IFDIR | 0700;
    st->st_nlink = 2;
    st->st_ino = 1;
    return 0;
  }
  if (!file(path))
    return -ENOENT;
  pthread_mutex_lock(&mutex);
  st->st_mode = S_IFREG | 0600;
  st->st_nlink = 1;
  st->st_ino = 2;
  st->st_size = capacity;
  st->st_blocks = overlay_pages(active_overlay) * 8;
#ifdef __APPLE__
  st->st_mtimespec = st->st_ctimespec = modified;
#else
  st->st_mtim = st->st_ctim = modified;
#endif
  pthread_mutex_unlock(&mutex);
  return 0;
}
static int listing(const char *path, void *buf, fuse_fill_dir_t fill, off_t off,
                   struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
  (void)off;
  (void)fi;
  (void)flags;
  if (strcmp(path, "/"))
    return -ENOENT;
  fill(buf, ".", NULL, 0, 0);
  fill(buf, "..", NULL, 0, 0);
  fill(buf, "image", NULL, 0, 0);
  return 0;
}
static int opened(const char *path, struct fuse_file_info *fi) {
  if (!file(path))
    return -ENOENT;
  fi->direct_io = 1;
  fi->keep_cache = 0;
  return 0;
}
static int read_file(const char *path, char *data, size_t n, off_t off,
                     struct fuse_file_info *fi) {
  (void)fi;
  if (!file(path))
    return -ENOENT;
  if (off < 0)
    return -EINVAL;
  if ((uint64_t)off >= capacity)
    return 0;
  if (n > capacity - off)
    n = capacity - off;
  if (n > INT_MAX)
    return -EOVERFLOW;
  pthread_mutex_lock(&mutex);
  int e = overlay_read(active_overlay, off, n, data, 0);
  pthread_mutex_unlock(&mutex);
  return e ? -e : (int)n;
}
static int write_file(const char *path, const char *data, size_t n, off_t off,
                      struct fuse_file_info *fi) {
  (void)fi;
  if (!file(path))
    return -ENOENT;
  if (off < 0 || n > INT_MAX)
    return -EINVAL;
  pthread_mutex_lock(&mutex);
  int e = sealed ? EROFS : overlay_write(active_overlay, off, n, data);
  if (!e)
    clock_gettime(CLOCK_REALTIME, &modified);
  pthread_mutex_unlock(&mutex);
  return e ? -e : (int)n;
}
static int resized(const char *path, off_t size, struct fuse_file_info *fi) {
  (void)fi;
  return !file(path)                              ? -ENOENT
         : size < 0 || (uint64_t)size != capacity ? -EPERM
                                                  : 0;
}
static int flushed(const char *path, int datasync, struct fuse_file_info *fi) {
  (void)datasync;
  (void)fi;
  return file(path) ? 0 : -ENOENT;
}
static void *initialized(struct fuse_conn_info *conn, struct fuse_config *cfg) {
  (void)conn;
  cfg->entry_timeout = cfg->attr_timeout = cfg->negative_timeout = 0;
  cfg->direct_io = 1;
  unsigned char ready = 1;
  if (write(ready_fd, &ready, 1) != 1)
    fuse_exit(mount_fs);
  close(ready_fd);
  ready_fd = -1;
  return NULL;
}
static void *control(void *unused) {
  (void)unused;
  unsigned char command;
  ssize_t n;
  do {
    n = read(STDIN_FILENO, &command, 1);
  } while (n < 0 && errno == EINTR);
  pthread_mutex_lock(&mutex);
  if (n == 1 && command == 'S') {
    sealed = 1;
    result = overlay_publish(active_overlay);
    if (!result)
      result = overlay_stream(active_overlay, STDOUT_FILENO);
  }
  pthread_mutex_unlock(&mutex);
  fuse_exit(mount_fs);
  fuse_unmount(mount_fs);
  return NULL;
}
int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  if (argc != 5)
    return 2;
  char *end;
  errno = 0;
  unsigned long long pages = strtoull(argv[3], &end, 10);
  if (errno || *end || !pages || pages > 262144 || argv[3][0] == '-')
    return 2;
  long fd = strtol(argv[4], &end, 10);
  if (*end || fd < 3 || fd > INT_MAX)
    return 2;
  ready_fd = (int)fd;
  if (fcntl(ready_fd, F_SETFD, FD_CLOEXEC) < 0)
    return 1;
  struct stat source;
  if (lstat(argv[1], &source) || !S_ISREG(source.st_mode) ||
      source.st_uid != getuid() || source.st_nlink != 1 ||
      source.st_size <= 0 || source.st_size % 4096)
    return 1;
  capacity = source.st_size;
  active_overlay = overlay_open(argv[1], pages);
  if (!active_overlay) {
    perror("candidate source");
    return 1;
  }
  clock_gettime(CLOCK_REALTIME, &modified);
  struct fuse_operations operations = {.getattr = attributes,
                                       .readdir = listing,
                                       .open = opened,
                                       .read = read_file,
                                       .write = write_file,
                                       .truncate = resized,
                                       .fsync = flushed,
                                       .init = initialized};
  struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
  fuse_opt_add_arg(&args, "ext4-journal-candidate");
  fuse_opt_add_arg(&args, "-o");
  fuse_opt_add_arg(&args, "default_permissions");
  mount_fs = fuse_new(&args, &operations, sizeof(operations), NULL);
  fuse_opt_free_args(&args);
  if (!mount_fs) {
    overlay_close(active_overlay);
    return 1;
  }
  if (fuse_mount(mount_fs, argv[2])) {
    fuse_destroy(mount_fs);
    overlay_close(active_overlay);
    return 1;
  }
  pthread_t thread;
  if (pthread_create(&thread, NULL, control, NULL)) {
    fuse_unmount(mount_fs);
    fuse_destroy(mount_fs);
    overlay_close(active_overlay);
    return 1;
  }
  int loop = fuse_loop(mount_fs);
  pthread_join(thread, NULL);
  fuse_destroy(mount_fs);
  overlay_close(active_overlay);
  return loop || result ? 1 : 0;
}
