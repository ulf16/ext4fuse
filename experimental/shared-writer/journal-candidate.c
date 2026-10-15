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
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static struct fuse *mount_fs;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t main_thread;
static int loop_done;
static void wake_loop(int signal_number) { (void)signal_number; }
static uint64_t capacity;
static int ready_fd, sealed, notified, result = ECANCELED;
static void failed(int error) {
  if (error && !notified) {
    unsigned char message[4] = {error & 255, (error >> 8) & 255,
                                (error >> 16) & 255, (error >> 24) & 255};
    notified = 1;
    /* One bounded message wakes the supervisor even if e2fsprogs deadlocks in
     * its own write-error cleanup. The candidate never publishes after error.
     */
    (void)write(ready_fd, message, sizeof(message));
  }
}
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
  failed(e);
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
  failed(e);
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
  /* fuse_exit does not wake a blocking receive. Interrupt the main thread until
   * it observes exit; unmount only after joining this thread, since macFUSE's
   * unmount helper can fork and must not run from our control thread. */
  while (!__atomic_load_n(&loop_done, __ATOMIC_ACQUIRE)) {
    pthread_kill(main_thread, SIGUSR1);
    struct timespec pause = {0, 10000000};
    nanosleep(&pause, NULL);
  }
  return NULL;
}
static int detached(const char *path, dev_t host) {
  struct stat st;
  return !stat(path, &st) && st.st_dev == host;
}
static int cleanup_mount(const char *path, dev_t host) {
  if (detached(path, host))
    return 0;
  /* Some macFUSE libfuse3 versions return from fuse_unmount while the dead
   * mount remains. Use a separate executable and verify the host directory is
   * visible again. This also runs when the producer disappeared mid-stream. */
#ifdef __APPLE__
  char *args[] = {"/sbin/umount", "-f", (char *)path, NULL};
#else
  char *args[] = {"fusermount3", "-uz", (char *)path, NULL};
#endif
  extern char **environ;
  posix_spawn_file_actions_t actions;
  int e = posix_spawn_file_actions_init(&actions);
  if (e)
    return e;
  posix_spawn_file_actions_adddup2(&actions, STDERR_FILENO, STDOUT_FILENO);
  pid_t child;
  e = posix_spawnp(&child, args[0], &actions, NULL, args, environ);
  posix_spawn_file_actions_destroy(&actions);
  if (e)
    return e;
  int status;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR)
      return errno;
  }
  return detached(path, host) ? 0 : EIO;
}
int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  struct sigaction wake = {.sa_handler = wake_loop};
  sigemptyset(&wake.sa_mask);
  if (sigaction(SIGUSR1, &wake, NULL))
    return 1;
  main_thread = pthread_self();
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
  struct stat mount_info;
  if (stat(argv[2], &mount_info) || !S_ISDIR(mount_info.st_mode))
    return 1;
  dev_t host_device = mount_info.st_dev;
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
  __atomic_store_n(&loop_done, 1, __ATOMIC_RELEASE);
  pthread_join(thread, NULL);
  fuse_unmount(mount_fs);
  int cleanup = cleanup_mount(argv[2], host_device);
  close(ready_fd);
  fuse_destroy(mount_fs);
  overlay_close(active_overlay);
  return loop || result || cleanup ? 1 : 0;
}
