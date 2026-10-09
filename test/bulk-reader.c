/* SPDX-License-Identifier: GPL-2.0-only
 * Benchmark/profiling harness only: production disk code contains no counters.
 */
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
/* Linux kernel typedefs must precede this project's legacy __u* aliases. */
#ifdef __linux__
#include <linux/fs.h>
#undef BLOCK_SIZE
#endif
#include "inode.h"
#include "ops.h"
#include "logging.h"
static uint64_t calls, requested, tiny, inodes, blocks, large;
static ssize_t observed_pread(int fd, void *p, size_t size, off_t offset)
{
    calls++; requested += size;
    tiny += size == 4; inodes += size == 256;
    blocks += size == 4096; large += size > 4096;
    return pread(fd, p, size, offset);
}
#define pread observed_pread
#include "../disk.c"
#undef pread
static double now(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return t.tv_sec + t.tv_nsec * 1e-9;
}
int main(int argc, char **argv)
{
    if (argc < 5 || argc > 6) return 2;
    const char *mode = argv[1];
    size_t chunk = strtoul(argv[3], NULL, 10);
    unsigned reps = strtoul(argv[4], NULL, 10);
    if (!chunk || chunk > 16U*1024*1024 || !reps) return 2;
    int raw = !strcmp(mode, "raw"), snapshot = !strcmp(mode, "snapshot");
    if (!raw && !snapshot && strcmp(mode, "reader")) return 2;
    uint64_t size;
    struct fuse_file_info fi = {0};
    struct ext4_inode inode;
    if (raw) {
        struct stat st;
        if (disk_open(argv[2]) < 0 || fstat(disk_fd, &st) || st.st_size < 0) return 2;
        size = st.st_size;
    } else {
        if (disk_open(argv[2]) < 0 || super_fill() || super_group_fill() ||
            inode_init() || op_open("/payload", &fi) || inode_get_by_number(fi.fh, &inode)) return 2;
        size = inode_get_size(&inode);
    }
    FILE *dump = argc == 6 ? fopen(argv[5], "wb") : NULL;
    if (argc == 6 && !dump) return 2;
    char *buf = malloc(chunk);
    if (!buf) return 2;
    calls = requested = tiny = inodes = blocks = large = 0;
    uint64_t callbacks = 0;
    double start = now();
    for (unsigned repeat = 0; repeat < reps; repeat++) {
        for (uint64_t offset = 0; offset < size;) {
            size_t length = size - offset < chunk ? size - offset : chunk;
            int ret;
            if (raw) { ret = disk_read_exact(offset, length, buf); if (!ret) ret = length; }
            else if (snapshot) ret = inode_read_data(&inode, buf, length, offset);
            else ret = op_read("/payload", buf, length, offset, &fi);
            if (ret != (int)length) { fprintf(stderr,"read at %llu: %d != %zu\n",(unsigned long long)offset,ret,length); return 1; }
            if (dump && repeat == 0 && fwrite(buf, 1, length, dump) != length) return 2;
            offset += length; callbacks++;
        }
    }
    double elapsed = now() - start;
    if (dump && fclose(dump)) return 2;
    printf("{\"mode\":\"%s\",\"bytes\":%llu,\"chunk\":%zu,\"reps\":%u,\"seconds\":%.9f,\"mib_per_second\":%.3f,\"pread_calls\":%llu,\"pread_bytes\":%llu,\"pread_4\":%llu,\"pread_256\":%llu,\"pread_4096\":%llu,\"pread_large\":%llu,\"callbacks\":%llu}\n",mode,(unsigned long long)size,chunk,reps,elapsed,size*reps/1048576.0/elapsed,(unsigned long long)calls,(unsigned long long)requested,(unsigned long long)tiny,(unsigned long long)inodes,(unsigned long long)blocks,(unsigned long long)large,(unsigned long long)callbacks);
    free(buf);
    return 0;
}
