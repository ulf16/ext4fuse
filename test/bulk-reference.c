/* SPDX-License-Identifier: GPL-2.0-only */
#include <ext2fs/ext2fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
static double now(void)
{
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return t.tv_sec + t.tv_nsec * 1e-9;
}
int main(int argc, char **argv)
{
    if (argc != 4) return 2;
    unsigned chunk = strtoul(argv[2], NULL, 10), reps = strtoul(argv[3], NULL, 10);
    if (!chunk || chunk > 16U*1024*1024 || !reps) return 2;
    ext2_filsys fs; ext2_ino_t ino; ext2_file_t file;
    if (ext2fs_open(argv[1], 0, 0, 0, unix_io_manager, &fs) ||
        ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, "/payload", &ino) ||
        ext2fs_file_open(fs, ino, 0, &file)) return 2;
    __u64 size; if (ext2fs_file_get_lsize(file, &size)) return 2;
    char *buf = malloc(chunk); if (!buf) return 2;
    double start = now();
    for (unsigned repeat = 0; repeat < reps; repeat++) {
        if (ext2fs_file_llseek(file, 0, SEEK_SET, NULL)) return 2;
        for (__u64 offset = 0; offset < size;) {
            unsigned length = size - offset < chunk ? size - offset : chunk, got;
            if (ext2fs_file_read(file, buf, length, &got) || got != length) return 1;
            offset += got;
        }
    }
    double elapsed = now()-start;
    printf("{\"mode\":\"libext2fs\",\"bytes\":%llu,\"chunk\":%u,\"reps\":%u,\"seconds\":%.9f,\"mib_per_second\":%.3f}\n",(unsigned long long)size,chunk,reps,elapsed,size*reps/1048576.0/elapsed);
    free(buf); ext2fs_file_close(file); ext2fs_close(fs); return 0;
}
