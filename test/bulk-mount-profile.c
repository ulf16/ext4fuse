/* SPDX-License-Identifier: GPL-2.0-only
 * Observe callback sizes in a test daemon; do not alter the production daemon.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "ops.h"
static uint64_t reads, bytes, small, medium, large;
static int observed_read(const char *path, char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi)
{
    reads++; bytes += size;
    small += size <= 4096; medium += size > 4096 && size <= 65536;
    large += size > 65536;
    return op_read(path, buf, size, offset, fi);
}
static void *observed_init(struct fuse_conn_info *info)
{
    fprintf(stderr, "PROFILE: protocol=%u.%u max_write=%u max_readahead=%u",
        info->proto_major, info->proto_minor, info->max_write, info->max_readahead);
#if FUSE_MAJOR_VERSION >= 3
    fprintf(stderr, " max_read=%u", info->max_read);
#endif
    fprintf(stderr, "\n");
    return op_init(info);
}
#define op_init observed_init
#define op_read observed_read
#define main original_main
#include "../fuse-main.c"
#undef op_init
#undef op_read
#undef main
static void report(void)
{
    fprintf(stderr, "PROFILE: reads=%llu requested=%llu <=4K=%llu 4K..64K=%llu >64K=%llu\n",
        (unsigned long long)reads, (unsigned long long)bytes,
        (unsigned long long)small, (unsigned long long)medium, (unsigned long long)large);
}
int main(int argc, char **argv)
{
    atexit(report);
    return original_main(argc, argv);
}
