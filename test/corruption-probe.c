/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fuse.h>
#include <unistd.h>
#include "disk.h"
#include "inode.h"
#include "ops.h"
#include "super.h"
#include "logging.h"
static int fill(void *buf, const char *name, const struct stat *st, off_t off
#if FUSE_MAJOR_VERSION >= 3
                , enum fuse_fill_dir_flags flags
#endif
                )
{
    (void)buf; (void)name; (void)st; (void)off;
#if FUSE_MAJOR_VERSION >= 3
    (void)flags;
#endif
    return 0;
}
int main(int argc, char **argv)
{
    if (argc < 4 || logging_open("/dev/null") < 0 || disk_open(argv[1]) < 0 ||
        super_fill() < 0 || super_group_fill() < 0 || inode_init() < 0) return 2;
    int ret;
    char buf[64];
    off_t offset = argc > 4 ? strtoll(argv[4], NULL, 10) : 0;
    struct fuse_file_info fi = {0};
    /* Only the test harness deliberately shrinks its disposable fixture,
     * after preflight, to test propagation of real short reads. */
    if (!strncmp(argv[2], "truncate-", 9)) {
        struct ext4_inode inode;
        ret = inode_get_by_path(argv[3], &inode);
        uint64_t physical;
        if (ret < 0 || inode_get_data_pblock(&inode, 0, &physical, NULL) < 0 || !physical) return 2;
        if (truncate(argv[1], BLOCKS2BYTES(physical) + 10) < 0) return 2;
    }
    if (!strcmp(argv[2], "list") || !strcmp(argv[2], "truncate-list")) ret = op_readdir(argv[3], NULL, fill, offset, &fi);
    else if (!strcmp(argv[2], "lookup")) { struct ext4_inode inode; ret = inode_get_by_path(argv[3], &inode); }
    else if (!strcmp(argv[2], "link")) {
        if (offset < 0 || offset > (off_t)sizeof(buf)) return 2;
        ret = op_readlink(argv[3], buf, argc > 4 ? (size_t)offset : sizeof(buf));
        printf("%d\n", ret);
        if (!ret) printf("%s\n", buf);
        return 0;
    } else {
        ret = op_open(argv[3], &fi);
        if (!ret) ret = op_read(argv[3], buf, sizeof(buf), offset, &fi);
    }
    printf("%d\n", ret);
    if (ret > 0) { for (int i = 0; i < ret; i++) printf("%02x", (unsigned char)buf[i]); puts(""); }
    return 0;
}
