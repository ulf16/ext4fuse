/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fuse.h>
#include "disk.h"
#include "inode.h"
#include "super.h"
#include "ops.h"
#include "logging.h"

static int found_long_name;
static int list_entry(void *buf, const char *name, const struct stat *st, off_t off
#if FUSE_MAJOR_VERSION >= 3
                      , enum fuse_fill_dir_flags flags
#endif
                      )
{
#if FUSE_MAJOR_VERSION >= 3
    assert(flags == 0);
#endif
    (void)buf; (void)st; (void)off;
    if (strlen(name) == 255) found_long_name++;
    return 0;
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    assert(logging_open("/dev/null") == 0);
    assert(disk_open(argv[1]) == 0);
    assert(super_fill() == 0);
    assert(super_group_fill() == 0);
    assert(inode_init() == 0);
    struct stat st;
    assert(op_getattr("/", &st) == 0 && S_ISDIR(st.st_mode));
    assert(op_getattr("/payload", &st) == 0 && S_ISREG(st.st_mode));
    assert(!(st.st_mode & 0222));
    struct fuse_file_info fi = {0};
    fi.fh = inode_get_idx_by_path("/payload");
    char buf[64] = {0};
    assert(op_read("/payload", buf, sizeof(buf), 0, &fi) == 13);
    assert(memcmp(buf, "ext4 fixture\n", 13) == 0);
    memset(buf, 0, sizeof(buf));
    assert(op_read("/payload", buf, sizeof(buf), 5, &fi) == 8);
    assert(memcmp(buf, "fixture\n", 8) == 0);
    assert(op_read("/payload", buf, sizeof(buf), 13, &fi) == 0);
    for (int i = 0; i < 3; i++) {
        assert(op_getattr("/missing", &st) == -ENOENT);
        assert(op_getattr("/missing/child", &st) == -ENOENT);
        assert(op_getattr("/payload", &st) == 0);
    }
    assert(op_readdir("/", NULL, list_entry, 0, &fi) == 0);
    assert(found_long_name == 1);
    /* macOS metadata probes may prefix a valid name with ._, exceeding 255. */
    char overlong[259];
    overlong[0] = '/';
    memset(overlong + 1, 'x', 257);
    overlong[258] = 0;
    assert(op_getattr(overlong, &st) == -ENAMETOOLONG);
    overlong[257] = 0;
    assert(op_getattr(overlong, &st) == -ENAMETOOLONG);
    assert(op_getattr("/payload", &st) == 0);
    puts("PASS: content, offset/EOF, read-only modes, missing/overlong paths, 255-byte filename");
    return 0;
}
