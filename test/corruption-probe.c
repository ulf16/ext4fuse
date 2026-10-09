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
#include "checksum.h"
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
    /* Standard CRC32C check vector, with ext4's uncomplemented result. */
    if (checksum_crc32c(~0U,"123456789",9) != 0x1cf96d7cU ||
        checksum_crc32c(checksum_crc32c(~0U,"1234",4),"56789",5) != 0x1cf96d7cU ||
        checksum_crc16(0xffff,"123456789",9) != 0x4b37) return 2;
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
    if (!strcmp(argv[2], "xlist") || !strcmp(argv[2], "xget")) {
        char data[32768];
        int get = !strcmp(argv[2], "xget");
        size_t size = get ? (argc > 5 ? strtoul(argv[5], NULL, 10) : sizeof(data))
                          : (argc > 4 ? strtoul(argv[4], NULL, 10) : sizeof(data));
        if (size > sizeof(data) || (get && argc < 5)) return 2;
        ret = get ? op_getxattr(argv[3], argv[4], data, size) : op_listxattr(argv[3], data, size);
        printf("%d\n", ret);
        if (ret > 0 && size) {
            if ((size_t)ret > size) return 2;
            for (int i = 0; i < ret; i++) printf("%02x", (unsigned char)data[i]);
            puts("");
        }
        return 0;
    }
    if (!strcmp(argv[2], "bulk")) {
        size_t size = argc > 5 ? strtoul(argv[5],NULL,10) : 8U*1024*1024;
        if (!size || size > 16U*1024*1024) return 2;
        char *data = malloc(size);
        if (!data) return 2;
        ret = op_open(argv[3], &fi);
        if (!ret) ret = op_read(argv[3], data, size, offset, &fi);
        printf("%d\n",ret);
        fflush(stdout);
        if (ret > 0) fwrite(data,1,ret,stdout);
        free(data);
        return 0;
    }
    if (!strcmp(argv[2], "times")) {
        struct stat st;
        struct ext4_inode inode;
        struct inode_times times;
        ret = op_getattr(argv[3], &st);
        if (!ret) ret = inode_get_by_path(argv[3], &inode);
        if (!ret) ret = inode_get_times(&inode, &times);
        printf("%d\n", ret);
        if (!ret) {
#ifdef __APPLE__
            struct timespec a = st.st_atimespec, m = st.st_mtimespec, c = st.st_ctimespec;
            times.create = st.st_birthtimespec;
#else
            struct timespec a = st.st_atim, m = st.st_mtim, c = st.st_ctim;
#ifdef __FreeBSD__
            times.create = st.st_birthtim;
#endif
#endif
            printf("%lld %ld %lld %ld %lld %ld %lld %ld %d\n",
                   (long long)a.tv_sec, a.tv_nsec, (long long)m.tv_sec, m.tv_nsec,
                   (long long)c.tv_sec, c.tv_nsec, (long long)times.create.tv_sec,
                   times.create.tv_nsec, times.has_create);
        }
        return 0;
    }
    if (!strcmp(argv[2], "allocation")) {
        struct stat st;
        ret = op_getattr(argv[3], &st);
        printf("%d\n",ret);
        if (!ret) printf("%llu %llu %llu\n",(unsigned long long)st.st_size,
                         (unsigned long long)st.st_blocks,(unsigned long long)st.st_blksize);
        return 0;
    }
    if (!strcmp(argv[2], "stat")) {
        struct stat st;
        ret = op_getattr(argv[3], &st);
        printf("%d\n", ret);
        if (!ret) printf("%llu %llu %o %llu\n", (unsigned long long)st.st_uid,
                        (unsigned long long)st.st_gid, st.st_mode,
                        (unsigned long long)st.st_ino);
        return 0;
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
