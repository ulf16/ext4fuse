/*
 * Copyright (c) 2010, Gerard Lledó Vives, gerard.lledo@gmail.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */


#define _XOPEN_SOURCE 500
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#ifdef __APPLE__
#include <sys/disk.h>
#elif defined(__linux__)
#include <linux/fs.h>
#elif defined(__FreeBSD__)
#include <sys/disk.h>
#endif

#include "disk.h"
#include "logging.h"



static int disk_fd = -1;
static uint32_t disk_sector;


static int pread_wrapper(int disk_fd, void *p, size_t size, off_t where)
{
#if defined(__FreeBSD__) && !defined(__APPLE__)
#define PREAD_BLOCK_SIZE 1024
    /* FreeBSD needs to read aligned whole blocks.
     * TODO: Check what is a safe block size.
     */
    static __thread uint8_t block[PREAD_BLOCK_SIZE];
    off_t first_offset = where % PREAD_BLOCK_SIZE;
    int ret = 0;

    if (first_offset) {
        /* This is the case if the read doesn't start on a block boundary.
         * We still need to read the whole block and we do, but we only copy to
         * the out pointer the bytes that where actually asked for.  In this
         * case first_offset is the offset into the block. */
        int pread_ret = pread(disk_fd, block, PREAD_BLOCK_SIZE, where - first_offset);
        ASSERT(pread_ret == PREAD_BLOCK_SIZE);

        size_t first_size = MIN(size, (size_t)(PREAD_BLOCK_SIZE - first_offset));
        memcpy(p, block + first_offset, first_size);
        p += first_size;
        size -= first_size;
        where += first_size;
        ret += first_size;

        if (!size) return ret;
    }

    ASSERT(where % PREAD_BLOCK_SIZE == 0);

    size_t mid_read_size = (size / PREAD_BLOCK_SIZE) * PREAD_BLOCK_SIZE;
    if (mid_read_size) {
        int pread_ret_mid = pread(disk_fd, p, mid_read_size, where);
        ASSERT((size_t)pread_ret_mid == mid_read_size);

        p += mid_read_size;
        size -= mid_read_size;
        where += mid_read_size;
        ret += mid_read_size;

        if (!size) return ret;
    }

    ASSERT(size < PREAD_BLOCK_SIZE);

    int pread_ret_last = pread(disk_fd, block, PREAD_BLOCK_SIZE, where);
    ASSERT(pread_ret_last == PREAD_BLOCK_SIZE);

    memcpy(p, block, size);

    return ret + size;
#else
    return pread(disk_fd, p, size, where);
#endif
}

int disk_open(const char *path)
{
    disk_fd = open(path, O_RDONLY);
    if (disk_fd < 0) {
        return -errno;
    }

    disk_sector = 0;
#if defined(__APPLE__) || defined(__FreeBSD__)
    struct stat st;
    if (fstat(disk_fd, &st) < 0) return -errno;
    if (S_ISCHR(st.st_mode)) {
#ifdef __APPLE__
        unsigned long request = DKIOCGETBLOCKSIZE;
#else
        unsigned long request = DIOCGSECTORSIZE;
#endif
        int ret;
        do { ret = ioctl(disk_fd, request, &disk_sector); } while (ret < 0 && errno == EINTR);
        if (ret < 0) return -errno;
        if (!disk_sector || disk_sector > 65536 || (disk_sector & (disk_sector - 1))) return -EIO;
    }
#endif
    return 0;
}

/* Checked reads for pre-mount metadata. Existing reader call sites are audited
 * separately; do not silently change their assertion-based contracts here. */
int disk_read_exact(off_t where, size_t size, void *p)
{
    unsigned char *out = p;
    unsigned char *sector = NULL;
    while (size) {
        size_t length = size;
        off_t start = where;
        void *target = out;
        size_t inside = disk_sector ? (uint64_t)where % disk_sector : 0;
        int bounce = disk_sector && (inside || size < disk_sector);
        if (bounce) {
            if (!sector) sector = malloc(disk_sector);
            if (!sector) return -ENOMEM;
            start -= inside;
            length = disk_sector;
            target = sector;
        } else if (disk_sector) length -= length % disk_sector;
        ssize_t n = pread(disk_fd, target, length, start);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || (bounce && n != (ssize_t)length)) {
            int error = n < 0 ? -errno : -EIO;
            free(sector);
            return error;
        }
        size_t copied = bounce ? MIN(size, disk_sector - inside) : (size_t)n;
        if (bounce) memcpy(out, sector + inside, copied);
        out += copied;
        where += copied;
        size -= copied;
    }
    free(sector);
    return 0;
}

static int capacity_ioctl(unsigned long request, void *value)
{
    int ret;
    do { ret = ioctl(disk_fd, request, value); } while (ret < 0 && errno == EINTR);
    return ret < 0 ? -errno : 0;
}
int disk_check_size(uint64_t size)
{
    struct stat st;
    if (fstat(disk_fd, &st) < 0) return -errno;
    uint64_t capacity;
    if (S_ISREG(st.st_mode)) {
        if (st.st_size < 0) return -EIO;
        capacity = st.st_size;
    } else if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) {
        int ret;
#ifdef __APPLE__
        uint32_t sector = 0;
        uint64_t sectors = 0;
        ret = capacity_ioctl(DKIOCGETBLOCKSIZE, &sector);
        if (ret < 0) return ret;
        ret = capacity_ioctl(DKIOCGETBLOCKCOUNT, &sectors);
        if (ret < 0) return ret;
        if (!sector || !sectors) return -EIO;
        if (sectors > UINT64_MAX / sector) return -EOVERFLOW;
        capacity = sectors * sector;
#elif defined(__linux__)
        capacity = 0;
        ret = capacity_ioctl(BLKGETSIZE64, &capacity);
        if (ret < 0) return ret;
#elif defined(__FreeBSD__)
        off_t media = 0;
        ret = capacity_ioctl(DIOCGMEDIASIZE, &media);
        if (ret < 0) return ret;
        if (media <= 0) return -EIO;
        capacity = media;
#else
        return -ENOTSUP;
#endif
        if (!capacity) return -EIO;
    } else return -ENOTSUP;
    return capacity < size ? -EIO : 0;
}

int __disk_read(off_t where, size_t size, void *p, const char *func, int line)
{
    static pthread_mutex_t read_lock = PTHREAD_MUTEX_INITIALIZER;
    ssize_t pread_ret;

    ASSERT(disk_fd >= 0);

    pthread_mutex_lock(&read_lock);
    DEBUG("Disk Read: 0x%jx +0x%zx [%s:%d]", where, size, func, line);
    pread_ret = pread_wrapper(disk_fd, p, size, where);
    pthread_mutex_unlock(&read_lock);
    if (size == 0) WARNING("Read operation with 0 size");

    ASSERT((size_t)pread_ret == size);

    return pread_ret;
}

int disk_ctx_create(struct disk_ctx *ctx, off_t where, size_t size, uint32_t len)
{
    ASSERT(ctx);        /* Should be user allocated */
    ASSERT(size);

    ctx->cur = where;
    ctx->size = size * len;
    DEBUG("New disk context: 0x%jx +0x%jx", ctx->cur, ctx->size);

    return 0;
}

int __disk_ctx_read(struct disk_ctx *ctx, size_t size, void *p, const char *func, int line)
{
    int ret = 0;

    ASSERT(ctx->size);
    if (ctx->size == 0) {
        WARNING("Using a context with no bytes left");
        return ret;
    }

    /* Truncate if there are too many bytes requested */
    if (size > ctx->size) {
        size = ctx->size;
    }

    ret = __disk_read(ctx->cur, size, p, func, line);
    ctx->size -= ret;
    ctx->cur += ret;

    return ret;
}
