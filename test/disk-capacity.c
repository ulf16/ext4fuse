/* SPDX-License-Identifier: GPL-2.0-only */
/* Exercise actual platform capacity branches with mocked read-only OS queries. */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>
#ifdef __APPLE__
#include <sys/disk.h>
#elif defined(__linux__)
#include <linux/fs.h>
#elif defined(__FreeBSD__)
#include <sys/disk.h>
#endif
static struct stat fixture;
static uint64_t bytes = 4096, sectors = 8;
static uint32_t sector = 512;
static int calls, failure, stat_failure, interrupted;
static unsigned long failure_request;
static int read_failure, read_interrupt;
static int fixture_stat(int fd, struct stat *st)
{ (void)fd; if (stat_failure) { errno=stat_failure; return -1; } *st=fixture; return 0; }
static int fixture_ioctl(int fd, unsigned long request, ...)
{
    (void)fd; calls++;
    if (interrupted) { interrupted--; errno=EINTR; return -1; }
    if (failure && (!failure_request || request==failure_request)) { errno=failure; return -1; }
    va_list args; va_start(args, request); void *p=va_arg(args, void *); va_end(args);
#ifdef __APPLE__
    if (request==DKIOCGETBLOCKSIZE) *(uint32_t *)p=sector;
    else if (request==DKIOCGETBLOCKCOUNT) *(uint64_t *)p=sectors;
#elif defined(__linux__)
    if (request==BLKGETSIZE64) *(uint64_t *)p=bytes;
#elif defined(__FreeBSD__)
    if (request==DIOCGMEDIASIZE) *(off_t *)p=bytes;
#endif
    else { errno=ENOTTY; return -1; }
    return 0;
}
static ssize_t fixture_pread(int fd, void *p, size_t count, off_t offset)
{
    (void)fd;
    if (read_interrupt) { read_interrupt=0;errno=EINTR;return -1; }
    if (read_failure) { errno=read_failure;return -1; }
    if (sector && ((uint64_t)offset%sector || count%sector)) { errno=EINVAL;return -1; }
    if (offset<0 || (uint64_t)offset+count>4096) return 0;
    for (size_t i=0;i<count;i++) ((unsigned char *)p)[i]=(i+offset)%256;
    return count;
}
#define pread fixture_pread
#define fstat fixture_stat
#define ioctl fixture_ioctl
#include "../disk.c"
#undef fstat
#undef ioctl
#undef pread
int main(void)
{
    unsigned checks=0;
#define CHECK(size, result) do { assert(disk_check_size(size)==(result)); checks++; } while (0)
    fixture.st_mode=S_IFREG;fixture.st_size=4096;
    CHECK(4095,0);CHECK(4096,0);CHECK(4097,-EIO);assert(!calls);
    fixture.st_size=-1;CHECK(1,-EIO);
    stat_failure=EACCES;CHECK(1,-EACCES);stat_failure=0;
    for (unsigned i=0;i<2;i++) {
        fixture.st_mode=i ? S_IFCHR : S_IFBLK;
        CHECK(4095,0);CHECK(4096,0);CHECK(4097,-EIO);
        interrupted=1;CHECK(4096,0);assert(!interrupted);
        failure=ENOTTY;CHECK(1,-ENOTTY);failure=EACCES;CHECK(1,-EACCES);failure=0;
        bytes=0;sectors=0;CHECK(1,-EIO);bytes=4096;sectors=8;
    }
#ifdef __APPLE__
    sector=0;CHECK(1,-EIO);sector=512;
    sectors=UINT64_MAX;CHECK(1,-EOVERFLOW);sectors=8;
#endif
    fixture.st_mode=S_IFIFO;CHECK(1,-ENOTSUP);
#ifdef __APPLE__
    fixture.st_mode=S_IFCHR;failure=EACCES;failure_request=DKIOCGETBLOCKCOUNT;
    CHECK(1,-EACCES);failure=0;failure_request=0;
#endif
    /* Actual bounce-read implementation, with a device that rejects unaligned I/O. */
    disk_sector=512;sector=512;unsigned char data[1200];
    const unsigned offsets[]={0,10,500,512,3001};
    for (unsigned i=0;i<sizeof(offsets)/sizeof(*offsets);i++) {
        assert(disk_read_exact(offsets[i],sizeof(data),data)==(offsets[i]+sizeof(data)<=4096 ? 0 : -EIO));
        if (offsets[i]+sizeof(data)<=4096) for (unsigned j=0;j<sizeof(data);j++) assert(data[j]==(offsets[i]+j)%256);
        checks++;
    }
    read_interrupt=1;assert(!disk_read_exact(10,64,data));checks++;
    read_failure=EACCES;assert(disk_read_exact(10,64,data)==-EACCES);checks++;read_failure=0;
    assert(disk_read_exact(4090,64,data)==-EIO);checks++;
    puts("PASS: platform capacity ioctl bounds, errors, EINTR and overflow");
    printf("%u capacity checks\n",checks);
    return 0;
}
