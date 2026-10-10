/* SPDX-License-Identifier: GPL-2.0-only */
#include "acl.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>

static unsigned u16(const unsigned char *p) { return p[0] | (unsigned)p[1] << 8; }
static uint32_t u32(const unsigned char *p)
{ return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

int ext4_acl_to_xattr(const unsigned char *disk, size_t bytes, char *out, size_t size)
{
    if (bytes < 4 || u32(disk) != 1) return -EIO;
    size_t cursor = 4, count = 0;
    unsigned state = 0, named = 0, mask = 0;
    uint32_t previous = 0;
    unsigned have_previous = 0;
    while (cursor < bytes) {
        if (bytes - cursor < 4) return -EIO;
        unsigned tag = u16(disk + cursor), perm = u16(disk + cursor + 2);
        size_t step = (tag == 2 || tag == 8) ? 8 : 4;
        if (perm > 7 || step > bytes - cursor) return -EIO;
        uint32_t id = step == 8 ? u32(disk + cursor + 4) : 0;
        if (step == 8 && id == UINT32_MAX) return -EIO;
        switch (tag) {
        case 1: /* owner */
            if (state != 0) return -EIO;
            state = 1; break;
        case 2: /* sorted named users */
            if (state != 1 || (have_previous && id <= previous)) return -EIO;
            named = have_previous = 1; previous = id; break;
        case 4: /* owning group */
            if (state != 1) return -EIO;
            state = 2; have_previous = 0; break;
        case 8: /* sorted named groups */
            if (state != 2 || (have_previous && id <= previous)) return -EIO;
            named = have_previous = 1; previous = id; break;
        case 16: /* group class mask */
            if (state != 2) return -EIO;
            state = 3; mask = 1; break;
        case 32: /* other: final entry */
            if (state != 2 && state != 3) return -EIO;
            state = 4; break;
        default: return -EIO;
        }
        cursor += step; count++;
    }
    if (state != 4 || (named && !mask)) return -EIO;
    if (count > (INT32_MAX - 4) / 8) return -E2BIG;
    size_t needed = 4 + count * 8;
    if (!size) return (int)needed;
    if (size < needed) return -ERANGE;
    const unsigned char version[4] = {2,0,0,0}, undefined[4] = {255,255,255,255};
    memcpy(out, version, 4);
    cursor = 4;
    for (size_t i = 0; i < count; i++) {
        unsigned tag = u16(disk + cursor);
        size_t step = (tag == 2 || tag == 8) ? 8 : 4;
        memcpy(out + 4 + i * 8, disk + cursor, 4);
        memcpy(out + 8 + i * 8, step == 8 ? disk + cursor + 4 : undefined, 4);
        cursor += step;
    }
    return (int)needed;
}
