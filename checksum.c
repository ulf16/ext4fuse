/* SPDX-License-Identifier: GPL-2.0-only */
#include <errno.h>
#include <string.h>
#include "checksum.h"
#include "super.h"
uint16_t checksum_u16(const void *p) { uint16_t v; memcpy(&v,p,2); return v; }
uint32_t checksum_u32(const void *p) { uint32_t v; memcpy(&v,p,4); return v; }
uint32_t checksum_crc32c(uint32_t crc, const void *data, size_t size)
{
    const unsigned char *p = data;
    /* Reflected Castagnoli polynomial, with no final complement (ext4 ABI). */
    while (size--) {
        crc ^= *p++;
        for (unsigned i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1)));
    }
    return crc;
}
uint16_t checksum_crc16(uint16_t crc, const void *data, size_t size)
{
    const unsigned char *p = data;
    while (size--) {
        crc ^= *p++;
        for (unsigned i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0xa001U & (0U - (crc & 1)));
    }
    return crc;
}
int checksum_directory(const void *block, uint32_t seed, int indexed, uint32_t logical)
{
    if (!super_metadata_csum()) return 0;
    const unsigned char *p=block;
    size_t size=BLOCK_SIZE;
    /* Indexed roots and internal nodes carry dx_tail, not a dirent tail. */
    int dx = indexed && (!logical || (checksum_u32(p)==0 && checksum_u16(p+4)==size));
    if (dx) {
        size_t offset;
        if (!logical) {
            if (checksum_u16(p+4)!=12 || checksum_u16(p+16)!=size-12 ||
                checksum_u32(p+24)!=0 || p[29]!=8 || p[30]>1 || p[31]!=0) return -EIO;
            offset=32;
        } else offset=8;
        unsigned limit=checksum_u16(p+offset), count=checksum_u16(p+offset+2);
        if (!limit || !count || count>limit || limit>(size-offset-8)/8) return -EIO;
        size_t tail=offset+limit*8, used=offset+count*8;
        uint32_t zero=0;
        uint32_t crc=checksum_crc32c(seed,p,used);
        crc=checksum_crc32c(crc,p+tail,4);
        crc=checksum_crc32c(crc,&zero,4);
        return crc==checksum_u32(p+tail+4) ? 0 : -EIO;
    }
    size_t tail=size-12;
    if (checksum_u32(p+tail) || checksum_u16(p+tail+4)!=12 || p[tail+6] || p[tail+7]!=0xde) return -EIO;
    return checksum_crc32c(seed,p,tail)==checksum_u32(p+tail+8) ? 0 : -EIO;
}
