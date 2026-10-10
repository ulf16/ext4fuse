/* SPDX-License-Identifier: GPL-2.0-only */
/* Apple kauth_filesec portable encoding: big-endian header and ACE integers.
 * UUID byte order is unchanged. See Libc posix1e/acl_translate.c and XNU's
 * kauth_acl_evaluate. This core is portable so Linux CI can verify semantics. */
#include "acl.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NATIVE_MAX 128
#define READ (1U << 1)
#define EXEC (1U << 3)
#define DATA (READ | EXEC)
#define META ((1U << 7) | (1U << 9) | (1U << 11) | (1U << 20))
#define WRITE ((1U << 2) | (1U << 4) | (1U << 5) | (1U << 6) | (1U << 8) | (1U << 10) | (1U << 12) | (1U << 13))
struct ace { unsigned char uuid[16]; uint32_t kind, rights; };
struct native { struct ace ace[NATIVE_MAX]; unsigned count; };
static unsigned u16(const unsigned char *p) { return p[0] | (unsigned)p[1] << 8; }
static uint32_t u32(const unsigned char *p)
{ return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static void big32(unsigned char *p, uint32_t v)
{ p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
static void special(unsigned char uuid[16], unsigned code)
{
    const unsigned char prefix[12]={0xab,0xcd,0xef,0xab,0xcd,0xef,0xab,0xcd,0xef,0xab,0xcd,0xef};
    memcpy(uuid,prefix,12); big32(uuid+12,code);
}
static int wellknown(const unsigned char uuid[16])
{
    unsigned char ref[16]; special(ref,12);
    if (memcmp(uuid,ref,12)) return 0;
    unsigned code = (unsigned)uuid[12]<<24 | (unsigned)uuid[13]<<16 | (unsigned)uuid[14]<<8 | uuid[15];
    return code==12 || code==10 || code==16 || code==UINT32_MAX-1;
}
static uint32_t rights(unsigned perm)
{ return ((perm & 4) ? READ : 0) | ((perm & 1) ? EXEC : 0); }
static int add(struct native *n, const unsigned char uuid[16], unsigned kind, uint32_t bits)
{
    if (!bits) return 0;
    if (n->count == NATIVE_MAX) return -E2BIG;
    struct ace *a=&n->ace[n->count++];
    memcpy(a->uuid,uuid,16); a->kind=kind; a->rights=bits; return 0;
}
static int principal(unsigned tag, unsigned id, unsigned char uuid[16], ext4_acl_uuid_fn resolve)
{
    if (tag==1 || tag==4 || tag==32) { special(uuid,tag==1 ? 10 : tag==4 ? 16 : 12); return 0; }
    if (!resolve) return -EINVAL;
    int ret=resolve(tag==8,id,uuid);
    if (ret) return ret < 0 ? ret : -ret;
    /* Reserved Apple UUIDs would change a numeric identity into everybody,
     * nobody, owner or owning group. Reject rather than widening access. */
    return wellknown(uuid) ? -EOPNOTSUPP : 0;
}
int ext4_acl_to_macos(const unsigned char *disk, size_t bytes, unsigned mode,
                      char *out, size_t size, ext4_acl_uuid_fn resolve)
{
    int length=ext4_acl_to_xattr(disk,bytes,NULL,0);
    if (length < 0) return length;
    unsigned char *acl=malloc((size_t)length);
    if (!acl) return -ENOMEM;
    int ret=ext4_acl_to_xattr(disk,bytes,(char *)acl,(size_t)length);
    if (ret < 0) { free(acl); return ret; }
    unsigned mask=7, has_mask=0;
    for (int i=4;i<length;i+=8) if (u16(acl+i)==16) { mask=u16(acl+i+2); has_mask=1; }
    /* Apple accumulates allows across groups for a combined request, whereas
     * Linux requires one matching group to cover the complete request. Mixed
     * read-only and execute-only group grants cannot be represented exactly. */
    unsigned partial_read=0, partial_exec=0;
    if (!(has_mask && !(mode & 070))) {
        for (int i=4;i<length;i+=8) {
            unsigned tag=u16(acl+i);
            if (tag!=4 && tag!=8) continue;
            unsigned p=u16(acl+i+2)&mask&5;
            partial_read |= p==4; partial_exec |= p==1;
        }
    }
    if (partial_read && partial_exec) { free(acl); return -EOPNOTSUPP; }
    struct native n={0}; unsigned char uuid[16]; special(uuid,12);
    /* Satisfy metadata before data rules, since Apple deny entries examine
     * all requested rights, not merely the residual after earlier allows. */
    ret=add(&n,uuid,2,WRITE);
    if (!ret) ret=add(&n,uuid,1,META);
    /* Linux's zero group/mask mode fast path falls back to mode bits. */
    int mode_only=has_mask && !(mode & 070);
    for (int pass=0;pass<4 && !ret;pass++) {
        for (int i=4;i<length && !ret;i+=8) {
            unsigned tag=u16(acl+i), perm=u16(acl+i+2), id=u32(acl+i+4);
            if (tag==16) continue;
            if (mode_only && (tag==2 || tag==8)) continue;
            if (tag==1) perm=(mode>>6)&7; /* Linux's owner mode fast path. */
            if (mode_only && tag==4) perm=(mode>>3)&7;
            if (mode_only && tag==32) perm=mode&7;
            if (!mode_only && (tag==2 || tag==4 || tag==8)) perm &= mask;
            int user=tag==1 || tag==2, group=tag==4 || tag==8;
            if ((pass==0 && !user) || (pass==1 && !group) || (pass==2 && !group) || (pass==3 && tag!=32)) continue;
            ret=principal(tag,id,uuid,resolve);
            if (ret) break;
            uint32_t allowed=rights(perm);
            if (pass!=2) ret=add(&n,uuid,1,allowed);
            if (!ret && pass!=1) ret=add(&n,uuid,2,pass==2 ? DATA : DATA & ~allowed);
        }
    }
    free(acl);
    if (ret) return ret;
    size_t needed=44 + n.count*24;
    if (!size) return (int)needed;
    if (size<needed) return -ERANGE;
    unsigned char *p=(unsigned char *)out; memset(p,0,needed);
    big32(p,0x012cc16d); big32(p+36,n.count); big32(p+40,1U<<17); /* no inheritance */
    for (unsigned i=0;i<n.count;i++) {
        unsigned char *a=p+44+i*24;
        memcpy(a,n.ace[i].uuid,16); big32(a+16,n.ace[i].kind); big32(a+20,n.ace[i].rights);
    }
    return (int)needed;
}
