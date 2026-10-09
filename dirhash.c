/* SPDX-License-Identifier: GPL-2.0-only */
/* Ext4 legacy, half-MD4 and TEA filename hashes, signed and unsigned variants.
 * Algorithm reference: Linux fs/ext4/hash.c (Theodore Ts'o, 2002) and
 * e2fsprogs lib/ext2fs/dirhash.c (Daniel Phillips, 2001; Theodore Ts'o, 2002).
 * Written here using fixed-width unsigned arithmetic and bounded input chunks. */
#include <errno.h>
#include <string.h>
#include "dirhash.h"
static uint32_t rotate(uint32_t v, unsigned n) { return (v << n) | (v >> (32-n)); }
static void words(const char *name, size_t length, uint32_t *out, unsigned count, int unsign)
{
    uint32_t pad=(uint32_t)length | ((uint32_t)length<<8); pad|=pad<<16;
    for (unsigned word=0;word<count;word++) {
        uint32_t value=pad;
        for (unsigned byte=0;byte<4 && word*4+byte<length;byte++) {
            size_t i=word*4+byte;
            uint32_t c=unsign ? (unsigned char)name[i] : (uint32_t)(int32_t)(signed char)name[i];
            value=c+(value<<8);
        }
        out[word]=value;
    }
}
static void half_md4(uint32_t state[4], const uint32_t input[8])
{
    uint32_t v[4]; memcpy(v,state,sizeof(v));
    static const unsigned order[3][8]={{0,1,2,3,4,5,6,7},{1,3,5,7,0,2,4,6},{3,7,2,6,1,5,0,4}};
    static const unsigned shifts[3][4]={{3,7,11,19},{3,5,9,13},{3,9,11,15}};
    static const uint32_t add[3]={0,0x5a827999,0x6ed9eba1};
    for (unsigned round=0;round<3;round++) for (unsigned step=0;step<8;step++) {
        unsigned a=(4-step%4)%4,b=(a+1)%4,c=(a+2)%4,d=(a+3)%4;
        uint32_t f=round==0 ? v[d]^(v[b]&(v[c]^v[d])) :
                   round==1 ? (v[b]&v[c])+((v[b]^v[c])&v[d]) : v[b]^v[c]^v[d];
        v[a]=rotate(v[a]+f+input[order[round][step]]+add[round],shifts[round][step%4]);
    }
    for (unsigned i=0;i<4;i++) state[i]+=v[i];
}
static void tea(uint32_t state[4], const uint32_t input[4])
{
    uint32_t sum=0,a=state[0],b=state[1];
    for (unsigned i=0;i<16;i++) {
        sum+=0x9e3779b9;
        a+=((b<<4)+input[0])^(b+sum)^((b>>5)+input[1]);
        b+=((a<<4)+input[2])^(a+sum)^((a>>5)+input[3]);
    }
    state[0]+=a; state[1]+=b;
}
int directory_hash(unsigned version, const char *name, size_t length,
                   const uint32_t seed[4], uint32_t *hash)
{
    if (version>5 || length>255) return -EINVAL;
    int unsign=version>=3; version%=3;
    uint32_t value, state[4]={0x67452301,0xefcdab89,0x98badcfe,0x10325476};
    if (seed && (seed[0]|seed[1]|seed[2]|seed[3])) memcpy(state,seed,sizeof(state));
    if (!version) {
        uint32_t a=0x12a3fe2d,b=0x37abe8f9;
        for (size_t i=0;i<length;i++) {
            int c=unsign ? (unsigned char)name[i] : (signed char)name[i];
            uint32_t next=b+(a^(uint32_t)(c*7152373));
            if (next&0x80000000U) next-=0x7fffffff;
            b=a;a=next;
        }
        value=a<<1;
    } else {
        size_t chunk=version==1 ? 32 : 16;
        while (length) {
            uint32_t input[8];words(name,length,input,chunk/4,unsign);
            if (version==1) half_md4(state,input);else tea(state,input);
            size_t consumed=length<chunk ? length : chunk;
            name+=consumed;length-=consumed;
        }
        value=state[version==1 ? 1 : 0];
    }
    value&=~1U;
    if (value==0xfffffffeU) value=0xfffffffcU;
    *hash=value;
    return 0;
}
