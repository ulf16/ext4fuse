/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>
#include <ext2fs/ext2fs.h>
#include "dirhash.h"
int main(void)
{
    static const unsigned lengths[]={0,1,3,4,15,16,17,31,32,33,63,64,127,128,255};
    uint32_t random=0x823459ab,checks=0;
    for (unsigned trial=0;trial<32;trial++) {
        char name[255];for (unsigned i=0;i<sizeof(name);i++) { random=random*1664525+1013904223;name[i]=random>>24; }
        for (unsigned seedkind=0;seedkind<3;seedkind++) {
            uint32_t seed[4];for (unsigned i=0;i<4;i++) seed[i]=seedkind==0 ? 0 : seedkind==1 ? i+1 : (random=random*1664525+1013904223);
            for (unsigned version=0;version<6;version++) for (unsigned n=0;n<sizeof(lengths)/sizeof(*lengths);n++) {
                uint32_t actual,expected,minor;
                assert(!ext2fs_dirhash(version,name,lengths[n],seed,&expected,&minor));
                if (expected==0xfffffffeU) expected=0xfffffffcU;
                assert(!directory_hash(version,name,lengths[n],seed,&actual));
                assert(actual==expected);checks++;
            }
        }
    }
    printf("PASS: %u filename hash comparisons against libext2fs\n",checks);
    return 0;
}
