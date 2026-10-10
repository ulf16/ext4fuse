/* SPDX-License-Identifier: GPL-2.0-only */
#include "acl.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static int resolve(int group, unsigned id, unsigned char uuid[16])
{ memset(uuid,0,16); uuid[0]=group+1; uuid[12]=id>>24; uuid[13]=id>>16; uuid[14]=id>>8; uuid[15]=id; return 0; }

int main(void)
{
    /* Compact ext4 ACL: owner, users 10/20, owning group, groups 30/40,
     * mask, other. Golden Linux xattr encoding uses full eight-byte entries. */
    const unsigned char disk[] = {1,0,0,0, 1,0,6,0,
        2,0,4,0,10,0,0,0, 2,0,0,0,20,0,0,0, 4,0,4,0,
        8,0,2,0,30,0,0,0, 8,0,4,0,40,0,0,0, 16,0,4,0, 32,0,0,0};
    const unsigned char golden[] = {2,0,0,0, 1,0,6,0,255,255,255,255,
        2,0,4,0,10,0,0,0, 2,0,0,0,20,0,0,0, 4,0,4,0,255,255,255,255,
        8,0,2,0,30,0,0,0, 8,0,4,0,40,0,0,0,
        16,0,4,0,255,255,255,255, 32,0,0,0,255,255,255,255};
    char out[sizeof(golden)]; unsigned checks = 0;
    assert(ext4_acl_to_xattr(disk,sizeof(disk),NULL,0)==sizeof(golden)); checks++;
    assert(ext4_acl_to_xattr(disk,sizeof(disk),out,sizeof(out))==sizeof(golden));
    assert(!memcmp(out,golden,sizeof(out))); checks++;
    assert(ext4_acl_to_xattr(disk,sizeof(disk),out,sizeof(out)-1)==-ERANGE); checks++;
    for (size_t n=0;n<sizeof(disk);n++) {
        assert(ext4_acl_to_xattr(disk,n,NULL,0)==-EIO); checks++;
    }
    /* Invalid version, unknown/duplicate/out-of-order tags, permissions,
     * undefined, duplicate and unsorted IDs, missing mask and trailing entry. */
    const unsigned mutations[][2] = {{0,2},{4,4},{8,1},{8,8},{6,8},
        {20,10},{20,9},{24,16},{36,30},{36,29},{40,30},{44,32}};
    for(size_t i=0;i<sizeof(mutations)/sizeof(*mutations);i++) {
        unsigned char bad[sizeof(disk)]; memcpy(bad,disk,sizeof(bad));
        bad[mutations[i][0]]=mutations[i][1];
        assert(ext4_acl_to_xattr(bad,sizeof(bad),NULL,0)==-EIO); checks++;
    }
    unsigned char bad[sizeof(disk)]; memcpy(bad,disk,sizeof(bad)); memset(bad+12,255,4);
    assert(ext4_acl_to_xattr(bad,sizeof(bad),NULL,0)==-EIO); checks++;
    /* Named principals require a mask. */
    memcpy(bad,disk,44); memcpy(bad+44,disk+48,4);
    assert(ext4_acl_to_xattr(bad,48,NULL,0)==-EIO); checks++;
    const unsigned char basic[]={1,0,0,0,1,0,4,0,4,0,4,0,32,0,0,0};
    assert(ext4_acl_to_xattr(basic,sizeof(basic),NULL,0)==28); checks++;
    /* Exhaustive byte mutations exercise the native converter under sanitizers.
     * Accepted values must retain a bounded, complete portable filesec header. */
    unsigned char native[44+128*24+32];
    for(size_t at=0;at<sizeof(disk);at++) for(unsigned value=0;value<256;value++) {
        unsigned char input[sizeof(disk)]; memcpy(input,disk,sizeof(input));input[at]=value;
        memset(native,0xa5,sizeof(native));
        int result=ext4_acl_to_macos(input,sizeof(input),0670,(char *)native,sizeof(native)-32,resolve);
        if(result>0) {
            assert(result>=44 && result<=44+128*24 && (result-44)%24==0);
            assert(native[0]==1 && native[1]==0x2c && native[2]==0xc1 && native[3]==0x6d);
        }
        for(size_t i=sizeof(native)-32;i<sizeof(native);i++) assert(native[i]==0xa5);
        checks++;
    }
    assert(ext4_acl_to_macos(disk,sizeof(disk),0670,NULL,0,NULL)==-EINVAL); checks++;
    printf("PASS: %u ACL structure and wire-format checks\n",checks);
}
