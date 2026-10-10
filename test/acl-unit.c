/* SPDX-License-Identifier: GPL-2.0-only */
#include "acl.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

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
    printf("PASS: %u ACL structure and wire-format checks\n",checks);
}
