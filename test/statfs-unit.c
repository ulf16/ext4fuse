/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <string.h>
/* Exercise counter boundaries without allocating multi-terabyte fixtures. */
#include "../super.c"
#include "ops.h"
int main(void)
{
    struct statvfs st, sentinel;
    memset(&super, 0, sizeof(super));
    super.s_log_block_size = 2;
    super.s_feature_incompat = INCOMPAT_64BIT;
    super.s_blocks_count_hi = 3;
    super.s_blocks_count_lo = 123;
    super.s_free_blocks_count_hi = 2;
    super.s_free_blocks_count_lo = 17;
    super.s_r_blocks_count_hi = 1;
    super.s_r_blocks_count_lo = 3;
    super.s_inodes_count = 0xffffffffU;
    super.s_free_inodes_count = 0xfffffffeU;
    int ret = op_statfs("/missing", &st);
    if (sizeof(st.f_blocks) < 8) {
        assert(ret == -EOVERFLOW);
    } else {
        assert(ret == 0);
        assert(st.f_blocks == (3ULL << 32) + 123);
        assert(st.f_bfree == (2ULL << 32) + 17);
        assert(st.f_bavail == (1ULL << 32) + 14);
        assert(st.f_files == 0xffffffffU && st.f_ffree == 0xfffffffeU);
        assert(st.f_flag & ST_RDONLY);
    }
    /* High reserved/free fields have no meaning without the 64bit feature. */
    super.s_feature_incompat = 0;
    super.s_blocks_count_hi = 0;
    assert(op_statfs(NULL, &st) == 0);
    assert(st.f_blocks == 123 && st.f_bfree == 17 && st.f_bavail == 14);
    super.s_r_blocks_count_lo = 20;
    assert(op_statfs("/", &st) == 0 && st.f_bavail == 0);
    super.s_free_blocks_count_lo = 0;
    super.s_free_inodes_count = 0;
    assert(op_statfs("/", &st) == 0 && st.f_bfree == 0 && st.f_ffree == 0);
    memset(&sentinel, 0xa5, sizeof(sentinel));
    st = sentinel;
    super.s_free_blocks_count_lo = 124;
    assert(op_statfs("/", &st) == -EIO && !memcmp(&st, &sentinel, sizeof(st)));
    super.s_free_blocks_count_lo = 17;
    super.s_r_blocks_count_lo = 124;
    assert(op_statfs("/", &st) == -EIO && !memcmp(&st, &sentinel, sizeof(st)));
    super.s_r_blocks_count_lo = 3;
    super.s_inodes_count = 10;
    super.s_free_inodes_count = 11;
    assert(op_statfs("/", &st) == -EIO && !memcmp(&st, &sentinel, sizeof(st)));
    puts("PASS: statfs high counters, legacy fields, saturation, empty counts and errors");
    return 0;
}
