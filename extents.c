/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2010, Gerard Lledó Vives, gerard.lledo@gmail.com
 * Derived from Gerard Lledó Vives's ext4fuse extent reader (2010).
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "disk.h"
#include "extents.h"
#include "super.h"

static int walk(const void *node, size_t capacity, uint32_t logical,
                uint64_t lower, uint64_t upper, int expected_depth,
                uint64_t *physical, uint32_t *run)
{
    struct ext4_extent_header h;
    if (capacity < sizeof(h)) return -EIO;
    memcpy(&h, node, sizeof(h));
    size_t slots = (capacity - sizeof(h)) / sizeof(struct ext4_extent);
    if (h.eh_magic != EXT4_EXT_MAGIC || !h.eh_max || h.eh_max > slots ||
        h.eh_entries > h.eh_max || h.eh_depth > 5 ||
        (expected_depth >= 0 && h.eh_depth != expected_depth)) return -EIO;
    const unsigned char *entries = (const unsigned char *)node + sizeof(h);
    if (expected_depth >= 0) {
        uint32_t first_key;
        if (!h.eh_entries) return -EIO;
        memcpy(&first_key, entries, sizeof(first_key));
        if (first_key != lower) return -EIO;
    }
    uint64_t previous = lower;
    int selected = -1;
    if (!h.eh_depth) {
        for (unsigned i = 0; i < h.eh_entries; i++) {
            struct ext4_extent e;
            memcpy(&e, entries + i * sizeof(e), sizeof(e));
            uint32_t length = e.ee_len > 32768 ? e.ee_len - 32768 : e.ee_len;
            uint64_t end = (uint64_t)e.ee_block + length;
            if (!length || e.ee_block < previous || end > upper ||
                e.ee_start_hi || !e.ee_start_lo || e.ee_start_lo >= super_block_count() ||
                length > super_block_count() - e.ee_start_lo) return -EIO;
            previous = end;
            if (logical >= e.ee_block && logical < end) selected = i;
        }
        if (selected < 0) { *physical = 0; *run = 1; return 0; }
        struct ext4_extent e;
        memcpy(&e, entries + selected * sizeof(e), sizeof(e));
        uint32_t length = e.ee_len > 32768 ? e.ee_len - 32768 : e.ee_len;
        uint32_t delta = logical - e.ee_block;
        *physical = e.ee_len > 32768 ? 0 : (uint64_t)e.ee_start_lo + delta;
        *run = length - delta;
        return 0;
    }
    if (!h.eh_entries) return -EIO;
    for (unsigned i = 0; i < h.eh_entries; i++) {
        struct ext4_extent_idx e;
        memcpy(&e, entries + i * sizeof(e), sizeof(e));
        if (e.ei_block < lower || e.ei_block >= upper ||
            (i && e.ei_block <= previous) || e.ei_leaf_hi || !e.ei_leaf_lo ||
            e.ei_leaf_lo >= super_block_count()) return -EIO;
        previous = e.ei_block;
        if (e.ei_block <= logical) selected = i;
    }
    if (selected < 0) { *physical = 0; *run = 1; return 0; }
    struct ext4_extent_idx chosen, next;
    memcpy(&chosen, entries + selected * sizeof(chosen), sizeof(chosen));
    if (selected + 1 < h.eh_entries) {
        memcpy(&next, entries + (selected + 1) * sizeof(next), sizeof(next));
        upper = next.ei_block;
    }
    void *child = malloc(BLOCK_SIZE);
    if (!child) return -ENOMEM;
    int ret = disk_read_exact(BLOCKS2BYTES(chosen.ei_leaf_lo), BLOCK_SIZE, child);
    if (!ret) ret = walk(child, BLOCK_SIZE, logical, chosen.ei_block, upper,
                         h.eh_depth - 1, physical, run);
    free(child);
    return ret;
}

int extent_get_pblock(const void *node, size_t capacity, uint32_t logical,
                      uint64_t *physical, uint32_t *run)
{
    uint32_t local_run;
    if (!run) run = &local_run;
    *physical = 0;
    *run = 1;
    return walk(node, capacity, logical, 0, (uint64_t)UINT32_MAX + 1,
                -1, physical, run);
}
