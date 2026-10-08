#ifndef EXTENTS_H
#define EXTENTS_H

#include <stddef.h>
#include "types/ext4_extents.h"

int extent_get_pblock(const void *inode_extents, size_t capacity, uint32_t lblock,
                      uint64_t *pblock, uint32_t *len);

#endif
