/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_HANDLES_H
#define EXPERIMENTAL_HANDLES_H
#include "grant.h"
/* Reader pipe commands 7=open,8=read,9=size,10=release,11=writer grant,
 * 12=unique live inode pin snapshot (reply size is the orphan-list head). */
int handles_dispatch(const char *image, const struct credentials *credentials,
                     unsigned command, const unsigned char *path, size_t bytes,
                     uint64_t offset, uint64_t length, uint64_t *size,
                     unsigned char **data, size_t *count);
#endif
