/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EXPERIMENTAL_HANDLES_H
#define EXPERIMENTAL_HANDLES_H
#include "grant.h"
/* Reader pipe commands 7=open,8=read,9=size,10=release,11=writer grant,
 * 12=unique live inode/ancestor pins (reply size is the orphan-list head),
 * 14=directory open,15=directory stat,16=names,17=path,18=directory duplicate,
 * 19=cwd traversal/open,20=legacy relative parent path,21=directory capability,
 * 22=read-only at-open admission,23=reserve slot/pin,24=activate committed
 * open, 25=statat,26=readlinkat,27=directory
 * page,28=tell/seek,29=rewind,30=handle full stat, 31=path full stat,32=mounted
 * geometry/admission,34=access,35=bounded xattr query,36=metadata grant.
 * Command 33 updates trusted mount credentials in reader-server. Token zero is
 * the immutable virtual root for 15/17/19/20/21/22/25/26/30/31/32/34/35/36; no
 * root slot or non-root pin is implied.
 */
void handles_destroy(void);
int handles_dispatch(const char *image, const struct credentials *credentials,
                     unsigned command, const unsigned char *path, size_t bytes,
                     uint64_t offset, uint64_t length, uint64_t *size,
                     unsigned char **data, size_t *count);
#endif
