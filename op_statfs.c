/* SPDX-License-Identifier: GPL-2.0-only */
#include "common.h"
#include "ops.h"
#include "super.h"

int op_statfs(const char *path, struct statvfs *st)
{
    /* Space is mount-wide; FUSE may pass a path that no longer exists. */
    UNUSED(path);
    return super_statfs(st);
}
