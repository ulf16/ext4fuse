/* SPDX-License-Identifier: GPL-2.0-only
 * Only the private offline reader-server links this variant. Its attach and
 * refresh gates validate the legacy orphan list before invoking super_fill.
 * Production/read-only reader builds retain the nonempty-orphan rejection.
 */
#define EXT4_EXPERIMENTAL_SESSION_ORPHANS 1
#include "../../super.c"
