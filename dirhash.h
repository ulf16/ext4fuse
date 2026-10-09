/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DIRHASH_H
#define DIRHASH_H
#include <stdint.h>
#include <stddef.h>
int directory_hash(unsigned version, const char *name, size_t length,
                   const uint32_t seed[4], uint32_t *hash);
#endif
