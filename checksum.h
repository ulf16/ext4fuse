/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CHECKSUM_H
#define CHECKSUM_H
#include <stdint.h>
#include <stddef.h>
uint32_t checksum_crc32c(uint32_t crc, const void *data, size_t size);
uint16_t checksum_crc16(uint16_t crc, const void *data, size_t size);
uint16_t checksum_u16(const void *p);
uint32_t checksum_u32(const void *p);
int checksum_directory(const void *block, uint32_t seed, int indexed, uint32_t logical, uint64_t directory_blocks);
#endif
