/* SPDX-License-Identifier: GPL-2.0-only */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "ops.h"
#include "inode.h"
#include "super.h"
#include "disk.h"
#include "checksum.h"

#ifdef __APPLE__
#define NO_ATTRIBUTE ENOATTR
#else
#define NO_ATTRIBUTE ENODATA
#endif

/* At most one inode body and one block; ea_inode remains unsupported. */
struct attribute {
    char name[256];
    const unsigned char *value;
    size_t size;
    unsigned index;
};
struct attributes {
    unsigned char inode[4096], block[4096];
    struct attribute entries[512];
    size_t count;
};

static int parse(struct attributes *attrs, const unsigned char *raw,
                 size_t length, size_t first, size_t base, int sorted)
{
    size_t cursor = first, floor = length;
    const unsigned char *previous = NULL;
    while (1) {
        if (cursor > length || length - cursor < 4) return -EIO;
        if (!checksum_u32(raw + cursor)) { cursor += 4; break; }
        if (length - cursor < 16) return -EIO;
        const unsigned char *entry = raw + cursor;
        size_t names = entry[0], step = (16 + names + 3) & ~(size_t)3;
        unsigned index = entry[1];
        if (step > length - cursor || memchr(entry + 16, 0, names) ||
            checksum_u32(entry + 4)) return -EIO;
        size_t value = base + checksum_u16(entry + 2);
        size_t bytes = checksum_u32(entry + 8), padded = (bytes + 3) & ~(size_t)3;
        if (bytes && (bytes > length || value % 4 || value > length || padded < bytes || padded > length - value)) return -EIO;
        if (bytes && value < floor) floor = value;
        if (sorted && previous) {
            int order = (int)index - previous[1];
            if (!order) order = (int)names - previous[0];
            if (!order) order = memcmp(entry + 16, previous + 16, names);
            if (order <= 0) return -EIO;
        }
        previous = entry;
        const char *prefix = NULL;
        switch (index) {
        case 0: prefix = ""; break;
        case 1: prefix = "user."; break;
        case 2: prefix = "system.posix_acl_access"; break;
        case 3: prefix = "system.posix_acl_default"; break;
        case 4: prefix = "trusted."; break;
        case 6: prefix = "security."; break;
        case 7: prefix = "system."; break;
        case 8: prefix = "system.richacl"; break;
        }
        /* system.data holds inline file/directory contents, not public metadata.
         * Unknown namespace indices are validated but cannot be named. */
        int hidden = index == 7 && names == 4 && !memcmp(entry + 16, "data", 4);
        if (prefix && !hidden) {
            size_t prefix_size = strlen(prefix);
            if ((index == 2 || index == 3 || index == 8) ? names != 0 : names == 0)
                return -EIO;
            if (prefix_size + names > 255 || attrs->count == 512) return -EIO;
            struct attribute *attr = &attrs->entries[attrs->count];
            memcpy(attr->name, prefix, prefix_size);
            memcpy(attr->name + prefix_size, entry + 16, names);
            attr->name[prefix_size + names] = 0;
            attr->value = bytes ? raw + value : NULL;
            attr->size = bytes; attr->index = index;
            for (size_t i = 0; i < attrs->count; i++)
                if (!strcmp(attr->name, attrs->entries[i].name)) return -EIO;
            attrs->count++;
        }
        cursor += step;
    }
    return cursor > floor ? -EIO : 0;
}

static int load(const char *path, struct attributes *attrs)
{
    uint32_t number;
    struct ext4_inode inode;
    int ret = inode_lookup(path, &number);
    if (ret < 0) return ret;
    ret = inode_get_raw(number, &inode, attrs->inode);
    if (ret < 0) return ret;
    size_t length = super_inode_size();
    if (super_linux_inode_format() && length > 128) {
        size_t header = 128 + inode.i_extra_isize;
        if (length - header >= 4 && checksum_u32(attrs->inode + header)) {
            if (checksum_u32(attrs->inode + header) != 0xea020000U) return -EIO;
            ret = parse(attrs, attrs->inode, length, header + 4, header + 4, 0);
            if (ret < 0) return ret;
        }
    }
    uint64_t block = inode.i_file_acl_lo;
    if (super_linux_inode_format()) block |= (uint64_t)inode.osd2.linux2.l_i_file_acl_high << 32;
    if (!block) return 0;
    if (block >= super_block_count()) return -EIO;
    ret = disk_read_exact(BLOCKS2BYTES(block), BLOCK_SIZE, attrs->block);
    if (ret < 0) return ret;
    unsigned char *raw = attrs->block;
    if (checksum_u32(raw) != 0xea020000U || !checksum_u32(raw + 4) ||
        checksum_u32(raw + 4) > 1024 || checksum_u32(raw + 8) != 1 ||
        checksum_u32(raw + 20) || checksum_u32(raw + 24) || checksum_u32(raw + 28)) return -EIO;
    if (super_metadata_csum()) {
        uint32_t supplied = checksum_u32(raw + 16);
        memset(raw + 16, 0, 4);
        uint32_t crc = checksum_crc32c(super_checksum_seed(), &block, 8);
        if (checksum_crc32c(crc, raw, BLOCK_SIZE) != supplied) return -EIO;
    }
    return parse(attrs, raw, BLOCK_SIZE, 32, 0, 1);
}

/* ext4 ACL v1 uses four-byte entries for unnamed principals; Linux xattr
 * ACL v2 uses eight bytes for every entry. Return the userspace encoding. */
static int acl_value(const struct attribute *attr, char *value, size_t size)
{
    if (attr->size < 4 || checksum_u32(attr->value) != 1) return -EIO;
    size_t cursor = 4, count = 0;
    while (cursor < attr->size) {
        if (attr->size - cursor < 4) return -EIO;
        unsigned tag = checksum_u16(attr->value + cursor);
        unsigned perm = checksum_u16(attr->value + cursor + 2);
        size_t step;
        switch (tag) {
        case 1: case 4: case 16: case 32: step = 4; break;
        case 2: case 8: step = 8; break;
        default: return -EIO;
        }
        if (perm > 7 || step > attr->size - cursor) return -EIO;
        if (step == 8 && checksum_u32(attr->value + cursor + 4) == UINT32_MAX) return -EIO;
        cursor += step; count++;
    }
    size_t needed = 4 + count * 8;
    if (!size) return needed;
    if (size < needed) return -ERANGE;
    uint32_t version = 2, undefined = UINT32_MAX;
    memcpy(value, &version, 4);
    cursor = 4;
    for (size_t i = 0; i < count; i++) {
        unsigned tag = checksum_u16(attr->value + cursor);
        size_t step = (tag == 2 || tag == 8) ? 8 : 4;
        memcpy(value + 4 + i * 8, attr->value + cursor, 4);
        memcpy(value + 8 + i * 8, step == 8 ? attr->value + cursor + 4 : (const unsigned char *)&undefined, 4);
        cursor += step;
    }
    return needed;
}

static int operation(const char *path, const char *name, char *buf, size_t size)
{
    struct attributes *attrs = calloc(1, sizeof(*attrs));
    if (!attrs) return -ENOMEM;
    int ret = load(path, attrs);
    if (ret < 0) goto done;
    for (size_t i = 0; i < attrs->count; i++) {
        const struct attribute *attr = &attrs->entries[i];
        if ((attr->index == 2 || attr->index == 3) && acl_value(attr, NULL, 0) < 0) {
            ret = -EIO; goto done;
        }
    }
    if (name) {
        ret = -NO_ATTRIBUTE;
        for (size_t i = 0; i < attrs->count; i++) {
            const struct attribute *attr = &attrs->entries[i];
            if (strcmp(name, attr->name)) continue;
            if (attr->index == 2 || attr->index == 3) ret = acl_value(attr, buf, size);
            else if (size && size < attr->size) ret = -ERANGE;
            else {
                ret = attr->size;
                if (size && ret) memcpy(buf, attr->value, ret);
            }
            break;
        }
    } else {
        size_t needed = 0;
        for (size_t i = 0; i < attrs->count; i++) needed += strlen(attrs->entries[i].name) + 1;
        ret = needed;
        if (size && size < needed) ret = -ERANGE;
        else if (size) {
            for (size_t i = 0; i < attrs->count; i++) {
                size_t bytes = strlen(attrs->entries[i].name) + 1;
                memcpy(buf, attrs->entries[i].name, bytes); buf += bytes;
            }
        }
    }
done:
    free(attrs);
    return ret;
}

int op_listxattr(const char *path, char *list, size_t size)
{
    return operation(path, NULL, list, size);
}
int op_getxattr(const char *path, const char *name, char *value, size_t size)
{
    if (!name || !*name) return -EINVAL;
    return operation(path, name, value, size);
}
