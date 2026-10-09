/* SPDX-License-Identifier: GPL-2.0-only */
/* Fixture writer: debugfs -f reads only one filesystem block of input.
 * Usage: ea-set image [inode attribute value-file]... */
#include <stdio.h>
#include <stdlib.h>
#include <ext2fs/ext2fs.h>
int main(int argc, char **argv)
{
    if (argc < 5 || argc % 3 != 2) return 2;
    ext2_filsys fs = NULL;
    errcode_t err = ext2fs_open(argv[1], EXT2_FLAG_RW | EXT2_FLAG_64BITS, 0, 0,
                               unix_io_manager, &fs);
    if (!err) err = ext2fs_read_bitmaps(fs);
    for (int arg = 2; !err && arg < argc; arg += 3) {
        FILE *input = fopen(argv[arg + 2], "rb");
        if (!input || fseek(input, 0, SEEK_END)) return 2;
        long length = ftell(input);
        if (length < 0 || length > 65536 || fseek(input, 0, SEEK_SET)) return 2;
        unsigned char value[65536];
        if (fread(value, 1, length, input) != (size_t)length) return 2;
        fclose(input);
        struct ext2_xattr_handle *handle = NULL;
        err = ext2fs_xattrs_open(fs, strtoul(argv[arg], NULL, 10), &handle);
        if (!err) err = ext2fs_xattrs_read(handle);
        if (!err) err = ext2fs_xattr_set(handle, argv[arg + 1], value, length);
        if (handle) { errcode_t closed = ext2fs_xattrs_close(&handle); if (!err) err = closed; }
    }
    if (fs) { errcode_t closed = ext2fs_close(fs); if (!err) err = closed; }
    if (err) fprintf(stderr, "EA fixture writer error: %ld\n", (long)err);
    return err ? 1 : 0;
}
