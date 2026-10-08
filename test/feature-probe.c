/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include "disk.h"
#include "super.h"
#include "logging.h"
int main(int argc, char **argv)
{
    if (argc != 2 || logging_open("/dev/null") < 0) return 2;
    if (disk_open(argv[1]) < 0) { perror("disk_open"); return 1; }
    if (super_fill() < 0 || super_group_fill() < 0) return 1;
    puts("PASS: feature and geometry preflight");
    return 0;
}
