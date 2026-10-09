/* SPDX-License-Identifier: GPL-2.0-only
 * macOS mounted-stat oracle, including birthtime nanoseconds absent from Python.
 */
#include <stdio.h>
#include <sys/stat.h>
int main(int argc, char **argv)
{
    struct stat st;
    if (argc != 2 || stat(argv[1], &st) < 0) return 1;
    printf("%lld %ld %lld %ld %lld %ld %lld %ld\n",
           (long long)st.st_atimespec.tv_sec, st.st_atimespec.tv_nsec,
           (long long)st.st_mtimespec.tv_sec, st.st_mtimespec.tv_nsec,
           (long long)st.st_ctimespec.tv_sec, st.st_ctimespec.tv_nsec,
           (long long)st.st_birthtimespec.tv_sec, st.st_birthtimespec.tv_nsec);
    return 0;
}
