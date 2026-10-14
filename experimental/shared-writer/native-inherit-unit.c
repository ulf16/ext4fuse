/* SPDX-License-Identifier: GPL-2.0-only */
/* Streaming oracle adapter for Python/C inheritance equivalence checks. */
#include "policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
  char hex[1320];
  unsigned baseline, owner, gid, directory;
  while (scanf("%1319s %u %u %u %u", hex, &baseline, &owner, &gid,
               &directory) == 5) {
    size_t n = strlen(hex);
    unsigned char data[660], *acl = NULL;
    size_t length = 0;
    if (n % 2 || n / 2 > sizeof(data))
      return 2;
    for (size_t i = 0; i < n / 2; i++) {
      unsigned v;
      if (sscanf(hex + i * 2, "%2x", &v) != 1)
        return 2;
      data[i] = v;
    }
    unsigned mode = 0;
    int e = policy_native_create(data, n / 2, baseline, owner, gid, directory,
                                 &mode, &acl, &length);
    printf("%d %u ", e, mode);
    for (size_t i = 0; !e && i < length; i++)
      printf("%02x", acl[i]);
    puts("");
    free(acl);
  }
  return ferror(stdin) ? 2 : 0;
}
