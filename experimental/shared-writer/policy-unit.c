/* SPDX-License-Identifier: GPL-2.0-only */
#include "policy.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
static unsigned long checks;
static void put(unsigned char *p, uint32_t v, unsigned n) {
  for (unsigned i = 0; i < n; i++)
    p[i] = v >> (8 * i);
}
static size_t entry(unsigned char *acl, size_t at, unsigned tag, unsigned perm,
                    unsigned id) {
  put(acl + at, tag, 2);
  put(acl + at + 2, perm, 2);
  if (tag == 2 || tag == 8) {
    put(acl + at + 4, id, 4);
    return at + 8;
  }
  return at + 4;
}
static size_t extended(unsigned char *acl, const unsigned *p) {
  put(acl, 1, 4);
  size_t n = 4;
  n = entry(acl, n, 1, p[0], 0);
  n = entry(acl, n, 2, p[1], 101);
  n = entry(acl, n, 2, p[2], 102);
  n = entry(acl, n, 4, p[3], 0);
  n = entry(acl, n, 8, p[4], 201);
  n = entry(acl, n, 8, p[5], 202);
  n = entry(acl, n, 16, p[6], 0);
  return entry(acl, n, 32, p[7], 0);
}
int main(void) {
  struct credentials c = {.gid = 999};
  unsigned char acl[64], copy[64], expected[64];
  uint32_t random = 29421;
  const unsigned actors[] = {100, 101, 102, 999, 0};
  for (unsigned sample = 0; sample < 512; sample++) {
    unsigned perms[8];
    for (unsigned i = 0; i < 8; i++) {
      random = random * 1664525 + 1013904223;
      perms[i] = (random >> 16) & 7;
    }
    size_t n = extended(acl, perms);
    unsigned mode = perms[0] << 6 | perms[6] << 3 | perms[7];
    for (unsigned actor = 0; actor < 5; actor++) {
      c.uid = actors[actor];
      for (unsigned groups = 0; groups < 8; groups++) {
        c.ngroups = 0;
        for (unsigned i = 0; i < 3; i++)
          if (groups & (1U << i))
            c.groups[c.ngroups++] = 200 + i;
        for (unsigned want = 0; want < 8; want++) {
          int allowed;
          if (!c.uid)
            allowed = 1;
          else if (c.uid == 100)
            allowed = (perms[0] & want) == want;
          else if (c.uid == 101 || c.uid == 102)
            allowed = (perms[c.uid - 100] & perms[6] & want) == want;
          else if (groups) {
            allowed = 0;
            for (unsigned i = 0; i < 3; i++)
              if ((groups & (1U << i)) &&
                  (perms[3 + i] & perms[6] & want) == want)
                allowed = 1;
          } else
            allowed = (perms[7] & want) == want;
          assert(policy_acl(acl, n, mode, 100, 200, &c, want) ==
                 (allowed ? 0 : EACCES));
          checks++;
        }
      }
    }
    if (sample < 8)
      for (unsigned requested = 0; requested < 512; requested++) {
        memcpy(copy, acl, n);
        memcpy(expected, acl, n);
        unsigned next[8];
        memcpy(next, perms, sizeof(next));
        next[0] &= requested >> 6;
        next[6] &= (requested >> 3) & 7;
        next[7] &= requested & 7;
        extended(expected, next);
        unsigned resulting;
        assert(!policy_inherit(copy, n, requested, &resulting));
        checks++;
        assert(resulting == (next[0] << 6 | next[6] << 3 | next[7]) &&
               !memcmp(copy, expected, n));
        checks++;
      }
  }
  for (unsigned mode = 0; mode < 512; mode++)
    for (unsigned actor = 0; actor < 5; actor++) {
      c.uid = actors[actor];
      c.ngroups = 0;
      for (unsigned group = 0; group < 2; group++) {
        c.gid = group ? 200 : 999;
        for (unsigned want = 0; want < 8; want++) {
          unsigned p = actor == 0 ? mode >> 6 : group ? mode >> 3 : mode;
          int allowed = !c.uid || (p & want) == want;
          assert(policy_acl(NULL, 0, mode, 100, 200, &c, want) ==
                 (allowed ? 0 : EACCES));
          checks++;
        }
      }
    }
  unsigned perms[8] = {6, 0, 7, 1, 2, 4, 7, 7};
  size_t n = extended(acl, perms);
  c = (struct credentials){
      .uid = 999, .gid = 999, .ngroups = 2, .groups = {200, 201}};
  assert(policy_acl(acl, n, 0677, 100, 200, &c, 3) == EACCES);
  checks++; /* cannot union w+x */
  c.uid = 101;
  assert(policy_acl(acl, n, 0677, 100, 200, &c, 4) == EACCES);
  checks++; /* named denial dominates other */
  c.uid = 0;
  for (size_t bytes = 0; bytes < n; bytes++) {
    assert(policy_acl(acl, bytes, 0677, 100, 200, &c, 4) == EIO);
    checks++;
  }
  assert(policy_acl(acl, n, 0777, 100, 200, &c, 4) == EIO);
  checks++; /* root does not hide corruption */
  memcpy(copy, acl, n);
  copy[0] = 2;
  assert(policy_acl(copy, n, 0677, 100, 200, &c, 4) == EIO);
  checks++;
  c.uid = UINT32_MAX;
  assert(policy_credentials(&c) == EINVAL);
  checks++;
  c.uid = 1;
  c.ngroups = 65;
  assert(policy_credentials(&c) == EINVAL);
  checks++;
  c.ngroups = 2;
  c.groups[0] = 200;
  c.groups[1] = 200;
  assert(policy_credentials(&c) == EINVAL);
  checks++;
  unsigned char context[16] = {0};
  struct credentials decoded;
  for (unsigned bytes = 0; bytes < 16; bytes++) {
    assert(policy_decode(context, bytes, &decoded) == EINVAL);
    checks++;
  }
  put(context + 12, 65, 4);
  assert(policy_decode(context, 16, &decoded) == EINVAL);
  checks++;
  memset(context, 0, 16);
  assert(!policy_decode(context, 16, &decoded));
  checks++;
  assert(policy_decode(context, 17, &decoded) == EINVAL);
  checks++;
  printf("PASS %lu policy checks\n", checks);
  return 0;
}
