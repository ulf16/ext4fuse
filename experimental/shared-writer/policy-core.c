/* SPDX-License-Identifier: GPL-2.0-only */
#include "acl.h"
#include "policy.h"
#include <errno.h>
#include <string.h>
static uint32_t le(const unsigned char *p, unsigned n) {
  uint32_t v = 0;
  for (unsigned i = 0; i < n; i++)
    v |= (uint32_t)p[i] << (8 * i);
  return v;
}
int policy_errno(errcode_t e) {
  if (!e)
    return 0;
  if (e == EXT2_ET_FILE_NOT_FOUND)
    return ENOENT;
  if (e == EXT2_ET_NO_MEMORY)
    return ENOMEM;
  if (e == EXT2_ET_BLOCK_ALLOC_FAIL || e == EXT2_ET_INODE_ALLOC_FAIL ||
      e == EXT2_ET_DIR_NO_SPACE || e == EXT2_ET_DIR_NO_SPACE_FOR_CSUM ||
      e == EXT2_ET_EA_NO_SPACE)
    return ENOSPC;
  return e > 0 && e < 4096 ? e : EIO;
}
int policy_credentials(const struct credentials *c) {
  if (!c || c->uid == UINT32_MAX || c->gid == UINT32_MAX || c->umask > 0777 ||
      c->ngroups > POLICY_GROUPS)
    return EINVAL;
  for (unsigned i = 0; i < c->ngroups; i++)
    if (c->groups[i] == UINT32_MAX || (i && c->groups[i - 1] >= c->groups[i]))
      return EINVAL;
  return 0;
}
int policy_decode(const unsigned char *data, size_t n, struct credentials *c) {
  if (n < 16 || n > 16 + 4 * POLICY_GROUPS)
    return EINVAL;
  memset(c, 0, sizeof(*c));
  c->uid = le(data, 4);
  c->gid = le(data + 4, 4);
  c->umask = le(data + 8, 4);
  c->ngroups = le(data + 12, 4);
  if (c->ngroups > POLICY_GROUPS || n != 16 + 4 * c->ngroups)
    return EINVAL;
  for (unsigned i = 0; i < c->ngroups; i++)
    c->groups[i] = le(data + 16 + 4 * i, 4);
  return policy_credentials(c);
}
int policy_group(const struct credentials *c, uint32_t gid) {
  if (c->gid == gid)
    return 1;
  for (unsigned i = 0; i < c->ngroups; i++)
    if (c->groups[i] == gid)
      return 1;
  return 0;
}
static int valid(const unsigned char *acl, size_t n) {
  if (!acl || n > POLICY_ACL_LIMIT || ext4_acl_to_xattr(acl, n, NULL, 0) < 0)
    return EIO;
  return 0;
}
int policy_acl(const unsigned char *acl, size_t n, unsigned mode, uint32_t uid,
               uint32_t gid, const struct credentials *c, unsigned want) {
  if (policy_credentials(c) || want > 7)
    return EINVAL;
  if (!acl && !n) {
    if (!c->uid)
      return 0;
    unsigned perm = c->uid == uid          ? mode >> 6
                    : policy_group(c, gid) ? mode >> 3
                                           : mode;
    return (perm & want) == want ? 0 : EACCES;
  }
  int e = valid(acl, n);
  if (e)
    return e;
  unsigned owner = 0, group = 0, other = 0, mask = 7, have_mask = 0;
  int named = -1, matched = 0, sufficient = 0;
  for (size_t p = 4; p < n;) {
    unsigned tag = le(acl + p, 2), perm = le(acl + p + 2, 2);
    uint32_t id = (tag == 2 || tag == 8) ? le(acl + p + 4, 4) : 0;
    if (tag == 1)
      owner = perm;
    if (tag == 2 && id == c->uid)
      named = perm;
    if (tag == 4)
      group = perm;
    if ((tag == 4 && policy_group(c, gid)) ||
        (tag == 8 && policy_group(c, id))) {
      matched = 1;
      if ((perm & want) == want)
        sufficient = 1;
    }
    if (tag == 16) {
      mask = perm;
      have_mask = 1;
    }
    if (tag == 32)
      other = perm;
    p += tag == 2 || tag == 8 ? 8 : 4;
  }
  /* A mismatch is corruption, never a mode-only fallback. */
  if (((mode >> 6) & 7) != owner ||
      ((mode >> 3) & 7) != (have_mask ? mask : group) || (mode & 7) != other)
    return EIO;
  if (!c->uid)
    return 0;
  if (c->uid == uid)
    return (owner & want) == want ? 0 : EACCES;
  if (named >= 0)
    return (named & mask & want) == want ? 0 : EACCES;
  /* POSIX requires one matching group to supply the complete request; do not
   * combine separate read/write/search grants from different group entries. */
  if (matched)
    return sufficient && (mask & want) == want ? 0 : EACCES;
  return (other & want) == want ? 0 : EACCES;
}
int policy_inherit(unsigned char *acl, size_t n, unsigned requested,
                   unsigned *mode) {
  if (requested > 0777)
    return EINVAL;
  int e = valid(acl, n);
  if (e)
    return e;
  int have_mask = 0;
  for (size_t p = 4; p < n;) {
    unsigned tag = le(acl + p, 2);
    if (tag == 16)
      have_mask = 1;
    p += tag == 2 || tag == 8 ? 8 : 4;
  }
  *mode = 0;
  for (size_t p = 4; p < n;) {
    unsigned tag = le(acl + p, 2), perm = le(acl + p + 2, 2);
    if (tag == 1) {
      perm &= requested >> 6;
      *mode |= perm << 6;
    }
    if (tag == 16 || (tag == 4 && !have_mask)) {
      perm &= (requested >> 3) & 7;
      *mode |= perm << 3;
    }
    if (tag == 32) {
      perm &= requested & 7;
      *mode |= perm;
    }
    acl[p + 2] = perm;
    acl[p + 3] = 0;
    p += tag == 2 || tag == 8 ? 8 : 4;
  }
  return 0;
}
