/* SPDX-License-Identifier: GPL-2.0-only */
#include "acl.h"
#include "policy.h"
#include <errno.h>
#include <stdlib.h>
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

/* Versioned numeric native template. Uniform file/directory inheritance only;
 * no UUID resolution in the producer and no reliance on POSIX mode clipping. */
#define NDATA (2 | 4 | 8 | 32)
static unsigned nrights(unsigned p, int dir) {
  return (p & 4 ? 2 : 0) | (p & 2 ? 36 : 0) | (p & 1 ? 8 : 0) |
         (dir && (p & 3) == 3 ? 64 : 0);
}
int policy_native_valid(const unsigned char *data, size_t n) {
  if (!data || n < 12 || memcmp(data, "NACL0001", 8))
    return EIO;
  unsigned count = le(data + 8, 4), users = 0;
  uint32_t ids[8];
  if (!count || count > 32 || n != 12 + 16 * count)
    return EIO;
  for (size_t at = 12; at < n; at += 16) {
    unsigned tag = le(data + at, 4), kind = le(data + at + 8, 4);
    uint32_t id = le(data + at + 4, 4), bits = le(data + at + 12, 4);
    if ((tag != 1 && tag != 2 && tag != 4 && tag != 32) ||
        (kind != 1 && kind != 2) || (bits & ~(NDATA | 64)) ||
        (tag == 2 ? id == UINT32_MAX : id != UINT32_MAX))
      return EIO;
    if (tag == 2) {
      unsigned i;
      for (i = 0; i < users && ids[i] != id; i++)
        ;
      if (i == users) {
        if (users == 8)
          return E2BIG;
        ids[users++] = id;
      }
    }
  }
  return 0;
}
static int native_decision(const unsigned char *data, size_t n, unsigned mode,
                           uint32_t owner, uint32_t uid, int group,
                           unsigned requested, int directory) {
  unsigned remaining = requested;
  for (size_t at = 12; at < n; at += 16) {
    unsigned tag = le(data + at, 4), kind = le(data + at + 8, 4);
    uint32_t id = le(data + at + 4, 4), bits = le(data + at + 12, 4);
    if (!directory)
      bits &= ~64U;
    if (!(tag == 32 || (tag == 1 && uid == owner) || (tag == 2 && uid == id) ||
          (tag == 4 && group)))
      continue;
    if (kind == 2 && (bits & requested))
      return 0;
    if (kind == 1) {
      remaining &= ~bits;
      if (!remaining)
        return 1;
    }
  }
  unsigned fallback = uid == owner ? mode >> 6 : group ? mode >> 3 : mode;
  return !(remaining & ~nrights(fallback & 7, directory));
}
static int native_perm(const unsigned char *data, size_t n, unsigned mode,
                       uint32_t owner, uint32_t uid, int group, int dir) {
  int r = native_decision(data, n, mode, owner, uid, group, 2, dir);
  int w = native_decision(data, n, mode, owner, uid, group, 4, dir);
  int a = native_decision(data, n, mode, owner, uid, group, 32, dir);
  int x = native_decision(data, n, mode, owner, uid, group, 8, dir);
  return w != a ? -1 : (r ? 4 : 0) | (w ? 2 : 0) | (x ? 1 : 0);
}
static void nput(unsigned char *p, uint32_t v, unsigned bytes) {
  for (unsigned i = 0; i < bytes; i++)
    p[i] = v >> (8 * i);
}
int policy_native_create(const unsigned char *data, size_t n, unsigned baseline,
                         uint32_t owner, int dir, unsigned *mode,
                         unsigned char **acl, size_t *length) {
  if (baseline > 0777 || owner == UINT32_MAX || (dir != 0 && dir != 1))
    return EINVAL;
  int error = policy_native_valid(data, n);
  if (error)
    return error;
  uint32_t users[8];
  unsigned count = 0;
  for (size_t at = 12; at < n; at += 16) {
    uint32_t id = le(data + at + 4, 4);
    if (le(data + at, 4) != 2 || id == owner ||
        !(le(data + at + 12, 4) & (NDATA | (dir ? 64 : 0))))
      continue;
    unsigned i;
    for (i = 0; i < count && users[i] != id; i++)
      ;
    if (i == count)
      users[count++] = id;
  }
  for (unsigned i = 0; i < count; i++)
    for (unsigned j = i + 1; j < count; j++)
      if (users[j] < users[i]) {
        uint32_t t = users[i];
        users[i] = users[j];
        users[j] = t;
      }
  uint32_t other = UINT32_MAX;
  int perms[11];
  perms[0] = native_perm(data, n, baseline, owner, owner, 0, dir);
  for (unsigned i = 0; i < count; i++)
    perms[i + 1] = native_perm(data, n, baseline, owner, users[i], 0, dir);
  perms[count + 1] = native_perm(data, n, baseline, owner, other, 1, dir);
  perms[count + 2] = native_perm(data, n, baseline, owner, other, 0, dir);
  for (unsigned i = 0; i < count + 3; i++)
    if (perms[i] < 0)
      return EOPNOTSUPP;
  for (unsigned i = 0; i < count + 2; i++) {
    uint32_t uid = i == 0 ? owner : i <= count ? users[i - 1] : other;
    for (int group = 0; group < 2; group++)
      for (unsigned subset = 1; subset < (dir ? 32 : 16); subset++) {
        unsigned requested = (subset & 1 ? 2 : 0) | (subset & 2 ? 4 : 0) |
                             (subset & 4 ? 32 : 0) | (subset & 8 ? 8 : 0) |
                             (subset & 16 ? 64 : 0);
        unsigned want = (subset & 1 ? 4 : 0) | (subset & 6 ? 2 : 0) |
                        (subset & 8 ? 1 : 0) | (subset & 16 ? 3 : 0);
        int perm = i <= count ? perms[i] : perms[count + (group ? 1 : 2)];
        if (native_decision(data, n, baseline, owner, uid, group, requested,
                            dir) != ((perm & want) == want))
          return EOPNOTSUPP;
      }
  }
  unsigned mask = perms[count + 1];
  for (unsigned i = 1; i <= count; i++)
    mask |= perms[i];
  *mode = (perms[0] << 6) | (mask << 3) | perms[count + 2];
  *length = 4 + 4 * (3 + (count ? 1 : 0)) + 8 * count;
  *acl = calloc(*length, 1);
  if (!*acl)
    return ENOMEM;
  nput(*acl, 1, 4);
  size_t at = 4;
  nput(*acl + at, 1, 2);
  nput(*acl + at + 2, perms[0], 2);
  at += 4;
  for (unsigned i = 0; i < count; i++) {
    nput(*acl + at, 2, 2);
    nput(*acl + at + 2, perms[i + 1], 2);
    nput(*acl + at + 4, users[i], 4);
    at += 8;
  }
  nput(*acl + at, 4, 2);
  nput(*acl + at + 2, perms[count + 1], 2);
  at += 4;
  if (count) {
    nput(*acl + at, 16, 2);
    nput(*acl + at + 2, mask, 2);
    at += 4;
  }
  nput(*acl + at, 32, 2);
  nput(*acl + at + 2, perms[count + 2], 2);
  return 0;
}
