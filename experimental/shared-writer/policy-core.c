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

/* Numeric policies v1 (uniform) and v2 (per-entry propagation). */
#define NDATA (2 | 4 | 8 | 32)
#define NFILE 32
#define NDIR 64
#define NLIMIT 128
struct native_ace {
  unsigned tag, kind, bits, flags;
  uint32_t id;
};
struct native_policy {
  unsigned count;
  struct native_ace ace[32];
};
static unsigned nrights(unsigned p, int dir) {
  return (p & 4 ? 2 : 0) | (p & 2 ? 36 : 0) | (p & 1 ? 8 : 0) |
         (dir && (p & 3) == 3 ? 64 : 0);
}
static void nput(unsigned char *p, uint32_t v, unsigned n) {
  for (unsigned i = 0; i < n; i++)
    p[i] = v >> (8 * i);
}
static int native_parse(const unsigned char *data, size_t n,
                        struct native_policy *out) {
  if (!data || n < 12)
    return EIO;
  unsigned stride = !memcmp(data, "NACL0001", 8)   ? 16
                    : !memcmp(data, "NACL0002", 8) ? 20
                                                   : 0;
  unsigned count = le(data + 8, 4), nu = 0, ng = 0;
  uint32_t users[8], groups[7];
  if (!stride || !count || count > 32 || n != 12 + stride * count)
    return EIO;
  out->count = count;
  for (unsigned i = 0; i < count; i++) {
    const unsigned char *p = data + 12 + stride * i;
    struct native_ace *a = &out->ace[i];
    *a = (struct native_ace){.tag = le(p, 4),
                             .id = le(p + 4, 4),
                             .kind = le(p + 8, 4),
                             .bits = le(p + 12, 4),
                             .flags =
                                 stride == 16 ? NFILE | NDIR : le(p + 16, 4)};
    if ((a->tag != 1 && a->tag != 2 && a->tag != 4 && a->tag != 8 &&
         a->tag != 32) ||
        (a->kind != 1 && a->kind != 2) || (a->bits & ~(NDATA | 64)) ||
        ((a->tag == 2 || a->tag == 8) ? a->id == UINT32_MAX
                                      : a->id != UINT32_MAX) ||
        (a->flags & ~(NFILE | NDIR | NLIMIT)) || !(a->flags & (NFILE | NDIR)))
      return EIO;
    if (a->tag == 2 || a->tag == 8) {
      uint32_t *ids = a->tag == 2 ? users : groups;
      unsigned *num = a->tag == 2 ? &nu : &ng;
      unsigned j;
      for (j = 0; j < *num && ids[j] != a->id; j++)
        ;
      if (j == *num) {
        if (*num == (a->tag == 2 ? 8 : 7))
          return E2BIG;
        ids[(*num)++] = a->id;
      }
    }
  }
  return 0;
}
int policy_native_valid(const unsigned char *data, size_t n) {
  struct native_policy p;
  return native_parse(data, n, &p);
}
int policy_native_child(const unsigned char *data, size_t n,
                        unsigned char **out, size_t *length) {
  *out = NULL;
  *length = 0;
  struct native_policy p;
  int e = native_parse(data, n, &p);
  if (e)
    return e;
  unsigned count = 0;
  for (unsigned i = 0; i < p.count; i++)
    if ((p.ace[i].flags & NDIR) && !(p.ace[i].flags & NLIMIT))
      count++;
  if (!count)
    return 0;
  *length = 12 + 20 * count;
  *out = calloc(*length, 1);
  if (!*out)
    return ENOMEM;
  memcpy(*out, "NACL0002", 8);
  nput(*out + 8, count, 4);
  size_t at = 12;
  for (unsigned i = 0; i < p.count; i++) {
    struct native_ace *a = &p.ace[i];
    if (!(a->flags & NDIR) || (a->flags & NLIMIT))
      continue;
    nput(*out + at, a->tag, 4);
    nput(*out + at + 4, a->id, 4);
    nput(*out + at + 8, a->kind, 4);
    nput(*out + at + 12, a->bits, 4);
    nput(*out + at + 16, a->flags, 4);
    at += 20;
  }
  return 0;
}
static void sort_ids(uint32_t *ids, unsigned n) {
  for (unsigned i = 0; i < n; i++)
    for (unsigned j = i + 1; j < n; j++)
      if (ids[j] < ids[i]) {
        uint32_t t = ids[i];
        ids[i] = ids[j];
        ids[j] = t;
      }
}
static unsigned group_index(const uint32_t *groups, unsigned count,
                            uint32_t gid) {
  for (unsigned i = 0; i < count; i++)
    if (groups[i] == gid)
      return i;
  return count;
}
static int native_decision(const struct native_policy *p, unsigned mode,
                           uint32_t owner, uint32_t uid, unsigned membership,
                           const uint32_t *groups, unsigned ng,
                           unsigned requested, int dir) {
  unsigned remaining = requested;
  for (unsigned i = 0; i < p->count; i++) {
    const struct native_ace *a = &p->ace[i];
    if (!(a->flags & (dir ? NDIR : NFILE)))
      continue;
    unsigned bits = a->bits & (NDATA | (dir ? 64 : 0));
    unsigned gi = a->tag == 8 ? group_index(groups, ng, a->id) : 0;
    if (!(a->tag == 32 || (a->tag == 1 && uid == owner) ||
          (a->tag == 2 && uid == a->id) ||
          ((a->tag == 4 || a->tag == 8) && gi < ng &&
           (membership & (1U << gi)))))
      continue;
    if (a->kind == 2 && (bits & requested))
      return 0;
    if (a->kind == 1) {
      remaining &= ~bits;
      if (!remaining)
        return 1;
    }
  }
  unsigned fallback = uid == owner     ? mode >> 6
                      : membership & 1 ? mode >> 3
                                       : mode;
  return !(remaining & ~nrights(fallback & 7, dir));
}
static int native_perm(const struct native_policy *p, unsigned mode,
                       uint32_t owner, uint32_t uid, unsigned membership,
                       const uint32_t *groups, unsigned ng, int dir) {
  int r = native_decision(p, mode, owner, uid, membership, groups, ng, 2, dir);
  int w = native_decision(p, mode, owner, uid, membership, groups, ng, 4, dir);
  int a = native_decision(p, mode, owner, uid, membership, groups, ng, 32, dir);
  int x = native_decision(p, mode, owner, uid, membership, groups, ng, 8, dir);
  return w != a ? -1 : (r ? 4 : 0) | (w ? 2 : 0) | (x ? 1 : 0);
}
int policy_native_create(const unsigned char *data, size_t n, unsigned baseline,
                         uint32_t owner, uint32_t gid, int dir, unsigned *mode,
                         unsigned char **acl, size_t *length) {
  *acl = NULL;
  *length = 0;
  if (baseline > 0777 || owner == UINT32_MAX || gid == UINT32_MAX ||
      (dir != 0 && dir != 1))
    return EINVAL;
  struct native_policy p;
  int e = native_parse(data, n, &p);
  if (e)
    return e;
  uint32_t users[8], groups[8] = {gid};
  unsigned nu = 0, ng = 1, applicable = 0;
  for (unsigned i = 0; i < p.count; i++) {
    struct native_ace *a = &p.ace[i];
    if (!(a->flags & (dir ? NDIR : NFILE)))
      continue;
    if (!(a->bits & (NDATA | (dir ? 64 : 0))))
      continue;
    applicable++;
    if (a->tag == 2 && a->id != owner) {
      unsigned j;
      for (j = 0; j < nu && users[j] != a->id; j++)
        ;
      if (j == nu)
        users[nu++] = a->id;
    }
    if (a->tag == 8 && group_index(groups, ng, a->id) == ng)
      groups[ng++] = a->id;
  }
  if (!applicable) {
    *mode = baseline;
    return 0;
  }
  sort_ids(users, nu);
  sort_ids(groups + 1, ng - 1);
  int up[9], gp[8], other;
  up[0] = native_perm(&p, baseline, owner, owner, 0, groups, ng, dir);
  for (unsigned i = 0; i < nu; i++)
    up[i + 1] = native_perm(&p, baseline, owner, users[i], 0, groups, ng, dir);
  for (unsigned i = 0; i < ng; i++)
    gp[i] =
        native_perm(&p, baseline, owner, UINT32_MAX, 1U << i, groups, ng, dir);
  other = native_perm(&p, baseline, owner, UINT32_MAX, 0, groups, ng, dir);
  if (other < 0)
    return EOPNOTSUPP;
  for (unsigned i = 0; i <= nu; i++)
    if (up[i] < 0)
      return EOPNOTSUPP;
  for (unsigned i = 0; i < ng; i++)
    if (gp[i] < 0)
      return EOPNOTSUPP;
  for (unsigned actor = 0; actor < nu + 2; actor++) {
    uint32_t uid = actor == 0    ? owner
                   : actor <= nu ? users[actor - 1]
                                 : UINT32_MAX;
    for (unsigned membership = 0; membership < (1U << ng); membership++)
      for (unsigned subset = 1; subset < (dir ? 32 : 16); subset++) {
        unsigned requested = (subset & 1 ? 2 : 0) | (subset & 2 ? 4 : 0) |
                             (subset & 4 ? 32 : 0) | (subset & 8 ? 8 : 0) |
                             (subset & 16 ? 64 : 0);
        unsigned want = (subset & 1 ? 4 : 0) | (subset & 6 ? 2 : 0) |
                        (subset & 8 ? 1 : 0) | (subset & 16 ? 3 : 0);
        int posix = actor <= nu   ? (up[actor] & want) == want
                    : !membership ? (other & want) == want
                                  : 0;
        if (actor > nu && membership)
          for (unsigned g = 0; g < ng; g++)
            if ((membership & (1U << g)) && (gp[g] & want) == want)
              posix = 1;
        if (native_decision(&p, baseline, owner, uid, membership, groups, ng,
                            requested, dir) != posix)
          return EOPNOTSUPP;
      }
  }
  unsigned mask = 0;
  for (unsigned i = 0; i < ng; i++)
    mask |= gp[i];
  for (unsigned i = 1; i <= nu; i++)
    mask |= up[i];
  *mode = (up[0] << 6) | (mask << 3) | other;
  int extended = nu || ng > 1;
  *length = 16 + (extended ? 4 : 0) + 8 * (nu + ng - 1);
  *acl = calloc(*length, 1);
  if (!*acl)
    return ENOMEM;
  nput(*acl, 1, 4);
  size_t at = 4;
  nput(*acl + at, 1, 2);
  nput(*acl + at + 2, up[0], 2);
  at += 4;
  for (unsigned i = 0; i < nu; i++) {
    nput(*acl + at, 2, 2);
    nput(*acl + at + 2, up[i + 1], 2);
    nput(*acl + at + 4, users[i], 4);
    at += 8;
  }
  nput(*acl + at, 4, 2);
  nput(*acl + at + 2, gp[0], 2);
  at += 4;
  for (unsigned i = 1; i < ng; i++) {
    nput(*acl + at, 8, 2);
    nput(*acl + at + 2, gp[i], 2);
    nput(*acl + at + 4, groups[i], 4);
    at += 8;
  }
  if (extended) {
    nput(*acl + at, 16, 2);
    nput(*acl + at + 2, mask, 2);
    at += 4;
  }
  nput(*acl + at, 32, 2);
  nput(*acl + at + 2, other, 2);
  return 0;
}
