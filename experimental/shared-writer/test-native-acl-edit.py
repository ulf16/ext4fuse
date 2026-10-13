#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Portable native editing model, exhaustive classes and fail-closed limits."""
import argparse,errno,json,random,struct
from pathlib import Path
import native_acl as n
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args();checks=0
U=2**32-1
def check(x):
 global checks
 assert x;checks+=1
def fail(fn,code=errno.EOPNOTSUPP):
 try:fn()
 except OSError as e:check(e.errno==code)
 else:raise AssertionError('unrepresentable ACL accepted')
def resolve(group,ident):return bytes([2 if group else 1])+bytes(11)+struct.pack('>I',ident)
def identify(uuid):
 if uuid[:12] not in (bytes([1])+bytes(11),bytes([2])+bytes(11)):n.fail(detail='unknown test UUID')
 return uuid[0]==2,struct.unpack_from('>I',uuid,12)[0]
def acl(entries):return struct.pack('<I',2)+b''.join(struct.pack('<HHI',*e) for e in entries)
def blob(aces,flags=0):return struct.pack('>I',0x012cc16d)+bytes(32)+struct.pack('>II',len(aces),flags)+b''.join(uuid+struct.pack('>II',kind,bits) for uuid,kind,bits in aces)
def posix_right(raw,mode,uid,groups,want):
 entries=n.posix(raw)
 if uid==100:return (mode>>6)&want==want
 mask=next((p for t,p,_ in entries if t==16),7)
 named=next((p for t,p,i in entries if t==2 and i==uid),None)
 if named is not None:return named&mask&want==want
 perms=[p for t,p,i in entries if t==4 and 200 in groups or t==8 and i in groups]
 return any(p&mask&want==want for p in perms) if perms else entries[-1][1]&want==want
check(n.rights(2)==36);check(not n.DATA&16)
fail(lambda:n.decode(blob([(resolve(False,101),1,16)]),0o600,100,200,identify))
rng=random.Random(215)
for i in range(256):
 owner,mask,other=[rng.randrange(8) for _ in range(3)];base=rng.randrange(8)&mask
 # Nested group permissions guarantee ordered native union cannot widen a
 # combined request beyond one POSIX group; named users may have any mask.
 upper=base|(rng.randrange(8)&mask)
 entries=[(1,owner,U),(2,rng.randrange(8),101),(2,rng.randrange(8),102),(4,base,U),(8,upper,201),(16,mask,U),(32,other,U)]
 raw=acl(entries);mode=(0o040000 if i%2 else 0o100000)|owner<<6|mask<<3|other;native=n.render(raw,mode,resolve);converted=n.decode(native,mode,100,200,identify);check(converted is not None)
 e=n.posix(converted);newmode=e[0][1]<<6|next((p for t,p,_ in e if t==16),next(p for t,p,_ in e if t==4))<<3|e[-1][1]
 for uid in (100,101,102,999):
  for membership in ([],[200],[201],[200,201]):
   for want in range(1,8):check(posix_right(raw,mode,uid,membership,want)==posix_right(converted,newmode,uid,membership,want))
 # Adding a no-op metadata scaffold position must not affect data decisions.
 check(n.decode(blob([(n.EVERYBODY,1,n.META)]+[(native[j:j+16],*struct.unpack_from('>II',native,j+16)) for j in range(44,len(native),24)]),mode,100,200,identify)==converted)
read_user=blob([(resolve(False,101),1,2)])
raw=n.decode(read_user,0o600,100,200,identify);check((2,4,101) in n.posix(raw))
# Inserting at position zero, as chmod +a does, extends that named user's grant.
projected=n.render(raw,0o640,resolve)
edited=blob([(resolve(False,101),1,4|32)]+[(projected[j:j+16],*struct.unpack_from('>II',projected,j+16)) for j in range(44,len(projected),24)])
check((2,6,101) in n.posix(n.decode(edited,0o640,100,200,identify)))
# A named deny can be represented if it selects a stable complete POSIX class.
check((2,0,101) in n.posix(n.decode(blob([(resolve(False,101),2,2)]),0o644,100,200,identify)))
fail(lambda:n.decode(blob([(resolve(False,101),1,4)]),0o600,100,200,identify))
fail(lambda:n.decode(read_user,0o620,100,200,identify))
fail(lambda:n.decode(blob([(resolve(True,201),1,4|32)]),0o640,100,200,identify))
fail(lambda:n.decode(blob([(resolve(False,101),1,1<<13)]),0o600,100,200,identify))
fail(lambda:n.decode(blob([(resolve(False,101),1|(1<<5),2)]),0o600,100,200,identify))
fail(lambda:n.decode(blob([(bytes(16),1,2)]),0o600,100,200,identify))
fail(lambda:n.decode(blob([],flags=1<<16),0o600,100,200,identify))
check((2,3,101) in n.posix(n.decode(blob([(resolve(False,101),1,4|32|8|64)]),0o040700,100,200,identify)))
fail(lambda:n.decode(blob([(resolve(False,101),1,64)]),0o040700,100,200,identify))
fail(lambda:n.decode(read_user[:-1],0o600,100,200,identify),errno.EINVAL)
fail(lambda:n.decode(bytes(44),0o600,100,200,identify),errno.EINVAL)
header=bytearray(read_user);header[4]=1;fail(lambda:n.decode(bytes(header),0o600,100,200,identify))
fail(lambda:n.decode(blob([(resolve(True,300+i),1,2) for i in range(8)]),0o600,100,200,identify),errno.E2BIG)
check(n.decode(blob([]),0o600,100,200,identify) is None)
check(n.decode(struct.pack('>I',0x012cc16d)+bytes(32)+struct.pack('>II',U,0),0o600,100,200,identify) is None)
(a.work/'native-acl-edit-results.json').write_text(json.dumps(dict(result='passed',checks=checks,random_cases=256),indent=2)+'\n');print('PASS',checks,'native ACL editing equivalence checks')
