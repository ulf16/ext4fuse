#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compare producer inheritance to the native ordered-ACL proof, all BSD modes."""
import argparse,errno,json,struct,subprocess
from pathlib import Path
import native_acl as n
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args()
checks=0;cases=[];U=2**32-1
policies=[[(2,101,1,2)],[(2,101,2,n.DATA|64)],[(1,U,1,2)],[(4,U,2,n.DATA|64)],[(32,U,1,n.DATA|64)],[(2,101,1,36|8|64)],[(2,101,1,4)],[(2,101,1,64)]]
def resolve(group,ident):return bytes([2 if group else 1])+bytes(11)+struct.pack('>I',ident)
def identify(uuid):return uuid[0]==2,struct.unpack_from('>I',uuid,12)[0]
def check(v):
 global checks
 assert v;checks+=1
for entries in policies:
 policy=n.POLICY_MAGIC+struct.pack('<I',len(entries))+b''.join(struct.pack('<IIII',*e) for e in entries)
 for directory in (False,True):
  native=n.pack_native(n.policy_native(policy,resolve,isdir=directory))
  for owner in (100,101):
   for mode in range(512):
    try:expected=n.decode(native,(0o040000 if directory else 0o100000)|mode,owner,200,identify);error=0
    except OSError as e:expected=None;error=e.errno
    cases.append((policy,mode,owner,directory,expected,error))
request=''.join(f'{policy.hex()} {mode} {owner} {int(directory)}\n' for policy,mode,owner,directory,_,_ in cases)
r=subprocess.run([a.work/'native-inherit-unit'],input=request,text=True,capture_output=True,timeout=60);check(r.returncode==0)
lines=r.stdout.splitlines();check(len(lines)==len(cases))
accepted=rejected=0
for case,line in zip(cases,lines):
 policy,mode,owner,directory,expected,error=case;parts=line.split();actual=int(parts[0]);newmode=int(parts[1]);check(actual==error)
 if error:rejected+=1;continue
 accepted+=1
 packed=bytes.fromhex(parts[2]);check(struct.unpack_from('<I',packed)[0]==1)
 entries=[];at=4
 while at<len(packed):
  tag,perm=struct.unpack_from('<HH',packed,at);ident=struct.unpack_from('<I',packed,at+4)[0] if tag in (2,8) else U
  entries.append((tag,perm,ident));at+=8 if tag in (2,8) else 4
 candidate=struct.pack('<I',2)+b''.join(struct.pack('<HHI',*e) for e in entries)
 # Compare effective POSIX entries: inactive mask bits need not be preserved.
 def effective(raw):
  entries=n.posix(raw);mask=next((p for t,p,_ in entries if t==16),7)
  return [(t,p&mask if t in (2,4,8) else p,i) for t,p,i in entries if t!=16]
 assert effective(candidate)==effective(expected),(case,effective(candidate),effective(expected))
 check(True)
 check(newmode&0o700==entries[0][1]<<6 and newmode&7==entries[-1][1])
# Native flag parsing and projection, including inherit-only parent isolation.
value=n.pack_native([(resolve(False,101),1|n.BOTH|n.ONLY,2)])
access,policy=n.split(value,0o040700,100,200,identify);check(access is None)
check(n.policy_entries(policy)==[(2,101,1,2)])
projected=n.project(None,policy,0o040700,resolve)
access2,policy2=n.split(projected,0o040700,100,200,identify);check(policy2==policy)
for flags in (1|(1<<5),1|(1<<6),1|n.BOTH|(1<<7),1|n.ONLY):
 try:n.split(n.pack_native([(resolve(False,101),flags,2)]),0o040700,100,200,identify)
 except OSError as e:check(e.errno==errno.EOPNOTSUPP)
 else:raise AssertionError('unsupported propagation accepted')
(a.work/'native-inherit-results.json').write_text(json.dumps(dict(result='passed',checks=checks,cases=len(cases),accepted=accepted,rejected=rejected),indent=2)+'\n')
print('PASS',checks,'native inheritance equivalence checks;',accepted,'representable and',rejected,'rejected creation policies')
