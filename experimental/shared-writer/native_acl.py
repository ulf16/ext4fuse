# SPDX-License-Identifier: GPL-2.0-only
"""Bounded macOS access-ACL editing through an exact POSIX data-right model.

No delete/owner/security grants or opaque UUID coercion. Native
ordered decisions are checked for all referenced identity/group combinations.
"""
import ctypes
import errno
import struct
import sys
DATA=2|4|8|32
META=(1<<7)|(1<<9)|(1<<11)|(1<<20)
PREFIX=bytes.fromhex('abcdefabcdefabcdefabcdef')
OWNER=PREFIX+struct.pack('>I',10)
GROUP=PREFIX+struct.pack('>I',16)
EVERYBODY=PREFIX+struct.pack('>I',12)
MAX_ACE=128
MAX_USERS=32
MAX_GROUPS=8
NO_INHERIT=1<<17

def fail(code=errno.EOPNOTSUPP,detail='native ACL has no supported POSIX equivalent'):
    raise OSError(code,detail)

def rights(perm):return (2 if perm&4 else 0)|(4|32 if perm&2 else 0)|(8 if perm&1 else 0)

def posix(raw):
    if len(raw)<28 or len(raw)>65536 or (len(raw)-4)%8 or struct.unpack_from('<I',raw)[0]!=2:fail(errno.EIO,'invalid POSIX ACL')
    entries=[struct.unpack_from('<HHI',raw,i) for i in range(4,len(raw),8)]
    state=0;last=-1;named=False;mask=False
    for tag,perm,ident in entries:
        if perm>7 or (tag in (2,8) and ident==2**32-1) or (tag not in (2,8) and ident!=2**32-1):fail(errno.EIO)
        if tag==1 and state==0:state=1
        elif tag==2 and state==1 and ident>last:named=True;last=ident
        elif tag==4 and state==1:state=2;last=-1
        elif tag==8 and state==2 and ident>last:named=True;last=ident
        elif tag==16 and state==2:state=3;mask=True
        elif tag==32 and state in (2,3):state=4
        else:fail(errno.EIO)
    if state!=4 or (named and not mask):fail(errno.EIO)
    return entries

def render(raw,mode,resolve):
    entries=posix(raw);mask=next((p for t,p,_ in entries if t==16),7)
    owner=entries[0][1];group=next(p for t,p,_ in entries if t==4);other=entries[-1][1]
    if (mode&0o777)!=(owner<<6|(mask if any(t==16 for t,_,_ in entries) else group)<<3|other):fail(errno.EIO,'ACL/mode mismatch')
    groups=[p&mask for t,p,_ in entries if t in (4,8)]
    if any((a|b) not in (a,b) for a in groups for b in groups):fail(detail='mixed group grants cannot preserve combined requests')
    isdir=(mode&0o170000)==0o040000
    domain=DATA|(64 if isdir else 0)
    def access(p):return rights(p)|(64 if isdir and p&3==3 else 0)
    aces=[(EVERYBODY,1,META)]
    principals=[]
    for tag,perm,ident in entries:
        if tag==16:continue
        uuid=OWNER if tag==1 else GROUP if tag==4 else EVERYBODY if tag==32 else resolve(tag==8,ident)
        if len(uuid)!=16 or (tag in (2,8) and uuid.startswith(PREFIX)):fail(detail='reserved numeric UUID')
        if tag in (2,4,8):perm&=mask
        principals.append((tag,uuid,access(perm)))
    def add(uuid,kind,bits):
        if bits:aces.append((uuid,kind,bits))
    for tag,uuid,bits in principals:
        if tag in (1,2):add(uuid,1,bits);add(uuid,2,domain&~bits)
    for tag,uuid,bits in principals:
        if tag in (4,8):add(uuid,1,bits)
    for tag,uuid,_ in principals:
        if tag in (4,8):add(uuid,2,domain)
    add(EVERYBODY,1,access(other));add(EVERYBODY,2,domain&~access(other))
    if len(aces)>MAX_ACE:fail(errno.E2BIG)
    return struct.pack('>I',0x012cc16d)+bytes(32)+struct.pack('>II',len(aces),NO_INHERIT)+b''.join(u+struct.pack('>II',k,r) for u,k,r in aces)

def decode(blob,mode,owner,gid,identify):
    if len(blob)<44 or len(blob)>44+24*MAX_ACE:fail(errno.EINVAL,'native ACL length')
    magic=struct.unpack_from('>I',blob)[0];count,flags=struct.unpack_from('>II',blob,36)
    if magic!=0x012cc16d:fail(errno.EINVAL,'native ACL magic')
    if any(blob[4:36]):fail(detail='ACL header cannot change inode owner/group UUIDs')
    if flags not in (0,NO_INHERIT):fail(detail='native ACL inheritance flags')
    if count==2**32-1:
        if len(blob)!=44:fail(errno.EINVAL)
        return None
    if count>MAX_ACE or len(blob)!=44+count*24:fail(errno.EINVAL,'native ACE count')
    if not count:return None
    isdir=(mode&0o170000)==0o040000
    domain=DATA|(64 if isdir else 0)
    aces=[];users=set();groups={gid};uids={}
    for at in range(44,len(blob),24):
        uuid=blob[at:at+16];kind,bits=struct.unpack_from('>II',blob,at+16)
        if kind not in (1,2):fail(detail='inherited or unsupported native ACE flags')
        if uuid==EVERYBODY and kind==1 and bits==META:continue
        if bits&~domain:fail(detail='native metadata/delete/generic rights are not POSIX data permissions')
        if not bits:continue
        if uuid==OWNER:principal=('uid',owner)
        elif uuid==GROUP:principal=('gid',gid)
        elif uuid==EVERYBODY:principal=('all',0)
        elif uuid.startswith(PREFIX):fail(detail='unsupported reserved UUID')
        else:
            if uuid not in uids:uids[uuid]=identify(uuid)
            isgroup,ident=uids[uuid]
            if type(isgroup) is not bool or type(ident) is not int or not 0<=ident<2**32-1:fail(detail='unresolved native UUID')
            principal=('gid' if isgroup else 'uid',ident)
        if principal[0]=='uid' and principal[1]!=owner:users.add(principal[1])
        if principal[0]=='gid':groups.add(principal[1])
        aces.append((principal,kind,bits))
    users=sorted(users);groups=[gid]+sorted(groups-{gid})
    if len(users)>MAX_USERS or len(groups)>MAX_GROUPS:fail(errno.E2BIG,'ACL identity proof bound')
    groupbit={g:1<<i for i,g in enumerate(groups)}
    def apple(uid,membership,requested):
        remaining=requested
        for (tag,ident),kind,bits in aces:
            if tag!='all' and not (tag=='uid' and uid==ident or tag=='gid' and membership&groupbit[ident]):continue
            if kind==2 and bits&requested:return False
            if kind==1:
                remaining&=~bits
                if not remaining:return True
        fallback=(mode>>6)&7 if uid==owner else (mode>>3)&7 if membership&1 else mode&7
        return not remaining&~(rights(fallback)|(64 if isdir and fallback&3==3 else 0))
    def perm(uid,membership):
        r=apple(uid,membership,2);w=apple(uid,membership,4);append=apple(uid,membership,32);x=apple(uid,membership,8)
        if w!=append:fail(detail='write and append rights must agree')
        return (4 if r else 0)|(2 if w else 0)|(1 if x else 0)
    ownerperm=perm(owner,0);userperm={u:perm(u,0) for u in users}
    groupperm={g:perm(None,groupbit[g]) for g in groups};otherperm=perm(None,0)
    def linux(uid,membership,want):
        if uid==owner:return ownerperm&want==want
        if uid in userperm:return userperm[uid]&want==want
        matched=[groupperm[g] for g in groups if membership&groupbit[g]]
        return any(p&want==want for p in matched) if matched else otherperm&want==want
    # Exhaustive over every relevant identity and group-membership equivalence
    # class, plus every combination of read/write/append/execute. No sampling.
    for uid in [owner,*users,None]:
        for membership in range(1<<len(groups)):
            for subset in range(1,32 if isdir else 16):
                requested=(2 if subset&1 else 0)|(4 if subset&2 else 0)|(32 if subset&4 else 0)|(8 if subset&8 else 0)|(64 if subset&16 else 0)
                want=(4 if subset&1 else 0)|(2 if subset&6 else 0)|(1 if subset&8 else 0)|(3 if subset&16 else 0)
                if apple(uid,membership,requested)!=linux(uid,membership,want):fail(detail='ordered/group-combination behavior is not representable')
    mask=(mode>>3)&7
    for p in [*userperm.values(),*groupperm.values()]:mask|=p
    entries=[(1,ownerperm,2**32-1),*[(2,userperm[u],u) for u in users],(4,groupperm[gid],2**32-1),*[(8,groupperm[g],g) for g in sorted(groups[1:])]]
    if users or len(groups)>1:entries.append((16,mask,2**32-1))
    entries.append((32,otherperm,2**32-1))
    return struct.pack('<I',2)+b''.join(struct.pack('<HHI',*e) for e in entries)

class Membership:
    def __init__(self):
        if sys.platform!='darwin':fail(detail='native membership requires macOS')
        self.lib=ctypes.CDLL(None,use_errno=True)
        self.lib.mbr_uid_to_uuid.argtypes=[ctypes.c_uint32,ctypes.c_void_p]
        self.lib.mbr_gid_to_uuid.argtypes=[ctypes.c_uint32,ctypes.c_void_p]
        self.lib.mbr_uuid_to_id.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_int)]
        for name in ('mbr_uid_to_uuid','mbr_gid_to_uuid','mbr_uuid_to_id'):getattr(self.lib,name).restype=ctypes.c_int
    def resolve(self,group,ident):
        out=ctypes.create_string_buffer(16);result=(self.lib.mbr_gid_to_uuid if group else self.lib.mbr_uid_to_uuid)(ident,out)
        if result:fail(errno.EOPNOTSUPP,'numeric identity has no native UUID')
        return out.raw
    def identify(self,uuid):
        raw=ctypes.create_string_buffer(uuid);ident=ctypes.c_uint32();kind=ctypes.c_int()
        result=self.lib.mbr_uuid_to_id(raw,ctypes.byref(ident),ctypes.byref(kind))
        if result or kind.value not in (0,1):fail(detail='unknown native UUID identity')
        group=kind.value==1
        if self.resolve(group,ident.value)!=uuid:fail(detail='native UUID identity does not round-trip')
        return group,ident.value

# Native inheritance is not a POSIX default ACL: macOS grants survive creation
# mode clipping. Persist numeric ordered rules and evaluate at child creation.
INHERIT_KEY='user.ext4fuse.native_inherit'
INHERITED=1<<4
BOTH=(1<<5)|(1<<6)
ONLY=1<<8
POLICY_MAGIC=b'NACL0001'

def pack_native(aces,flags=NO_INHERIT):
    if len(aces)>MAX_ACE:fail(errno.E2BIG)
    return struct.pack('>I',0x012cc16d)+bytes(32)+struct.pack('>II',len(aces),flags)+b''.join(u+struct.pack('>II',k,r) for u,k,r in aces)

def unpack_native(value):
    # Reuse all header/length checks before considering inheritance flags.
    if len(value)<44:fail(errno.EINVAL)
    count,flags=struct.unpack_from('>II',value,36)
    if count==2**32-1:count=0
    if count>MAX_ACE or len(value)!=44+24*count:fail(errno.EINVAL)
    decode(value[:36]+struct.pack('>II',0,flags),0,0,0,lambda _:None)
    return [(value[i:i+16],*struct.unpack_from('>II',value,i+16)) for i in range(44,len(value),24)]

def policy_entries(value):
    if len(value)<12 or value[:8]!=POLICY_MAGIC:fail(errno.EIO,'invalid native inheritance policy')
    count=struct.unpack_from('<I',value,8)[0]
    if not 1<=count<=32 or len(value)!=12+16*count:fail(errno.EIO)
    entries=[struct.unpack_from('<IIII',value,i) for i in range(12,len(value),16)]
    users=set()
    for tag,ident,kind,bits in entries:
        if tag not in (1,2,4,32) or kind not in (1,2) or bits&~(DATA|64):fail(errno.EIO)
        if (tag!=2 and ident!=2**32-1) or (tag==2 and ident==2**32-1):fail(errno.EIO)
        if tag==2:users.add(ident)
    if len(users)>8:fail(errno.E2BIG)
    return entries

def policy_native(value,resolve,inherit=False,isdir=True):
    aces=[]
    for tag,ident,kind,bits in policy_entries(value):
        uuid=OWNER if tag==1 else GROUP if tag==4 else EVERYBODY if tag==32 else resolve(False,ident)
        if not isdir:bits&=~64
        aces.append((uuid,kind|(BOTH|ONLY if inherit else 0),bits))
    return aces

def split(value,mode,owner,gid,identify):
    active=[];template=[]
    isdir=(mode&0o170000)==0o040000
    for uuid,flags,bits in unpack_native(value):
        kind=flags&15
        controls=flags&~(15|INHERITED)
        if kind not in (1,2) or controls not in (0,BOTH,BOTH|ONLY):fail(detail='selective/limited inheritance is unsupported')
        if controls and not isdir:fail(detail='inheritance requires a directory')
        if not controls&ONLY:active.append((uuid,kind,bits))
        if controls&BOTH:
            if uuid==EVERYBODY and kind==1 and bits==META:continue
            if bits&~(DATA|64):fail(detail='unsupported inheritance rights')
            if uuid==OWNER:tag,ident=1,2**32-1
            elif uuid==GROUP:tag,ident=4,2**32-1
            elif uuid==EVERYBODY:tag,ident=32,2**32-1
            else:
                if uuid.startswith(PREFIX):fail()
                group,ident=identify(uuid)
                if type(group) is not bool or type(ident) is not int or not 0<=ident<2**32-1:fail(detail="unresolved native UUID")
                if group:fail(detail='named-group inheritance is not yet supported')
                tag=2
            template.append((tag,ident,kind,bits))
    access=decode(pack_native(active),mode,owner,gid,identify)
    policy=None
    if template:
        if len(template)>32:fail(errno.E2BIG,"inheritance ACE bound")
        policy=POLICY_MAGIC+struct.pack('<I',len(template))+b''.join(struct.pack('<IIII',*e) for e in template)
        policy_entries(policy)
        # Validate the template against an empty BSD fallback. The producer
        # proves the complete combined policy for the actual creation mode,
        # umask and child ownership before allocating an inode. Some unusual
        # creation modes cannot represent native group-dependent decisions.
        generic=next(i for i in range(2**32-2,2**32-12,-1) if all(t!=2 or ident!=i for t,ident,_,_ in template))
        numeric=lambda group,ident:bytes([2 if group else 1])+bytes(11)+struct.pack('>I',ident)
        inverse=lambda uuid:(uuid[0]==2,struct.unpack_from('>I',uuid,12)[0])
        for directory in (False,True):
            native=pack_native(policy_native(policy,numeric,isdir=directory))
            decode(native,0o040000 if directory else 0o100000,generic,200,inverse)
    return access,policy

def project(access,policy,mode,resolve):
    aces=unpack_native(render(access,mode,resolve)) if access is not None else [(EVERYBODY,1,META)] if policy is not None else []
    if policy is not None:
        if (mode&0o170000)!=0o040000:fail(errno.EIO,"inheritance policy on non-directory")
        aces+=policy_native(policy,resolve,inherit=True)
    if not aces:fail(errno.ENODATA,'native ACL missing')
    return pack_native(aces)
