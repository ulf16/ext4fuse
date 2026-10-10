#!/usr/bin/env python3
"""Compare translated ordered Apple ACEs with Linux ACL access semantics."""
import ctypes, errno, os, pathlib, random, shlex, struct, subprocess, sys, tempfile
READ, EXEC, META = 2, 8, (1<<7)|(1<<9)|(1<<11)|(1<<20)
OWNER, GROUP, EVERYBODY = 10, 16, 12
PREFIX=bytes.fromhex('abcdefabcdefabcdefabcdef')
checks=0
with tempfile.TemporaryDirectory(prefix='ext4-native-acl-') as temp:
    library=pathlib.Path(temp)/'acl.so'
    flags=shlex.split(os.environ.get('ACL_TEST_CFLAGS','-O2'))
    subprocess.run(shlex.split(os.environ.get('CC','cc'))+flags+['-shared','-fPIC','-I.','acl.c','acl-macos.c','-o',str(library)],check=True)
    lib=ctypes.CDLL(str(library))
    RESOLVE=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(ctypes.c_ubyte))
    @RESOLVE
    def resolve(group,ident,out):
        value=bytes([2 if group else 1])+bytes(11)+struct.pack('>I',ident)
        ctypes.memmove(out,value,16);return 0
    convert=lib.ext4_acl_to_macos
    convert.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p,ctypes.c_size_t,RESOLVE]
    convert.restype=ctypes.c_int
    def compact(entries):
        return struct.pack('<I',1)+b''.join(struct.pack('<HH',t,p)+(struct.pack('<I',i) if t in (2,8) else b'') for t,p,i in entries)
    def translate(entries,mode,resolver=resolve):
        raw=compact(entries);buf=ctypes.create_string_buffer(44+128*24)
        n=convert(raw,len(raw),mode,buf,len(buf),resolver)
        return n,buf.raw[:max(0,n)]
    def applies(uuid,uid,groups):
        if uuid[:12]==PREFIX:
            code=struct.unpack('>I',uuid[12:])[0]
            return code==EVERYBODY or code==OWNER and uid==100 or code==GROUP and 200 in groups
        ident=struct.unpack('>I',uuid[12:])[0]
        return uuid[0]==1 and uid==ident or uuid[0]==2 and ident in groups
    def apple(blob,uid,groups,requested):
        magic,=struct.unpack_from('>I',blob)
        count,flags=struct.unpack_from('>II',blob,36)
        assert magic==0x012cc16d and flags==1<<17 and len(blob)==44+count*24
        remaining=requested
        for offset in range(44,len(blob),24):
            uuid=blob[offset:offset+16];kind,bits=struct.unpack_from('>II',blob,offset+16)
            if not applies(uuid,uid,groups):continue
            if kind==2 and bits&requested:return False
            if kind==1:
                remaining &= ~bits
                if not remaining:return True
        return False
    def linux(entries,mode,uid,groups,want):
        if uid==100:return mode>>6 & want == want
        if not mode&0o70:
            perm=(mode>>3)&7 if 200 in groups else mode&7
            return perm&want==want
        mask=next(p for t,p,i in entries if t==16)
        users=[p for t,p,i in entries if t==2 and i==uid]
        if users:return users[0]&mask&want==want
        matched=[p for t,p,i in entries if t==4 and 200 in groups or t==8 and i in groups]
        if matched:return any(p&mask&want==want for p in matched)
        return entries[-1][1]&want==want
    rng=random.Random(214)
    for sample in range(1024):
        owner,u1,u2,g0,g1,g2,mask,other=[rng.randrange(8) for _ in range(8)]
        entries=[(1,owner,0),(2,u1,101),(2,u2,102),(4,g0,0),(8,g1,201),(8,g2,202),(16,mask,0),(32,other,0)]
        mode=owner<<6 | mask<<3 | other
        n,blob=translate(entries,mode)
        perms={p&mask&5 for p in (g0,g1,g2)}
        if mask and 1 in perms and 4 in perms:
            assert n==-errno.EOPNOTSUPP;checks+=1;continue
        assert n>0,(entries,n)
        assert convert(compact(entries),len(compact(entries)),mode,None,0,resolve)==n;checks+=1
        small=ctypes.create_string_buffer(n-1)
        assert convert(compact(entries),len(compact(entries)),mode,small,n-1,resolve)==-errno.ERANGE;checks+=1
        for uid in (100,101,102,999):
            for bits in range(8):
                groups=[200+i for i in range(3) if bits&(1<<i)]
                for want in (1,4,5):
                    requested=(READ if want&4 else 0)|(EXEC if want&1 else 0)
                    expected=linux(entries,mode,uid,groups,want)
                    for metadata in (0,META):
                        assert apple(blob,uid,groups,requested|metadata)==expected,(entries,uid,groups,want,metadata)
                        checks+=1
                assert not apple(blob,uid,groups,4|META);checks+=1
                assert apple(blob,uid,groups,META);checks+=1
        if sys.platform=='darwin' and sample<20:
            libc=ctypes.CDLL(None,use_errno=True)
            libc.acl_copy_int.argtypes=[ctypes.c_void_p];libc.acl_copy_int.restype=ctypes.c_void_p
            libc.acl_copy_ext.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_ssize_t];libc.acl_copy_ext.restype=ctypes.c_ssize_t
            libc.acl_free.argtypes=[ctypes.c_void_p]
            source=ctypes.create_string_buffer(blob);acl=libc.acl_copy_int(source)
            assert acl,ctypes.get_errno()
            out=ctypes.create_string_buffer(len(blob))
            assert libc.acl_copy_ext(out,acl,len(blob))==len(blob) and out.raw==blob
            libc.acl_free(acl);checks+=1
    basic=[(1,4,0),(2,4,101),(4,0,0),(16,4,0),(32,0,0)]
    @RESOLVE
    def fail(group,ident,out):return errno.EIO
    assert translate(basic,0o440,fail)[0]==-errno.EIO;checks+=1
    @RESOLVE
    def reserved(group,ident,out):ctypes.memmove(out,PREFIX+struct.pack('>I',EVERYBODY),16);return 0
    assert translate(basic,0o440,reserved)[0]==-errno.EOPNOTSUPP;checks+=1
    huge=[(1,4,0)]+[(2,4,i) for i in range(100,180)]+[(4,0,0),(16,4,0),(32,0,0)]
    assert translate(huge,0o440)[0]==-errno.E2BIG;checks+=1
    broken=compact(basic)[:-1];buf=ctypes.create_string_buffer(4096)
    assert convert(broken,len(broken),0o440,buf,len(buf),resolve)==-errno.EIO;checks+=1
print(f'PASS: {checks} native ACL translation, ordering, identity, bound and Linux-semantics checks')
