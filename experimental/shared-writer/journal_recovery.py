# SPDX-License-Identifier: GPL-2.0-only
"""Opt-in native journal replay on private candidates, never source devices."""
import contextlib,contextvars,errno,fcntl,os,re,selectors,shutil,struct,subprocess,sys,time
from pathlib import Path
import chain,inplace,merkle
from durable import boundary,digest,directory,regular,sync

def crc32c(data):
 crc=0xffffffff
 for byte in data:
  crc^=byte
  for bit in range(8):crc=(crc>>1)^(0x82f63b78 if crc&1 else 0)
 return crc

def tool(name):
 executable=shutil.which(name)
 if executable is None:raise OSError(errno.ENOENT,name+' is required for native journal recovery')
 return str(Path(executable).resolve())

_abort_fd=contextvars.ContextVar('journal_candidate_abort',default=None)

@contextlib.contextmanager
def abort_on(fd):
 token=_abort_fd.set(fd)
 try:yield
 finally:_abort_fd.reset(token)

def command(argv,env,output=None,timeout=600,pass_fds=()):
 """Bound trusted tool output as well as wall time; never accept prompts."""
 data=bytearray();deadline=time.monotonic()+timeout
 with subprocess.Popen(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,pass_fds=pass_fds) as child:
  try:
   with selectors.DefaultSelector() as poll:
    poll.register(child.stdout,selectors.EVENT_READ,'output')
    abort=_abort_fd.get()
    if abort is not None:poll.register(abort,selectors.EVENT_READ,'abort')
    while child.stdout.fileno() in poll.get_map():
     left=deadline-time.monotonic()
     if left<=0:raise OSError(errno.ETIMEDOUT,'journal recovery tool timed out')
     for key,_ in poll.select(min(left,1)):
      if key.data=='abort':
       message=os.read(key.fd,4)
       code=int.from_bytes(message,'little') if len(message)==4 else errno.EIO
       raise OSError(code if 0<code<4096 else errno.EIO,'journal candidate I/O failed; replay tool terminated')
      chunk=os.read(key.fd,8192)
      if not chunk:poll.unregister(key.fileobj);continue
      data.extend(chunk)
      if len(data)>262144:raise OSError(errno.EFBIG,'journal recovery tool output exceeded bound')
      if output is not None:output.write(chunk)
    rc=child.wait(timeout=max(.01,deadline-time.monotonic()))
  except BaseException:
   child.kill();child.wait();raise
 return rc,bytes(data)

def validate_journal(candidate,header,env):
 # Read-only debugfs resolves the journal inode through libext2fs. Reject bad
 # superblocks ourselves: preen can otherwise offer to recreate a corrupt log.
 rc,mapping=command([tool('debugfs'),'-R',f"bmap <{header['journal']}> 0",candidate],env,timeout=60)
 lines=mapping.strip().splitlines()
 if rc or not lines or not lines[-1].isdigit():raise ValueError('journal block mapping could not be verified')
 block=int(lines[-1])
 if not 0<block<header['blocks']:raise ValueError('journal superblock outside filesystem')
 with regular(candidate) as image:image.seek(block*header['block']);sb=bytearray(image.read(1024))
 if len(sb)!=1024:raise ValueError('short journal superblock')
 u32=lambda n:struct.unpack_from('>I',sb,n)[0]
 if u32(0)!=0xc03b3998 or u32(4)!=4:raise ValueError('unsupported or damaged JBD2 superblock')
 rc,details=command([tool('debugfs'),'-R',f"stat <{header['journal']}>",candidate],env,timeout=60)
 inode=re.search(rb'Type:\s+regular\b.*?Size:\s+(\d+)',details,re.S)
 length,first,start=u32(16),u32(20),u32(28)
 if rc or inode is None or int(inode[1])!=length*header['block']:
  raise ValueError('internal journal inode capacity does not match journal superblock')
 if u32(12)!=header['block'] or not 0<first<length<=header['blocks'] or (start and not first<=start<length):
  raise ValueError('invalid internal journal geometry')
 compat,incompat,ro=u32(36),u32(40),u32(44)
 if u32(32) or compat&~1 or incompat&~31 or ro or u32(64)!=1 or sb[48:64].hex()!=header['uuid']:
  raise ValueError('journal error, feature or identity outside recovery admission')
 if (incompat&24)==24 or (incompat&24 and compat&1):raise ValueError('conflicting journal checksum versions')
 if incompat&24:
  expected=u32(252);sb[252:256]=bytes(4)
  if sb[80]!=4:raise ValueError('unsupported journal checksum algorithm')
  # e2fsprogs journal.c: CRC32C(~0, the complete 1024-byte JBD2 superblock).
  crc=crc32c(sb)
  if crc!=expected:raise ValueError('journal superblock checksum mismatch')

def inspect(path,*,replayed=False):
 with regular(path) as image:
  info=os.fstat(image.fileno())
  if info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_size<=0 or info.st_size%4096:
   raise ValueError('journal candidate must be owned, singly linked and page aligned')
  image.seek(1024);sb=image.read(1024)
  if len(sb)!=1024 or sb[56:58]!=b'\x53\xef':raise ValueError('invalid primary ext4 superblock')
  u16=lambda n:struct.unpack_from('<H',sb,n)[0]
  u32=lambda n:struct.unpack_from('<I',sb,n)[0]
  compat,incompat,ro=u32(92),u32(96),u32(100)
  if ro&0x400 and crc32c(sb[:1020])!=u32(1020):raise ValueError('primary ext4 superblock checksum mismatch')
  if u32(24)>2 or u32(72)!=0:raise ValueError('unsupported journal filesystem geometry or creator')
  block=1024<<u32(24);blocks=u32(4)|((u32(336)<<32) if incompat&0x80 else 0)
  if not blocks or blocks*block>info.st_size:raise ValueError('filesystem exceeds recovery image capacity')
  # No external journal discovery or mounted/shared MMP ownership is allowed.
  if incompat&(0x8|0x100) or u32(228) or any(sb[208:224]):raise ValueError('external journals and MMP are unsupported')
  if compat&0x400:raise ValueError('fast-commit journal recovery is not admitted')
  if incompat&(0x400|0x4000|0x8000|0x10000|0x20000) or ro&(0x100|0x200|0x1000|0x2000|0x8000|0x10000):
   raise ValueError('filesystem feature profile is outside journal recovery admission')
  if u16(58)&~1:raise ValueError('filesystem records errors or unsupported recovery state')
  uuid=sb[104:120].hex()
  if not any(sb[104:120]):raise ValueError('filesystem UUID required')
  needed=bool(incompat&4)
  if needed and (not compat&4 or not 0<u32(224)<=u32(0)):
   raise ValueError('internal journal inode required for pending recovery')
  if not needed and not u16(58)&1 and not replayed:raise ValueError('unclean filesystem has no pending journal to replay')
  return dict(uuid=uuid,block=block,blocks=blocks,size=info.st_size,compat=compat,
              incompat=incompat&~4,ro=ro,journal=u32(224),needed=needed)

def replay_candidate(candidate,log):
 before=inspect(candidate)
 if not before['needed']:return before
 executable=tool('e2fsck')
 env=dict(os.environ)
 for key in list(env):
  if key.startswith(('E2FSCK_','E2FSPROGS_','JBD2_','LIBEXT2FS_')):del env[key]
 env.update(E2FSCK_CONFIG='/dev/null',LC_ALL='C')
 validate_journal(candidate,before,env)
 fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as output:
  result,_=command([executable,'-p','-E','journal_only,nodiscard',candidate],env,output)
  output.flush();sync(output.fileno())
 boundary('journal:replayed')
 if result not in (0,1):raise OSError(errno.EIO,'journal-only recovery failed; candidate log retained')
 after=inspect(candidate,replayed=True)
 if after['needed'] or {k:v for k,v in before.items() if k!='needed'}!={k:v for k,v in after.items() if k!='needed'}:
  raise OSError(errno.EIO,'journal replay changed geometry, identity or feature admission')
 # journal_only deliberately leaves an originally unclean VALID_FS bit alone.
 # A full read-only check must first prove consistency; only then may the
 # private candidate be marked clean, with the superblock checksum updated.
 audit,_=command([executable,'-fn',candidate],env)
 if audit:raise OSError(errno.EIO,'replayed filesystem still needs repair; refusing automatic repair')
 with regular(candidate) as image:
  image.seek(1082);valid=bool(int.from_bytes(image.read(2),'little')&1)
 if not valid:
  mark,_=command([tool('debugfs'),'-w','-R','set_super_value state 1',candidate],env,timeout=60)
  if mark:raise OSError(errno.EIO,'could not mark verified journal candidate clean')
 final=inspect(candidate)
 audit,_=command([executable,'-fn',candidate],env)
 if audit or final['needed'] or final['uuid']!=before['uuid']:
  raise OSError(errno.EIO,'sealed journal candidate failed read-only filesystem validation')
 with regular(candidate) as image:sync(image.fileno())
 boundary('journal:checked');return after

def producer(source):
 source=Path(source).absolute();state=chain.read_state(source.parent)
 if state['pending'] is None:raise ValueError('journal producer requires a sealed chain intent')
 generation=source.parent/f"g-{state['pending']:08d}"
 chain.inspect_tree(generation,os.stat(source.parent).st_dev)
 candidate=generation/'journal-candidate'
 with regular(source) as base:
  fcntl.flock(base,fcntl.LOCK_SH|fcntl.LOCK_NB);before=digest(base);base.seek(0)
  fd=os.open(candidate,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as copied:
   shutil.copyfileobj(base,copied,1024*1024);copied.flush();sync(copied.fileno())
  directory(generation);boundary('journal:copied')
  replay_candidate(candidate,generation/'journal-replay.log')
  if digest(base)!=before:raise ValueError('source changed while replaying journal candidate')
  with regular(candidate) as result:
   size=os.fstat(base.fileno()).st_size
   if os.fstat(result.fileno()).st_size!=size:raise ValueError('replayed candidate capacity changed')
   count=0;base.seek(0)
   for index in range(size//4096):
    if base.read(4096)!=result.read(4096):count+=1
   if count>min(merkle.MAX_RECORDS,size//4096):raise ValueError('journal replay exceeds redo record bound')
   boundary('journal:stream-ready');out=sys.stdout.buffer
   out.write(struct.pack('<8sQQ',b'E4OVL001',size,count));base.seek(0);result.seek(0)
   for index in range(size//4096):
    old,new=base.read(4096),result.read(4096)
    if old!=new:out.write(inplace.RECORD.pack(index,old,new))
   out.flush()
 with regular(source) as checked:
  if digest(checked)!=before:raise ValueError('source changed during replay stream')
 candidate.unlink();directory(generation)
 boundary('journal:streamed')

def managed_locked(root,state=None):
 root=Path(root)
 state=chain.recover_locked(root) if state is None else state
 header=inspect(root/'image.img')
 if not header['needed']:return state
 state,cache=merkle.activate(root,state)
 return chain.append_locked(root,Path(__file__).with_name('journal-producer.py'),cache)

def managed(root):
 with chain.locked(root) as root:return managed_locked(root)
