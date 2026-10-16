#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Beyond-old-boundary inode pools, large HTree enumeration and cache isolation."""
import argparse,errno,importlib.util,json,os,resource,struct,subprocess,sys,tempfile,time
from pathlib import Path
import chain,session
from credentials import Credentials
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--names',type=int,default=70000);p.add_argument('--handles',type=int,default=8192);p.add_argument('--pins',type=int,default=4200);p.add_argument('--mount',action='store_true');a=p.parse_args();checks=0;times={}
assert 65536<a.names<=100000 and 128<a.handles<=8192 and 4096<a.pins<=a.names

def check(v,detail='scaling check failed'):
 global checks
 assert v,detail;checks+=1

def run(argv):
 r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=300);check(r.returncode==0,r.stdout+r.stderr);return r.stdout

def denied(fn,code):
 try:fn()
 except OSError as e:check(e.errno==code,repr(e))
 else:raise AssertionError('unsafe scaling operation accepted')

with tempfile.TemporaryDirectory(prefix='scaling-',dir=a.work) as tmp:
 tmp=Path(tmp);image=tmp/'seed.img'
 with image.open('wb') as f:f.truncate(256*1024**2)
 run(['mke2fs','-q','-F','-t','ext4','-b','1024','-N',100500,'-O','dir_index,metadata_csum,^orphan_file',image])
 payload=tmp/'empty';payload.write_bytes(b'')
 script=tmp/'seed.commands';script.write_text('set_super_value def_hash_version half_md4\nmkdir /many\n'+''.join(f'write {payload} /many/seed-{i:04d}\n' for i in range(200)))
 run(['debugfs','-w','-f',script,image]);r=subprocess.run(['e2fsck','-fyD',str(image)],capture_output=True);check(r.returncode in (0,1),r.stdout+r.stderr)
 start=time.monotonic();run([a.work/'index-scale-fixture',image,a.names]);run(['e2fsck','-fn',image]);times['seed_seconds']=time.monotonic()-start
 stats=json.loads(run([a.work/'index-cache-unit',image]));check(stats['reused']==1001 and stats['full_scans']==7,stats)
 print('PASS large index and cache invalidation',stats,flush=True)
 root=tmp/'chain';chain.clone(image,root)
 with session.Session(root,a.work/'mutation-producer',a.work/'reader-server',Credentials(0,0)) as s:
  start=time.monotonic()
  held=[s.open('/many/scale-00000000') for unused in range(a.handles)]
  check(len({h._token for h in held})==a.handles)
  if a.handles==8192:
   head=s.state['head'];denied(lambda:s.open('/many/scale-00000000','w',truncate=True),errno.EMFILE);check(s.state['head']==head)
  old=held[0]._token;held[0].close();replacement=s.open('/many/scale-00000000');check(replacement._token!=old)
  denied(lambda:s._rpc(9,struct.pack('<Q',old)),errno.EBADF)
  for h in held:h.close()
  replacement.close();times['handles_seconds']=time.monotonic()-start
  print('PASS concurrent data handles',a.handles,flush=True)
  s._mount_nodes();directory,ino,generation=s._mount_lookup(None,'many')
  start=time.monotonic();nodes=[s._mount_lookup(directory,f'scale-{i:08d}')[0] for i in range(a.pins)]
  _,pins=s._rpc(12);check(len(pins)//8==a.pins+1,'unique pin snapshot lost nodes')
  check(s._mount_lookup(directory,'scale-00000000')[0] is nodes[0],'lookup pin was duplicated')
  # A real transaction must carry more than the old 4096 pins safely.
  s.rename('/many/scale-00000000','/many/renamed');s.unlink('/many/renamed')
  writer=s._mount_open_node(nodes[0],3);writer.write(b'held after unlink');check(writer.read()==b'held after unlink');writer.close()
  for h in nodes:h.close()
  directory.close();check(s._rpc(12)[0]==0,'orphan survived its last pin');times['pins_seconds']=time.monotonic()-start
  start=time.monotonic()
  with s.opendir('/many') as d:
   count=0;seen=set()
   while True:
    page=d.readdir(4096,max_bytes=1024*1024)
    for entry in page['entries']:
     name=entry['name'];check(name not in seen,'duplicate stream name');seen.add(name);count+=1
    if page['eof']:break
   check(count==a.names+201,'large stream lost entries')
  times['stream_seconds']=time.monotonic()-start
  # Mutation on the large directory validates the changed view, including rollback.
  head=s.state['head']
  denied(lambda:s.apply([dict(kind='create',path='/many/rollback',data_hex=''),dict(kind='unlink',path='/many/missing')]),errno.ENOENT)
  check(s.state['head']==head)
  s.mkdir('/many/sub');s.rmdir('/many/sub')
 run(['e2fsck','-fn',root/'image.img'])
 # A small-pool build proves C preflight fails before a durable create, without
 # requiring a default-sized exhaustion workload in every regression job.
 here=Path(__file__).resolve().parent
 spec=importlib.util.spec_from_file_location('scaling_broker',here/'mount-broker.py');broker=importlib.util.module_from_spec(spec);spec.loader.exec_module(broker)
 with session.Session(root,a.work/'mutation-producer',a.work/'reader-server-handle-limits',Credentials(0,0)) as s:
  s.chmod('/',0o777);s.chmod('/many',0o777)
  b=broker.LowBroker(s)
  def call(op,ino=1,path=b'',arg=0):return b.dispatch(op,path,b'',os.getuid(),os.getgid(),0,os.getgroups(),ino,0,arg)
  call(100,ino=0);directory,_=call(101,path=b'many')
  for i in range(1,255):call(101,directory,path=f'scale-{i:08d}'.encode())
  head=s.state['head'];denied(lambda:call(105,directory,path=b'exhausted',arg=(0o600<<32)|os.O_CREAT|os.O_RDWR),errno.EMFILE);check(s.state['head']==head)
  for number,node in list(b.nodes.items()):
   if number!=1:call(102,number,arg=node['lookups'])
  check(len(b.nodes)==1)
 if a.mount:
  soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE);native_count=600 if hard==resource.RLIM_INFINITY else min(600,hard-64)
  check(native_count>128,'host fd limit too small')
  resource.setrlimit(resource.RLIMIT_NOFILE,(max(soft,native_count+64),hard))
  mount=tmp/'mnt';mount.mkdir();fds=[];proc=None;active=False;logpath=tmp/'mount.log'
  try:
   with logpath.open('wb') as log:
    proc=subprocess.Popen([sys.executable,here/'mount-broker.py','--root',root,'--work',a.work,'--mountpoint',mount],stdout=log,stderr=log)
    for unused in range(200):
     if os.path.ismount(mount):active=True;break
     if proc.poll() is not None:break
     time.sleep(.1)
    check(active,logpath.read_text())
    for i in range(1,native_count+1):fds.append(os.open(mount/'many'/f'scale-{i:08d}',os.O_RDONLY))
    check(len(fds)==native_count);check(all(os.read(fd,1)==b'' for fd in fds))
    names=os.listdir(mount/'many');check(len(names)==a.names+199 and len(names)==len(set(names)),'native large readdir lost names')
    for fd in fds:os.close(fd)
    fds=[]
    command=['/sbin/umount',mount] if sys.platform=='darwin' else ['fusermount3','-u',mount]
    run(command);active=False;check(proc.wait(timeout=30)==0,logpath.read_text())
  finally:
   for fd in fds:os.close(fd)
   if active and os.path.ismount(mount):subprocess.run(['/sbin/umount',mount] if sys.platform=='darwin' else ['fusermount3','-u',mount],check=True)
   if proc and proc.poll() is None:proc.wait(timeout=30)
   resource.setrlimit(resource.RLIMIT_NOFILE,(soft,hard))
  run(['e2fsck','-fn',root/'image.img']);print('PASS native mounted scaling',native_count,'fds',len(names),'names',flush=True)
 report=dict(result='passed',checks=checks,names=a.names,handles=a.handles,pins=a.pins,cache=stats,times=times,mounted=a.mount,native_handles=native_count if a.mount else 0,native_names=len(names) if a.mount else 0)
 (a.work/'scaling-results.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS scaling',report,flush=True)
