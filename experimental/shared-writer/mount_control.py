# SPDX-License-Identifier: GPL-2.0-only
"""Explicitly enabled, owner-only bounded control socket outside the filesystem."""
import contextlib,ctypes,errno,json,os,socket,stat,struct,sys,threading
from pathlib import Path
from credentials import Credentials

@contextlib.contextmanager
def control(s,path,notify):
 if path is None:yield;return
 path=Path(path).absolute();parent=path.parent
 info=os.lstat(parent)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077 or parent.is_symlink():
  raise ValueError('control socket parent must be a private owned directory')
 if path.exists() or path.is_symlink():raise FileExistsError(path)
 if path.resolve().is_relative_to(s.root):raise ValueError('control socket must be outside chain')
 identity=None
 server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);stop=threading.Event();thread=None
 try:
  server.bind(str(path));os.chmod(path,0o600);server.listen(4);server.settimeout(.2)
  identity=os.lstat(path)
  def serve():
   while not stop.is_set():
    try:client,_=server.accept()
    except socket.timeout:continue
    except OSError:break
    with client:
     try:
      client.settimeout(2)
      if sys.platform=='linux':
       _,uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
      elif sys.platform=='darwin':
       peer_uid=ctypes.c_uint();peer_gid=ctypes.c_uint();getpeer=ctypes.CDLL(None,use_errno=True).getpeereid
       getpeer.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)]
       if getpeer(client.fileno(),ctypes.byref(peer_uid),ctypes.byref(peer_gid)):raise OSError(errno.EACCES,'peer credentials unavailable')
       uid=peer_uid.value
      else:raise OSError(errno.EOPNOTSUPP,'peer authentication unavailable')
      if uid!=os.getuid():raise OSError(errno.EACCES,'private mount owner required')
      with client.makefile('rb') as f:
       raw=f.readline(32769)
      if len(raw)>32768 or not raw.endswith(b'\n'):raise ValueError('bounded control frame required')
      request=json.loads(raw)
      if not isinstance(request,dict) or set(request)!={'operation','path','offset','length'}:raise ValueError('control schema')
      mode={'allocate':0,'keep-size':1,'punch':3}.get(request['operation'])
      name=request['path'];offset=request['offset'];length=request['length']
      if mode is None or not isinstance(name,str) or not name.startswith('/') or '\0' in name or len(os.fsencode(name))>4096:raise ValueError('control operation or path')
      if type(offset) is not int or type(length) is not int or not 0<=offset<2**63 or not 0<length<=2**63-1-offset:raise ValueError('control range')
      # No untrusted inode grants or credentials enter this protocol. The private
      # directory admits only the launching owner; normal write policy applies.
      with s._mutex:
       s._mount_context(Credentials(os.getuid(),os.getgid(),tuple(os.getgroups()),0o077))
       with s.openat(None,name,'w') as h:
        inode=int.from_bytes(s._mount_stat(handle=h)[:8],'little')
        state=h.allocate(offset,length,mode)
      notify(inode)
      reply=dict(error=0,head=state['head'])
     except (ValueError,TypeError,KeyError,RecursionError,json.JSONDecodeError) as e:reply=dict(error=errno.EINVAL,message=str(e))
     except OSError as e:reply=dict(error=e.errno or errno.EIO,message=str(e))
     try:client.sendall(json.dumps(reply).encode()+b'\n')
     except OSError:pass
  thread=threading.Thread(target=serve,name='ext4-mount-control',daemon=True);thread.start()
  yield
 finally:
  stop.set()
  if thread:thread.join(timeout=5)
  server.close()
  # Never remove an unrelated replacement path.
  if identity is not None and path.exists():
   now=os.lstat(path)
   if (now.st_dev,now.st_ino)==(identity.st_dev,identity.st_ino):path.unlink()
  if thread and thread.is_alive():raise RuntimeError('control operation still running at unmount')
