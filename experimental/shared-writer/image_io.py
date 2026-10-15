# SPDX-License-Identifier: GPL-2.0-only
"""Explicit process-local device views; ordinary image paths retain file I/O."""
import contextlib,os,stat,threading
from pathlib import Path
_views={}
_lock=threading.RLock()

def key(path):return str(Path(path).absolute())

def lookup(path):
 with _lock:return _views.get(key(path))

@contextlib.contextmanager
def register(path,view):
 name=key(path)
 with _lock:
  if name in _views:raise ValueError('device view already registered')
  _views[name]=view
 try:yield
 finally:
  with _lock:
   if _views.pop(name,None) is not view:raise ValueError('device view registration changed')

def opened(path,writable=False):
 view=lookup(path)
 if view is not None:return view.open(writable)
 fd=os.open(path,(os.O_RDWR if writable else os.O_RDONLY)|os.O_NOFOLLOW)
 if not stat.S_ISREG(os.fstat(fd).st_mode):os.close(fd);raise ValueError('only regular image files are supported')
 return os.fdopen(fd,'r+b' if writable else 'rb',buffering=0)

def write_at(image,data,offset):
 if hasattr(image,'write_at'):return image.write_at(data,offset)
 return os.pwrite(image.fileno(),data,offset)

def flush(image):
 from durable import sync
 if hasattr(image,'flush_device'):image.flush_device()
 sync(image.fileno())

def child(path):
 """Only explicitly selected native reader/producer children get read access."""
 view=lookup(path);env=dict(os.environ);env.pop('EXT4_DEVICE_VIEW',None)
 if view is None:return dict(env=env)
 env['EXT4_DEVICE_VIEW']=view.config()
 return dict(env=env,pass_fds=(view.read_fd,))
