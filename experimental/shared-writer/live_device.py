# SPDX-License-Identifier: GPL-2.0-only
"""Continuous device publication with an exclusively claimed, guarded target.

A private full-size shadow preserves the existing native reader/mutator. Every
acknowledged mutation reaches and flushes the device before the reader resumes.
Only a clean close restores the primary superblock magic. External journal and
shadow storage must survive together; this is not native JBD2 journaling.
"""
import contextlib
import importlib.util
import os
from pathlib import Path

import chain
import inplace
import merkle
from durable import regular, digest, directory, sync, boundary
from device_admission import Device, PAGE, refuse

spec = importlib.util.spec_from_file_location('offline_device', Path(__file__).with_name('device-writer.py'))
offline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(offline)
MAGIC = offline.MAGIC
STATE_FIELDS = {'version','identity','size','sector','uuid','head','sha256','phase'}
PENDING_FIELDS = {'version','head','count','base_sha256','sha256','log_sha256'}


def valid_hash(value):
    return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)


def validate_state(state,target):
    if not isinstance(state,dict) or set(state)!=STATE_FIELDS or type(state['version']) is not int or state['version']!=1:
        refuse('invalid continuous device state')
    if (state['identity'],state['size'],state['sector'])!=(target.identity,target.size,target.sector):
        refuse('continuous target identity or geometry changed')
    if type(state['head']) is not int or not 0<=state['head']<99_999_999 or not valid_hash(state['sha256']):
        refuse('invalid continuous head or root')
    if type(state['size']) is not int or type(state['sector']) is not int or state['size']<=0 or state['size']%PAGE:
        refuse('invalid continuous capacity')
    if state['phase'] not in ('clean','arming','active','closing'):
        refuse('invalid continuous guard phase')
    uuid=state['uuid']
    if not isinstance(uuid,str) or len(uuid)!=32 or not all(c in '0123456789abcdef' for c in uuid) or uuid=='0'*32:
        refuse('invalid continuous filesystem UUID')


class DeviceView:
    """Aligned reads with only the deliberately guarded magic normalized."""
    def __init__(self,target):
        self.target=target;self.position=0
    def seek(self,offset):
        if not 0<=offset<=self.target.size or offset%PAGE:
            refuse('unaligned guarded device read')
        self.position=offset
    def read(self,n):
        if n<0 or n%self.target.sector or self.position+n>self.target.size:
            refuse('invalid guarded device read bounds')
        pos=self.position
        data=bytearray(offline.read_at(self.target.fd,n,pos))
        if pos<=MAGIC and MAGIC+2<=pos+n:
            data[MAGIC-pos:MAGIC-pos+2]=b'\x53\xef'
        self.position+=n
        return bytes(data)


def scan(target):
    target.check()
    tree=merkle.Tree(target.size);view=DeviceView(target)
    for i in range(tree.count):
        view.seek(i*merkle.CHUNK)
        tree.set(tree.width+i,merkle.leaf(i,view.read(min(merkle.CHUNK,target.size-i*merkle.CHUNK))))
    tree.finish();target.check()
    return tree


def magic(target):
    start=MAGIC//target.sector*target.sector
    return offline.read_at(target.fd,target.sector,start)[MAGIC-start:MAGIC-start+2]


def guard(target):
    target.check();start=MAGIC//target.sector*target.sector
    data=bytearray(offline.read_at(target.fd,target.sector,start))
    data[MAGIC-start:MAGIC-start+2]=b'\0\0'
    offline.write_at(target.fd,data,start);target.flush()
    if offline.read_at(target.fd,target.sector,start)!=data:
        refuse('continuous device guard did not persist')
    boundary('live:guarded')


def init(device,root):
    """Capture one owned shadow while holding admission; no target writes."""
    root=inplace.block.canonical(root);root.mkdir(mode=0o700);directory(root.parent)
    with offline.locked(root),Device(device,root) as target:
        merkle.Tree(target.size) # reject over-budget geometry before copying
        if magic(target)!=b'\x53\xef':refuse('initial device must have an intact primary superblock')
        baseline=scan(target)
        managed=root/'chain';managed.mkdir(mode=0o700);directory(root)
        fd=os.open(managed/'image.img',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as copied:
            for pos in range(0,target.size,merkle.CHUNK):
                copied.write(offline.read_at(target.fd,min(merkle.CHUNK,target.size-pos),pos))
            copied.flush();sync(copied.fileno())
        directory(managed)
        uuid=offline.clean_image(managed/'image.img',target.size)
        with regular(managed/'image.img') as image:
            st=os.fstat(image.fileno())
            saved=dict(version=2,algorithm=merkle.ALGORITHM,head=0,pending=None,
                       sha256=baseline.root(),device=st.st_dev,inode=st.st_ino,size=target.size)
            if merkle.scan(image,saved).root()!=baseline.root():refuse('device snapshot differs')
        target.check()
        if scan(target).root()!=baseline.root() or magic(target)!=b'\x53\xef':refuse('device changed during continuous snapshot')
        inplace.seal(managed,'chain-state',saved)
        inplace.seal(root,'live-state',dict(version=1,identity=target.identity,size=target.size,
                     sector=target.sector,uuid=uuid,head=0,sha256=baseline.root(),phase='clean'))
    return root


class Controller:
    """Own device admission/lock for the entire Session and FUSE mount lifetime."""
    def __init__(self,root,device):
        self.root=Path(root);self.path=device;self.target=None;self.tree=None;self.failed=False;self.stack=None
        self.chain=self.root/'chain'
    def __enter__(self):
        self.stack=contextlib.ExitStack()
        try:
            self.root=self.stack.enter_context(offline.locked(self.root));self.chain=self.root/'chain'
            self.target=self.stack.enter_context(Device(self.path,self.root))
            self.state=offline.load(self.root,'live-state');validate_state(self.state,self.target)
            return self
        except BaseException:
            self.stack.close();raise
    def __exit__(self,*unused):
        # Never publish a clean superblock just because an exception unwinds.
        # Successful callers explicitly finish after Session releases all pins.
        self.stack.close()
    def _seal_state(self,**changes):
        updated=dict(self.state,**changes)
        inplace.seal(self.root,'live-state',updated)
        self.state=updated
    def _require_guard(self):
        self.target.check()
        if magic(self.target)!=b'\0\0':refuse('active device guard changed')
    def _check_shadow(self,current):
        if (current['version']!=2 or current['algorithm']!=merkle.ALGORITHM or
            current['pending'] is not None or current['size']!=self.target.size or current['head']<self.state['head']):
            refuse('continuous shadow state is stale or incompatible')
        with regular(self.chain/'image.img') as image:
            sb=offline.read_at(image.fileno(),1024,1024)
            if sb[56:58]!=b'\x53\xef' or sb[104:120].hex()!=self.state['uuid']:
                refuse('continuous shadow filesystem identity changed')
    def _activate(self):
        phase=self.state['phase']
        if phase=='closing':
            self._complete_close()
            phase='clean'
        if phase=='clean':
            if magic(self.target)!=b'\x53\xef':refuse('clean continuous device was changed')
            self.tree=scan(self.target)
            if self.tree.root()!=self.state['sha256']:refuse('clean device differs from committed root')
            self._seal_state(phase='arming');boundary('live:arming')
            phase='arming'
        if phase=='arming':
            # A crash while installing the guard may tear its two reserved bytes.
            # Every other byte must still match the fully committed old root.
            self.tree=scan(self.target)
            if self.tree.root()!=self.state['sha256']:refuse('device changed while arming guard')
            guard(self.target);self._seal_state(phase='active');boundary('live:active')
        self._require_guard()
    def _generation(self,pending):
        if not isinstance(pending,dict) or set(pending)!=PENDING_FIELDS or type(pending['version']) is not int or pending['version']!=1:
            refuse('invalid continuous pending schema')
        if type(pending['head']) is not int or not 1<=pending['head']<99_999_999:
            refuse('invalid continuous pending head')
        if type(pending['count']) is not int or not 0<=pending['count']<=min(merkle.MAX_RECORDS,self.target.size//PAGE):
            refuse('invalid continuous redo bounds')
        for key in ('base_sha256','sha256','log_sha256'):
            if not valid_hash(pending[key]):refuse('invalid continuous pending hash')
        generation=self.chain/f"g-{pending['head']:08d}"
        chain.inspect_tree(generation,os.lstat(self.chain).st_dev)
        meta=offline.load(generation,'transaction')
        with regular(self.chain/'image.img') as image:
            info=os.fstat(image.fileno())
        if (set(meta)!=inplace.FIELDS|{'algorithm'} or type(meta['version']) is not int or
            meta['version']!=3 or meta['algorithm']!=merkle.ALGORITHM or
            (meta['device'],meta['inode'],meta['size'])!=(info.st_dev,info.st_ino,self.target.size) or
            (meta['count'],meta['base_sha256'],meta['image_sha256'],meta['log_sha256'])!=
            (pending['count'],pending['base_sha256'],pending['sha256'],pending['log_sha256'])):
            refuse('continuous redo does not match sealed shadow generation')
        with regular(generation/'pages') as log:
            st=os.fstat(log.fileno())
            if st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_size!=pending['count']*inplace.RECORD.size or digest(log)!=pending['log_sha256']:
                refuse('continuous redo log integrity mismatch')
        return generation
    def _marker(self,pending):
        return dict(head=pending['head'],log_sha256=pending['log_sha256'],identity=self.state['identity'])
    def _clear_pending(self):
        for name in ('live-started','live-started.pending','live-pending','live-pending.pending'):
            path=self.root/name
            if path.exists() or path.is_symlink():
                with regular(path) as f:
                    st=os.fstat(f.fileno())
                    if st.st_uid!=os.getuid() or st.st_nlink!=1:refuse('unsafe continuous retirement marker')
                path.unlink();directory(self.root);boundary('live:retire-marker')
        boundary('live:retired')
    def _replay(self,pending):
        self._require_guard();generation=self._generation(pending)
        started=(self.root/'live-started').exists() or (self.root/'live-started').is_symlink()
        if started and offline.load(self.root,'live-started')!=self._marker(pending):refuse('continuous start marker changed')
        if pending['head']==self.state['head']:
            if pending['sha256']!=self.state['sha256']:refuse('stale continuous pending root')
            verified=scan(self.target)
            if verified.root()!=self.state['sha256']:refuse('completed continuous device changed')
            self.tree=verified;self._clear_pending();return
        if pending['head']!=self.state['head']+1 or pending['base_sha256']!=self.state['sha256']:
            refuse('continuous redo does not extend device head')
        cold=self.tree is None
        tree=merkle.Tree(self.target.size) if cold else self.tree
        with regular(generation/'pages') as log:
            changes=merkle.plan(DeviceView(self.target),log,pending['count'],tree,'partial' if started else 'base',cold)
            if tree.root()!=pending['base_sha256'] or tree.root(changes)!=pending['sha256']:
                refuse('clean device bytes or continuous preimages changed')
            boundary('live:validated')
            if not started:inplace.seal(self.root,'live-started',self._marker(pending))
            boundary('live:started')
            for number,(index,old,new) in enumerate(merkle.records(log,pending['count'],self.target.size)):
                data=bytearray(new)
                if index==0:data[MAGIC:MAGIC+2]=b'\0\0'
                for at in range(0,PAGE,self.target.sector):
                    self.target.check();offline.write_at(self.target.fd,data[at:at+self.target.sector],index*PAGE+at)
                    boundary(f'live:sector:{number}:{at//self.target.sector}')
            self.target.flush();boundary('live:data-synced')
            self._require_guard()
            # Authenticate touched chunks, including all their clean bytes, and
            # verify every new logged page before advancing the durable head.
            merkle.plan(DeviceView(self.target),log,pending['count'],tree,'result')
            boundary('live:verified')
        self._seal_state(head=pending['head'],sha256=pending['sha256'])
        boundary('live:head-published')
        tree.commit(changes);self.tree=tree
        self._clear_pending()
    def recover(self,current):
        self._check_shadow(current)
        self._activate()
        # Startup/crash recovery always builds a cold device tree, including
        # every untouched chunk. Warm publication alone uses the cached tree.
        self.tree=None
        pending_path=self.root/'live-pending'
        if pending_path.exists() or pending_path.is_symlink():
            self._replay(offline.load(self.root,'live-pending'))
        elif (self.root/'live-started').exists() or (self.root/'live-started').is_symlink():
            refuse('continuous start marker has no sealed transaction')
        if self.tree is None:
            self.tree=scan(self.target)
            if self.tree.root()!=self.state['sha256']:refuse('continuous device edited outside journal')
        while self.state['head']<current['head']:
            self._publish_head(self.state['head']+1)
        if self.state['sha256']!=current['sha256']:refuse('shadow and continuous device heads diverged')
        boundary('live:recovered')
    def _publish_head(self,head):
        generation=self.chain/f'g-{head:08d}'
        meta=offline.load(generation,'transaction')
        pending=dict(version=1,head=head,count=meta['count'],base_sha256=meta['base_sha256'],
                     sha256=meta['image_sha256'],log_sha256=meta['log_sha256'])
        self._generation(pending)
        if pending['base_sha256']!=self.state['sha256']:refuse('continuous successor has wrong base root')
        inplace.seal(self.root,'live-pending',pending);boundary('live:prepared')
        self._replay(pending)
    def publish(self,previous,current):
        try:
            self._check_shadow(current);self._require_guard()
            if (previous['head'],previous['sha256'])!=(self.state['head'],self.state['sha256']) or current['head']!=previous['head']+1:
                refuse('continuous session/device epoch changed')
            self._publish_head(current['head'])
            if self.state['sha256']!=current['sha256']:refuse('continuous published head differs from shadow')
            boundary('live:acknowledge-ready')
        except BaseException:
            self.failed=True;raise
    def checkpoint(self,current):
        if self.failed:refuse('failed continuous device session requires recovery')
        self._check_shadow(current);self._require_guard()
        if (current['head'],current['sha256'])!=(self.state['head'],self.state['sha256']) or (self.root/'live-pending').exists():
            refuse('continuous checkpoint has outstanding publication')
        verified=scan(self.target)
        if verified.root()!=self.state['sha256']:refuse('continuous checkpoint found untouched corruption')
        self.tree=verified;boundary('live:checkpoint-verified')
    def _complete_close(self):
        if (self.root/'live-pending').exists() or (self.root/'live-started').exists():refuse('close has outstanding redo')
        verified=scan(self.target)
        if verified.root()!=self.state['sha256']:refuse('device changed during continuous close')
        with regular(self.chain/'image.img') as image:
            state=chain.read_state(self.chain)
            if (state['head'],state['sha256'])!=(self.state['head'],self.state['sha256']):refuse('shadow changed during continuous close')
            merkle.identity(image,state)
            if merkle.scan(image,state).root()!=self.state['sha256']:refuse('closing shadow bytes changed')
            if offline.clean_image(self.chain/'image.img',self.target.size)!=self.state['uuid']:refuse('closing filesystem identity changed')
            start=MAGIC//self.target.sector*self.target.sector
            image.seek(start);clean=image.read(self.target.sector)
        self.target.check();offline.write_at(self.target.fd,clean,start);self.target.flush()
        boundary('live:magic-restored')
        if magic(self.target)!=b'\x53\xef' or scan(self.target).root()!=self.state['sha256']:
            refuse('clean continuous publication verification failed')
        self._seal_state(phase='clean');boundary('live:closed')
    def abort(self):
        self.failed=True
    def finish(self):
        if self.failed:refuse('failed continuous session must keep its device guarded')
        with chain.locked(self.chain):
            current=chain.recover_locked(self.chain)
            self.recover(current)
            self.checkpoint(current)
            if offline.clean_image(self.chain/'image.img',self.target.size)!=self.state['uuid']:
                refuse('continuous clean-close filesystem identity changed')
            self._seal_state(phase='closing');boundary('live:closing')
            self._complete_close()
